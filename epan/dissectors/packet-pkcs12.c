/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* ./packet-pkcs12.c                                                          */
/* ../../tools/asn2wrs.py -b -e -p pkcs12 -c pkcs12.cnf -s packet-pkcs12-template pkcs12.asn */

/* Input file: packet-pkcs12-template.c */

#line 1 "packet-pkcs12-template.c"
/* packet-pkcs12.c
 * Routines for PKCS#12: Personal Information Exchange packet dissection
 * Graeme Lunt 2006
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/oid_resolv.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-pkcs12.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-cms.h"

#define PNAME  "PKCS#12: Personal Information Exchange"
#define PSNAME "PKCS12"
#define PFNAME "pkcs12"

/* Initialize the protocol and registered fields */
int proto_pkcs12 = -1;

static const char *object_identifier_id = NULL; 
static const gchar *pref_password = NULL;


static void dissect_AuthenticatedSafe_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_SafeContents_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/*--- Included file: packet-pkcs12-hf.c ---*/
#line 1 "packet-pkcs12-hf.c"
static int hf_pkcs12_PFX_PDU = -1;                /* PFX */
static int hf_pkcs12_AuthenticatedSafe_PDU = -1;  /* AuthenticatedSafe */
static int hf_pkcs12_SafeContents_PDU = -1;       /* SafeContents */
static int hf_pkcs12_KeyBag_PDU = -1;             /* KeyBag */
static int hf_pkcs12_PKCS8ShroudedKeyBag_PDU = -1;  /* PKCS8ShroudedKeyBag */
static int hf_pkcs12_CertBag_PDU = -1;            /* CertBag */
static int hf_pkcs12_CRLBag_PDU = -1;             /* CRLBag */
static int hf_pkcs12_SecretBag_PDU = -1;          /* SecretBag */
static int hf_pkcs12_EncryptedPrivateKeyInfo_PDU = -1;  /* EncryptedPrivateKeyInfo */
static int hf_pkcs12_PBEParameter_PDU = -1;       /* PBEParameter */
static int hf_pkcs12_PBKDF2Params_PDU = -1;       /* PBKDF2Params */
static int hf_pkcs12_PBES2Params_PDU = -1;        /* PBES2Params */
static int hf_pkcs12_PBMAC1Params_PDU = -1;       /* PBMAC1Params */
static int hf_pkcs12_version = -1;                /* T_version */
static int hf_pkcs12_authSafe = -1;               /* ContentInfo */
static int hf_pkcs12_macData = -1;                /* MacData */
static int hf_pkcs12_mac = -1;                    /* DigestInfo */
static int hf_pkcs12_macSalt = -1;                /* OCTET_STRING */
static int hf_pkcs12_iterations = -1;             /* INTEGER */
static int hf_pkcs12_digestAlgorithm = -1;        /* DigestAlgorithmIdentifier */
static int hf_pkcs12_digest = -1;                 /* Digest */
static int hf_pkcs12_AuthenticatedSafe_item = -1;  /* ContentInfo */
static int hf_pkcs12_SafeContents_item = -1;      /* SafeBag */
static int hf_pkcs12_bagId = -1;                  /* OBJECT_IDENTIFIER */
static int hf_pkcs12_bagValue = -1;               /* T_bagValue */
static int hf_pkcs12_bagAttributes = -1;          /* SET_OF_PKCS12Attribute */
static int hf_pkcs12_bagAttributes_item = -1;     /* PKCS12Attribute */
static int hf_pkcs12_certId = -1;                 /* OBJECT_IDENTIFIER */
static int hf_pkcs12_certValue = -1;              /* T_certValue */
static int hf_pkcs12_crlId = -1;                  /* OBJECT_IDENTIFIER */
static int hf_pkcs12_crlValue = -1;               /* T_crlValue */
static int hf_pkcs12_secretTypeId = -1;           /* OBJECT_IDENTIFIER */
static int hf_pkcs12_secretValue = -1;            /* T_secretValue */
static int hf_pkcs12_attrId = -1;                 /* OBJECT_IDENTIFIER */
static int hf_pkcs12_attrValues = -1;             /* T_attrValues */
static int hf_pkcs12_attrValues_item = -1;        /* T_attrValues_item */
static int hf_pkcs12_privateKeyVersion = -1;      /* Version */
static int hf_pkcs12_privateKeyAlgorithm = -1;    /* AlgorithmIdentifier */
static int hf_pkcs12_privateKey = -1;             /* PrivateKey */
static int hf_pkcs12_attributes = -1;             /* Attributes */
static int hf_pkcs12_Attributes_item = -1;        /* Attribute */
static int hf_pkcs12_encryptionAlgorithm = -1;    /* AlgorithmIdentifier */
static int hf_pkcs12_encryptedData = -1;          /* EncryptedData */
static int hf_pkcs12_salt = -1;                   /* OCTET_STRING */
static int hf_pkcs12_iterationCount = -1;         /* INTEGER */
static int hf_pkcs12_saltChoice = -1;             /* T_saltChoice */
static int hf_pkcs12_specified = -1;              /* OCTET_STRING */
static int hf_pkcs12_otherSource = -1;            /* AlgorithmIdentifier */
static int hf_pkcs12_keyLength = -1;              /* INTEGER_1_MAX */
static int hf_pkcs12_prf = -1;                    /* AlgorithmIdentifier */
static int hf_pkcs12_keyDerivationFunc = -1;      /* AlgorithmIdentifier */
static int hf_pkcs12_encryptionScheme = -1;       /* AlgorithmIdentifier */
static int hf_pkcs12_messageAuthScheme = -1;      /* AlgorithmIdentifier */

/*--- End of included file: packet-pkcs12-hf.c ---*/
#line 59 "packet-pkcs12-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkcs12-ett.c ---*/
#line 1 "packet-pkcs12-ett.c"
static gint ett_pkcs12_PFX = -1;
static gint ett_pkcs12_MacData = -1;
static gint ett_pkcs12_DigestInfo = -1;
static gint ett_pkcs12_AuthenticatedSafe = -1;
static gint ett_pkcs12_SafeContents = -1;
static gint ett_pkcs12_SafeBag = -1;
static gint ett_pkcs12_SET_OF_PKCS12Attribute = -1;
static gint ett_pkcs12_CertBag = -1;
static gint ett_pkcs12_CRLBag = -1;
static gint ett_pkcs12_SecretBag = -1;
static gint ett_pkcs12_PKCS12Attribute = -1;
static gint ett_pkcs12_T_attrValues = -1;
static gint ett_pkcs12_PrivateKeyInfo = -1;
static gint ett_pkcs12_Attributes = -1;
static gint ett_pkcs12_EncryptedPrivateKeyInfo = -1;
static gint ett_pkcs12_PBEParameter = -1;
static gint ett_pkcs12_PBKDF2Params = -1;
static gint ett_pkcs12_T_saltChoice = -1;
static gint ett_pkcs12_PBES2Params = -1;
static gint ett_pkcs12_PBMAC1Params = -1;

/*--- End of included file: packet-pkcs12-ett.c ---*/
#line 62 "packet-pkcs12-template.c"


/*--- Included file: packet-pkcs12-fn.c ---*/
#line 1 "packet-pkcs12-fn.c"
/*--- Fields for imported types ---*/

static int dissect_authSafe(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentInfo(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_authSafe);
}
static int dissect_digestAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_DigestAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_digestAlgorithm);
}
static int dissect_digest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Digest(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_digest);
}
static int dissect_AuthenticatedSafe_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentInfo(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_AuthenticatedSafe_item);
}
static int dissect_privateKeyAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_privateKeyAlgorithm);
}
static int dissect_Attributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_Attributes_item);
}
static int dissect_encryptionAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_encryptionAlgorithm);
}
static int dissect_otherSource(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_otherSource);
}
static int dissect_prf(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_prf);
}
static int dissect_keyDerivationFunc(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_keyDerivationFunc);
}
static int dissect_encryptionScheme(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_encryptionScheme);
}
static int dissect_messageAuthScheme(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_messageAuthScheme);
}


static const value_string pkcs12_T_version_vals[] = {
  {   3, "v3" },
  { 0, NULL }
};


static int
dissect_pkcs12_T_version(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_T_version(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_version);
}


static const ber_sequence_t DigestInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_digestAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_digest },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_DigestInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DigestInfo_sequence, hf_index, ett_pkcs12_DigestInfo);

  return offset;
}
static int dissect_mac(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_DigestInfo(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_mac);
}



static int
dissect_pkcs12_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_macSalt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_macSalt);
}
static int dissect_salt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_salt);
}
static int dissect_specified(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_specified);
}



static int
dissect_pkcs12_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_iterations(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_iterations);
}
static int dissect_iterationCount(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_iterationCount);
}


static const ber_sequence_t MacData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mac },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_macSalt },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_iterations },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_MacData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MacData_sequence, hf_index, ett_pkcs12_MacData);

  return offset;
}
static int dissect_macData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_MacData(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_macData);
}


static const ber_sequence_t PFX_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_authSafe },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_macData },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PFX(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 60 "pkcs12.cnf"
	dissector_handle_t dissector_handle;

	/* we change the CMS id-data dissector to dissect as AuthenticatedSafe
	   not sure why PKCS#12 couldn't have used its own content type OID for AuthenticatedSafe */
	dissector_handle=create_dissector_handle(dissect_AuthenticatedSafe_OCTETSTRING_PDU, proto_pkcs12);
	dissector_change_string("ber.oid", "1.2.840.113549.1.7.1", dissector_handle);

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PFX_sequence, hf_index, ett_pkcs12_PFX);


	/* restore the original dissector */
	dissector_reset_string("ber.oid", "1.2.840.113549.1.7.1");



  return offset;
}


static const ber_sequence_t AuthenticatedSafe_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AuthenticatedSafe_item },
};

static int
dissect_pkcs12_AuthenticatedSafe(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 73 "pkcs12.cnf"
	dissector_handle_t dissector_handle;

	/* we change the CMS id-data dissector to dissect as SafeContents */
	dissector_handle=create_dissector_handle(dissect_SafeContents_OCTETSTRING_PDU, proto_pkcs12);
	dissector_change_string("ber.oid", "1.2.840.113549.1.7.1", dissector_handle);

	  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AuthenticatedSafe_sequence_of, hf_index, ett_pkcs12_AuthenticatedSafe);


	/* restore the original dissector */
	dissector_reset_string("ber.oid", "1.2.840.113549.1.7.1");



  return offset;
}



static int
dissect_pkcs12_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 88 "pkcs12.cnf"
  	const char *name = NULL;

	  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &object_identifier_id);

  
	name = get_oid_str_name(object_identifier_id);
	proto_item_append_text(tree, " (%s)", name ? name : object_identifier_id); 



  return offset;
}
static int dissect_bagId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_bagId);
}
static int dissect_certId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_certId);
}
static int dissect_crlId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_crlId);
}
static int dissect_secretTypeId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_secretTypeId);
}
static int dissect_attrId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_attrId);
}



static int
dissect_pkcs12_T_bagValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 96 "pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_bagValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_T_bagValue(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_bagValue);
}



static int
dissect_pkcs12_T_attrValues_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 100 "pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_attrValues_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_T_attrValues_item(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_attrValues_item);
}


static const ber_sequence_t T_attrValues_set_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_attrValues_item },
};

static int
dissect_pkcs12_T_attrValues(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_attrValues_set_of, hf_index, ett_pkcs12_T_attrValues);

  return offset;
}
static int dissect_attrValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_T_attrValues(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_attrValues);
}


static const ber_sequence_t PKCS12Attribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attrId },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_attrValues },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PKCS12Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PKCS12Attribute_sequence, hf_index, ett_pkcs12_PKCS12Attribute);

  return offset;
}
static int dissect_bagAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_PKCS12Attribute(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_bagAttributes_item);
}


static const ber_sequence_t SET_OF_PKCS12Attribute_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_bagAttributes_item },
};

static int
dissect_pkcs12_SET_OF_PKCS12Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_PKCS12Attribute_set_of, hf_index, ett_pkcs12_SET_OF_PKCS12Attribute);

  return offset;
}
static int dissect_bagAttributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_SET_OF_PKCS12Attribute(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_bagAttributes);
}


static const ber_sequence_t SafeBag_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_bagId },
  { BER_CLASS_CON, 0, 0, dissect_bagValue },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_bagAttributes },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_SafeBag(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SafeBag_sequence, hf_index, ett_pkcs12_SafeBag);

  return offset;
}
static int dissect_SafeContents_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_SafeBag(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_SafeContents_item);
}


static const ber_sequence_t SafeContents_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SafeContents_item },
};

static int
dissect_pkcs12_SafeContents(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SafeContents_sequence_of, hf_index, ett_pkcs12_SafeContents);

  return offset;
}


static const value_string pkcs12_Version_vals[] = {
  {   0, "v1" },
  { 0, NULL }
};


static int
dissect_pkcs12_Version(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_privateKeyVersion(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_Version(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_privateKeyVersion);
}



static int
dissect_pkcs12_PrivateKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_privateKey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_PrivateKey(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_privateKey);
}


static const ber_sequence_t Attributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Attributes_item },
};

static int
dissect_pkcs12_Attributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 Attributes_set_of, hf_index, ett_pkcs12_Attributes);

  return offset;
}
static int dissect_attributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_Attributes(TRUE, tvb, offset, pinfo, tree, hf_pkcs12_attributes);
}


static const ber_sequence_t PrivateKeyInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_privateKeyVersion },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_privateKeyAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_privateKey },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attributes_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PrivateKeyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PrivateKeyInfo_sequence, hf_index, ett_pkcs12_PrivateKeyInfo);

  return offset;
}



static int
dissect_pkcs12_KeyBag(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_pkcs12_PrivateKeyInfo(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_pkcs12_EncryptedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_encryptedData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_EncryptedData(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_encryptedData);
}


static const ber_sequence_t EncryptedPrivateKeyInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_encryptionAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_encryptedData },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_EncryptedPrivateKeyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EncryptedPrivateKeyInfo_sequence, hf_index, ett_pkcs12_EncryptedPrivateKeyInfo);

  return offset;
}



static int
dissect_pkcs12_PKCS8ShroudedKeyBag(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_pkcs12_EncryptedPrivateKeyInfo(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_pkcs12_T_certValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 104 "pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_certValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_T_certValue(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_certValue);
}


static const ber_sequence_t CertBag_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_certId },
  { BER_CLASS_CON, 0, 0, dissect_certValue },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_CertBag(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertBag_sequence, hf_index, ett_pkcs12_CertBag);

  return offset;
}



static int
dissect_pkcs12_T_crlValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 108 "pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_crlValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_T_crlValue(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_crlValue);
}


static const ber_sequence_t CRLBag_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_crlId },
  { BER_CLASS_CON, 0, 0, dissect_crlValue },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_CRLBag(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CRLBag_sequence, hf_index, ett_pkcs12_CRLBag);

  return offset;
}



static int
dissect_pkcs12_T_secretValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 112 "pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_secretValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_T_secretValue(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_secretValue);
}


static const ber_sequence_t SecretBag_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_secretTypeId },
  { BER_CLASS_CON, 0, 0, dissect_secretValue },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_SecretBag(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SecretBag_sequence, hf_index, ett_pkcs12_SecretBag);

  return offset;
}


static const ber_sequence_t PBEParameter_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_salt },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_iterationCount },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PBEParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PBEParameter_sequence, hf_index, ett_pkcs12_PBEParameter);

  return offset;
}


static const value_string pkcs12_T_saltChoice_vals[] = {
  {   0, "specified" },
  {   1, "otherSource" },
  { 0, NULL }
};

static const ber_choice_t T_saltChoice_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_specified },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_otherSource },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_T_saltChoice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_saltChoice_choice, hf_index, ett_pkcs12_T_saltChoice,
                                 NULL);

  return offset;
}
static int dissect_saltChoice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_T_saltChoice(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_saltChoice);
}



static int
dissect_pkcs12_INTEGER_1_MAX(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_keyLength(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs12_INTEGER_1_MAX(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_keyLength);
}


static const ber_sequence_t PBKDF2Params_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_saltChoice },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_iterationCount },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_keyLength },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_prf },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PBKDF2Params(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PBKDF2Params_sequence, hf_index, ett_pkcs12_PBKDF2Params);

  return offset;
}


static const ber_sequence_t PBES2Params_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_keyDerivationFunc },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_encryptionScheme },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PBES2Params(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PBES2Params_sequence, hf_index, ett_pkcs12_PBES2Params);

  return offset;
}


static const ber_sequence_t PBMAC1Params_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_keyDerivationFunc },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_messageAuthScheme },
  { 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PBMAC1Params(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PBMAC1Params_sequence, hf_index, ett_pkcs12_PBMAC1Params);

  return offset;
}

/*--- PDUs ---*/

static void dissect_PFX_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_PFX(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_PFX_PDU);
}
static void dissect_AuthenticatedSafe_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_AuthenticatedSafe(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_AuthenticatedSafe_PDU);
}
static void dissect_SafeContents_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_SafeContents(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_SafeContents_PDU);
}
static void dissect_KeyBag_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_KeyBag(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_KeyBag_PDU);
}
static void dissect_PKCS8ShroudedKeyBag_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_PKCS8ShroudedKeyBag(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_PKCS8ShroudedKeyBag_PDU);
}
static void dissect_CertBag_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_CertBag(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_CertBag_PDU);
}
static void dissect_CRLBag_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_CRLBag(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_CRLBag_PDU);
}
static void dissect_SecretBag_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_SecretBag(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_SecretBag_PDU);
}
static void dissect_EncryptedPrivateKeyInfo_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_EncryptedPrivateKeyInfo(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_EncryptedPrivateKeyInfo_PDU);
}
static void dissect_PBEParameter_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_PBEParameter(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_PBEParameter_PDU);
}
static void dissect_PBKDF2Params_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_PBKDF2Params(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_PBKDF2Params_PDU);
}
static void dissect_PBES2Params_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_PBES2Params(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_PBES2Params_PDU);
}
static void dissect_PBMAC1Params_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkcs12_PBMAC1Params(FALSE, tvb, 0, pinfo, tree, hf_pkcs12_PBMAC1Params_PDU);
}


/*--- End of included file: packet-pkcs12-fn.c ---*/
#line 64 "packet-pkcs12-template.c"

static int strip_octet_string(tvbuff_t *tvb, proto_tree *tree) 
{
  gint8 class;
  gboolean pc, ind;
  gint32 tag;
  guint32 len;
  int offset = 0;

  /* PKCS#7 encodes the content as OCTET STRING, whereas CMS is just any ANY */
  /* if we use CMS (rather than PKCS#7) - which we are - we need to strip the OCTET STRING tag */
  /* before proceeding */

  offset = get_ber_identifier(tvb, 0, &class, &pc, &tag);
  offset = get_ber_length(NULL, tvb, offset, &len, &ind);

  if((class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_OCTETSTRING))
    return offset;

  proto_tree_add_text(tree, tvb, 0, 1, "BER Error: OCTET STRING expected");

  return 0;

}

static void dissect_AuthenticatedSafe_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  int offset = 0;

  if((offset = strip_octet_string(tvb, tree)) > 0)
    dissect_pkcs12_AuthenticatedSafe(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_AuthenticatedSafe_PDU);
}

static void dissect_SafeContents_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
  int offset = 0;

  if((offset = strip_octet_string(tvb, tree)) > 0)
    dissect_pkcs12_SafeContents(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_SafeContents_PDU);
}

#if 0 
static int decrypt_data(tvbuff_t *encrypted_data, 
			/* enc_params */
			gnu_tls_ciper_algorithm cipher,
			int iter_count,
			/* kdf_params */
			gnutls_datum_t *salt, size_t salt_size,
			gnutls_datum_t *iv, size_t iv_size,
			size_t key_size, 
			tvb_buff_t **decrypted_data)
{


  

  if(key_size == 0) 
    key_size = gnutls_cipher_get_key_size(cipher);


}
			
# endif /* 0 */

/*--- proto_register_pkcs12 ----------------------------------------------*/
void proto_register_pkcs12(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-pkcs12-hfarr.c ---*/
#line 1 "packet-pkcs12-hfarr.c"
    { &hf_pkcs12_PFX_PDU,
      { "PFX", "pkcs12.PFX",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.PFX", HFILL }},
    { &hf_pkcs12_AuthenticatedSafe_PDU,
      { "AuthenticatedSafe", "pkcs12.AuthenticatedSafe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkcs12.AuthenticatedSafe", HFILL }},
    { &hf_pkcs12_SafeContents_PDU,
      { "SafeContents", "pkcs12.SafeContents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkcs12.SafeContents", HFILL }},
    { &hf_pkcs12_KeyBag_PDU,
      { "KeyBag", "pkcs12.KeyBag",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.KeyBag", HFILL }},
    { &hf_pkcs12_PKCS8ShroudedKeyBag_PDU,
      { "PKCS8ShroudedKeyBag", "pkcs12.PKCS8ShroudedKeyBag",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.PKCS8ShroudedKeyBag", HFILL }},
    { &hf_pkcs12_CertBag_PDU,
      { "CertBag", "pkcs12.CertBag",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.CertBag", HFILL }},
    { &hf_pkcs12_CRLBag_PDU,
      { "CRLBag", "pkcs12.CRLBag",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.CRLBag", HFILL }},
    { &hf_pkcs12_SecretBag_PDU,
      { "SecretBag", "pkcs12.SecretBag",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.SecretBag", HFILL }},
    { &hf_pkcs12_EncryptedPrivateKeyInfo_PDU,
      { "EncryptedPrivateKeyInfo", "pkcs12.EncryptedPrivateKeyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.EncryptedPrivateKeyInfo", HFILL }},
    { &hf_pkcs12_PBEParameter_PDU,
      { "PBEParameter", "pkcs12.PBEParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.PBEParameter", HFILL }},
    { &hf_pkcs12_PBKDF2Params_PDU,
      { "PBKDF2Params", "pkcs12.PBKDF2Params",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.PBKDF2Params", HFILL }},
    { &hf_pkcs12_PBES2Params_PDU,
      { "PBES2Params", "pkcs12.PBES2Params",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.PBES2Params", HFILL }},
    { &hf_pkcs12_PBMAC1Params_PDU,
      { "PBMAC1Params", "pkcs12.PBMAC1Params",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.PBMAC1Params", HFILL }},
    { &hf_pkcs12_version,
      { "version", "pkcs12.version",
        FT_UINT32, BASE_DEC, VALS(pkcs12_T_version_vals), 0,
        "pkcs12.T_version", HFILL }},
    { &hf_pkcs12_authSafe,
      { "authSafe", "pkcs12.authSafe",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.ContentInfo", HFILL }},
    { &hf_pkcs12_macData,
      { "macData", "pkcs12.macData",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.MacData", HFILL }},
    { &hf_pkcs12_mac,
      { "mac", "pkcs12.mac",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.DigestInfo", HFILL }},
    { &hf_pkcs12_macSalt,
      { "macSalt", "pkcs12.macSalt",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkcs12.OCTET_STRING", HFILL }},
    { &hf_pkcs12_iterations,
      { "iterations", "pkcs12.iterations",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs12.INTEGER", HFILL }},
    { &hf_pkcs12_digestAlgorithm,
      { "digestAlgorithm", "pkcs12.digestAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.DigestAlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_digest,
      { "digest", "pkcs12.digest",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.Digest", HFILL }},
    { &hf_pkcs12_AuthenticatedSafe_item,
      { "Item", "pkcs12.AuthenticatedSafe_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.ContentInfo", HFILL }},
    { &hf_pkcs12_SafeContents_item,
      { "Item", "pkcs12.SafeContents_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.SafeBag", HFILL }},
    { &hf_pkcs12_bagId,
      { "bagId", "pkcs12.bagId",
        FT_OID, BASE_NONE, NULL, 0,
        "pkcs12.OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkcs12_bagValue,
      { "bagValue", "pkcs12.bagValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.T_bagValue", HFILL }},
    { &hf_pkcs12_bagAttributes,
      { "bagAttributes", "pkcs12.bagAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkcs12.SET_OF_PKCS12Attribute", HFILL }},
    { &hf_pkcs12_bagAttributes_item,
      { "Item", "pkcs12.bagAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.PKCS12Attribute", HFILL }},
    { &hf_pkcs12_certId,
      { "certId", "pkcs12.certId",
        FT_OID, BASE_NONE, NULL, 0,
        "pkcs12.OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkcs12_certValue,
      { "certValue", "pkcs12.certValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.T_certValue", HFILL }},
    { &hf_pkcs12_crlId,
      { "crlId", "pkcs12.crlId",
        FT_OID, BASE_NONE, NULL, 0,
        "pkcs12.OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkcs12_crlValue,
      { "crlValue", "pkcs12.crlValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.T_crlValue", HFILL }},
    { &hf_pkcs12_secretTypeId,
      { "secretTypeId", "pkcs12.secretTypeId",
        FT_OID, BASE_NONE, NULL, 0,
        "pkcs12.OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkcs12_secretValue,
      { "secretValue", "pkcs12.secretValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.T_secretValue", HFILL }},
    { &hf_pkcs12_attrId,
      { "attrId", "pkcs12.attrId",
        FT_OID, BASE_NONE, NULL, 0,
        "pkcs12.OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkcs12_attrValues,
      { "attrValues", "pkcs12.attrValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkcs12.T_attrValues", HFILL }},
    { &hf_pkcs12_attrValues_item,
      { "Item", "pkcs12.attrValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.T_attrValues_item", HFILL }},
    { &hf_pkcs12_privateKeyVersion,
      { "version", "pkcs12.version",
        FT_INT32, BASE_DEC, VALS(x509af_Version_vals), 0,
        "pkcs12.Version", HFILL }},
    { &hf_pkcs12_privateKeyAlgorithm,
      { "privateKeyAlgorithm", "pkcs12.privateKeyAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_privateKey,
      { "privateKey", "pkcs12.privateKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkcs12.PrivateKey", HFILL }},
    { &hf_pkcs12_attributes,
      { "attributes", "pkcs12.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkcs12.Attributes", HFILL }},
    { &hf_pkcs12_Attributes_item,
      { "Item", "pkcs12.Attributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509if.Attribute", HFILL }},
    { &hf_pkcs12_encryptionAlgorithm,
      { "encryptionAlgorithm", "pkcs12.encryptionAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_encryptedData,
      { "encryptedData", "pkcs12.encryptedData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkcs12.EncryptedData", HFILL }},
    { &hf_pkcs12_salt,
      { "salt", "pkcs12.salt",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkcs12.OCTET_STRING", HFILL }},
    { &hf_pkcs12_iterationCount,
      { "iterationCount", "pkcs12.iterationCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs12.INTEGER", HFILL }},
    { &hf_pkcs12_saltChoice,
      { "salt", "pkcs12.salt",
        FT_UINT32, BASE_DEC, VALS(pkcs12_T_saltChoice_vals), 0,
        "pkcs12.T_saltChoice", HFILL }},
    { &hf_pkcs12_specified,
      { "specified", "pkcs12.specified",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkcs12.OCTET_STRING", HFILL }},
    { &hf_pkcs12_otherSource,
      { "otherSource", "pkcs12.otherSource",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_keyLength,
      { "keyLength", "pkcs12.keyLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkcs12.INTEGER_1_MAX", HFILL }},
    { &hf_pkcs12_prf,
      { "prf", "pkcs12.prf",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_keyDerivationFunc,
      { "keyDerivationFunc", "pkcs12.keyDerivationFunc",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_encryptionScheme,
      { "encryptionScheme", "pkcs12.encryptionScheme",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_messageAuthScheme,
      { "messageAuthScheme", "pkcs12.messageAuthScheme",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},

/*--- End of included file: packet-pkcs12-hfarr.c ---*/
#line 134 "packet-pkcs12-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkcs12-ettarr.c ---*/
#line 1 "packet-pkcs12-ettarr.c"
    &ett_pkcs12_PFX,
    &ett_pkcs12_MacData,
    &ett_pkcs12_DigestInfo,
    &ett_pkcs12_AuthenticatedSafe,
    &ett_pkcs12_SafeContents,
    &ett_pkcs12_SafeBag,
    &ett_pkcs12_SET_OF_PKCS12Attribute,
    &ett_pkcs12_CertBag,
    &ett_pkcs12_CRLBag,
    &ett_pkcs12_SecretBag,
    &ett_pkcs12_PKCS12Attribute,
    &ett_pkcs12_T_attrValues,
    &ett_pkcs12_PrivateKeyInfo,
    &ett_pkcs12_Attributes,
    &ett_pkcs12_EncryptedPrivateKeyInfo,
    &ett_pkcs12_PBEParameter,
    &ett_pkcs12_PBKDF2Params,
    &ett_pkcs12_T_saltChoice,
    &ett_pkcs12_PBES2Params,
    &ett_pkcs12_PBMAC1Params,

/*--- End of included file: packet-pkcs12-ettarr.c ---*/
#line 139 "packet-pkcs12-template.c"
  };

  /* Register protocol */
  proto_pkcs12 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkcs12, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_ber_syntax_dissector("PKCS#12", proto_pkcs12, dissect_PFX_PDU); 
  register_ber_oid_syntax(".p12", NULL, "PKCS#12");
  register_ber_oid_syntax(".pfx", NULL, "PKCS#12");
}


/*--- proto_reg_handoff_pkcs12 -------------------------------------------*/
void proto_reg_handoff_pkcs12(void) {

/*--- Included file: packet-pkcs12-dis-tab.c ---*/
#line 1 "packet-pkcs12-dis-tab.c"
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.1", dissect_KeyBag_PDU, proto_pkcs12, "keyBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.2", dissect_PKCS8ShroudedKeyBag_PDU, proto_pkcs12, "pkcs8ShroudedKeyBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.3", dissect_CertBag_PDU, proto_pkcs12, "certBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.4", dissect_SecretBag_PDU, proto_pkcs12, "secretBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.5", dissect_CRLBag_PDU, proto_pkcs12, "crlBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.6", dissect_SafeContents_PDU, proto_pkcs12, "safeContentsBag");
  register_ber_oid_dissector("2.16.840.1.113730.3.1.216", dissect_PFX_PDU, proto_pkcs12, "pkcs-9-at-PKCS12");
  register_ber_oid_dissector("1.2.840.113549.1.9.25.2", dissect_EncryptedPrivateKeyInfo_PDU, proto_pkcs12, "pkcs-9-at-encryptedPrivateKeyInfo");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.1", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd128BitRC4");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.2", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd40BitRC4");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.3", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd3-KeyTripleDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.4", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd2-KeyTripleDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.5", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd128BitRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.6", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd128BitRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.1", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithMD2AndDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.3", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithMD5AndDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.4", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithMD2AndRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.6", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithMD5AndRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.10", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHA1AndDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.11", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHA1AndRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.12", dissect_PBKDF2Params_PDU, proto_pkcs12, "id-PBKDF2");
  register_ber_oid_dissector("1.2.840.113549.1.5.13", dissect_PBES2Params_PDU, proto_pkcs12, "id-PBES2");
  register_ber_oid_dissector("1.2.840.113549.1.5.14", dissect_PBMAC1Params_PDU, proto_pkcs12, "id-PBMAC1");


/*--- End of included file: packet-pkcs12-dis-tab.c ---*/
#line 157 "packet-pkcs12-template.c"

}

