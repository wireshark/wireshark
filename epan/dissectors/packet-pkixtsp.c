/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-pkixtsp.c                                                         */
/* ../../tools/asn2eth.py -X -b -e -p pkixtsp -c pkixtsp.cnf -s packet-pkixtsp-template PKIXTSP.asn */

/* Input file: packet-pkixtsp-template.c */

#line 1 "packet-pkixtsp-template.c"
/* packet-pkixtsp.c
 * Routines for RFC2634 Extended Security Services packet dissection
 *   Ronnie Sahlberg 2004
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-pkixtsp.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-cms.h"

#define PNAME  "PKIX Time Stamp Protocol"
#define PSNAME "PKIXTSP"
#define PFNAME "pkixtsp"

/* Initialize the protocol and registered fields */
static int proto_pkixtsp = -1;

/*--- Included file: packet-pkixtsp-hf.c ---*/
#line 1 "packet-pkixtsp-hf.c"
static int hf_pkixtsp_version = -1;               /* T_version */
static int hf_pkixtsp_messageImprint = -1;        /* MessageImprint */
static int hf_pkixtsp_reqPolicy = -1;             /* TSAPolicyId */
static int hf_pkixtsp_nonce = -1;                 /* INTEGER */
static int hf_pkixtsp_certReq = -1;               /* BOOLEAN */
static int hf_pkixtsp_extensions = -1;            /* Extensions */
static int hf_pkixtsp_hashAlgorithm = -1;         /* AlgorithmIdentifier */
static int hf_pkixtsp_hashedMessage = -1;         /* OCTET_STRING */
static int hf_pkixtsp_status = -1;                /* PKIStatusInfo */
static int hf_pkixtsp_timeStampToken = -1;        /* TimeStampToken */
static int hf_pkixtsp_pki_status = -1;            /* PKIStatus */
static int hf_pkixtsp_failInfo = -1;              /* PKIFailureInfo */
static int hf_pkixtsp_tst_version = -1;           /* tst_version */
static int hf_pkixtsp_policy = -1;                /* TSAPolicyId */
static int hf_pkixtsp_serialNumber = -1;          /* INTEGER */
static int hf_pkixtsp_genTime = -1;               /* GeneralizedTime */
static int hf_pkixtsp_accuracy = -1;              /* Accuracy */
static int hf_pkixtsp_ordering = -1;              /* BOOLEAN */
static int hf_pkixtsp_tsa = -1;                   /* GeneralName */
static int hf_pkixtsp_seconds = -1;               /* INTEGER */
static int hf_pkixtsp_millis = -1;                /* INTEGER_1_999 */
static int hf_pkixtsp_micros = -1;                /* INTEGER_1_999 */
/* named bits */
static int hf_pkixtsp_PKIFailureInfo_badAlg = -1;
static int hf_pkixtsp_PKIFailureInfo_badRequest = -1;
static int hf_pkixtsp_PKIFailureInfo_badDataFormat = -1;
static int hf_pkixtsp_PKIFailureInfo_timeNotAvailable = -1;
static int hf_pkixtsp_PKIFailureInfo_unacceptedPolicy = -1;
static int hf_pkixtsp_PKIFailureInfo_unacceptedExtension = -1;
static int hf_pkixtsp_PKIFailureInfo_addInfoNotAvailable = -1;
static int hf_pkixtsp_PKIFailureInfo_systemFailure = -1;

/*--- End of included file: packet-pkixtsp-hf.c ---*/
#line 49 "packet-pkixtsp-template.c"

/* Initialize the subtree pointers */
static gint ett_pkixtsp = -1;

/*--- Included file: packet-pkixtsp-ett.c ---*/
#line 1 "packet-pkixtsp-ett.c"
static gint ett_pkixtsp_TimeStampReq = -1;
static gint ett_pkixtsp_MessageImprint = -1;
static gint ett_pkixtsp_TimeStampResp = -1;
static gint ett_pkixtsp_PKIStatusInfo = -1;
static gint ett_pkixtsp_PKIFailureInfo = -1;
static gint ett_pkixtsp_TSTInfo = -1;
static gint ett_pkixtsp_Accuracy = -1;

/*--- End of included file: packet-pkixtsp-ett.c ---*/
#line 53 "packet-pkixtsp-template.c"



/*--- Included file: packet-pkixtsp-fn.c ---*/
#line 1 "packet-pkixtsp-fn.c"
/*--- Fields for imported types ---*/

static int dissect_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Extensions(TRUE, tvb, offset, pinfo, tree, hf_pkixtsp_extensions);
}
static int dissect_hashAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_hashAlgorithm);
}
static int dissect_tsa_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_GeneralName(TRUE, tvb, offset, pinfo, tree, hf_pkixtsp_tsa);
}


static const value_string pkixtsp_T_version_vals[] = {
  {   1, "v1" },
  { 0, NULL }
};


static int
dissect_pkixtsp_T_version(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_T_version(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_version);
}



static int
dissect_pkixtsp_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_hashedMessage(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_hashedMessage);
}


static const ber_sequence_t MessageImprint_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_hashAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_hashedMessage },
  { 0, 0, 0, NULL }
};

static int
dissect_pkixtsp_MessageImprint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MessageImprint_sequence, hf_index, ett_pkixtsp_MessageImprint);

  return offset;
}
static int dissect_messageImprint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_MessageImprint(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_messageImprint);
}



static int
dissect_pkixtsp_TSAPolicyId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_reqPolicy(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_TSAPolicyId(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_reqPolicy);
}
static int dissect_policy(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_TSAPolicyId(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_policy);
}



static int
dissect_pkixtsp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_nonce(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_nonce);
}
static int dissect_serialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_serialNumber);
}
static int dissect_seconds(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_seconds);
}



static int
dissect_pkixtsp_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_certReq(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_certReq);
}
static int dissect_ordering(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_ordering);
}


static const ber_sequence_t TimeStampReq_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_messageImprint },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_reqPolicy },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_nonce },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_certReq },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_pkixtsp_TimeStampReq(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TimeStampReq_sequence, hf_index, ett_pkixtsp_TimeStampReq);

  return offset;
}


static const value_string pkixtsp_PKIStatus_vals[] = {
  {   0, "granted" },
  {   1, "grantedWithMods" },
  {   2, "rejection" },
  {   3, "waiting" },
  {   4, "revocationWarning" },
  {   5, "revocationNotification" },
  { 0, NULL }
};


static int
dissect_pkixtsp_PKIStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_pki_status(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_PKIStatus(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_pki_status);
}


static const asn_namedbit PKIFailureInfo_bits[] = {
  {  0, &hf_pkixtsp_PKIFailureInfo_badAlg, -1, -1, "badAlg", NULL },
  {  2, &hf_pkixtsp_PKIFailureInfo_badRequest, -1, -1, "badRequest", NULL },
  {  5, &hf_pkixtsp_PKIFailureInfo_badDataFormat, -1, -1, "badDataFormat", NULL },
  { 14, &hf_pkixtsp_PKIFailureInfo_timeNotAvailable, -1, -1, "timeNotAvailable", NULL },
  { 15, &hf_pkixtsp_PKIFailureInfo_unacceptedPolicy, -1, -1, "unacceptedPolicy", NULL },
  { 16, &hf_pkixtsp_PKIFailureInfo_unacceptedExtension, -1, -1, "unacceptedExtension", NULL },
  { 17, &hf_pkixtsp_PKIFailureInfo_addInfoNotAvailable, -1, -1, "addInfoNotAvailable", NULL },
  { 25, &hf_pkixtsp_PKIFailureInfo_systemFailure, -1, -1, "systemFailure", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_pkixtsp_PKIFailureInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    PKIFailureInfo_bits, hf_index, ett_pkixtsp_PKIFailureInfo,
                                    NULL);

  return offset;
}
static int dissect_failInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_PKIFailureInfo(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_failInfo);
}


static const ber_sequence_t PKIStatusInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pki_status },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_failInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_pkixtsp_PKIStatusInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PKIStatusInfo_sequence, hf_index, ett_pkixtsp_PKIStatusInfo);

  return offset;
}
static int dissect_status(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_PKIStatusInfo(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_status);
}



static int
dissect_pkixtsp_TimeStampToken(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_cms_ContentInfo(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_timeStampToken(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_TimeStampToken(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_timeStampToken);
}


static const ber_sequence_t TimeStampResp_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_status },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_timeStampToken },
  { 0, 0, 0, NULL }
};

static int
dissect_pkixtsp_TimeStampResp(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TimeStampResp_sequence, hf_index, ett_pkixtsp_TimeStampResp);

  return offset;
}


static const value_string pkixtsp_tst_version_vals[] = {
  {   1, "v1" },
  { 0, NULL }
};


static int
dissect_pkixtsp_tst_version(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_tst_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_tst_version(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_tst_version);
}



static int
dissect_pkixtsp_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_genTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_genTime);
}



static int
dissect_pkixtsp_INTEGER_1_999(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_millis_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_INTEGER_1_999(TRUE, tvb, offset, pinfo, tree, hf_pkixtsp_millis);
}
static int dissect_micros_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_INTEGER_1_999(TRUE, tvb, offset, pinfo, tree, hf_pkixtsp_micros);
}


static const ber_sequence_t Accuracy_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_seconds },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_millis_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_micros_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_pkixtsp_Accuracy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Accuracy_sequence, hf_index, ett_pkixtsp_Accuracy);

  return offset;
}
static int dissect_accuracy(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixtsp_Accuracy(FALSE, tvb, offset, pinfo, tree, hf_pkixtsp_accuracy);
}


static const ber_sequence_t TSTInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tst_version },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_policy },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_messageImprint },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serialNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_genTime },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_accuracy },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ordering },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_nonce },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tsa_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_pkixtsp_TSTInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TSTInfo_sequence, hf_index, ett_pkixtsp_TSTInfo);

  return offset;
}


/*--- End of included file: packet-pkixtsp-fn.c ---*/
#line 56 "packet-pkixtsp-template.c"


static int
dissect_timestamp_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKIXTSP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		
		col_add_fstr(pinfo->cinfo, COL_INFO, "Reply");
	}


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_pkixtsp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_pkixtsp);
	}

	return dissect_pkixtsp_TimeStampResp(FALSE, tvb, 0, pinfo, tree, -1);
}

static int
dissect_timestamp_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKIXTSP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		
		col_add_fstr(pinfo->cinfo, COL_INFO, "Query");
	}


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_pkixtsp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_pkixtsp);
	}

	return dissect_pkixtsp_TimeStampReq(FALSE, tvb, 0, pinfo, tree, -1);
}


/*--- proto_register_pkixtsp ----------------------------------------------*/
void proto_register_pkixtsp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkixtsp-hfarr.c ---*/
#line 1 "packet-pkixtsp-hfarr.c"
    { &hf_pkixtsp_version,
      { "version", "pkixtsp.version",
        FT_INT32, BASE_DEC, VALS(pkixtsp_T_version_vals), 0,
        "TimeStampReq/version", HFILL }},
    { &hf_pkixtsp_messageImprint,
      { "messageImprint", "pkixtsp.messageImprint",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_pkixtsp_reqPolicy,
      { "reqPolicy", "pkixtsp.reqPolicy",
        FT_OID, BASE_NONE, NULL, 0,
        "TimeStampReq/reqPolicy", HFILL }},
    { &hf_pkixtsp_nonce,
      { "nonce", "pkixtsp.nonce",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_pkixtsp_certReq,
      { "certReq", "pkixtsp.certReq",
        FT_BOOLEAN, 8, NULL, 0,
        "TimeStampReq/certReq", HFILL }},
    { &hf_pkixtsp_extensions,
      { "extensions", "pkixtsp.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_pkixtsp_hashAlgorithm,
      { "hashAlgorithm", "pkixtsp.hashAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageImprint/hashAlgorithm", HFILL }},
    { &hf_pkixtsp_hashedMessage,
      { "hashedMessage", "pkixtsp.hashedMessage",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MessageImprint/hashedMessage", HFILL }},
    { &hf_pkixtsp_status,
      { "status", "pkixtsp.status",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeStampResp/status", HFILL }},
    { &hf_pkixtsp_timeStampToken,
      { "timeStampToken", "pkixtsp.timeStampToken",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeStampResp/timeStampToken", HFILL }},
    { &hf_pkixtsp_pki_status,
      { "status", "pkixtsp.status",
        FT_INT32, BASE_DEC, VALS(pkixtsp_PKIStatus_vals), 0,
        "PKIStatusInfo/status", HFILL }},
    { &hf_pkixtsp_failInfo,
      { "failInfo", "pkixtsp.failInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKIStatusInfo/failInfo", HFILL }},
    { &hf_pkixtsp_tst_version,
      { "version", "pkixtsp.version",
        FT_INT32, BASE_DEC, VALS(pkixtsp_tst_version_vals), 0,
        "TSTInfo/version", HFILL }},
    { &hf_pkixtsp_policy,
      { "policy", "pkixtsp.policy",
        FT_OID, BASE_NONE, NULL, 0,
        "TSTInfo/policy", HFILL }},
    { &hf_pkixtsp_serialNumber,
      { "serialNumber", "pkixtsp.serialNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "TSTInfo/serialNumber", HFILL }},
    { &hf_pkixtsp_genTime,
      { "genTime", "pkixtsp.genTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "TSTInfo/genTime", HFILL }},
    { &hf_pkixtsp_accuracy,
      { "accuracy", "pkixtsp.accuracy",
        FT_NONE, BASE_NONE, NULL, 0,
        "TSTInfo/accuracy", HFILL }},
    { &hf_pkixtsp_ordering,
      { "ordering", "pkixtsp.ordering",
        FT_BOOLEAN, 8, NULL, 0,
        "TSTInfo/ordering", HFILL }},
    { &hf_pkixtsp_tsa,
      { "tsa", "pkixtsp.tsa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TSTInfo/tsa", HFILL }},
    { &hf_pkixtsp_seconds,
      { "seconds", "pkixtsp.seconds",
        FT_INT32, BASE_DEC, NULL, 0,
        "Accuracy/seconds", HFILL }},
    { &hf_pkixtsp_millis,
      { "millis", "pkixtsp.millis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Accuracy/millis", HFILL }},
    { &hf_pkixtsp_micros,
      { "micros", "pkixtsp.micros",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Accuracy/micros", HFILL }},
    { &hf_pkixtsp_PKIFailureInfo_badAlg,
      { "badAlg", "pkixtsp.badAlg",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_pkixtsp_PKIFailureInfo_badRequest,
      { "badRequest", "pkixtsp.badRequest",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_pkixtsp_PKIFailureInfo_badDataFormat,
      { "badDataFormat", "pkixtsp.badDataFormat",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_pkixtsp_PKIFailureInfo_timeNotAvailable,
      { "timeNotAvailable", "pkixtsp.timeNotAvailable",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_pkixtsp_PKIFailureInfo_unacceptedPolicy,
      { "unacceptedPolicy", "pkixtsp.unacceptedPolicy",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_pkixtsp_PKIFailureInfo_unacceptedExtension,
      { "unacceptedExtension", "pkixtsp.unacceptedExtension",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_pkixtsp_PKIFailureInfo_addInfoNotAvailable,
      { "addInfoNotAvailable", "pkixtsp.addInfoNotAvailable",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_pkixtsp_PKIFailureInfo_systemFailure,
      { "systemFailure", "pkixtsp.systemFailure",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},

/*--- End of included file: packet-pkixtsp-hfarr.c ---*/
#line 113 "packet-pkixtsp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	&ett_pkixtsp,

/*--- Included file: packet-pkixtsp-ettarr.c ---*/
#line 1 "packet-pkixtsp-ettarr.c"
    &ett_pkixtsp_TimeStampReq,
    &ett_pkixtsp_MessageImprint,
    &ett_pkixtsp_TimeStampResp,
    &ett_pkixtsp_PKIStatusInfo,
    &ett_pkixtsp_PKIFailureInfo,
    &ett_pkixtsp_TSTInfo,
    &ett_pkixtsp_Accuracy,

/*--- End of included file: packet-pkixtsp-ettarr.c ---*/
#line 119 "packet-pkixtsp-template.c"
  };

  /* Register protocol */
  proto_pkixtsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixtsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkixtsp -------------------------------------------*/
void proto_reg_handoff_pkixtsp(void) {
	dissector_handle_t timestamp_reply_handle;
	dissector_handle_t timestamp_query_handle;

	timestamp_reply_handle = new_create_dissector_handle(dissect_timestamp_reply, proto_pkixtsp);
	dissector_add_string("media_type", "application/timestamp-reply", timestamp_reply_handle);

	timestamp_query_handle = new_create_dissector_handle(dissect_timestamp_query, proto_pkixtsp);
	dissector_add_string("media_type", "application/timestamp-query", timestamp_query_handle);

/*#include "packet-pkixtsp-dis-tab.c"*/
}

