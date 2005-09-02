/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-cmp.c                                                             */
/* ../../tools/asn2eth.py -X -b -e -p cmp -c cmp.cnf -s packet-cmp-template CMP.asn */

/* Input file: packet-cmp-template.c */

/* packet-cmp.c
 * Routines for RFC2510 Certificate Management Protocol packet dissection
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-cmp.h"
#include "packet-crmf.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"

#define PNAME  "Certificate Management Protocol"
#define PSNAME "CMP"
#define PFNAME "cmp"

/* Initialize the protocol and registered fields */
int proto_cmp = -1;
static int hf_cmp_type_oid = -1;

/*--- Included file: packet-cmp-hf.c ---*/

static int hf_cmp_header = -1;                    /* PKIHeader */
static int hf_cmp_body = -1;                      /* PKIBody */
static int hf_cmp_protection = -1;                /* PKIProtection */
static int hf_cmp_extraCerts = -1;                /* SEQUENCE_SIZE_1_MAX_OF_Certificate */
static int hf_cmp_extraCerts_item = -1;           /* Certificate */
static int hf_cmp_pvno = -1;                      /* T_pvno */
static int hf_cmp_sender = -1;                    /* GeneralName */
static int hf_cmp_recipient = -1;                 /* GeneralName */
static int hf_cmp_messageTime = -1;               /* GeneralizedTime */
static int hf_cmp_protectionAlg = -1;             /* AlgorithmIdentifier */
static int hf_cmp_senderKID = -1;                 /* KeyIdentifier */
static int hf_cmp_recipKID = -1;                  /* KeyIdentifier */
static int hf_cmp_transactionID = -1;             /* OCTET_STRING */
static int hf_cmp_senderNonce = -1;               /* OCTET_STRING */
static int hf_cmp_recipNonce = -1;                /* OCTET_STRING */
static int hf_cmp_freeText = -1;                  /* PKIFreeText */
static int hf_cmp_generalInfo = -1;               /* SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue */
static int hf_cmp_generalInfo_item = -1;          /* InfoTypeAndValue */
static int hf_cmp_PKIFreeText_item = -1;          /* UTF8String */
static int hf_cmp_ir = -1;                        /* CertReqMessages */
static int hf_cmp_ip = -1;                        /* CertRepMessage */
static int hf_cmp_cr = -1;                        /* CertReqMessages */
static int hf_cmp_cp = -1;                        /* CertRepMessage */
static int hf_cmp_popdecc = -1;                   /* POPODecKeyChallContent */
static int hf_cmp_popdecr = -1;                   /* POPODecKeyRespContent */
static int hf_cmp_kur = -1;                       /* CertReqMessages */
static int hf_cmp_kup = -1;                       /* CertRepMessage */
static int hf_cmp_krr = -1;                       /* CertReqMessages */
static int hf_cmp_krp = -1;                       /* KeyRecRepContent */
static int hf_cmp_rr = -1;                        /* RevReqContent */
static int hf_cmp_rp = -1;                        /* RevRepContent */
static int hf_cmp_ccr = -1;                       /* CertReqMessages */
static int hf_cmp_ccp = -1;                       /* CertRepMessage */
static int hf_cmp_ckuann = -1;                    /* CAKeyUpdAnnContent */
static int hf_cmp_cann = -1;                      /* CertAnnContent */
static int hf_cmp_rann = -1;                      /* RevAnnContent */
static int hf_cmp_crlann = -1;                    /* CRLAnnContent */
static int hf_cmp_conf = -1;                      /* PKIConfirmContent */
static int hf_cmp_nested = -1;                    /* NestedMessageContent */
static int hf_cmp_genm = -1;                      /* GenMsgContent */
static int hf_cmp_genp = -1;                      /* GenRepContent */
static int hf_cmp_error = -1;                     /* ErrorMsgContent */
static int hf_cmp_salt = -1;                      /* OCTET_STRING */
static int hf_cmp_owf = -1;                       /* AlgorithmIdentifier */
static int hf_cmp_iterationCount = -1;            /* INTEGER */
static int hf_cmp_mac = -1;                       /* AlgorithmIdentifier */
static int hf_cmp_status = -1;                    /* PKIStatus */
static int hf_cmp_statusString = -1;              /* PKIFreeText */
static int hf_cmp_failInfo = -1;                  /* PKIFailureInfo */
static int hf_cmp_hashAlg = -1;                   /* AlgorithmIdentifier */
static int hf_cmp_certId = -1;                    /* CertId */
static int hf_cmp_hashVal = -1;                   /* BIT_STRING */
static int hf_cmp_POPODecKeyChallContent_item = -1;  /* Challenge */
static int hf_cmp_witness = -1;                   /* OCTET_STRING */
static int hf_cmp_challenge = -1;                 /* OCTET_STRING */
static int hf_cmp_POPODecKeyRespContent_item = -1;  /* INTEGER */
static int hf_cmp_caPubs = -1;                    /* SEQUENCE_SIZE_1_MAX_OF_Certificate */
static int hf_cmp_caPubs_item = -1;               /* Certificate */
static int hf_cmp_response = -1;                  /* SEQUENCE_OF_CertResponse */
static int hf_cmp_response_item = -1;             /* CertResponse */
static int hf_cmp_certReqId = -1;                 /* INTEGER */
static int hf_cmp_status1 = -1;                   /* PKIStatusInfo */
static int hf_cmp_certifiedKeyPair = -1;          /* CertifiedKeyPair */
static int hf_cmp_rspInfo = -1;                   /* OCTET_STRING */
static int hf_cmp_certOrEncCert = -1;             /* CertOrEncCert */
static int hf_cmp_privateKey = -1;                /* EncryptedValue */
static int hf_cmp_publicationInfo = -1;           /* PKIPublicationInfo */
static int hf_cmp_certificate = -1;               /* Certificate */
static int hf_cmp_encryptedCert = -1;             /* EncryptedValue */
static int hf_cmp_newSigCert = -1;                /* Certificate */
static int hf_cmp_caCerts = -1;                   /* SEQUENCE_SIZE_1_MAX_OF_Certificate */
static int hf_cmp_caCerts_item = -1;              /* Certificate */
static int hf_cmp_keyPairHist = -1;               /* SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair */
static int hf_cmp_keyPairHist_item = -1;          /* CertifiedKeyPair */
static int hf_cmp_RevReqContent_item = -1;        /* RevDetails */
static int hf_cmp_certDetails = -1;               /* CertTemplate */
static int hf_cmp_revocationReason = -1;          /* ReasonFlags */
static int hf_cmp_badSinceDate = -1;              /* GeneralizedTime */
static int hf_cmp_crlEntryDetails = -1;           /* Extensions */
static int hf_cmp_status2 = -1;                   /* SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo */
static int hf_cmp_status_item = -1;               /* PKIStatusInfo */
static int hf_cmp_revCerts = -1;                  /* SEQUENCE_SIZE_1_MAX_OF_CertId */
static int hf_cmp_revCerts_item = -1;             /* CertId */
static int hf_cmp_crls = -1;                      /* SEQUENCE_SIZE_1_MAX_OF_CertificateList */
static int hf_cmp_crls_item = -1;                 /* CertificateList */
static int hf_cmp_oldWithNew = -1;                /* Certificate */
static int hf_cmp_newWithOld = -1;                /* Certificate */
static int hf_cmp_newWithNew = -1;                /* Certificate */
static int hf_cmp_willBeRevokedAt = -1;           /* GeneralizedTime */
static int hf_cmp_crlDetails = -1;                /* Extensions */
static int hf_cmp_CRLAnnContent_item = -1;        /* CertificateList */
static int hf_cmp_infoType = -1;                  /* T_infoType */
static int hf_cmp_infoValue = -1;                 /* T_infoValue */
static int hf_cmp_GenMsgContent_item = -1;        /* InfoTypeAndValue */
static int hf_cmp_GenRepContent_item = -1;        /* InfoTypeAndValue */
static int hf_cmp_pKIStatusInfo = -1;             /* PKIStatusInfo */
static int hf_cmp_errorCode = -1;                 /* INTEGER */
static int hf_cmp_errorDetails = -1;              /* PKIFreeText */
/* named bits */
static int hf_cmp_PKIFailureInfo_badAlg = -1;
static int hf_cmp_PKIFailureInfo_badMessageCheck = -1;
static int hf_cmp_PKIFailureInfo_badRequest = -1;
static int hf_cmp_PKIFailureInfo_badTime = -1;
static int hf_cmp_PKIFailureInfo_badCertId = -1;
static int hf_cmp_PKIFailureInfo_badDataFormat = -1;
static int hf_cmp_PKIFailureInfo_wrongAuthority = -1;
static int hf_cmp_PKIFailureInfo_incorrectData = -1;
static int hf_cmp_PKIFailureInfo_missingTimeStamp = -1;
static int hf_cmp_PKIFailureInfo_badPOP = -1;

/*--- End of included file: packet-cmp-hf.c ---*/


/* Initialize the subtree pointers */
static gint ett_cmp = -1;

/*--- Included file: packet-cmp-ett.c ---*/

static gint ett_cmp_PKIMessage = -1;
static gint ett_cmp_SEQUENCE_SIZE_1_MAX_OF_Certificate = -1;
static gint ett_cmp_PKIHeader = -1;
static gint ett_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue = -1;
static gint ett_cmp_PKIFreeText = -1;
static gint ett_cmp_PKIBody = -1;
static gint ett_cmp_ProtectedPart = -1;
static gint ett_cmp_PBMParameter = -1;
static gint ett_cmp_DHBMParameter = -1;
static gint ett_cmp_PKIFailureInfo = -1;
static gint ett_cmp_PKIStatusInfo = -1;
static gint ett_cmp_OOBCertHash = -1;
static gint ett_cmp_POPODecKeyChallContent = -1;
static gint ett_cmp_Challenge = -1;
static gint ett_cmp_POPODecKeyRespContent = -1;
static gint ett_cmp_CertRepMessage = -1;
static gint ett_cmp_SEQUENCE_OF_CertResponse = -1;
static gint ett_cmp_CertResponse = -1;
static gint ett_cmp_CertifiedKeyPair = -1;
static gint ett_cmp_CertOrEncCert = -1;
static gint ett_cmp_KeyRecRepContent = -1;
static gint ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair = -1;
static gint ett_cmp_RevReqContent = -1;
static gint ett_cmp_RevDetails = -1;
static gint ett_cmp_RevRepContent = -1;
static gint ett_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo = -1;
static gint ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId = -1;
static gint ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList = -1;
static gint ett_cmp_CAKeyUpdAnnContent = -1;
static gint ett_cmp_RevAnnContent = -1;
static gint ett_cmp_CRLAnnContent = -1;
static gint ett_cmp_InfoTypeAndValue = -1;
static gint ett_cmp_GenMsgContent = -1;
static gint ett_cmp_GenRepContent = -1;
static gint ett_cmp_ErrorMsgContent = -1;

/*--- End of included file: packet-cmp-ett.c ---*/


static char object_identifier_id[BER_MAX_OID_STR_LEN];



/*--- Included file: packet-cmp-fn.c ---*/

/*--- Cyclic dependencies ---*/

/* PKIMessage -> PKIBody -> NestedMessageContent -> PKIMessage */
int dissect_cmp_PKIMessage(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);



/*--- Fields for imported types ---*/

static int dissect_extraCerts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_extraCerts_item);
}
static int dissect_sender(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_cmp_sender);
}
static int dissect_recipient(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_cmp_recipient);
}
static int dissect_protectionAlg(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cmp_protectionAlg);
}
static int dissect_ir(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, pinfo, tree, hf_cmp_ir);
}
static int dissect_cr(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, pinfo, tree, hf_cmp_cr);
}
static int dissect_kur(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, pinfo, tree, hf_cmp_kur);
}
static int dissect_krr(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, pinfo, tree, hf_cmp_krr);
}
static int dissect_ccr(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, pinfo, tree, hf_cmp_ccr);
}
static int dissect_owf(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cmp_owf);
}
static int dissect_mac(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cmp_mac);
}
static int dissect_hashAlg(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cmp_hashAlg);
}
static int dissect_certId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertId(FALSE, tvb, offset, pinfo, tree, hf_cmp_certId);
}
static int dissect_caPubs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_caPubs_item);
}
static int dissect_privateKey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_EncryptedValue(FALSE, tvb, offset, pinfo, tree, hf_cmp_privateKey);
}
static int dissect_publicationInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_PKIPublicationInfo(FALSE, tvb, offset, pinfo, tree, hf_cmp_publicationInfo);
}
static int dissect_certificate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_certificate);
}
static int dissect_encryptedCert(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_EncryptedValue(FALSE, tvb, offset, pinfo, tree, hf_cmp_encryptedCert);
}
static int dissect_newSigCert(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_newSigCert);
}
static int dissect_caCerts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_caCerts_item);
}
static int dissect_certDetails(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertTemplate(FALSE, tvb, offset, pinfo, tree, hf_cmp_certDetails);
}
static int dissect_revocationReason(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_ReasonFlags(FALSE, tvb, offset, pinfo, tree, hf_cmp_revocationReason);
}
static int dissect_crlEntryDetails(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Extensions(FALSE, tvb, offset, pinfo, tree, hf_cmp_crlEntryDetails);
}
static int dissect_revCerts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertId(FALSE, tvb, offset, pinfo, tree, hf_cmp_revCerts_item);
}
static int dissect_crls_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_CertificateList(FALSE, tvb, offset, pinfo, tree, hf_cmp_crls_item);
}
static int dissect_oldWithNew(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_oldWithNew);
}
static int dissect_newWithOld(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_newWithOld);
}
static int dissect_newWithNew(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_newWithNew);
}
static int dissect_crlDetails(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Extensions(FALSE, tvb, offset, pinfo, tree, hf_cmp_crlDetails);
}
static int dissect_CRLAnnContent_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_CertificateList(FALSE, tvb, offset, pinfo, tree, hf_cmp_CRLAnnContent_item);
}



static int
dissect_cmp_KeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_senderKID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_KeyIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cmp_senderKID);
}
static int dissect_recipKID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_KeyIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cmp_recipKID);
}


static const value_string cmp_T_pvno_vals[] = {
  {   1, "ietf-version2" },
  { 0, NULL }
};


static int
dissect_cmp_T_pvno(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_pvno(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_T_pvno(FALSE, tvb, offset, pinfo, tree, hf_cmp_pvno);
}



static int
dissect_cmp_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_messageTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_cmp_messageTime);
}
static int dissect_badSinceDate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_cmp_badSinceDate);
}
static int dissect_willBeRevokedAt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_cmp_willBeRevokedAt);
}



static int
dissect_cmp_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_transactionID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cmp_transactionID);
}
static int dissect_senderNonce(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cmp_senderNonce);
}
static int dissect_recipNonce(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cmp_recipNonce);
}
static int dissect_salt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cmp_salt);
}
static int dissect_witness(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cmp_witness);
}
static int dissect_challenge(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cmp_challenge);
}
static int dissect_rspInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cmp_rspInfo);
}



static int
dissect_cmp_UTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_PKIFreeText_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_UTF8String(FALSE, tvb, offset, pinfo, tree, hf_cmp_PKIFreeText_item);
}


static const ber_sequence_t PKIFreeText_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_PKIFreeText_item },
};

int
dissect_cmp_PKIFreeText(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      PKIFreeText_sequence_of, hf_index, ett_cmp_PKIFreeText);

  return offset;
}
static int dissect_freeText(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIFreeText(FALSE, tvb, offset, pinfo, tree, hf_cmp_freeText);
}
static int dissect_statusString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIFreeText(FALSE, tvb, offset, pinfo, tree, hf_cmp_statusString);
}
static int dissect_errorDetails(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIFreeText(FALSE, tvb, offset, pinfo, tree, hf_cmp_errorDetails);
}



static int
dissect_cmp_T_infoType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(FALSE, pinfo, tree, tvb, offset,
                                         hf_cmp_type_oid, object_identifier_id);


  return offset;
}
static int dissect_infoType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_T_infoType(FALSE, tvb, offset, pinfo, tree, hf_cmp_infoType);
}



static int
dissect_cmp_T_infoValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);


  return offset;
}
static int dissect_infoValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_T_infoValue(FALSE, tvb, offset, pinfo, tree, hf_cmp_infoValue);
}


static const ber_sequence_t InfoTypeAndValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_infoType },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_infoValue },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_InfoTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InfoTypeAndValue_sequence, hf_index, ett_cmp_InfoTypeAndValue);

  return offset;
}
static int dissect_generalInfo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_InfoTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_cmp_generalInfo_item);
}
static int dissect_GenMsgContent_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_InfoTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_cmp_GenMsgContent_item);
}
static int dissect_GenRepContent_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_InfoTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_cmp_GenRepContent_item);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_generalInfo_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue);

  return offset;
}
static int dissect_generalInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_cmp_generalInfo);
}


static const ber_sequence_t PKIHeader_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pvno },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_sender },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_recipient },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_messageTime },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_protectionAlg },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_senderKID },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_recipKID },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_transactionID },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_senderNonce },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_recipNonce },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_freeText },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_generalInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_PKIHeader(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PKIHeader_sequence, hf_index, ett_cmp_PKIHeader);

  return offset;
}
static int dissect_header(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIHeader(FALSE, tvb, offset, pinfo, tree, hf_cmp_header);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_Certificate_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_extraCerts_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_Certificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_Certificate_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_Certificate);

  return offset;
}
static int dissect_extraCerts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_extraCerts);
}
static int dissect_caPubs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_caPubs);
}
static int dissect_caCerts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cmp_caCerts);
}



static int
dissect_cmp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_iterationCount(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_cmp_iterationCount);
}
static int dissect_POPODecKeyRespContent_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_cmp_POPODecKeyRespContent_item);
}
static int dissect_certReqId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_cmp_certReqId);
}
static int dissect_errorCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_cmp_errorCode);
}


const value_string cmp_PKIStatus_vals[] = {
  {   0, "granted" },
  {   1, "grantedWithMods" },
  {   2, "rejection" },
  {   3, "waiting" },
  {   4, "revocationWarning" },
  {   5, "revocationNotification" },
  {   6, "keyUpdateWarning" },
  { 0, NULL }
};


int
dissect_cmp_PKIStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_status(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIStatus(FALSE, tvb, offset, pinfo, tree, hf_cmp_status);
}


static const asn_namedbit PKIFailureInfo_bits[] = {
  {  0, &hf_cmp_PKIFailureInfo_badAlg, -1, -1, "badAlg", NULL },
  {  1, &hf_cmp_PKIFailureInfo_badMessageCheck, -1, -1, "badMessageCheck", NULL },
  {  2, &hf_cmp_PKIFailureInfo_badRequest, -1, -1, "badRequest", NULL },
  {  3, &hf_cmp_PKIFailureInfo_badTime, -1, -1, "badTime", NULL },
  {  4, &hf_cmp_PKIFailureInfo_badCertId, -1, -1, "badCertId", NULL },
  {  5, &hf_cmp_PKIFailureInfo_badDataFormat, -1, -1, "badDataFormat", NULL },
  {  6, &hf_cmp_PKIFailureInfo_wrongAuthority, -1, -1, "wrongAuthority", NULL },
  {  7, &hf_cmp_PKIFailureInfo_incorrectData, -1, -1, "incorrectData", NULL },
  {  8, &hf_cmp_PKIFailureInfo_missingTimeStamp, -1, -1, "missingTimeStamp", NULL },
  {  9, &hf_cmp_PKIFailureInfo_badPOP, -1, -1, "badPOP", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_cmp_PKIFailureInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    PKIFailureInfo_bits, hf_index, ett_cmp_PKIFailureInfo,
                                    NULL);

  return offset;
}
static int dissect_failInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIFailureInfo(FALSE, tvb, offset, pinfo, tree, hf_cmp_failInfo);
}


static const ber_sequence_t PKIStatusInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_status },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_statusString },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_failInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_PKIStatusInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PKIStatusInfo_sequence, hf_index, ett_cmp_PKIStatusInfo);

  return offset;
}
static int dissect_status1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIStatusInfo(FALSE, tvb, offset, pinfo, tree, hf_cmp_status1);
}
static int dissect_status_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIStatusInfo(FALSE, tvb, offset, pinfo, tree, hf_cmp_status_item);
}
static int dissect_pKIStatusInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIStatusInfo(FALSE, tvb, offset, pinfo, tree, hf_cmp_pKIStatusInfo);
}


const value_string cmp_CertOrEncCert_vals[] = {
  {   0, "certificate" },
  {   1, "encryptedCert" },
  { 0, NULL }
};

static const ber_choice_t CertOrEncCert_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_certificate },
  {   1, BER_CLASS_CON, 1, 0, dissect_encryptedCert },
  { 0, 0, 0, 0, NULL }
};

int
dissect_cmp_CertOrEncCert(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CertOrEncCert_choice, hf_index, ett_cmp_CertOrEncCert,
                                 NULL);

  return offset;
}
static int dissect_certOrEncCert(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CertOrEncCert(FALSE, tvb, offset, pinfo, tree, hf_cmp_certOrEncCert);
}


static const ber_sequence_t CertifiedKeyPair_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_certOrEncCert },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_privateKey },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_publicationInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_CertifiedKeyPair(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertifiedKeyPair_sequence, hf_index, ett_cmp_CertifiedKeyPair);

  return offset;
}
static int dissect_certifiedKeyPair(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CertifiedKeyPair(FALSE, tvb, offset, pinfo, tree, hf_cmp_certifiedKeyPair);
}
static int dissect_keyPairHist_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CertifiedKeyPair(FALSE, tvb, offset, pinfo, tree, hf_cmp_keyPairHist_item);
}


static const ber_sequence_t CertResponse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_certReqId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_status1 },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_certifiedKeyPair },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_rspInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_CertResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertResponse_sequence, hf_index, ett_cmp_CertResponse);

  return offset;
}
static int dissect_response_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CertResponse(FALSE, tvb, offset, pinfo, tree, hf_cmp_response_item);
}


static const ber_sequence_t SEQUENCE_OF_CertResponse_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_response_item },
};

static int
dissect_cmp_SEQUENCE_OF_CertResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_CertResponse_sequence_of, hf_index, ett_cmp_SEQUENCE_OF_CertResponse);

  return offset;
}
static int dissect_response(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_SEQUENCE_OF_CertResponse(FALSE, tvb, offset, pinfo, tree, hf_cmp_response);
}


static const ber_sequence_t CertRepMessage_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_caPubs },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_response },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_CertRepMessage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertRepMessage_sequence, hf_index, ett_cmp_CertRepMessage);

  return offset;
}
static int dissect_ip(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CertRepMessage(FALSE, tvb, offset, pinfo, tree, hf_cmp_ip);
}
static int dissect_cp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CertRepMessage(FALSE, tvb, offset, pinfo, tree, hf_cmp_cp);
}
static int dissect_kup(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CertRepMessage(FALSE, tvb, offset, pinfo, tree, hf_cmp_kup);
}
static int dissect_ccp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CertRepMessage(FALSE, tvb, offset, pinfo, tree, hf_cmp_ccp);
}


static const ber_sequence_t Challenge_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_owf },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_witness },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_challenge },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_Challenge(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Challenge_sequence, hf_index, ett_cmp_Challenge);

  return offset;
}
static int dissect_POPODecKeyChallContent_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_Challenge(FALSE, tvb, offset, pinfo, tree, hf_cmp_POPODecKeyChallContent_item);
}


static const ber_sequence_t POPODecKeyChallContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_POPODecKeyChallContent_item },
};

int
dissect_cmp_POPODecKeyChallContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      POPODecKeyChallContent_sequence_of, hf_index, ett_cmp_POPODecKeyChallContent);

  return offset;
}
static int dissect_popdecc(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_POPODecKeyChallContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_popdecc);
}


static const ber_sequence_t POPODecKeyRespContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_POPODecKeyRespContent_item },
};

int
dissect_cmp_POPODecKeyRespContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      POPODecKeyRespContent_sequence_of, hf_index, ett_cmp_POPODecKeyRespContent);

  return offset;
}
static int dissect_popdecr(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_POPODecKeyRespContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_popdecr);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_keyPairHist_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair);

  return offset;
}
static int dissect_keyPairHist(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair(FALSE, tvb, offset, pinfo, tree, hf_cmp_keyPairHist);
}


static const ber_sequence_t KeyRecRepContent_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_status1 },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_newSigCert },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_caCerts },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_keyPairHist },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_KeyRecRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   KeyRecRepContent_sequence, hf_index, ett_cmp_KeyRecRepContent);

  return offset;
}
static int dissect_krp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_KeyRecRepContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_krp);
}


static const ber_sequence_t RevDetails_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certDetails },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_revocationReason },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_badSinceDate },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_crlEntryDetails },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_RevDetails(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RevDetails_sequence, hf_index, ett_cmp_RevDetails);

  return offset;
}
static int dissect_RevReqContent_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_RevDetails(FALSE, tvb, offset, pinfo, tree, hf_cmp_RevReqContent_item);
}


static const ber_sequence_t RevReqContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RevReqContent_item },
};

int
dissect_cmp_RevReqContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RevReqContent_sequence_of, hf_index, ett_cmp_RevReqContent);

  return offset;
}
static int dissect_rr(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_RevReqContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_rr);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_status_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo);

  return offset;
}
static int dissect_status2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo(FALSE, tvb, offset, pinfo, tree, hf_cmp_status2);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertId_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_revCerts_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CertId_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId);

  return offset;
}
static int dissect_revCerts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId(FALSE, tvb, offset, pinfo, tree, hf_cmp_revCerts);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertificateList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crls_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CertificateList_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList);

  return offset;
}
static int dissect_crls(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList(FALSE, tvb, offset, pinfo, tree, hf_cmp_crls);
}


static const ber_sequence_t RevRepContent_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_status2 },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_revCerts },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_crls },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_RevRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RevRepContent_sequence, hf_index, ett_cmp_RevRepContent);

  return offset;
}
static int dissect_rp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_RevRepContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_rp);
}


static const ber_sequence_t CAKeyUpdAnnContent_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_oldWithNew },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_newWithOld },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_newWithNew },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_CAKeyUpdAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CAKeyUpdAnnContent_sequence, hf_index, ett_cmp_CAKeyUpdAnnContent);

  return offset;
}
static int dissect_ckuann(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CAKeyUpdAnnContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_ckuann);
}



int
dissect_cmp_CertAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_pkix1explicit_Certificate(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_cann(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CertAnnContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_cann);
}


static const ber_sequence_t RevAnnContent_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_status },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certId },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_willBeRevokedAt },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_badSinceDate },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_crlDetails },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_RevAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RevAnnContent_sequence, hf_index, ett_cmp_RevAnnContent);

  return offset;
}
static int dissect_rann(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_RevAnnContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_rann);
}


static const ber_sequence_t CRLAnnContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CRLAnnContent_item },
};

int
dissect_cmp_CRLAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CRLAnnContent_sequence_of, hf_index, ett_cmp_CRLAnnContent);

  return offset;
}
static int dissect_crlann(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_CRLAnnContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_crlann);
}



int
dissect_cmp_PKIConfirmContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_conf(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIConfirmContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_conf);
}



int
dissect_cmp_NestedMessageContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_cmp_PKIMessage(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_nested(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_NestedMessageContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_nested);
}


static const ber_sequence_t GenMsgContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_GenMsgContent_item },
};

int
dissect_cmp_GenMsgContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      GenMsgContent_sequence_of, hf_index, ett_cmp_GenMsgContent);

  return offset;
}
static int dissect_genm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_GenMsgContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_genm);
}


static const ber_sequence_t GenRepContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_GenRepContent_item },
};

int
dissect_cmp_GenRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      GenRepContent_sequence_of, hf_index, ett_cmp_GenRepContent);

  return offset;
}
static int dissect_genp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_GenRepContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_genp);
}


static const ber_sequence_t ErrorMsgContent_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pKIStatusInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_errorCode },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_errorDetails },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_ErrorMsgContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ErrorMsgContent_sequence, hf_index, ett_cmp_ErrorMsgContent);

  return offset;
}
static int dissect_error(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_ErrorMsgContent(FALSE, tvb, offset, pinfo, tree, hf_cmp_error);
}


const value_string cmp_PKIBody_vals[] = {
  {   0, "ir" },
  {   1, "ip" },
  {   2, "cr" },
  {   3, "cp" },
  {   5, "popdecc" },
  {   6, "popdecr" },
  {   7, "kur" },
  {   8, "kup" },
  {   9, "krr" },
  {  10, "krp" },
  {  11, "rr" },
  {  12, "rp" },
  {  13, "ccr" },
  {  14, "ccp" },
  {  15, "ckuann" },
  {  16, "cann" },
  {  17, "rann" },
  {  18, "crlann" },
  {  19, "conf" },
  {  20, "nested" },
  {  21, "genm" },
  {  22, "genp" },
  {  23, "error" },
  { 0, NULL }
};

static const ber_choice_t PKIBody_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_ir },
  {   1, BER_CLASS_CON, 1, 0, dissect_ip },
  {   2, BER_CLASS_CON, 2, 0, dissect_cr },
  {   3, BER_CLASS_CON, 3, 0, dissect_cp },
  {   5, BER_CLASS_CON, 5, 0, dissect_popdecc },
  {   6, BER_CLASS_CON, 6, 0, dissect_popdecr },
  {   7, BER_CLASS_CON, 7, 0, dissect_kur },
  {   8, BER_CLASS_CON, 8, 0, dissect_kup },
  {   9, BER_CLASS_CON, 9, 0, dissect_krr },
  {  10, BER_CLASS_CON, 10, 0, dissect_krp },
  {  11, BER_CLASS_CON, 11, 0, dissect_rr },
  {  12, BER_CLASS_CON, 12, 0, dissect_rp },
  {  13, BER_CLASS_CON, 13, 0, dissect_ccr },
  {  14, BER_CLASS_CON, 14, 0, dissect_ccp },
  {  15, BER_CLASS_CON, 15, 0, dissect_ckuann },
  {  16, BER_CLASS_CON, 16, 0, dissect_cann },
  {  17, BER_CLASS_CON, 17, 0, dissect_rann },
  {  18, BER_CLASS_CON, 18, 0, dissect_crlann },
  {  19, BER_CLASS_CON, 19, 0, dissect_conf },
  {  20, BER_CLASS_CON, 20, 0, dissect_nested },
  {  21, BER_CLASS_CON, 21, 0, dissect_genm },
  {  22, BER_CLASS_CON, 22, 0, dissect_genp },
  {  23, BER_CLASS_CON, 23, 0, dissect_error },
  { 0, 0, 0, 0, NULL }
};

int
dissect_cmp_PKIBody(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PKIBody_choice, hf_index, ett_cmp_PKIBody,
                                 NULL);

  return offset;
}
static int dissect_body(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIBody(FALSE, tvb, offset, pinfo, tree, hf_cmp_body);
}



int
dissect_cmp_PKIProtection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_protection(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_PKIProtection(FALSE, tvb, offset, pinfo, tree, hf_cmp_protection);
}


static const ber_sequence_t PKIMessage_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_header },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_body },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_protection },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_extraCerts },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_PKIMessage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PKIMessage_sequence, hf_index, ett_cmp_PKIMessage);

  return offset;
}


static const ber_sequence_t ProtectedPart_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_header },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_body },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_ProtectedPart(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ProtectedPart_sequence, hf_index, ett_cmp_ProtectedPart);

  return offset;
}



int
dissect_cmp_PasswordBasedMac(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PBMParameter_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_salt },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_owf },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_iterationCount },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mac },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_PBMParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PBMParameter_sequence, hf_index, ett_cmp_PBMParameter);

  return offset;
}



int
dissect_cmp_DHBasedMac(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t DHBMParameter_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_owf },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mac },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_DHBMParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DHBMParameter_sequence, hf_index, ett_cmp_DHBMParameter);

  return offset;
}



int
dissect_cmp_OOBCert(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_pkix1explicit_Certificate(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_cmp_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_hashVal(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmp_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_cmp_hashVal);
}


static const ber_sequence_t OOBCertHash_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_hashAlg },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_certId },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_hashVal },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_OOBCertHash(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OOBCertHash_sequence, hf_index, ett_cmp_OOBCertHash);

  return offset;
}


/*--- End of included file: packet-cmp-fn.c ---*/


static int
dissect_cmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		
		col_add_fstr(pinfo->cinfo, COL_INFO, "PKIXCMP");
	}


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	return dissect_cmp_PKIMessage(FALSE, tvb, 0, pinfo, tree, -1);
}

/*--- proto_register_cmp ----------------------------------------------*/
void proto_register_cmp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cmp_type_oid,
      { "InfoType", "cmp.type.oid",
        FT_STRING, BASE_NONE, NULL, 0,
        "Type of InfoTypeAndValue", HFILL }},

/*--- Included file: packet-cmp-hfarr.c ---*/

    { &hf_cmp_header,
      { "header", "cmp.header",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmp_body,
      { "body", "cmp.body",
        FT_UINT32, BASE_DEC, VALS(cmp_PKIBody_vals), 0,
        "", HFILL }},
    { &hf_cmp_protection,
      { "protection", "cmp.protection",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKIMessage/protection", HFILL }},
    { &hf_cmp_extraCerts,
      { "extraCerts", "cmp.extraCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIMessage/extraCerts", HFILL }},
    { &hf_cmp_extraCerts_item,
      { "Item", "cmp.extraCerts_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIMessage/extraCerts/_item", HFILL }},
    { &hf_cmp_pvno,
      { "pvno", "cmp.pvno",
        FT_INT32, BASE_DEC, VALS(cmp_T_pvno_vals), 0,
        "PKIHeader/pvno", HFILL }},
    { &hf_cmp_sender,
      { "sender", "cmp.sender",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIHeader/sender", HFILL }},
    { &hf_cmp_recipient,
      { "recipient", "cmp.recipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIHeader/recipient", HFILL }},
    { &hf_cmp_messageTime,
      { "messageTime", "cmp.messageTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "PKIHeader/messageTime", HFILL }},
    { &hf_cmp_protectionAlg,
      { "protectionAlg", "cmp.protectionAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIHeader/protectionAlg", HFILL }},
    { &hf_cmp_senderKID,
      { "senderKID", "cmp.senderKID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKIHeader/senderKID", HFILL }},
    { &hf_cmp_recipKID,
      { "recipKID", "cmp.recipKID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKIHeader/recipKID", HFILL }},
    { &hf_cmp_transactionID,
      { "transactionID", "cmp.transactionID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKIHeader/transactionID", HFILL }},
    { &hf_cmp_senderNonce,
      { "senderNonce", "cmp.senderNonce",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKIHeader/senderNonce", HFILL }},
    { &hf_cmp_recipNonce,
      { "recipNonce", "cmp.recipNonce",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKIHeader/recipNonce", HFILL }},
    { &hf_cmp_freeText,
      { "freeText", "cmp.freeText",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIHeader/freeText", HFILL }},
    { &hf_cmp_generalInfo,
      { "generalInfo", "cmp.generalInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIHeader/generalInfo", HFILL }},
    { &hf_cmp_generalInfo_item,
      { "Item", "cmp.generalInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIHeader/generalInfo/_item", HFILL }},
    { &hf_cmp_PKIFreeText_item,
      { "Item", "cmp.PKIFreeText_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PKIFreeText/_item", HFILL }},
    { &hf_cmp_ir,
      { "ir", "cmp.ir",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/ir", HFILL }},
    { &hf_cmp_ip,
      { "ip", "cmp.ip",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/ip", HFILL }},
    { &hf_cmp_cr,
      { "cr", "cmp.cr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/cr", HFILL }},
    { &hf_cmp_cp,
      { "cp", "cmp.cp",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/cp", HFILL }},
    { &hf_cmp_popdecc,
      { "popdecc", "cmp.popdecc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/popdecc", HFILL }},
    { &hf_cmp_popdecr,
      { "popdecr", "cmp.popdecr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/popdecr", HFILL }},
    { &hf_cmp_kur,
      { "kur", "cmp.kur",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/kur", HFILL }},
    { &hf_cmp_kup,
      { "kup", "cmp.kup",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/kup", HFILL }},
    { &hf_cmp_krr,
      { "krr", "cmp.krr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/krr", HFILL }},
    { &hf_cmp_krp,
      { "krp", "cmp.krp",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/krp", HFILL }},
    { &hf_cmp_rr,
      { "rr", "cmp.rr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/rr", HFILL }},
    { &hf_cmp_rp,
      { "rp", "cmp.rp",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/rp", HFILL }},
    { &hf_cmp_ccr,
      { "ccr", "cmp.ccr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/ccr", HFILL }},
    { &hf_cmp_ccp,
      { "ccp", "cmp.ccp",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/ccp", HFILL }},
    { &hf_cmp_ckuann,
      { "ckuann", "cmp.ckuann",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/ckuann", HFILL }},
    { &hf_cmp_cann,
      { "cann", "cmp.cann",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/cann", HFILL }},
    { &hf_cmp_rann,
      { "rann", "cmp.rann",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/rann", HFILL }},
    { &hf_cmp_crlann,
      { "crlann", "cmp.crlann",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/crlann", HFILL }},
    { &hf_cmp_conf,
      { "conf", "cmp.conf",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/conf", HFILL }},
    { &hf_cmp_nested,
      { "nested", "cmp.nested",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/nested", HFILL }},
    { &hf_cmp_genm,
      { "genm", "cmp.genm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/genm", HFILL }},
    { &hf_cmp_genp,
      { "genp", "cmp.genp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIBody/genp", HFILL }},
    { &hf_cmp_error,
      { "error", "cmp.error",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIBody/error", HFILL }},
    { &hf_cmp_salt,
      { "salt", "cmp.salt",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PBMParameter/salt", HFILL }},
    { &hf_cmp_owf,
      { "owf", "cmp.owf",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmp_iterationCount,
      { "iterationCount", "cmp.iterationCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "PBMParameter/iterationCount", HFILL }},
    { &hf_cmp_mac,
      { "mac", "cmp.mac",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmp_status,
      { "status", "cmp.status",
        FT_INT32, BASE_DEC, VALS(cmp_PKIStatus_vals), 0,
        "", HFILL }},
    { &hf_cmp_statusString,
      { "statusString", "cmp.statusString",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIStatusInfo/statusString", HFILL }},
    { &hf_cmp_failInfo,
      { "failInfo", "cmp.failInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKIStatusInfo/failInfo", HFILL }},
    { &hf_cmp_hashAlg,
      { "hashAlg", "cmp.hashAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "OOBCertHash/hashAlg", HFILL }},
    { &hf_cmp_certId,
      { "certId", "cmp.certId",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmp_hashVal,
      { "hashVal", "cmp.hashVal",
        FT_BYTES, BASE_HEX, NULL, 0,
        "OOBCertHash/hashVal", HFILL }},
    { &hf_cmp_POPODecKeyChallContent_item,
      { "Item", "cmp.POPODecKeyChallContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "POPODecKeyChallContent/_item", HFILL }},
    { &hf_cmp_witness,
      { "witness", "cmp.witness",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Challenge/witness", HFILL }},
    { &hf_cmp_challenge,
      { "challenge", "cmp.challenge",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Challenge/challenge", HFILL }},
    { &hf_cmp_POPODecKeyRespContent_item,
      { "Item", "cmp.POPODecKeyRespContent_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "POPODecKeyRespContent/_item", HFILL }},
    { &hf_cmp_caPubs,
      { "caPubs", "cmp.caPubs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertRepMessage/caPubs", HFILL }},
    { &hf_cmp_caPubs_item,
      { "Item", "cmp.caPubs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage/caPubs/_item", HFILL }},
    { &hf_cmp_response,
      { "response", "cmp.response",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertRepMessage/response", HFILL }},
    { &hf_cmp_response_item,
      { "Item", "cmp.response_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage/response/_item", HFILL }},
    { &hf_cmp_certReqId,
      { "certReqId", "cmp.certReqId",
        FT_INT32, BASE_DEC, NULL, 0,
        "CertResponse/certReqId", HFILL }},
    { &hf_cmp_status1,
      { "status", "cmp.status",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmp_certifiedKeyPair,
      { "certifiedKeyPair", "cmp.certifiedKeyPair",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertResponse/certifiedKeyPair", HFILL }},
    { &hf_cmp_rspInfo,
      { "rspInfo", "cmp.rspInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CertResponse/rspInfo", HFILL }},
    { &hf_cmp_certOrEncCert,
      { "certOrEncCert", "cmp.certOrEncCert",
        FT_UINT32, BASE_DEC, VALS(cmp_CertOrEncCert_vals), 0,
        "CertifiedKeyPair/certOrEncCert", HFILL }},
    { &hf_cmp_privateKey,
      { "privateKey", "cmp.privateKey",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertifiedKeyPair/privateKey", HFILL }},
    { &hf_cmp_publicationInfo,
      { "publicationInfo", "cmp.publicationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertifiedKeyPair/publicationInfo", HFILL }},
    { &hf_cmp_certificate,
      { "certificate", "cmp.certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertOrEncCert/certificate", HFILL }},
    { &hf_cmp_encryptedCert,
      { "encryptedCert", "cmp.encryptedCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertOrEncCert/encryptedCert", HFILL }},
    { &hf_cmp_newSigCert,
      { "newSigCert", "cmp.newSigCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyRecRepContent/newSigCert", HFILL }},
    { &hf_cmp_caCerts,
      { "caCerts", "cmp.caCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "KeyRecRepContent/caCerts", HFILL }},
    { &hf_cmp_caCerts_item,
      { "Item", "cmp.caCerts_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyRecRepContent/caCerts/_item", HFILL }},
    { &hf_cmp_keyPairHist,
      { "keyPairHist", "cmp.keyPairHist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "KeyRecRepContent/keyPairHist", HFILL }},
    { &hf_cmp_keyPairHist_item,
      { "Item", "cmp.keyPairHist_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyRecRepContent/keyPairHist/_item", HFILL }},
    { &hf_cmp_RevReqContent_item,
      { "Item", "cmp.RevReqContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevReqContent/_item", HFILL }},
    { &hf_cmp_certDetails,
      { "certDetails", "cmp.certDetails",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevDetails/certDetails", HFILL }},
    { &hf_cmp_revocationReason,
      { "revocationReason", "cmp.revocationReason",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RevDetails/revocationReason", HFILL }},
    { &hf_cmp_badSinceDate,
      { "badSinceDate", "cmp.badSinceDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmp_crlEntryDetails,
      { "crlEntryDetails", "cmp.crlEntryDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RevDetails/crlEntryDetails", HFILL }},
    { &hf_cmp_status2,
      { "status", "cmp.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RevRepContent/status", HFILL }},
    { &hf_cmp_status_item,
      { "Item", "cmp.status_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevRepContent/status/_item", HFILL }},
    { &hf_cmp_revCerts,
      { "revCerts", "cmp.revCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RevRepContent/revCerts", HFILL }},
    { &hf_cmp_revCerts_item,
      { "Item", "cmp.revCerts_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevRepContent/revCerts/_item", HFILL }},
    { &hf_cmp_crls,
      { "crls", "cmp.crls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RevRepContent/crls", HFILL }},
    { &hf_cmp_crls_item,
      { "Item", "cmp.crls_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevRepContent/crls/_item", HFILL }},
    { &hf_cmp_oldWithNew,
      { "oldWithNew", "cmp.oldWithNew",
        FT_NONE, BASE_NONE, NULL, 0,
        "CAKeyUpdAnnContent/oldWithNew", HFILL }},
    { &hf_cmp_newWithOld,
      { "newWithOld", "cmp.newWithOld",
        FT_NONE, BASE_NONE, NULL, 0,
        "CAKeyUpdAnnContent/newWithOld", HFILL }},
    { &hf_cmp_newWithNew,
      { "newWithNew", "cmp.newWithNew",
        FT_NONE, BASE_NONE, NULL, 0,
        "CAKeyUpdAnnContent/newWithNew", HFILL }},
    { &hf_cmp_willBeRevokedAt,
      { "willBeRevokedAt", "cmp.willBeRevokedAt",
        FT_STRING, BASE_NONE, NULL, 0,
        "RevAnnContent/willBeRevokedAt", HFILL }},
    { &hf_cmp_crlDetails,
      { "crlDetails", "cmp.crlDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RevAnnContent/crlDetails", HFILL }},
    { &hf_cmp_CRLAnnContent_item,
      { "Item", "cmp.CRLAnnContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CRLAnnContent/_item", HFILL }},
    { &hf_cmp_infoType,
      { "infoType", "cmp.infoType",
        FT_STRING, BASE_NONE, NULL, 0,
        "InfoTypeAndValue/infoType", HFILL }},
    { &hf_cmp_infoValue,
      { "infoValue", "cmp.infoValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoTypeAndValue/infoValue", HFILL }},
    { &hf_cmp_GenMsgContent_item,
      { "Item", "cmp.GenMsgContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenMsgContent/_item", HFILL }},
    { &hf_cmp_GenRepContent_item,
      { "Item", "cmp.GenRepContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenRepContent/_item", HFILL }},
    { &hf_cmp_pKIStatusInfo,
      { "pKIStatusInfo", "cmp.pKIStatusInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ErrorMsgContent/pKIStatusInfo", HFILL }},
    { &hf_cmp_errorCode,
      { "errorCode", "cmp.errorCode",
        FT_INT32, BASE_DEC, NULL, 0,
        "ErrorMsgContent/errorCode", HFILL }},
    { &hf_cmp_errorDetails,
      { "errorDetails", "cmp.errorDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ErrorMsgContent/errorDetails", HFILL }},
    { &hf_cmp_PKIFailureInfo_badAlg,
      { "badAlg", "cmp.badAlg",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_badMessageCheck,
      { "badMessageCheck", "cmp.badMessageCheck",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_badRequest,
      { "badRequest", "cmp.badRequest",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_badTime,
      { "badTime", "cmp.badTime",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_badCertId,
      { "badCertId", "cmp.badCertId",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_badDataFormat,
      { "badDataFormat", "cmp.badDataFormat",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_wrongAuthority,
      { "wrongAuthority", "cmp.wrongAuthority",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_incorrectData,
      { "incorrectData", "cmp.incorrectData",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_missingTimeStamp,
      { "missingTimeStamp", "cmp.missingTimeStamp",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_badPOP,
      { "badPOP", "cmp.badPOP",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},

/*--- End of included file: packet-cmp-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_cmp,

/*--- Included file: packet-cmp-ettarr.c ---*/

    &ett_cmp_PKIMessage,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_Certificate,
    &ett_cmp_PKIHeader,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue,
    &ett_cmp_PKIFreeText,
    &ett_cmp_PKIBody,
    &ett_cmp_ProtectedPart,
    &ett_cmp_PBMParameter,
    &ett_cmp_DHBMParameter,
    &ett_cmp_PKIFailureInfo,
    &ett_cmp_PKIStatusInfo,
    &ett_cmp_OOBCertHash,
    &ett_cmp_POPODecKeyChallContent,
    &ett_cmp_Challenge,
    &ett_cmp_POPODecKeyRespContent,
    &ett_cmp_CertRepMessage,
    &ett_cmp_SEQUENCE_OF_CertResponse,
    &ett_cmp_CertResponse,
    &ett_cmp_CertifiedKeyPair,
    &ett_cmp_CertOrEncCert,
    &ett_cmp_KeyRecRepContent,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair,
    &ett_cmp_RevReqContent,
    &ett_cmp_RevDetails,
    &ett_cmp_RevRepContent,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList,
    &ett_cmp_CAKeyUpdAnnContent,
    &ett_cmp_RevAnnContent,
    &ett_cmp_CRLAnnContent,
    &ett_cmp_InfoTypeAndValue,
    &ett_cmp_GenMsgContent,
    &ett_cmp_GenRepContent,
    &ett_cmp_ErrorMsgContent,

/*--- End of included file: packet-cmp-ettarr.c ---*/

  };

  /* Register protocol */
  proto_cmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_cmp -------------------------------------------*/
void proto_reg_handoff_cmp(void) {
	dissector_handle_t cmp_handle;

	cmp_handle = new_create_dissector_handle(dissect_cmp, proto_cmp);
	dissector_add_string("media_type", "application/pkixcmp", cmp_handle);

/*#include "packet-cmp-dis-tab.c"*/
}

