/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* ./packet-cmp.c                                                             */
/* ../../tools/asn2wrs.py -b -e -p cmp -c cmp.cnf -s packet-cmp-template CMP.asn */

/* Input file: packet-cmp-template.c */

#line 1 "packet-cmp-template.c"
/* packet-cmp.c
 * Routines for RFC2510 Certificate Management Protocol packet dissection
 *   Ronnie Sahlberg 2004
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

#include <stdio.h>
#include <string.h>

#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-cmp.h"
#include "packet-crmf.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include <epan/emem.h>
#include "packet-tcp.h"
#include <epan/prefs.h>
#include <epan/nstime.h>

#define PNAME  "Certificate Management Protocol"
#define PSNAME "CMP"
#define PFNAME "cmp"

#define TCP_PORT_CMP 829

/* desegmentation of CMP over TCP */
static gboolean cmp_desegment = TRUE;

/* Initialize the protocol and registered fields */
int proto_cmp = -1;
static int hf_cmp_type_oid = -1;
static int hf_cmp_rm = -1;
static int hf_cmp_type = -1;
static int hf_cmp_poll_ref = -1;
static int hf_cmp_next_poll_ref = -1;
static int hf_cmp_ttcb = -1;

/*--- Included file: packet-cmp-hf.c ---*/
#line 1 "packet-cmp-hf.c"
static int hf_cmp_PBMParameter_PDU = -1;          /* PBMParameter */
static int hf_cmp_DHBMParameter_PDU = -1;         /* DHBMParameter */
static int hf_cmp_CAProtEncCertValue_PDU = -1;    /* CAProtEncCertValue */
static int hf_cmp_SignKeyPairTypesValue_PDU = -1;  /* SignKeyPairTypesValue */
static int hf_cmp_EncKeyPairTypesValue_PDU = -1;  /* EncKeyPairTypesValue */
static int hf_cmp_PreferredSymmAlgValue_PDU = -1;  /* PreferredSymmAlgValue */
static int hf_cmp_CAKeyUpdateInfoValue_PDU = -1;  /* CAKeyUpdateInfoValue */
static int hf_cmp_CurrentCRLValue_PDU = -1;       /* CurrentCRLValue */
static int hf_cmp_UnsupportedOIDsValue_PDU = -1;  /* UnsupportedOIDsValue */
static int hf_cmp_KeyPairParamReqValue_PDU = -1;  /* KeyPairParamReqValue */
static int hf_cmp_KeyPairParamRepValue_PDU = -1;  /* KeyPairParamRepValue */
static int hf_cmp_RevPassphraseValue_PDU = -1;    /* RevPassphraseValue */
static int hf_cmp_ImplicitConfirmValue_PDU = -1;  /* ImplicitConfirmValue */
static int hf_cmp_ConfirmWaitTimeValue_PDU = -1;  /* ConfirmWaitTimeValue */
static int hf_cmp_OrigPKIMessageValue_PDU = -1;   /* OrigPKIMessageValue */
static int hf_cmp_SuppLangTagsValue_PDU = -1;     /* SuppLangTagsValue */
static int hf_cmp_x509v3PKCert = -1;              /* Certificate */
static int hf_cmp_header = -1;                    /* PKIHeader */
static int hf_cmp_body = -1;                      /* PKIBody */
static int hf_cmp_protection = -1;                /* PKIProtection */
static int hf_cmp_extraCerts = -1;                /* SEQUENCE_SIZE_1_MAX_OF_CMPCertificate */
static int hf_cmp_extraCerts_item = -1;           /* CMPCertificate */
static int hf_cmp_PKIMessages_item = -1;          /* PKIMessage */
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
static int hf_cmp_pkiconf = -1;                   /* PKIConfirmContent */
static int hf_cmp_nested = -1;                    /* NestedMessageContent */
static int hf_cmp_genm = -1;                      /* GenMsgContent */
static int hf_cmp_genp = -1;                      /* GenRepContent */
static int hf_cmp_error = -1;                     /* ErrorMsgContent */
static int hf_cmp_certConf = -1;                  /* CertConfirmContent */
static int hf_cmp_pollReq = -1;                   /* PollReqContent */
static int hf_cmp_pollRep = -1;                   /* PollRepContent */
static int hf_cmp_salt = -1;                      /* OCTET_STRING */
static int hf_cmp_owf = -1;                       /* AlgorithmIdentifier */
static int hf_cmp_iterationCount = -1;            /* INTEGER */
static int hf_cmp_mac = -1;                       /* AlgorithmIdentifier */
static int hf_cmp_pkistatus = -1;                 /* PKIStatus */
static int hf_cmp_statusString = -1;              /* PKIFreeText */
static int hf_cmp_failInfo = -1;                  /* PKIFailureInfo */
static int hf_cmp_hashAlg = -1;                   /* AlgorithmIdentifier */
static int hf_cmp_certId = -1;                    /* CertId */
static int hf_cmp_hashVal = -1;                   /* BIT_STRING */
static int hf_cmp_POPODecKeyChallContent_item = -1;  /* Challenge */
static int hf_cmp_witness = -1;                   /* OCTET_STRING */
static int hf_cmp_challenge = -1;                 /* OCTET_STRING */
static int hf_cmp_POPODecKeyRespContent_item = -1;  /* INTEGER */
static int hf_cmp_caPubs = -1;                    /* SEQUENCE_SIZE_1_MAX_OF_CMPCertificate */
static int hf_cmp_caPubs_item = -1;               /* CMPCertificate */
static int hf_cmp_response = -1;                  /* SEQUENCE_OF_CertResponse */
static int hf_cmp_response_item = -1;             /* CertResponse */
static int hf_cmp_certReqId = -1;                 /* INTEGER */
static int hf_cmp_pkistatusinf = -1;              /* PKIStatusInfo */
static int hf_cmp_certifiedKeyPair = -1;          /* CertifiedKeyPair */
static int hf_cmp_rspInfo = -1;                   /* OCTET_STRING */
static int hf_cmp_certOrEncCert = -1;             /* CertOrEncCert */
static int hf_cmp_privateKey = -1;                /* EncryptedValue */
static int hf_cmp_publicationInfo = -1;           /* PKIPublicationInfo */
static int hf_cmp_certificate = -1;               /* CMPCertificate */
static int hf_cmp_encryptedCert = -1;             /* EncryptedValue */
static int hf_cmp_newSigCert = -1;                /* CMPCertificate */
static int hf_cmp_caCerts = -1;                   /* SEQUENCE_SIZE_1_MAX_OF_CMPCertificate */
static int hf_cmp_caCerts_item = -1;              /* CMPCertificate */
static int hf_cmp_keyPairHist = -1;               /* SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair */
static int hf_cmp_keyPairHist_item = -1;          /* CertifiedKeyPair */
static int hf_cmp_RevReqContent_item = -1;        /* RevDetails */
static int hf_cmp_certDetails = -1;               /* CertTemplate */
static int hf_cmp_crlEntryDetails = -1;           /* Extensions */
static int hf_cmp_rvrpcnt_status = -1;            /* SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo */
static int hf_cmp_rvrpcnt_status_item = -1;       /* PKIStatusInfo */
static int hf_cmp_revCerts = -1;                  /* SEQUENCE_SIZE_1_MAX_OF_CertId */
static int hf_cmp_revCerts_item = -1;             /* CertId */
static int hf_cmp_crls = -1;                      /* SEQUENCE_SIZE_1_MAX_OF_CertificateList */
static int hf_cmp_crls_item = -1;                 /* CertificateList */
static int hf_cmp_oldWithNew = -1;                /* CMPCertificate */
static int hf_cmp_newWithOld = -1;                /* CMPCertificate */
static int hf_cmp_newWithNew = -1;                /* CMPCertificate */
static int hf_cmp_willBeRevokedAt = -1;           /* GeneralizedTime */
static int hf_cmp_badSinceDate = -1;              /* GeneralizedTime */
static int hf_cmp_crlDetails = -1;                /* Extensions */
static int hf_cmp_CRLAnnContent_item = -1;        /* CertificateList */
static int hf_cmp_CertConfirmContent_item = -1;   /* CertStatus */
static int hf_cmp_certHash = -1;                  /* OCTET_STRING */
static int hf_cmp_statusInfo = -1;                /* PKIStatusInfo */
static int hf_cmp_infoType = -1;                  /* T_infoType */
static int hf_cmp_infoValue = -1;                 /* T_infoValue */
static int hf_cmp_SignKeyPairTypesValue_item = -1;  /* AlgorithmIdentifier */
static int hf_cmp_EncKeyPairTypesValue_item = -1;  /* AlgorithmIdentifier */
static int hf_cmp_UnsupportedOIDsValue_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_cmp_SuppLangTagsValue_item = -1;    /* UTF8String */
static int hf_cmp_GenMsgContent_item = -1;        /* InfoTypeAndValue */
static int hf_cmp_GenRepContent_item = -1;        /* InfoTypeAndValue */
static int hf_cmp_pKIStatusInfo = -1;             /* PKIStatusInfo */
static int hf_cmp_errorCode = -1;                 /* INTEGER */
static int hf_cmp_errorDetails = -1;              /* PKIFreeText */
static int hf_cmp_PollReqContent_item = -1;       /* PollReqContent_item */
static int hf_cmp_PollRepContent_item = -1;       /* PollRepContent_item */
static int hf_cmp_checkAfter = -1;                /* INTEGER */
static int hf_cmp_reason = -1;                    /* PKIFreeText */
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
static int hf_cmp_PKIFailureInfo_certRevoked = -1;
static int hf_cmp_PKIFailureInfo_certConfirmed = -1;
static int hf_cmp_PKIFailureInfo_wrongIntegrity = -1;
static int hf_cmp_PKIFailureInfo_badRecipientNonce = -1;
static int hf_cmp_PKIFailureInfo_timeNotAvailable = -1;
static int hf_cmp_PKIFailureInfo_unacceptedPolicy = -1;
static int hf_cmp_PKIFailureInfo_unacceptedExtension = -1;
static int hf_cmp_PKIFailureInfo_addInfoNotAvailable = -1;
static int hf_cmp_PKIFailureInfo_badSenderNonce = -1;
static int hf_cmp_PKIFailureInfo_badCertTemplate = -1;
static int hf_cmp_PKIFailureInfo_signerNotTrusted = -1;
static int hf_cmp_PKIFailureInfo_transactionIdInUse = -1;
static int hf_cmp_PKIFailureInfo_unsupportedVersion = -1;
static int hf_cmp_PKIFailureInfo_notAuthorized = -1;
static int hf_cmp_PKIFailureInfo_systemUnavail = -1;
static int hf_cmp_PKIFailureInfo_systemFailure = -1;
static int hf_cmp_PKIFailureInfo_duplicateCertReq = -1;

/*--- End of included file: packet-cmp-hf.c ---*/
#line 66 "packet-cmp-template.c"

/* Initialize the subtree pointers */
static gint ett_cmp = -1;

/*--- Included file: packet-cmp-ett.c ---*/
#line 1 "packet-cmp-ett.c"
static gint ett_cmp_CMPCertificate = -1;
static gint ett_cmp_PKIMessage = -1;
static gint ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate = -1;
static gint ett_cmp_PKIMessages = -1;
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
static gint ett_cmp_CertConfirmContent = -1;
static gint ett_cmp_CertStatus = -1;
static gint ett_cmp_InfoTypeAndValue = -1;
static gint ett_cmp_SignKeyPairTypesValue = -1;
static gint ett_cmp_EncKeyPairTypesValue = -1;
static gint ett_cmp_UnsupportedOIDsValue = -1;
static gint ett_cmp_SuppLangTagsValue = -1;
static gint ett_cmp_GenMsgContent = -1;
static gint ett_cmp_GenRepContent = -1;
static gint ett_cmp_ErrorMsgContent = -1;
static gint ett_cmp_PollReqContent = -1;
static gint ett_cmp_PollReqContent_item = -1;
static gint ett_cmp_PollRepContent = -1;
static gint ett_cmp_PollRepContent_item = -1;

/*--- End of included file: packet-cmp-ett.c ---*/
#line 70 "packet-cmp-template.c"

static const char *object_identifier_id;



/*--- Included file: packet-cmp-fn.c ---*/
#line 1 "packet-cmp-fn.c"
/*--- Cyclic dependencies ---*/

/* PKIMessage -> PKIBody -> NestedMessageContent -> PKIMessages -> PKIMessage */
int dissect_cmp_PKIMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

static int dissect_PKIMessages_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIMessage(FALSE, tvb, offset, actx, tree, hf_cmp_PKIMessages_item);
}


/*--- Fields for imported types ---*/

static int dissect_x509v3PKCert(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_Certificate(FALSE, tvb, offset, actx, tree, hf_cmp_x509v3PKCert);
}
static int dissect_sender(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1implicit_GeneralName(FALSE, tvb, offset, actx, tree, hf_cmp_sender);
}
static int dissect_recipient(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1implicit_GeneralName(FALSE, tvb, offset, actx, tree, hf_cmp_recipient);
}
static int dissect_protectionAlg(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, actx, tree, hf_cmp_protectionAlg);
}
static int dissect_senderKID(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1implicit_KeyIdentifier(FALSE, tvb, offset, actx, tree, hf_cmp_senderKID);
}
static int dissect_recipKID(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1implicit_KeyIdentifier(FALSE, tvb, offset, actx, tree, hf_cmp_recipKID);
}
static int dissect_ir(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, actx, tree, hf_cmp_ir);
}
static int dissect_cr(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, actx, tree, hf_cmp_cr);
}
static int dissect_kur(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, actx, tree, hf_cmp_kur);
}
static int dissect_krr(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, actx, tree, hf_cmp_krr);
}
static int dissect_ccr(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_CertReqMessages(FALSE, tvb, offset, actx, tree, hf_cmp_ccr);
}
static int dissect_owf(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, actx, tree, hf_cmp_owf);
}
static int dissect_mac(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, actx, tree, hf_cmp_mac);
}
static int dissect_hashAlg(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, actx, tree, hf_cmp_hashAlg);
}
static int dissect_certId(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_CertId(FALSE, tvb, offset, actx, tree, hf_cmp_certId);
}
static int dissect_privateKey(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_EncryptedValue(FALSE, tvb, offset, actx, tree, hf_cmp_privateKey);
}
static int dissect_publicationInfo(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_PKIPublicationInfo(FALSE, tvb, offset, actx, tree, hf_cmp_publicationInfo);
}
static int dissect_encryptedCert(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_EncryptedValue(FALSE, tvb, offset, actx, tree, hf_cmp_encryptedCert);
}
static int dissect_certDetails(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_CertTemplate(FALSE, tvb, offset, actx, tree, hf_cmp_certDetails);
}
static int dissect_crlEntryDetails(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_Extensions(FALSE, tvb, offset, actx, tree, hf_cmp_crlEntryDetails);
}
static int dissect_revCerts_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_crmf_CertId(FALSE, tvb, offset, actx, tree, hf_cmp_revCerts_item);
}
static int dissect_crls_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_CertificateList(FALSE, tvb, offset, actx, tree, hf_cmp_crls_item);
}
static int dissect_crlDetails(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_Extensions(FALSE, tvb, offset, actx, tree, hf_cmp_crlDetails);
}
static int dissect_CRLAnnContent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_CertificateList(FALSE, tvb, offset, actx, tree, hf_cmp_CRLAnnContent_item);
}
static int dissect_SignKeyPairTypesValue_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, actx, tree, hf_cmp_SignKeyPairTypesValue_item);
}
static int dissect_EncKeyPairTypesValue_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, actx, tree, hf_cmp_EncKeyPairTypesValue_item);
}


const value_string cmp_CMPCertificate_vals[] = {
  {   0, "x509v3PKCert" },
  { 0, NULL }
};

static const ber_old_choice_t CMPCertificate_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509v3PKCert },
  { 0, 0, 0, 0, NULL }
};

int
dissect_cmp_CMPCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     CMPCertificate_choice, hf_index, ett_cmp_CMPCertificate,
                                     NULL);

  return offset;
}
static int dissect_extraCerts_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_extraCerts_item);
}
static int dissect_caPubs_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_caPubs_item);
}
static int dissect_certificate(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_certificate);
}
static int dissect_newSigCert(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_newSigCert);
}
static int dissect_caCerts_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_caCerts_item);
}
static int dissect_oldWithNew(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_oldWithNew);
}
static int dissect_newWithOld(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_newWithOld);
}
static int dissect_newWithNew(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_newWithNew);
}


static const value_string cmp_T_pvno_vals[] = {
  {   1, "cmp1999" },
  {   2, "cmp2000" },
  { 0, NULL }
};


static int
dissect_cmp_T_pvno(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_pvno(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_T_pvno(FALSE, tvb, offset, actx, tree, hf_cmp_pvno);
}



static int
dissect_cmp_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_messageTime(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_GeneralizedTime(FALSE, tvb, offset, actx, tree, hf_cmp_messageTime);
}
static int dissect_willBeRevokedAt(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_GeneralizedTime(FALSE, tvb, offset, actx, tree, hf_cmp_willBeRevokedAt);
}
static int dissect_badSinceDate(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_GeneralizedTime(FALSE, tvb, offset, actx, tree, hf_cmp_badSinceDate);
}



static int
dissect_cmp_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_transactionID(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_cmp_transactionID);
}
static int dissect_senderNonce(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_cmp_senderNonce);
}
static int dissect_recipNonce(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_cmp_recipNonce);
}
static int dissect_salt(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_cmp_salt);
}
static int dissect_witness(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_cmp_witness);
}
static int dissect_challenge(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_cmp_challenge);
}
static int dissect_rspInfo(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_cmp_rspInfo);
}
static int dissect_certHash(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_cmp_certHash);
}



static int
dissect_cmp_UTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_PKIFreeText_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_UTF8String(FALSE, tvb, offset, actx, tree, hf_cmp_PKIFreeText_item);
}
static int dissect_SuppLangTagsValue_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_UTF8String(FALSE, tvb, offset, actx, tree, hf_cmp_SuppLangTagsValue_item);
}


static const ber_old_sequence_t PKIFreeText_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_PKIFreeText_item },
};

int
dissect_cmp_PKIFreeText(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          PKIFreeText_sequence_of, hf_index, ett_cmp_PKIFreeText);

  return offset;
}
static int dissect_freeText(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIFreeText(FALSE, tvb, offset, actx, tree, hf_cmp_freeText);
}
static int dissect_statusString(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIFreeText(FALSE, tvb, offset, actx, tree, hf_cmp_statusString);
}
static int dissect_errorDetails(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIFreeText(FALSE, tvb, offset, actx, tree, hf_cmp_errorDetails);
}
static int dissect_reason(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIFreeText(FALSE, tvb, offset, actx, tree, hf_cmp_reason);
}



static int
dissect_cmp_T_infoType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cmp_type_oid, &object_identifier_id);

  return offset;
}
static int dissect_infoType(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_T_infoType(FALSE, tvb, offset, actx, tree, hf_cmp_infoType);
}



static int
dissect_cmp_T_infoValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 90 "cmp.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}
static int dissect_infoValue(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_T_infoValue(FALSE, tvb, offset, actx, tree, hf_cmp_infoValue);
}


static const ber_old_sequence_t InfoTypeAndValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_infoType },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_infoValue },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_InfoTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       InfoTypeAndValue_sequence, hf_index, ett_cmp_InfoTypeAndValue);

  return offset;
}
static int dissect_generalInfo_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_InfoTypeAndValue(FALSE, tvb, offset, actx, tree, hf_cmp_generalInfo_item);
}
static int dissect_GenMsgContent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_InfoTypeAndValue(FALSE, tvb, offset, actx, tree, hf_cmp_GenMsgContent_item);
}
static int dissect_GenRepContent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_InfoTypeAndValue(FALSE, tvb, offset, actx, tree, hf_cmp_GenRepContent_item);
}


static const ber_old_sequence_t SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_generalInfo_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue);

  return offset;
}
static int dissect_generalInfo(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue(FALSE, tvb, offset, actx, tree, hf_cmp_generalInfo);
}


static const ber_old_sequence_t PKIHeader_sequence[] = {
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
dissect_cmp_PKIHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PKIHeader_sequence, hf_index, ett_cmp_PKIHeader);

  return offset;
}
static int dissect_header(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIHeader(FALSE, tvb, offset, actx, tree, hf_cmp_header);
}


static const ber_old_sequence_t SEQUENCE_SIZE_1_MAX_OF_CMPCertificate_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extraCerts_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_SIZE_1_MAX_OF_CMPCertificate_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate);

  return offset;
}
static int dissect_extraCerts(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_extraCerts);
}
static int dissect_caPubs(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_caPubs);
}
static int dissect_caCerts(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate(FALSE, tvb, offset, actx, tree, hf_cmp_caCerts);
}



static int
dissect_cmp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_iterationCount(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_INTEGER(FALSE, tvb, offset, actx, tree, hf_cmp_iterationCount);
}
static int dissect_POPODecKeyRespContent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_INTEGER(FALSE, tvb, offset, actx, tree, hf_cmp_POPODecKeyRespContent_item);
}
static int dissect_certReqId(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_INTEGER(FALSE, tvb, offset, actx, tree, hf_cmp_certReqId);
}
static int dissect_errorCode(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_INTEGER(FALSE, tvb, offset, actx, tree, hf_cmp_errorCode);
}
static int dissect_checkAfter(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_INTEGER(FALSE, tvb, offset, actx, tree, hf_cmp_checkAfter);
}


const value_string cmp_PKIStatus_vals[] = {
  {   0, "accepted" },
  {   1, "grantedWithMods" },
  {   2, "rejection" },
  {   3, "waiting" },
  {   4, "revocationWarning" },
  {   5, "revocationNotification" },
  {   6, "keyUpdateWarning" },
  { 0, NULL }
};


int
dissect_cmp_PKIStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_pkistatus(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIStatus(FALSE, tvb, offset, actx, tree, hf_cmp_pkistatus);
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
  { 10, &hf_cmp_PKIFailureInfo_certRevoked, -1, -1, "certRevoked", NULL },
  { 11, &hf_cmp_PKIFailureInfo_certConfirmed, -1, -1, "certConfirmed", NULL },
  { 12, &hf_cmp_PKIFailureInfo_wrongIntegrity, -1, -1, "wrongIntegrity", NULL },
  { 13, &hf_cmp_PKIFailureInfo_badRecipientNonce, -1, -1, "badRecipientNonce", NULL },
  { 14, &hf_cmp_PKIFailureInfo_timeNotAvailable, -1, -1, "timeNotAvailable", NULL },
  { 15, &hf_cmp_PKIFailureInfo_unacceptedPolicy, -1, -1, "unacceptedPolicy", NULL },
  { 16, &hf_cmp_PKIFailureInfo_unacceptedExtension, -1, -1, "unacceptedExtension", NULL },
  { 17, &hf_cmp_PKIFailureInfo_addInfoNotAvailable, -1, -1, "addInfoNotAvailable", NULL },
  { 18, &hf_cmp_PKIFailureInfo_badSenderNonce, -1, -1, "badSenderNonce", NULL },
  { 19, &hf_cmp_PKIFailureInfo_badCertTemplate, -1, -1, "badCertTemplate", NULL },
  { 20, &hf_cmp_PKIFailureInfo_signerNotTrusted, -1, -1, "signerNotTrusted", NULL },
  { 21, &hf_cmp_PKIFailureInfo_transactionIdInUse, -1, -1, "transactionIdInUse", NULL },
  { 22, &hf_cmp_PKIFailureInfo_unsupportedVersion, -1, -1, "unsupportedVersion", NULL },
  { 23, &hf_cmp_PKIFailureInfo_notAuthorized, -1, -1, "notAuthorized", NULL },
  { 24, &hf_cmp_PKIFailureInfo_systemUnavail, -1, -1, "systemUnavail", NULL },
  { 25, &hf_cmp_PKIFailureInfo_systemFailure, -1, -1, "systemFailure", NULL },
  { 26, &hf_cmp_PKIFailureInfo_duplicateCertReq, -1, -1, "duplicateCertReq", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_cmp_PKIFailureInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    PKIFailureInfo_bits, hf_index, ett_cmp_PKIFailureInfo,
                                    NULL);

  return offset;
}
static int dissect_failInfo(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIFailureInfo(FALSE, tvb, offset, actx, tree, hf_cmp_failInfo);
}


static const ber_old_sequence_t PKIStatusInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkistatus },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_statusString },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_failInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_PKIStatusInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PKIStatusInfo_sequence, hf_index, ett_cmp_PKIStatusInfo);

  return offset;
}
static int dissect_pkistatusinf(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIStatusInfo(FALSE, tvb, offset, actx, tree, hf_cmp_pkistatusinf);
}
static int dissect_rvrpcnt_status_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIStatusInfo(FALSE, tvb, offset, actx, tree, hf_cmp_rvrpcnt_status_item);
}
static int dissect_statusInfo(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIStatusInfo(FALSE, tvb, offset, actx, tree, hf_cmp_statusInfo);
}
static int dissect_pKIStatusInfo(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIStatusInfo(FALSE, tvb, offset, actx, tree, hf_cmp_pKIStatusInfo);
}


const value_string cmp_CertOrEncCert_vals[] = {
  {   0, "certificate" },
  {   1, "encryptedCert" },
  { 0, NULL }
};

static const ber_old_choice_t CertOrEncCert_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_certificate },
  {   1, BER_CLASS_CON, 1, 0, dissect_encryptedCert },
  { 0, 0, 0, 0, NULL }
};

int
dissect_cmp_CertOrEncCert(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     CertOrEncCert_choice, hf_index, ett_cmp_CertOrEncCert,
                                     NULL);

  return offset;
}
static int dissect_certOrEncCert(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertOrEncCert(FALSE, tvb, offset, actx, tree, hf_cmp_certOrEncCert);
}


static const ber_old_sequence_t CertifiedKeyPair_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_certOrEncCert },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_privateKey },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_publicationInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_CertifiedKeyPair(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CertifiedKeyPair_sequence, hf_index, ett_cmp_CertifiedKeyPair);

  return offset;
}
static int dissect_certifiedKeyPair(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertifiedKeyPair(FALSE, tvb, offset, actx, tree, hf_cmp_certifiedKeyPair);
}
static int dissect_keyPairHist_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertifiedKeyPair(FALSE, tvb, offset, actx, tree, hf_cmp_keyPairHist_item);
}


static const ber_old_sequence_t CertResponse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_certReqId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkistatusinf },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_certifiedKeyPair },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_rspInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_CertResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CertResponse_sequence, hf_index, ett_cmp_CertResponse);

  return offset;
}
static int dissect_response_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertResponse(FALSE, tvb, offset, actx, tree, hf_cmp_response_item);
}


static const ber_old_sequence_t SEQUENCE_OF_CertResponse_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_response_item },
};

static int
dissect_cmp_SEQUENCE_OF_CertResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_OF_CertResponse_sequence_of, hf_index, ett_cmp_SEQUENCE_OF_CertResponse);

  return offset;
}
static int dissect_response(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_SEQUENCE_OF_CertResponse(FALSE, tvb, offset, actx, tree, hf_cmp_response);
}


static const ber_old_sequence_t CertRepMessage_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_caPubs },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_response },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_CertRepMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CertRepMessage_sequence, hf_index, ett_cmp_CertRepMessage);

  return offset;
}
static int dissect_ip(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertRepMessage(FALSE, tvb, offset, actx, tree, hf_cmp_ip);
}
static int dissect_cp(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertRepMessage(FALSE, tvb, offset, actx, tree, hf_cmp_cp);
}
static int dissect_kup(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertRepMessage(FALSE, tvb, offset, actx, tree, hf_cmp_kup);
}
static int dissect_ccp(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertRepMessage(FALSE, tvb, offset, actx, tree, hf_cmp_ccp);
}


static const ber_old_sequence_t Challenge_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_owf },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_witness },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_challenge },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_Challenge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       Challenge_sequence, hf_index, ett_cmp_Challenge);

  return offset;
}
static int dissect_POPODecKeyChallContent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_Challenge(FALSE, tvb, offset, actx, tree, hf_cmp_POPODecKeyChallContent_item);
}


static const ber_old_sequence_t POPODecKeyChallContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_POPODecKeyChallContent_item },
};

static int
dissect_cmp_POPODecKeyChallContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          POPODecKeyChallContent_sequence_of, hf_index, ett_cmp_POPODecKeyChallContent);

  return offset;
}
static int dissect_popdecc(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_POPODecKeyChallContent(FALSE, tvb, offset, actx, tree, hf_cmp_popdecc);
}


static const ber_old_sequence_t POPODecKeyRespContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_POPODecKeyRespContent_item },
};

int
dissect_cmp_POPODecKeyRespContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          POPODecKeyRespContent_sequence_of, hf_index, ett_cmp_POPODecKeyRespContent);

  return offset;
}
static int dissect_popdecr(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_POPODecKeyRespContent(FALSE, tvb, offset, actx, tree, hf_cmp_popdecr);
}


static const ber_old_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_keyPairHist_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair);

  return offset;
}
static int dissect_keyPairHist(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair(FALSE, tvb, offset, actx, tree, hf_cmp_keyPairHist);
}


static const ber_old_sequence_t KeyRecRepContent_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkistatusinf },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_newSigCert },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_caCerts },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_keyPairHist },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_KeyRecRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       KeyRecRepContent_sequence, hf_index, ett_cmp_KeyRecRepContent);

  return offset;
}
static int dissect_krp(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_KeyRecRepContent(FALSE, tvb, offset, actx, tree, hf_cmp_krp);
}


static const ber_old_sequence_t RevDetails_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certDetails },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_crlEntryDetails },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_RevDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RevDetails_sequence, hf_index, ett_cmp_RevDetails);

  return offset;
}
static int dissect_RevReqContent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_RevDetails(FALSE, tvb, offset, actx, tree, hf_cmp_RevReqContent_item);
}


static const ber_old_sequence_t RevReqContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RevReqContent_item },
};

int
dissect_cmp_RevReqContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          RevReqContent_sequence_of, hf_index, ett_cmp_RevReqContent);

  return offset;
}
static int dissect_rr(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_RevReqContent(FALSE, tvb, offset, actx, tree, hf_cmp_rr);
}


static const ber_old_sequence_t SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_rvrpcnt_status_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo);

  return offset;
}
static int dissect_rvrpcnt_status(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo(FALSE, tvb, offset, actx, tree, hf_cmp_rvrpcnt_status);
}


static const ber_old_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertId_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_revCerts_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_SIZE_1_MAX_OF_CertId_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId);

  return offset;
}
static int dissect_revCerts(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId(FALSE, tvb, offset, actx, tree, hf_cmp_revCerts);
}


static const ber_old_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertificateList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crls_item },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_SIZE_1_MAX_OF_CertificateList_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList);

  return offset;
}
static int dissect_crls(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList(FALSE, tvb, offset, actx, tree, hf_cmp_crls);
}


static const ber_old_sequence_t RevRepContent_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_rvrpcnt_status },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_revCerts },
  { BER_CLASS_CON, 1, 0, dissect_crls },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_RevRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RevRepContent_sequence, hf_index, ett_cmp_RevRepContent);

  return offset;
}
static int dissect_rp(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_RevRepContent(FALSE, tvb, offset, actx, tree, hf_cmp_rp);
}


static const ber_old_sequence_t CAKeyUpdAnnContent_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_oldWithNew },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_newWithOld },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_newWithNew },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_CAKeyUpdAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CAKeyUpdAnnContent_sequence, hf_index, ett_cmp_CAKeyUpdAnnContent);

  return offset;
}
static int dissect_ckuann(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CAKeyUpdAnnContent(FALSE, tvb, offset, actx, tree, hf_cmp_ckuann);
}



int
dissect_cmp_CertAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CMPCertificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_cann(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertAnnContent(FALSE, tvb, offset, actx, tree, hf_cmp_cann);
}


static const ber_old_sequence_t RevAnnContent_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkistatus },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certId },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_willBeRevokedAt },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_badSinceDate },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_crlDetails },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_RevAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RevAnnContent_sequence, hf_index, ett_cmp_RevAnnContent);

  return offset;
}
static int dissect_rann(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_RevAnnContent(FALSE, tvb, offset, actx, tree, hf_cmp_rann);
}


static const ber_old_sequence_t CRLAnnContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CRLAnnContent_item },
};

int
dissect_cmp_CRLAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          CRLAnnContent_sequence_of, hf_index, ett_cmp_CRLAnnContent);

  return offset;
}
static int dissect_crlann(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CRLAnnContent(FALSE, tvb, offset, actx, tree, hf_cmp_crlann);
}



int
dissect_cmp_PKIConfirmContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_pkiconf(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIConfirmContent(FALSE, tvb, offset, actx, tree, hf_cmp_pkiconf);
}


static const ber_old_sequence_t PKIMessages_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_PKIMessages_item },
};

int
dissect_cmp_PKIMessages(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          PKIMessages_sequence_of, hf_index, ett_cmp_PKIMessages);

  return offset;
}



int
dissect_cmp_NestedMessageContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_PKIMessages(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_nested(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_NestedMessageContent(FALSE, tvb, offset, actx, tree, hf_cmp_nested);
}


static const ber_old_sequence_t GenMsgContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_GenMsgContent_item },
};

int
dissect_cmp_GenMsgContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          GenMsgContent_sequence_of, hf_index, ett_cmp_GenMsgContent);

  return offset;
}
static int dissect_genm(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_GenMsgContent(FALSE, tvb, offset, actx, tree, hf_cmp_genm);
}


static const ber_old_sequence_t GenRepContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_GenRepContent_item },
};

static int
dissect_cmp_GenRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          GenRepContent_sequence_of, hf_index, ett_cmp_GenRepContent);

  return offset;
}
static int dissect_genp(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_GenRepContent(FALSE, tvb, offset, actx, tree, hf_cmp_genp);
}


static const ber_old_sequence_t ErrorMsgContent_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pKIStatusInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_errorCode },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_errorDetails },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_ErrorMsgContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ErrorMsgContent_sequence, hf_index, ett_cmp_ErrorMsgContent);

  return offset;
}
static int dissect_error(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_ErrorMsgContent(FALSE, tvb, offset, actx, tree, hf_cmp_error);
}


static const ber_old_sequence_t CertStatus_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_certHash },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_certReqId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_statusInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_CertStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CertStatus_sequence, hf_index, ett_cmp_CertStatus);

  return offset;
}
static int dissect_CertConfirmContent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertStatus(FALSE, tvb, offset, actx, tree, hf_cmp_CertConfirmContent_item);
}


static const ber_old_sequence_t CertConfirmContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CertConfirmContent_item },
};

int
dissect_cmp_CertConfirmContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          CertConfirmContent_sequence_of, hf_index, ett_cmp_CertConfirmContent);

  return offset;
}
static int dissect_certConf(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_CertConfirmContent(FALSE, tvb, offset, actx, tree, hf_cmp_certConf);
}


static const ber_old_sequence_t PollReqContent_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_certReqId },
  { 0, 0, 0, NULL }
};

static int
dissect_cmp_PollReqContent_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PollReqContent_item_sequence, hf_index, ett_cmp_PollReqContent_item);

  return offset;
}
static int dissect_PollReqContent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PollReqContent_item(FALSE, tvb, offset, actx, tree, hf_cmp_PollReqContent_item);
}


static const ber_old_sequence_t PollReqContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_PollReqContent_item },
};

int
dissect_cmp_PollReqContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          PollReqContent_sequence_of, hf_index, ett_cmp_PollReqContent);

  return offset;
}
static int dissect_pollReq(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PollReqContent(FALSE, tvb, offset, actx, tree, hf_cmp_pollReq);
}


static const ber_old_sequence_t PollRepContent_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_certReqId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_checkAfter },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_reason },
  { 0, 0, 0, NULL }
};

static int
dissect_cmp_PollRepContent_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PollRepContent_item_sequence, hf_index, ett_cmp_PollRepContent_item);

  return offset;
}
static int dissect_PollRepContent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PollRepContent_item(FALSE, tvb, offset, actx, tree, hf_cmp_PollRepContent_item);
}


static const ber_old_sequence_t PollRepContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_PollRepContent_item },
};

int
dissect_cmp_PollRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          PollRepContent_sequence_of, hf_index, ett_cmp_PollRepContent);

  return offset;
}
static int dissect_pollRep(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PollRepContent(FALSE, tvb, offset, actx, tree, hf_cmp_pollRep);
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
  {  19, "pkiconf" },
  {  20, "nested" },
  {  21, "genm" },
  {  22, "genp" },
  {  23, "error" },
  {  24, "certConf" },
  {  25, "pollReq" },
  {  26, "pollRep" },
  { 0, NULL }
};

static const ber_old_choice_t PKIBody_choice[] = {
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
  {  19, BER_CLASS_CON, 19, 0, dissect_pkiconf },
  {  20, BER_CLASS_CON, 20, 0, dissect_nested },
  {  21, BER_CLASS_CON, 21, 0, dissect_genm },
  {  22, BER_CLASS_CON, 22, 0, dissect_genp },
  {  23, BER_CLASS_CON, 23, 0, dissect_error },
  {  24, BER_CLASS_CON, 24, 0, dissect_certConf },
  {  25, BER_CLASS_CON, 25, 0, dissect_pollReq },
  {  26, BER_CLASS_CON, 26, 0, dissect_pollRep },
  { 0, 0, 0, 0, NULL }
};

int
dissect_cmp_PKIBody(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     PKIBody_choice, hf_index, ett_cmp_PKIBody,
                                     NULL);

  return offset;
}
static int dissect_body(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIBody(FALSE, tvb, offset, actx, tree, hf_cmp_body);
}



int
dissect_cmp_PKIProtection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_protection(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_PKIProtection(FALSE, tvb, offset, actx, tree, hf_cmp_protection);
}


static const ber_old_sequence_t PKIMessage_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_header },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_body },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_protection },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_extraCerts },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_PKIMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PKIMessage_sequence, hf_index, ett_cmp_PKIMessage);

  return offset;
}


static const ber_old_sequence_t ProtectedPart_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_header },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_body },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_ProtectedPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ProtectedPart_sequence, hf_index, ett_cmp_ProtectedPart);

  return offset;
}


static const ber_old_sequence_t PBMParameter_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_salt },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_owf },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_iterationCount },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mac },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_PBMParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PBMParameter_sequence, hf_index, ett_cmp_PBMParameter);

  return offset;
}


static const ber_old_sequence_t DHBMParameter_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_owf },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mac },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_DHBMParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       DHBMParameter_sequence, hf_index, ett_cmp_DHBMParameter);

  return offset;
}



int
dissect_cmp_OOBCert(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CMPCertificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_hashVal(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_BIT_STRING(FALSE, tvb, offset, actx, tree, hf_cmp_hashVal);
}


static const ber_old_sequence_t OOBCertHash_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_hashAlg },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_certId },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_hashVal },
  { 0, 0, 0, NULL }
};

int
dissect_cmp_OOBCertHash(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       OOBCertHash_sequence, hf_index, ett_cmp_OOBCertHash);

  return offset;
}



static int
dissect_cmp_CAProtEncCertValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CMPCertificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_old_sequence_t SignKeyPairTypesValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SignKeyPairTypesValue_item },
};

static int
dissect_cmp_SignKeyPairTypesValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SignKeyPairTypesValue_sequence_of, hf_index, ett_cmp_SignKeyPairTypesValue);

  return offset;
}


static const ber_old_sequence_t EncKeyPairTypesValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_EncKeyPairTypesValue_item },
};

static int
dissect_cmp_EncKeyPairTypesValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          EncKeyPairTypesValue_sequence_of, hf_index, ett_cmp_EncKeyPairTypesValue);

  return offset;
}



static int
dissect_cmp_PreferredSymmAlgValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkix1explicit_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_CAKeyUpdateInfoValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CAKeyUpdAnnContent(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_CurrentCRLValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkix1explicit_CertificateList(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_UnsupportedOIDsValue_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_cmp_OBJECT_IDENTIFIER(FALSE, tvb, offset, actx, tree, hf_cmp_UnsupportedOIDsValue_item);
}


static const ber_old_sequence_t UnsupportedOIDsValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_UnsupportedOIDsValue_item },
};

static int
dissect_cmp_UnsupportedOIDsValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          UnsupportedOIDsValue_sequence_of, hf_index, ett_cmp_UnsupportedOIDsValue);

  return offset;
}



static int
dissect_cmp_KeyPairParamReqValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cmp_KeyPairParamRepValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkix1explicit_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_RevPassphraseValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_crmf_EncryptedValue(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_ImplicitConfirmValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmp_ConfirmWaitTimeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmp_OrigPKIMessageValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_PKIMessages(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_old_sequence_t SuppLangTagsValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_SuppLangTagsValue_item },
};

static int
dissect_cmp_SuppLangTagsValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SuppLangTagsValue_sequence_of, hf_index, ett_cmp_SuppLangTagsValue);

  return offset;
}

/*--- PDUs ---*/

static void dissect_PBMParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_PBMParameter(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_PBMParameter_PDU);
}
static void dissect_DHBMParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_DHBMParameter(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_DHBMParameter_PDU);
}
static void dissect_CAProtEncCertValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_CAProtEncCertValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_CAProtEncCertValue_PDU);
}
static void dissect_SignKeyPairTypesValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_SignKeyPairTypesValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_SignKeyPairTypesValue_PDU);
}
static void dissect_EncKeyPairTypesValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_EncKeyPairTypesValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_EncKeyPairTypesValue_PDU);
}
static void dissect_PreferredSymmAlgValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_PreferredSymmAlgValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_PreferredSymmAlgValue_PDU);
}
static void dissect_CAKeyUpdateInfoValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_CAKeyUpdateInfoValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_CAKeyUpdateInfoValue_PDU);
}
static void dissect_CurrentCRLValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_CurrentCRLValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_CurrentCRLValue_PDU);
}
static void dissect_UnsupportedOIDsValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_UnsupportedOIDsValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_UnsupportedOIDsValue_PDU);
}
static void dissect_KeyPairParamReqValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_KeyPairParamReqValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_KeyPairParamReqValue_PDU);
}
static void dissect_KeyPairParamRepValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_KeyPairParamRepValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_KeyPairParamRepValue_PDU);
}
static void dissect_RevPassphraseValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_RevPassphraseValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_RevPassphraseValue_PDU);
}
static void dissect_ImplicitConfirmValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_ImplicitConfirmValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_ImplicitConfirmValue_PDU);
}
static void dissect_ConfirmWaitTimeValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_ConfirmWaitTimeValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_ConfirmWaitTimeValue_PDU);
}
static void dissect_OrigPKIMessageValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_OrigPKIMessageValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_OrigPKIMessageValue_PDU);
}
static void dissect_SuppLangTagsValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmp_SuppLangTagsValue(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmp_SuppLangTagsValue_PDU);
}


/*--- End of included file: packet-cmp-fn.c ---*/
#line 75 "packet-cmp-template.c"

static int
dissect_cmp_pdu(tvbuff_t *tvb, proto_tree *tree, asn1_ctx_t *actx)
{
	return dissect_cmp_PKIMessage(FALSE, tvb, 0, actx,tree, -1);
}

#define CMP_TYPE_PKIMSG		0
#define CMP_TYPE_POLLREP	1
#define CMP_TYPE_POLLREQ	2
#define CMP_TYPE_NEGPOLLREP	3
#define CMP_TYPE_PARTIALMSGREP	4
#define CMP_TYPE_FINALMSGREP	5
#define CMP_TYPE_ERRORMSGREP	6
static const value_string cmp_pdu_types[] = {
	{ CMP_TYPE_PKIMSG,		"pkiMsg" },
	{ CMP_TYPE_POLLREP,		"pollRep" },
	{ CMP_TYPE_POLLREQ,		"pollReq" },
	{ CMP_TYPE_NEGPOLLREP,		"negPollRep" },
	{ CMP_TYPE_PARTIALMSGREP,	"partialMsgRep" },
	{ CMP_TYPE_FINALMSGREP,		"finalMsgRep" },
	{ CMP_TYPE_ERRORMSGREP,		"errorMsgRep" },
	{ 0, NULL },
};

static void dissect_cmp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	tvbuff_t   *next_tvb;
	guint32 pdu_len;
	guint8 pdu_type;
	nstime_t	ts;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_guint8(tvb, 4);

	proto_tree_add_uint(tree, hf_cmp_rm, tvb, 0, 4, pdu_len);
	proto_tree_add_uint(tree, hf_cmp_type, tvb, 4, 1, pdu_type);

        if (check_col (pinfo->cinfo, COL_INFO)) {
            col_set_str (pinfo->cinfo, COL_INFO, val_to_str (pdu_type, cmp_pdu_types, "0x%x"));
        }

	switch(pdu_type){
	case CMP_TYPE_PKIMSG:
		next_tvb = tvb_new_subset(tvb, 5, tvb_length_remaining(tvb, 5), pdu_len);
		dissect_cmp_pdu(next_tvb, tree, &asn1_ctx);
		break;
	case CMP_TYPE_POLLREP:
		proto_tree_add_item(tree, hf_cmp_poll_ref, tvb, 0, 4, FALSE);

		ts.secs = tvb_get_ntohl(tvb, 4);
		ts.nsecs = 0;
		proto_tree_add_time(tree, hf_cmp_ttcb, tvb, 4, 4, &ts);
		break;
	case CMP_TYPE_POLLREQ:
		proto_tree_add_item(tree, hf_cmp_poll_ref, tvb, 0, 4, FALSE);
		break;
	case CMP_TYPE_NEGPOLLREP:
		break;
	case CMP_TYPE_PARTIALMSGREP:
		proto_tree_add_item(tree, hf_cmp_next_poll_ref, tvb, 0, 4, FALSE);

		ts.secs = tvb_get_ntohl(tvb, 4);
		ts.nsecs = 0;
		proto_tree_add_time(tree, hf_cmp_ttcb, tvb, 4, 4, &ts);

		next_tvb = tvb_new_subset(tvb, 13, tvb_length_remaining(tvb, 13), pdu_len);
		dissect_cmp_pdu(next_tvb, tree, &asn1_ctx);
		break;
	case CMP_TYPE_FINALMSGREP:
		next_tvb = tvb_new_subset(tvb, 5, tvb_length_remaining(tvb, 5), pdu_len);
		dissect_cmp_pdu(next_tvb, tree, &asn1_ctx);
		break;
	case CMP_TYPE_ERRORMSGREP:
		/*XXX to be added*/
		break;
	}

}

static guint get_cmp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 plen;

  /*
   * Get the length of the CMP-over-TCP packet.
   */
  plen = tvb_get_ntohl(tvb, offset);

  return plen+4;
}

/* CMP over TCP    RFC2510 section 5.2 */
static int
dissect_cmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint32 pdu_len;
	guint8 pdu_type;

	/* only attempt to dissect it as CMP over TCP if we have
	 * at least 5 bytes.
	 */
	if (!tvb_bytes_exist(tvb, 0, 5)) {
		return 0;
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_guint8(tvb, 4);

	/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes 
	 * in size.
	 * It is definitely at least 1 byte to accomodate the flags byte 
	 */
	if((pdu_len<=0)||(pdu_len>10000)){
		return 0;
	}
	/* type is between 0 and 6 */
	if(pdu_type>6){
		return 0;
	}
	/* type 0 contains a PKI message and must therefore be >= 3 bytes 
	 * long (flags + BER TAG + BER LENGTH
	 */
	if((pdu_type==0)&&(pdu_len<3)){
		return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, parent_tree, cmp_desegment, 4, get_cmp_pdu_len,
		dissect_cmp_tcp_pdu);

	return tvb_length(tvb);
}

static int
dissect_cmp_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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

	return dissect_cmp_pdu(tvb, tree, &asn1_ctx);
}


/*--- proto_register_cmp ----------------------------------------------*/
void proto_register_cmp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cmp_type_oid,
      { "InfoType", "cmp.type.oid",
        FT_STRING, BASE_NONE, NULL, 0,
        "Type of InfoTypeAndValue", HFILL }},
    { &hf_cmp_rm,
      { "Record Marker", "cmp.rm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Record Marker  length of PDU in bytes", HFILL }},
    { &hf_cmp_type,
      { "Type", "cmp.type",
        FT_UINT8, BASE_DEC, VALS(cmp_pdu_types), 0,
        "PDU Type", HFILL }},
    { &hf_cmp_poll_ref,
      { "Polling Reference", "cmp.poll_ref",
        FT_UINT32, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_cmp_next_poll_ref,
      { "Next Polling Reference", "cmp.next_poll_ref",
        FT_UINT32, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_cmp_ttcb,
      { "Time to check Back", "cmp.ttcb",
        FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0,
        "", HFILL }},

/*--- Included file: packet-cmp-hfarr.c ---*/
#line 1 "packet-cmp-hfarr.c"
    { &hf_cmp_PBMParameter_PDU,
      { "PBMParameter", "cmp.PBMParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PBMParameter", HFILL }},
    { &hf_cmp_DHBMParameter_PDU,
      { "DHBMParameter", "cmp.DHBMParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.DHBMParameter", HFILL }},
    { &hf_cmp_CAProtEncCertValue_PDU,
      { "CAProtEncCertValue", "cmp.CAProtEncCertValue",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CAProtEncCertValue", HFILL }},
    { &hf_cmp_SignKeyPairTypesValue_PDU,
      { "SignKeyPairTypesValue", "cmp.SignKeyPairTypesValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SignKeyPairTypesValue", HFILL }},
    { &hf_cmp_EncKeyPairTypesValue_PDU,
      { "EncKeyPairTypesValue", "cmp.EncKeyPairTypesValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.EncKeyPairTypesValue", HFILL }},
    { &hf_cmp_PreferredSymmAlgValue_PDU,
      { "PreferredSymmAlgValue", "cmp.PreferredSymmAlgValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PreferredSymmAlgValue", HFILL }},
    { &hf_cmp_CAKeyUpdateInfoValue_PDU,
      { "CAKeyUpdateInfoValue", "cmp.CAKeyUpdateInfoValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CAKeyUpdateInfoValue", HFILL }},
    { &hf_cmp_CurrentCRLValue_PDU,
      { "CurrentCRLValue", "cmp.CurrentCRLValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CurrentCRLValue", HFILL }},
    { &hf_cmp_UnsupportedOIDsValue_PDU,
      { "UnsupportedOIDsValue", "cmp.UnsupportedOIDsValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.UnsupportedOIDsValue", HFILL }},
    { &hf_cmp_KeyPairParamReqValue_PDU,
      { "KeyPairParamReqValue", "cmp.KeyPairParamReqValue",
        FT_OID, BASE_NONE, NULL, 0,
        "cmp.KeyPairParamReqValue", HFILL }},
    { &hf_cmp_KeyPairParamRepValue_PDU,
      { "KeyPairParamRepValue", "cmp.KeyPairParamRepValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.KeyPairParamRepValue", HFILL }},
    { &hf_cmp_RevPassphraseValue_PDU,
      { "RevPassphraseValue", "cmp.RevPassphraseValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.RevPassphraseValue", HFILL }},
    { &hf_cmp_ImplicitConfirmValue_PDU,
      { "ImplicitConfirmValue", "cmp.ImplicitConfirmValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.ImplicitConfirmValue", HFILL }},
    { &hf_cmp_ConfirmWaitTimeValue_PDU,
      { "ConfirmWaitTimeValue", "cmp.ConfirmWaitTimeValue",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmp.ConfirmWaitTimeValue", HFILL }},
    { &hf_cmp_OrigPKIMessageValue_PDU,
      { "OrigPKIMessageValue", "cmp.OrigPKIMessageValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.OrigPKIMessageValue", HFILL }},
    { &hf_cmp_SuppLangTagsValue_PDU,
      { "SuppLangTagsValue", "cmp.SuppLangTagsValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SuppLangTagsValue", HFILL }},
    { &hf_cmp_x509v3PKCert,
      { "x509v3PKCert", "cmp.x509v3PKCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.Certificate", HFILL }},
    { &hf_cmp_header,
      { "header", "cmp.header",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PKIHeader", HFILL }},
    { &hf_cmp_body,
      { "body", "cmp.body",
        FT_UINT32, BASE_DEC, VALS(cmp_PKIBody_vals), 0,
        "cmp.PKIBody", HFILL }},
    { &hf_cmp_protection,
      { "protection", "cmp.protection",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.PKIProtection", HFILL }},
    { &hf_cmp_extraCerts,
      { "extraCerts", "cmp.extraCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SEQUENCE_SIZE_1_MAX_OF_CMPCertificate", HFILL }},
    { &hf_cmp_extraCerts_item,
      { "Item", "cmp.extraCerts_item",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CMPCertificate", HFILL }},
    { &hf_cmp_PKIMessages_item,
      { "Item", "cmp.PKIMessages_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PKIMessage", HFILL }},
    { &hf_cmp_pvno,
      { "pvno", "cmp.pvno",
        FT_INT32, BASE_DEC, VALS(cmp_T_pvno_vals), 0,
        "cmp.T_pvno", HFILL }},
    { &hf_cmp_sender,
      { "sender", "cmp.sender",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkix1implicit.GeneralName", HFILL }},
    { &hf_cmp_recipient,
      { "recipient", "cmp.recipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkix1implicit.GeneralName", HFILL }},
    { &hf_cmp_messageTime,
      { "messageTime", "cmp.messageTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmp.GeneralizedTime", HFILL }},
    { &hf_cmp_protectionAlg,
      { "protectionAlg", "cmp.protectionAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.AlgorithmIdentifier", HFILL }},
    { &hf_cmp_senderKID,
      { "senderKID", "cmp.senderKID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkix1implicit.KeyIdentifier", HFILL }},
    { &hf_cmp_recipKID,
      { "recipKID", "cmp.recipKID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkix1implicit.KeyIdentifier", HFILL }},
    { &hf_cmp_transactionID,
      { "transactionID", "cmp.transactionID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.OCTET_STRING", HFILL }},
    { &hf_cmp_senderNonce,
      { "senderNonce", "cmp.senderNonce",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.OCTET_STRING", HFILL }},
    { &hf_cmp_recipNonce,
      { "recipNonce", "cmp.recipNonce",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.OCTET_STRING", HFILL }},
    { &hf_cmp_freeText,
      { "freeText", "cmp.freeText",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.PKIFreeText", HFILL }},
    { &hf_cmp_generalInfo,
      { "generalInfo", "cmp.generalInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue", HFILL }},
    { &hf_cmp_generalInfo_item,
      { "Item", "cmp.generalInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.InfoTypeAndValue", HFILL }},
    { &hf_cmp_PKIFreeText_item,
      { "Item", "cmp.PKIFreeText_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmp.UTF8String", HFILL }},
    { &hf_cmp_ir,
      { "ir", "cmp.ir",
        FT_UINT32, BASE_DEC, NULL, 0,
        "crmf.CertReqMessages", HFILL }},
    { &hf_cmp_ip,
      { "ip", "cmp.ip",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CertRepMessage", HFILL }},
    { &hf_cmp_cr,
      { "cr", "cmp.cr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "crmf.CertReqMessages", HFILL }},
    { &hf_cmp_cp,
      { "cp", "cmp.cp",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CertRepMessage", HFILL }},
    { &hf_cmp_popdecc,
      { "popdecc", "cmp.popdecc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.POPODecKeyChallContent", HFILL }},
    { &hf_cmp_popdecr,
      { "popdecr", "cmp.popdecr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.POPODecKeyRespContent", HFILL }},
    { &hf_cmp_kur,
      { "kur", "cmp.kur",
        FT_UINT32, BASE_DEC, NULL, 0,
        "crmf.CertReqMessages", HFILL }},
    { &hf_cmp_kup,
      { "kup", "cmp.kup",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CertRepMessage", HFILL }},
    { &hf_cmp_krr,
      { "krr", "cmp.krr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "crmf.CertReqMessages", HFILL }},
    { &hf_cmp_krp,
      { "krp", "cmp.krp",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.KeyRecRepContent", HFILL }},
    { &hf_cmp_rr,
      { "rr", "cmp.rr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.RevReqContent", HFILL }},
    { &hf_cmp_rp,
      { "rp", "cmp.rp",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.RevRepContent", HFILL }},
    { &hf_cmp_ccr,
      { "ccr", "cmp.ccr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "crmf.CertReqMessages", HFILL }},
    { &hf_cmp_ccp,
      { "ccp", "cmp.ccp",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CertRepMessage", HFILL }},
    { &hf_cmp_ckuann,
      { "ckuann", "cmp.ckuann",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CAKeyUpdAnnContent", HFILL }},
    { &hf_cmp_cann,
      { "cann", "cmp.cann",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CertAnnContent", HFILL }},
    { &hf_cmp_rann,
      { "rann", "cmp.rann",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.RevAnnContent", HFILL }},
    { &hf_cmp_crlann,
      { "crlann", "cmp.crlann",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.CRLAnnContent", HFILL }},
    { &hf_cmp_pkiconf,
      { "pkiconf", "cmp.pkiconf",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PKIConfirmContent", HFILL }},
    { &hf_cmp_nested,
      { "nested", "cmp.nested",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.NestedMessageContent", HFILL }},
    { &hf_cmp_genm,
      { "genm", "cmp.genm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.GenMsgContent", HFILL }},
    { &hf_cmp_genp,
      { "genp", "cmp.genp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.GenRepContent", HFILL }},
    { &hf_cmp_error,
      { "error", "cmp.error",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.ErrorMsgContent", HFILL }},
    { &hf_cmp_certConf,
      { "certConf", "cmp.certConf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.CertConfirmContent", HFILL }},
    { &hf_cmp_pollReq,
      { "pollReq", "cmp.pollReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.PollReqContent", HFILL }},
    { &hf_cmp_pollRep,
      { "pollRep", "cmp.pollRep",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.PollRepContent", HFILL }},
    { &hf_cmp_salt,
      { "salt", "cmp.salt",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.OCTET_STRING", HFILL }},
    { &hf_cmp_owf,
      { "owf", "cmp.owf",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.AlgorithmIdentifier", HFILL }},
    { &hf_cmp_iterationCount,
      { "iterationCount", "cmp.iterationCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmp.INTEGER", HFILL }},
    { &hf_cmp_mac,
      { "mac", "cmp.mac",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.AlgorithmIdentifier", HFILL }},
    { &hf_cmp_pkistatus,
      { "status", "cmp.status",
        FT_INT32, BASE_DEC, VALS(cmp_PKIStatus_vals), 0,
        "cmp.PKIStatus", HFILL }},
    { &hf_cmp_statusString,
      { "statusString", "cmp.statusString",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.PKIFreeText", HFILL }},
    { &hf_cmp_failInfo,
      { "failInfo", "cmp.failInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.PKIFailureInfo", HFILL }},
    { &hf_cmp_hashAlg,
      { "hashAlg", "cmp.hashAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.AlgorithmIdentifier", HFILL }},
    { &hf_cmp_certId,
      { "certId", "cmp.certId",
        FT_NONE, BASE_NONE, NULL, 0,
        "crmf.CertId", HFILL }},
    { &hf_cmp_hashVal,
      { "hashVal", "cmp.hashVal",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.BIT_STRING", HFILL }},
    { &hf_cmp_POPODecKeyChallContent_item,
      { "Item", "cmp.POPODecKeyChallContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.Challenge", HFILL }},
    { &hf_cmp_witness,
      { "witness", "cmp.witness",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.OCTET_STRING", HFILL }},
    { &hf_cmp_challenge,
      { "challenge", "cmp.challenge",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.OCTET_STRING", HFILL }},
    { &hf_cmp_POPODecKeyRespContent_item,
      { "Item", "cmp.POPODecKeyRespContent_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmp.INTEGER", HFILL }},
    { &hf_cmp_caPubs,
      { "caPubs", "cmp.caPubs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SEQUENCE_SIZE_1_MAX_OF_CMPCertificate", HFILL }},
    { &hf_cmp_caPubs_item,
      { "Item", "cmp.caPubs_item",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CMPCertificate", HFILL }},
    { &hf_cmp_response,
      { "response", "cmp.response",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SEQUENCE_OF_CertResponse", HFILL }},
    { &hf_cmp_response_item,
      { "Item", "cmp.response_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CertResponse", HFILL }},
    { &hf_cmp_certReqId,
      { "certReqId", "cmp.certReqId",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmp.INTEGER", HFILL }},
    { &hf_cmp_pkistatusinf,
      { "status", "cmp.status",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PKIStatusInfo", HFILL }},
    { &hf_cmp_certifiedKeyPair,
      { "certifiedKeyPair", "cmp.certifiedKeyPair",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CertifiedKeyPair", HFILL }},
    { &hf_cmp_rspInfo,
      { "rspInfo", "cmp.rspInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.OCTET_STRING", HFILL }},
    { &hf_cmp_certOrEncCert,
      { "certOrEncCert", "cmp.certOrEncCert",
        FT_UINT32, BASE_DEC, VALS(cmp_CertOrEncCert_vals), 0,
        "cmp.CertOrEncCert", HFILL }},
    { &hf_cmp_privateKey,
      { "privateKey", "cmp.privateKey",
        FT_NONE, BASE_NONE, NULL, 0,
        "crmf.EncryptedValue", HFILL }},
    { &hf_cmp_publicationInfo,
      { "publicationInfo", "cmp.publicationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "crmf.PKIPublicationInfo", HFILL }},
    { &hf_cmp_certificate,
      { "certificate", "cmp.certificate",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CMPCertificate", HFILL }},
    { &hf_cmp_encryptedCert,
      { "encryptedCert", "cmp.encryptedCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "crmf.EncryptedValue", HFILL }},
    { &hf_cmp_newSigCert,
      { "newSigCert", "cmp.newSigCert",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CMPCertificate", HFILL }},
    { &hf_cmp_caCerts,
      { "caCerts", "cmp.caCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SEQUENCE_SIZE_1_MAX_OF_CMPCertificate", HFILL }},
    { &hf_cmp_caCerts_item,
      { "Item", "cmp.caCerts_item",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CMPCertificate", HFILL }},
    { &hf_cmp_keyPairHist,
      { "keyPairHist", "cmp.keyPairHist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair", HFILL }},
    { &hf_cmp_keyPairHist_item,
      { "Item", "cmp.keyPairHist_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CertifiedKeyPair", HFILL }},
    { &hf_cmp_RevReqContent_item,
      { "Item", "cmp.RevReqContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.RevDetails", HFILL }},
    { &hf_cmp_certDetails,
      { "certDetails", "cmp.certDetails",
        FT_NONE, BASE_NONE, NULL, 0,
        "crmf.CertTemplate", HFILL }},
    { &hf_cmp_crlEntryDetails,
      { "crlEntryDetails", "cmp.crlEntryDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkix1explicit.Extensions", HFILL }},
    { &hf_cmp_rvrpcnt_status,
      { "status", "cmp.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo", HFILL }},
    { &hf_cmp_rvrpcnt_status_item,
      { "Item", "cmp.status_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PKIStatusInfo", HFILL }},
    { &hf_cmp_revCerts,
      { "revCerts", "cmp.revCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SEQUENCE_SIZE_1_MAX_OF_CertId", HFILL }},
    { &hf_cmp_revCerts_item,
      { "Item", "cmp.revCerts_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "crmf.CertId", HFILL }},
    { &hf_cmp_crls,
      { "crls", "cmp.crls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.SEQUENCE_SIZE_1_MAX_OF_CertificateList", HFILL }},
    { &hf_cmp_crls_item,
      { "Item", "cmp.crls_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.CertificateList", HFILL }},
    { &hf_cmp_oldWithNew,
      { "oldWithNew", "cmp.oldWithNew",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CMPCertificate", HFILL }},
    { &hf_cmp_newWithOld,
      { "newWithOld", "cmp.newWithOld",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CMPCertificate", HFILL }},
    { &hf_cmp_newWithNew,
      { "newWithNew", "cmp.newWithNew",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "cmp.CMPCertificate", HFILL }},
    { &hf_cmp_willBeRevokedAt,
      { "willBeRevokedAt", "cmp.willBeRevokedAt",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmp.GeneralizedTime", HFILL }},
    { &hf_cmp_badSinceDate,
      { "badSinceDate", "cmp.badSinceDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmp.GeneralizedTime", HFILL }},
    { &hf_cmp_crlDetails,
      { "crlDetails", "cmp.crlDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkix1explicit.Extensions", HFILL }},
    { &hf_cmp_CRLAnnContent_item,
      { "Item", "cmp.CRLAnnContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.CertificateList", HFILL }},
    { &hf_cmp_CertConfirmContent_item,
      { "Item", "cmp.CertConfirmContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.CertStatus", HFILL }},
    { &hf_cmp_certHash,
      { "certHash", "cmp.certHash",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmp.OCTET_STRING", HFILL }},
    { &hf_cmp_statusInfo,
      { "statusInfo", "cmp.statusInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PKIStatusInfo", HFILL }},
    { &hf_cmp_infoType,
      { "infoType", "cmp.infoType",
        FT_OID, BASE_NONE, NULL, 0,
        "cmp.T_infoType", HFILL }},
    { &hf_cmp_infoValue,
      { "infoValue", "cmp.infoValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.T_infoValue", HFILL }},
    { &hf_cmp_SignKeyPairTypesValue_item,
      { "Item", "cmp.SignKeyPairTypesValue_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.AlgorithmIdentifier", HFILL }},
    { &hf_cmp_EncKeyPairTypesValue_item,
      { "Item", "cmp.EncKeyPairTypesValue_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.AlgorithmIdentifier", HFILL }},
    { &hf_cmp_UnsupportedOIDsValue_item,
      { "Item", "cmp.UnsupportedOIDsValue_item",
        FT_OID, BASE_NONE, NULL, 0,
        "cmp.OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmp_SuppLangTagsValue_item,
      { "Item", "cmp.SuppLangTagsValue_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmp.UTF8String", HFILL }},
    { &hf_cmp_GenMsgContent_item,
      { "Item", "cmp.GenMsgContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.InfoTypeAndValue", HFILL }},
    { &hf_cmp_GenRepContent_item,
      { "Item", "cmp.GenRepContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.InfoTypeAndValue", HFILL }},
    { &hf_cmp_pKIStatusInfo,
      { "pKIStatusInfo", "cmp.pKIStatusInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PKIStatusInfo", HFILL }},
    { &hf_cmp_errorCode,
      { "errorCode", "cmp.errorCode",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmp.INTEGER", HFILL }},
    { &hf_cmp_errorDetails,
      { "errorDetails", "cmp.errorDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.PKIFreeText", HFILL }},
    { &hf_cmp_PollReqContent_item,
      { "Item", "cmp.PollReqContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PollReqContent_item", HFILL }},
    { &hf_cmp_PollRepContent_item,
      { "Item", "cmp.PollRepContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmp.PollRepContent_item", HFILL }},
    { &hf_cmp_checkAfter,
      { "checkAfter", "cmp.checkAfter",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmp.INTEGER", HFILL }},
    { &hf_cmp_reason,
      { "reason", "cmp.reason",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmp.PKIFreeText", HFILL }},
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
    { &hf_cmp_PKIFailureInfo_certRevoked,
      { "certRevoked", "cmp.certRevoked",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_certConfirmed,
      { "certConfirmed", "cmp.certConfirmed",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_wrongIntegrity,
      { "wrongIntegrity", "cmp.wrongIntegrity",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_badRecipientNonce,
      { "badRecipientNonce", "cmp.badRecipientNonce",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_timeNotAvailable,
      { "timeNotAvailable", "cmp.timeNotAvailable",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_unacceptedPolicy,
      { "unacceptedPolicy", "cmp.unacceptedPolicy",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_unacceptedExtension,
      { "unacceptedExtension", "cmp.unacceptedExtension",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_addInfoNotAvailable,
      { "addInfoNotAvailable", "cmp.addInfoNotAvailable",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_badSenderNonce,
      { "badSenderNonce", "cmp.badSenderNonce",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_badCertTemplate,
      { "badCertTemplate", "cmp.badCertTemplate",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_signerNotTrusted,
      { "signerNotTrusted", "cmp.signerNotTrusted",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_transactionIdInUse,
      { "transactionIdInUse", "cmp.transactionIdInUse",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_unsupportedVersion,
      { "unsupportedVersion", "cmp.unsupportedVersion",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_notAuthorized,
      { "notAuthorized", "cmp.notAuthorized",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_systemUnavail,
      { "systemUnavail", "cmp.systemUnavail",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_systemFailure,
      { "systemFailure", "cmp.systemFailure",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_cmp_PKIFailureInfo_duplicateCertReq,
      { "duplicateCertReq", "cmp.duplicateCertReq",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},

/*--- End of included file: packet-cmp-hfarr.c ---*/
#line 286 "packet-cmp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_cmp,

/*--- Included file: packet-cmp-ettarr.c ---*/
#line 1 "packet-cmp-ettarr.c"
    &ett_cmp_CMPCertificate,
    &ett_cmp_PKIMessage,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate,
    &ett_cmp_PKIMessages,
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
    &ett_cmp_CertConfirmContent,
    &ett_cmp_CertStatus,
    &ett_cmp_InfoTypeAndValue,
    &ett_cmp_SignKeyPairTypesValue,
    &ett_cmp_EncKeyPairTypesValue,
    &ett_cmp_UnsupportedOIDsValue,
    &ett_cmp_SuppLangTagsValue,
    &ett_cmp_GenMsgContent,
    &ett_cmp_GenRepContent,
    &ett_cmp_ErrorMsgContent,
    &ett_cmp_PollReqContent,
    &ett_cmp_PollReqContent_item,
    &ett_cmp_PollRepContent,
    &ett_cmp_PollRepContent_item,

/*--- End of included file: packet-cmp-ettarr.c ---*/
#line 292 "packet-cmp-template.c"
  };
  module_t *cmp_module;

  /* Register protocol */
  proto_cmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  cmp_module = prefs_register_protocol(proto_cmp, NULL);
  prefs_register_bool_preference(cmp_module, "desegment",
		"Reassemble CMP-over-TCP messages spanning multiple TCP segments",
		"Whether the CMP-over-TCP dissector should reassemble messages spanning multiple TCP segments. "
		"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&cmp_desegment);
}


/*--- proto_reg_handoff_cmp -------------------------------------------*/
void proto_reg_handoff_cmp(void) {
	dissector_handle_t cmp_http_handle;
	dissector_handle_t cmp_tcp_handle;

	cmp_http_handle = new_create_dissector_handle(dissect_cmp_http, proto_cmp);
	dissector_add_string("media_type", "application/pkixcmp", cmp_http_handle);

	cmp_tcp_handle = new_create_dissector_handle(dissect_cmp_tcp, proto_cmp);
	dissector_add("tcp.port", TCP_PORT_CMP, cmp_tcp_handle);

/*#include "packet-cmp-dis-tab.c"*/
}

