/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-cmp.c                                                               */
/* ../../tools/asn2wrs.py -b -p cmp -c ./cmp.cnf -s ./packet-cmp-template -D . -O ../../epan/dissectors CMP.asn */

/* Input file: packet-cmp-template.c */

#line 1 "../../asn1/cmp/packet-cmp-template.c"
/* packet-cmp.c
 *
 * Routines for RFC2510 Certificate Management Protocol packet dissection
 *   Ronnie Sahlberg 2004
 * Updated to RFC4210 CMPv2 and associated "Transport Protocols for CMP" draft
 *   Martin Peylo 2008
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

#include <epan/oids.h>
#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-cmp.h"
#include "packet-crmf.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-tcp.h"
#include "packet-http.h"
#include <epan/prefs.h>
#include <epan/nstime.h>

#define PNAME  "Certificate Management Protocol"
#define PSNAME "CMP"
#define PFNAME "cmp"

#define TCP_PORT_CMP 829

/* desegmentation of CMP over TCP */
static gboolean cmp_desegment = TRUE;

static guint cmp_alternate_tcp_port = 0;
static guint cmp_alternate_http_port = 0;
static guint cmp_alternate_tcp_style_http_port = 0;

/* Initialize the protocol and registered fields */
static int proto_cmp = -1;
static int hf_cmp_type_oid = -1;
static int hf_cmp_tcptrans_len = -1;
static int hf_cmp_tcptrans_type = -1;
static int hf_cmp_tcptrans_poll_ref = -1;
static int hf_cmp_tcptrans_next_poll_ref = -1;
static int hf_cmp_tcptrans_ttcb = -1;
static int hf_cmp_tcptrans10_version = -1;
static int hf_cmp_tcptrans10_flags = -1;

/*--- Included file: packet-cmp-hf.c ---*/
#line 1 "../../asn1/cmp/packet-cmp-hf.c"
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
static int hf_cmp_p10cr = -1;                     /* NULL */
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
#line 72 "../../asn1/cmp/packet-cmp-template.c"

/* Initialize the subtree pointers */
static gint ett_cmp = -1;

/*--- Included file: packet-cmp-ett.c ---*/
#line 1 "../../asn1/cmp/packet-cmp-ett.c"
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
#line 76 "../../asn1/cmp/packet-cmp-template.c"

static const char *object_identifier_id;



/*--- Included file: packet-cmp-fn.c ---*/
#line 1 "../../asn1/cmp/packet-cmp-fn.c"
/*--- Cyclic dependencies ---*/

/* PKIMessage -> PKIBody -> NestedMessageContent -> PKIMessages -> PKIMessage */
int dissect_cmp_PKIMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);



const value_string cmp_CMPCertificate_vals[] = {
  {   0, "x509v3PKCert" },
  { 0, NULL }
};

static const ber_choice_t CMPCertificate_choice[] = {
  {   0, &hf_cmp_x509v3PKCert    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_CMPCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CMPCertificate_choice, hf_index, ett_cmp_CMPCertificate,
                                 NULL);

  return offset;
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



static int
dissect_cmp_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmp_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_cmp_UTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PKIFreeText_sequence_of[1] = {
  { &hf_cmp_PKIFreeText_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_cmp_UTF8String },
};

int
dissect_cmp_PKIFreeText(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PKIFreeText_sequence_of, hf_index, ett_cmp_PKIFreeText);

  return offset;
}



static int
dissect_cmp_T_infoType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cmp_type_oid, &object_identifier_id);

  return offset;
}



static int
dissect_cmp_T_infoValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 90 "../../asn1/cmp/cmp.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t InfoTypeAndValue_sequence[] = {
  { &hf_cmp_infoType        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmp_T_infoType },
  { &hf_cmp_infoValue       , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_T_infoValue },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_InfoTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InfoTypeAndValue_sequence, hf_index, ett_cmp_InfoTypeAndValue);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue_sequence_of[1] = {
  { &hf_cmp_generalInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_InfoTypeAndValue },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue);

  return offset;
}


static const ber_sequence_t PKIHeader_sequence[] = {
  { &hf_cmp_pvno            , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_T_pvno },
  { &hf_cmp_sender          , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_GeneralName },
  { &hf_cmp_recipient       , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_GeneralName },
  { &hf_cmp_messageTime     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_cmp_GeneralizedTime },
  { &hf_cmp_protectionAlg   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_senderKID       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_pkix1implicit_KeyIdentifier },
  { &hf_cmp_recipKID        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_pkix1implicit_KeyIdentifier },
  { &hf_cmp_transactionID   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_cmp_OCTET_STRING },
  { &hf_cmp_senderNonce     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_cmp_OCTET_STRING },
  { &hf_cmp_recipNonce      , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_cmp_OCTET_STRING },
  { &hf_cmp_freeText        , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_cmp_PKIFreeText },
  { &hf_cmp_generalInfo     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_PKIHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKIHeader_sequence, hf_index, ett_cmp_PKIHeader);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CMPCertificate_sequence_of[1] = {
  { &hf_cmp_extraCerts_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CMPCertificate_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate);

  return offset;
}



static int
dissect_cmp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
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
#line 106 "../../asn1/cmp/cmp.cnf"
  guint32 value;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &value);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " Status=%s", val_to_str(value, cmp_PKIStatus_vals, "unknown"));



  return offset;
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


static const ber_sequence_t PKIStatusInfo_sequence[] = {
  { &hf_cmp_pkistatus       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatus },
  { &hf_cmp_statusString    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIFreeText },
  { &hf_cmp_failInfo        , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIFailureInfo },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_PKIStatusInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKIStatusInfo_sequence, hf_index, ett_cmp_PKIStatusInfo);

  return offset;
}


const value_string cmp_CertOrEncCert_vals[] = {
  {   0, "certificate" },
  {   1, "encryptedCert" },
  { 0, NULL }
};

static const ber_choice_t CertOrEncCert_choice[] = {
  {   0, &hf_cmp_certificate     , BER_CLASS_CON, 0, 0, dissect_cmp_CMPCertificate },
  {   1, &hf_cmp_encryptedCert   , BER_CLASS_CON, 1, 0, dissect_crmf_EncryptedValue },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_CertOrEncCert(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CertOrEncCert_choice, hf_index, ett_cmp_CertOrEncCert,
                                 NULL);

  return offset;
}


static const ber_sequence_t CertifiedKeyPair_sequence[] = {
  { &hf_cmp_certOrEncCert   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CertOrEncCert },
  { &hf_cmp_privateKey      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_crmf_EncryptedValue },
  { &hf_cmp_publicationInfo , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_crmf_PKIPublicationInfo },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_CertifiedKeyPair(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertifiedKeyPair_sequence, hf_index, ett_cmp_CertifiedKeyPair);

  return offset;
}


static const ber_sequence_t CertResponse_sequence[] = {
  { &hf_cmp_certReqId       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_pkistatusinf    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
  { &hf_cmp_certifiedKeyPair, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_CertifiedKeyPair },
  { &hf_cmp_rspInfo         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_CertResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertResponse_sequence, hf_index, ett_cmp_CertResponse);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CertResponse_sequence_of[1] = {
  { &hf_cmp_response_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_CertResponse },
};

static int
dissect_cmp_SEQUENCE_OF_CertResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CertResponse_sequence_of, hf_index, ett_cmp_SEQUENCE_OF_CertResponse);

  return offset;
}


static const ber_sequence_t CertRepMessage_sequence[] = {
  { &hf_cmp_caPubs          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate },
  { &hf_cmp_response        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_SEQUENCE_OF_CertResponse },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_CertRepMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertRepMessage_sequence, hf_index, ett_cmp_CertRepMessage);

  return offset;
}



static int
dissect_cmp_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t Challenge_sequence[] = {
  { &hf_cmp_owf             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_witness         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { &hf_cmp_challenge       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_Challenge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Challenge_sequence, hf_index, ett_cmp_Challenge);

  return offset;
}


static const ber_sequence_t POPODecKeyChallContent_sequence_of[1] = {
  { &hf_cmp_POPODecKeyChallContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_Challenge },
};

static int
dissect_cmp_POPODecKeyChallContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      POPODecKeyChallContent_sequence_of, hf_index, ett_cmp_POPODecKeyChallContent);

  return offset;
}


static const ber_sequence_t POPODecKeyRespContent_sequence_of[1] = {
  { &hf_cmp_POPODecKeyRespContent_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
};

int
dissect_cmp_POPODecKeyRespContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      POPODecKeyRespContent_sequence_of, hf_index, ett_cmp_POPODecKeyRespContent);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair_sequence_of[1] = {
  { &hf_cmp_keyPairHist_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_CertifiedKeyPair },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair);

  return offset;
}


static const ber_sequence_t KeyRecRepContent_sequence[] = {
  { &hf_cmp_pkistatusinf    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
  { &hf_cmp_newSigCert      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
  { &hf_cmp_caCerts         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate },
  { &hf_cmp_keyPairHist     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_KeyRecRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KeyRecRepContent_sequence, hf_index, ett_cmp_KeyRecRepContent);

  return offset;
}


static const ber_sequence_t RevDetails_sequence[] = {
  { &hf_cmp_certDetails     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_CertTemplate },
  { &hf_cmp_crlEntryDetails , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_RevDetails(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RevDetails_sequence, hf_index, ett_cmp_RevDetails);

  return offset;
}


static const ber_sequence_t RevReqContent_sequence_of[1] = {
  { &hf_cmp_RevReqContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_RevDetails },
};

int
dissect_cmp_RevReqContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RevReqContent_sequence_of, hf_index, ett_cmp_RevReqContent);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo_sequence_of[1] = {
  { &hf_cmp_rvrpcnt_status_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertId_sequence_of[1] = {
  { &hf_cmp_revCerts_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_CertId },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CertId_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertificateList_sequence_of[1] = {
  { &hf_cmp_crls_item       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_CertificateList },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CertificateList_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList);

  return offset;
}


static const ber_sequence_t RevRepContent_sequence[] = {
  { &hf_cmp_rvrpcnt_status  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo },
  { &hf_cmp_revCerts        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId },
  { &hf_cmp_crls            , BER_CLASS_CON, 1, 0, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_RevRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RevRepContent_sequence, hf_index, ett_cmp_RevRepContent);

  return offset;
}


static const ber_sequence_t CAKeyUpdAnnContent_sequence[] = {
  { &hf_cmp_oldWithNew      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
  { &hf_cmp_newWithOld      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
  { &hf_cmp_newWithNew      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_CAKeyUpdAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CAKeyUpdAnnContent_sequence, hf_index, ett_cmp_CAKeyUpdAnnContent);

  return offset;
}



int
dissect_cmp_CertAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CMPCertificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t RevAnnContent_sequence[] = {
  { &hf_cmp_pkistatus       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatus },
  { &hf_cmp_certId          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_CertId },
  { &hf_cmp_willBeRevokedAt , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_cmp_GeneralizedTime },
  { &hf_cmp_badSinceDate    , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_cmp_GeneralizedTime },
  { &hf_cmp_crlDetails      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_RevAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RevAnnContent_sequence, hf_index, ett_cmp_RevAnnContent);

  return offset;
}


static const ber_sequence_t CRLAnnContent_sequence_of[1] = {
  { &hf_cmp_CRLAnnContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_CertificateList },
};

int
dissect_cmp_CRLAnnContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CRLAnnContent_sequence_of, hf_index, ett_cmp_CRLAnnContent);

  return offset;
}



int
dissect_cmp_PKIConfirmContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t PKIMessages_sequence_of[1] = {
  { &hf_cmp_PKIMessages_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIMessage },
};

int
dissect_cmp_PKIMessages(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PKIMessages_sequence_of, hf_index, ett_cmp_PKIMessages);

  return offset;
}



int
dissect_cmp_NestedMessageContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_PKIMessages(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t GenMsgContent_sequence_of[1] = {
  { &hf_cmp_GenMsgContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_InfoTypeAndValue },
};

int
dissect_cmp_GenMsgContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      GenMsgContent_sequence_of, hf_index, ett_cmp_GenMsgContent);

  return offset;
}


static const ber_sequence_t GenRepContent_sequence_of[1] = {
  { &hf_cmp_GenRepContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_InfoTypeAndValue },
};

static int
dissect_cmp_GenRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      GenRepContent_sequence_of, hf_index, ett_cmp_GenRepContent);

  return offset;
}


static const ber_sequence_t ErrorMsgContent_sequence[] = {
  { &hf_cmp_pKIStatusInfo   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
  { &hf_cmp_errorCode       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_errorDetails    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIFreeText },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_ErrorMsgContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ErrorMsgContent_sequence, hf_index, ett_cmp_ErrorMsgContent);

  return offset;
}


static const ber_sequence_t CertStatus_sequence[] = {
  { &hf_cmp_certHash        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { &hf_cmp_certReqId       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_statusInfo      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_CertStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertStatus_sequence, hf_index, ett_cmp_CertStatus);

  return offset;
}


static const ber_sequence_t CertConfirmContent_sequence_of[1] = {
  { &hf_cmp_CertConfirmContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_CertStatus },
};

int
dissect_cmp_CertConfirmContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CertConfirmContent_sequence_of, hf_index, ett_cmp_CertConfirmContent);

  return offset;
}


static const ber_sequence_t PollReqContent_item_sequence[] = {
  { &hf_cmp_certReqId       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_PollReqContent_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PollReqContent_item_sequence, hf_index, ett_cmp_PollReqContent_item);

  return offset;
}


static const ber_sequence_t PollReqContent_sequence_of[1] = {
  { &hf_cmp_PollReqContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PollReqContent_item },
};

int
dissect_cmp_PollReqContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PollReqContent_sequence_of, hf_index, ett_cmp_PollReqContent);

  return offset;
}


static const ber_sequence_t PollRepContent_item_sequence[] = {
  { &hf_cmp_certReqId       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_checkAfter      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_reason          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIFreeText },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_PollRepContent_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PollRepContent_item_sequence, hf_index, ett_cmp_PollRepContent_item);

  return offset;
}


static const ber_sequence_t PollRepContent_sequence_of[1] = {
  { &hf_cmp_PollRepContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PollRepContent_item },
};

int
dissect_cmp_PollRepContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PollRepContent_sequence_of, hf_index, ett_cmp_PollRepContent);

  return offset;
}


const value_string cmp_PKIBody_vals[] = {
  {   0, "ir" },
  {   1, "ip" },
  {   2, "cr" },
  {   3, "cp" },
  {   4, "p10cr" },
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

static const ber_choice_t PKIBody_choice[] = {
  {   0, &hf_cmp_ir              , BER_CLASS_CON, 0, 0, dissect_crmf_CertReqMessages },
  {   1, &hf_cmp_ip              , BER_CLASS_CON, 1, 0, dissect_cmp_CertRepMessage },
  {   2, &hf_cmp_cr              , BER_CLASS_CON, 2, 0, dissect_crmf_CertReqMessages },
  {   3, &hf_cmp_cp              , BER_CLASS_CON, 3, 0, dissect_cmp_CertRepMessage },
  {   4, &hf_cmp_p10cr           , BER_CLASS_CON, 4, 0, dissect_cmp_NULL },
  {   5, &hf_cmp_popdecc         , BER_CLASS_CON, 5, 0, dissect_cmp_POPODecKeyChallContent },
  {   6, &hf_cmp_popdecr         , BER_CLASS_CON, 6, 0, dissect_cmp_POPODecKeyRespContent },
  {   7, &hf_cmp_kur             , BER_CLASS_CON, 7, 0, dissect_crmf_CertReqMessages },
  {   8, &hf_cmp_kup             , BER_CLASS_CON, 8, 0, dissect_cmp_CertRepMessage },
  {   9, &hf_cmp_krr             , BER_CLASS_CON, 9, 0, dissect_crmf_CertReqMessages },
  {  10, &hf_cmp_krp             , BER_CLASS_CON, 10, 0, dissect_cmp_KeyRecRepContent },
  {  11, &hf_cmp_rr              , BER_CLASS_CON, 11, 0, dissect_cmp_RevReqContent },
  {  12, &hf_cmp_rp              , BER_CLASS_CON, 12, 0, dissect_cmp_RevRepContent },
  {  13, &hf_cmp_ccr             , BER_CLASS_CON, 13, 0, dissect_crmf_CertReqMessages },
  {  14, &hf_cmp_ccp             , BER_CLASS_CON, 14, 0, dissect_cmp_CertRepMessage },
  {  15, &hf_cmp_ckuann          , BER_CLASS_CON, 15, 0, dissect_cmp_CAKeyUpdAnnContent },
  {  16, &hf_cmp_cann            , BER_CLASS_CON, 16, 0, dissect_cmp_CertAnnContent },
  {  17, &hf_cmp_rann            , BER_CLASS_CON, 17, 0, dissect_cmp_RevAnnContent },
  {  18, &hf_cmp_crlann          , BER_CLASS_CON, 18, 0, dissect_cmp_CRLAnnContent },
  {  19, &hf_cmp_pkiconf         , BER_CLASS_CON, 19, 0, dissect_cmp_PKIConfirmContent },
  {  20, &hf_cmp_nested          , BER_CLASS_CON, 20, 0, dissect_cmp_NestedMessageContent },
  {  21, &hf_cmp_genm            , BER_CLASS_CON, 21, 0, dissect_cmp_GenMsgContent },
  {  22, &hf_cmp_genp            , BER_CLASS_CON, 22, 0, dissect_cmp_GenRepContent },
  {  23, &hf_cmp_error           , BER_CLASS_CON, 23, 0, dissect_cmp_ErrorMsgContent },
  {  24, &hf_cmp_certConf        , BER_CLASS_CON, 24, 0, dissect_cmp_CertConfirmContent },
  {  25, &hf_cmp_pollReq         , BER_CLASS_CON, 25, 0, dissect_cmp_PollReqContent },
  {  26, &hf_cmp_pollRep         , BER_CLASS_CON, 26, 0, dissect_cmp_PollRepContent },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_PKIBody(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 96 "../../asn1/cmp/cmp.cnf"
  gint branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PKIBody_choice, hf_index, ett_cmp_PKIBody,
                                 &branch_taken);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " Body=%s", val_to_str(branch_taken, cmp_PKIBody_vals, "unknown"));



  return offset;
}



int
dissect_cmp_PKIProtection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t PKIMessage_sequence[] = {
  { &hf_cmp_header          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIHeader },
  { &hf_cmp_body            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_PKIBody },
  { &hf_cmp_protection      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_cmp_PKIProtection },
  { &hf_cmp_extraCerts      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_PKIMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKIMessage_sequence, hf_index, ett_cmp_PKIMessage);

  return offset;
}


static const ber_sequence_t ProtectedPart_sequence[] = {
  { &hf_cmp_header          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIHeader },
  { &hf_cmp_body            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_PKIBody },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_ProtectedPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtectedPart_sequence, hf_index, ett_cmp_ProtectedPart);

  return offset;
}


static const ber_sequence_t PBMParameter_sequence[] = {
  { &hf_cmp_salt            , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { &hf_cmp_owf             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_iterationCount  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_mac             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_PBMParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PBMParameter_sequence, hf_index, ett_cmp_PBMParameter);

  return offset;
}


static const ber_sequence_t DHBMParameter_sequence[] = {
  { &hf_cmp_owf             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_mac             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_DHBMParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
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


static const ber_sequence_t OOBCertHash_sequence[] = {
  { &hf_cmp_hashAlg         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_certId          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_crmf_CertId },
  { &hf_cmp_hashVal         , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_OOBCertHash(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OOBCertHash_sequence, hf_index, ett_cmp_OOBCertHash);

  return offset;
}



static int
dissect_cmp_CAProtEncCertValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CMPCertificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SignKeyPairTypesValue_sequence_of[1] = {
  { &hf_cmp_SignKeyPairTypesValue_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
};

static int
dissect_cmp_SignKeyPairTypesValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SignKeyPairTypesValue_sequence_of, hf_index, ett_cmp_SignKeyPairTypesValue);

  return offset;
}


static const ber_sequence_t EncKeyPairTypesValue_sequence_of[1] = {
  { &hf_cmp_EncKeyPairTypesValue_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
};

static int
dissect_cmp_EncKeyPairTypesValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
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


static const ber_sequence_t UnsupportedOIDsValue_sequence_of[1] = {
  { &hf_cmp_UnsupportedOIDsValue_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmp_OBJECT_IDENTIFIER },
};

static int
dissect_cmp_UnsupportedOIDsValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
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


static const ber_sequence_t SuppLangTagsValue_sequence_of[1] = {
  { &hf_cmp_SuppLangTagsValue_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_cmp_UTF8String },
};

static int
dissect_cmp_SuppLangTagsValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
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
#line 81 "../../asn1/cmp/packet-cmp-template.c"

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


static int dissect_cmp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	tvbuff_t   *next_tvb;
	guint32    pdu_len;
	guint8     pdu_type;
	nstime_t   ts;
	proto_item *item=NULL;
	proto_item *ti=NULL;
	proto_tree *tree=NULL;
	proto_tree *tcptrans_tree=NULL;
	asn1_ctx_t asn1_ctx;
	int offset=0;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");

	col_set_str(pinfo->cinfo, COL_INFO, "PKIXCMP");

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_guint8(tvb, 4);

	if (pdu_type < 10) {
		/* RFC2510 TCP transport */
		ti = proto_tree_add_item(tree, proto_cmp, tvb, offset, 5, ENC_NA);
		tcptrans_tree = proto_item_add_subtree(ti, ett_cmp);
		proto_tree_add_item(tree, hf_cmp_tcptrans_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_cmp_tcptrans_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	} else {
		/* post RFC2510 TCP transport - the former "type" field is now "version" */
		ti = proto_tree_add_text(tree, tvb, offset, 7, "TCP transport");
		tcptrans_tree = proto_item_add_subtree(ti, ett_cmp);
		pdu_type=tvb_get_guint8(tvb, 6);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans10_version, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans10_flags, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	}

	col_add_str (pinfo->cinfo, COL_INFO, val_to_str (pdu_type, cmp_pdu_types, "0x%x"));

	switch(pdu_type){
		case CMP_TYPE_PKIMSG:
			next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, tree, &asn1_ctx);
			offset += tvb_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_POLLREP:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			ts.secs = tvb_get_ntohl(tvb, 4);
			ts.nsecs = 0;
			proto_tree_add_time(tcptrans_tree, hf_cmp_tcptrans_ttcb, tvb, offset, 4, &ts);
			offset += 4;
			break;
		case CMP_TYPE_POLLREQ:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case CMP_TYPE_NEGPOLLREP:
			break;
		case CMP_TYPE_PARTIALMSGREP:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_next_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			ts.secs = tvb_get_ntohl(tvb, 4);
			ts.nsecs = 0;
			proto_tree_add_time(tcptrans_tree, hf_cmp_tcptrans_ttcb, tvb, offset, 4, &ts);
			offset += 4;

			next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, tree, &asn1_ctx);
			offset += tvb_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_FINALMSGREP:
			next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, tree, &asn1_ctx);
			offset += tvb_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_ERRORMSGREP:
			/*XXX to be added*/
			break;
	}

	return offset;
}

static void dissect_cmp_tcp_pdu_no_return(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	dissect_cmp_tcp_pdu(tvb, pinfo, parent_tree);
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


/* CMP over TCP: RFC2510 section 5.2 and "Transport Protocols for CMP" draft */
	static int
dissect_cmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint32 pdu_len;
	guint8 pdu_type;
	int offset=4; /* RFC2510 TCP transport header length */

	/* only attempt to dissect it as CMP over TCP if we have
	 * at least 5 bytes.
	 */
	if (!tvb_bytes_exist(tvb, 0, 5)) {
		return 0;
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_guint8(tvb, 4);

	if(pdu_type == 10) {
		/* post RFC2510 TCP transport */
		pdu_type = tvb_get_guint8(tvb, 7);
		offset = 7; /* post RFC2510 TCP transport header length */
		/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes
		 * in size.
		 * It is definitely at least 3 byte for post RFC2510 TCP transport
		 */
		if((pdu_len<=2)||(pdu_len>10000)){
			return 0;
		}
	} else {
		/* RFC2510 TCP transport */
		/* type is between 0 and 6 */
		if(pdu_type>6){
			return 0;
		}
		/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes
		 * in size.
		 * It is definitely at least 1 byte to accomodate the flags byte
		 */
		if((pdu_len<=0)||(pdu_len>10000)){
			return 0;
		}
	}

	/* type 0 contains a PKI message and must therefore be >= 3 bytes
	 * long (flags + BER TAG + BER LENGTH
	 */
	if((pdu_type==0)&&(pdu_len<3)){
		return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, parent_tree, cmp_desegment, offset, get_cmp_pdu_len,
			dissect_cmp_tcp_pdu_no_return);

	return tvb_length(tvb);
}


	static int
dissect_cmp_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");

	col_set_str(pinfo->cinfo, COL_INFO, "PKIXCMP");

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, ENC_NA);
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
		{ &hf_cmp_tcptrans_len,
			{ "Length", "cmp.tcptrans.length",
				FT_UINT32, BASE_DEC, NULL, 0,
				"TCP transport Length of PDU in bytes", HFILL }},
		{ &hf_cmp_tcptrans_type,
			{ "Type", "cmp.tcptrans.type",
				FT_UINT8, BASE_DEC, VALS(cmp_pdu_types), 0,
				"TCP transport PDU Type", HFILL }},
		{ &hf_cmp_tcptrans_poll_ref,
			{ "Polling Reference", "cmp.tcptrans.poll_ref",
				FT_UINT32, BASE_HEX, NULL, 0,
				"TCP transport Polling Reference", HFILL }},
		{ &hf_cmp_tcptrans_next_poll_ref,
			{ "Next Polling Reference", "cmp.tcptrans.next_poll_ref",
				FT_UINT32, BASE_HEX, NULL, 0,
				"TCP transport Next Polling Reference", HFILL }},
		{ &hf_cmp_tcptrans_ttcb,
			{ "Time to check Back", "cmp.tcptrans.ttcb",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
				"TCP transport Time to check Back", HFILL }},
		{ &hf_cmp_tcptrans10_version,
			{ "Version", "cmp.tcptrans10.version",
				FT_UINT8, BASE_DEC, NULL, 0,
				"TCP transport version", HFILL }},
		{ &hf_cmp_tcptrans10_flags,
			{ "Flags", "cmp.tcptrans10.flags",
				FT_UINT8, BASE_DEC, NULL, 0,
				"TCP transport flags", HFILL }},

/*--- Included file: packet-cmp-hfarr.c ---*/
#line 1 "../../asn1/cmp/packet-cmp-hfarr.c"
    { &hf_cmp_PBMParameter_PDU,
      { "PBMParameter", "cmp.PBMParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_DHBMParameter_PDU,
      { "DHBMParameter", "cmp.DHBMParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_CAProtEncCertValue_PDU,
      { "CAProtEncCertValue", "cmp.CAProtEncCertValue",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_SignKeyPairTypesValue_PDU,
      { "SignKeyPairTypesValue", "cmp.SignKeyPairTypesValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_EncKeyPairTypesValue_PDU,
      { "EncKeyPairTypesValue", "cmp.EncKeyPairTypesValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_PreferredSymmAlgValue_PDU,
      { "PreferredSymmAlgValue", "cmp.PreferredSymmAlgValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_CAKeyUpdateInfoValue_PDU,
      { "CAKeyUpdateInfoValue", "cmp.CAKeyUpdateInfoValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_CurrentCRLValue_PDU,
      { "CurrentCRLValue", "cmp.CurrentCRLValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_UnsupportedOIDsValue_PDU,
      { "UnsupportedOIDsValue", "cmp.UnsupportedOIDsValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_KeyPairParamReqValue_PDU,
      { "KeyPairParamReqValue", "cmp.KeyPairParamReqValue",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_KeyPairParamRepValue_PDU,
      { "KeyPairParamRepValue", "cmp.KeyPairParamRepValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_RevPassphraseValue_PDU,
      { "RevPassphraseValue", "cmp.RevPassphraseValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_ImplicitConfirmValue_PDU,
      { "ImplicitConfirmValue", "cmp.ImplicitConfirmValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_ConfirmWaitTimeValue_PDU,
      { "ConfirmWaitTimeValue", "cmp.ConfirmWaitTimeValue",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_OrigPKIMessageValue_PDU,
      { "OrigPKIMessageValue", "cmp.OrigPKIMessageValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_SuppLangTagsValue_PDU,
      { "SuppLangTagsValue", "cmp.SuppLangTagsValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_x509v3PKCert,
      { "x509v3PKCert", "cmp.x509v3PKCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_cmp_header,
      { "header", "cmp.header",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIHeader", HFILL }},
    { &hf_cmp_body,
      { "body", "cmp.body",
        FT_UINT32, BASE_DEC, VALS(cmp_PKIBody_vals), 0,
        "PKIBody", HFILL }},
    { &hf_cmp_protection,
      { "protection", "cmp.protection",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PKIProtection", HFILL }},
    { &hf_cmp_extraCerts,
      { "extraCerts", "cmp.extraCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CMPCertificate", HFILL }},
    { &hf_cmp_extraCerts_item,
      { "CMPCertificate", "cmp.CMPCertificate",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_PKIMessages_item,
      { "PKIMessage", "cmp.PKIMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_pvno,
      { "pvno", "cmp.pvno",
        FT_INT32, BASE_DEC, VALS(cmp_T_pvno_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_sender,
      { "sender", "cmp.sender",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_cmp_recipient,
      { "recipient", "cmp.recipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_cmp_messageTime,
      { "messageTime", "cmp.messageTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmp_protectionAlg,
      { "protectionAlg", "cmp.protectionAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cmp_senderKID,
      { "senderKID", "cmp.senderKID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "KeyIdentifier", HFILL }},
    { &hf_cmp_recipKID,
      { "recipKID", "cmp.recipKID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "KeyIdentifier", HFILL }},
    { &hf_cmp_transactionID,
      { "transactionID", "cmp.transactionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_senderNonce,
      { "senderNonce", "cmp.senderNonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_recipNonce,
      { "recipNonce", "cmp.recipNonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_freeText,
      { "freeText", "cmp.freeText",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIFreeText", HFILL }},
    { &hf_cmp_generalInfo,
      { "generalInfo", "cmp.generalInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue", HFILL }},
    { &hf_cmp_generalInfo_item,
      { "InfoTypeAndValue", "cmp.InfoTypeAndValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_PKIFreeText_item,
      { "PKIFreeText item", "cmp.PKIFreeText_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_cmp_ir,
      { "ir", "cmp.ir",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_ip,
      { "ip", "cmp.ip",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage", HFILL }},
    { &hf_cmp_cr,
      { "cr", "cmp.cr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_cp,
      { "cp", "cmp.cp",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage", HFILL }},
    { &hf_cmp_p10cr,
      { "p10cr", "cmp.p10cr",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_popdecc,
      { "popdecc", "cmp.popdecc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "POPODecKeyChallContent", HFILL }},
    { &hf_cmp_popdecr,
      { "popdecr", "cmp.popdecr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "POPODecKeyRespContent", HFILL }},
    { &hf_cmp_kur,
      { "kur", "cmp.kur",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_kup,
      { "kup", "cmp.kup",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage", HFILL }},
    { &hf_cmp_krr,
      { "krr", "cmp.krr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_krp,
      { "krp", "cmp.krp",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyRecRepContent", HFILL }},
    { &hf_cmp_rr,
      { "rr", "cmp.rr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RevReqContent", HFILL }},
    { &hf_cmp_rp,
      { "rp", "cmp.rp",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevRepContent", HFILL }},
    { &hf_cmp_ccr,
      { "ccr", "cmp.ccr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_ccp,
      { "ccp", "cmp.ccp",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage", HFILL }},
    { &hf_cmp_ckuann,
      { "ckuann", "cmp.ckuann",
        FT_NONE, BASE_NONE, NULL, 0,
        "CAKeyUpdAnnContent", HFILL }},
    { &hf_cmp_cann,
      { "cann", "cmp.cann",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CertAnnContent", HFILL }},
    { &hf_cmp_rann,
      { "rann", "cmp.rann",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevAnnContent", HFILL }},
    { &hf_cmp_crlann,
      { "crlann", "cmp.crlann",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CRLAnnContent", HFILL }},
    { &hf_cmp_pkiconf,
      { "pkiconf", "cmp.pkiconf",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIConfirmContent", HFILL }},
    { &hf_cmp_nested,
      { "nested", "cmp.nested",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NestedMessageContent", HFILL }},
    { &hf_cmp_genm,
      { "genm", "cmp.genm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenMsgContent", HFILL }},
    { &hf_cmp_genp,
      { "genp", "cmp.genp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenRepContent", HFILL }},
    { &hf_cmp_error,
      { "error", "cmp.error",
        FT_NONE, BASE_NONE, NULL, 0,
        "ErrorMsgContent", HFILL }},
    { &hf_cmp_certConf,
      { "certConf", "cmp.certConf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertConfirmContent", HFILL }},
    { &hf_cmp_pollReq,
      { "pollReq", "cmp.pollReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PollReqContent", HFILL }},
    { &hf_cmp_pollRep,
      { "pollRep", "cmp.pollRep",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PollRepContent", HFILL }},
    { &hf_cmp_salt,
      { "salt", "cmp.salt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_owf,
      { "owf", "cmp.owf",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cmp_iterationCount,
      { "iterationCount", "cmp.iterationCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_mac,
      { "mac", "cmp.mac",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cmp_pkistatus,
      { "status", "cmp.status",
        FT_INT32, BASE_DEC, VALS(cmp_PKIStatus_vals), 0,
        "PKIStatus", HFILL }},
    { &hf_cmp_statusString,
      { "statusString", "cmp.statusString",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIFreeText", HFILL }},
    { &hf_cmp_failInfo,
      { "failInfo", "cmp.failInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PKIFailureInfo", HFILL }},
    { &hf_cmp_hashAlg,
      { "hashAlg", "cmp.hashAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cmp_certId,
      { "certId", "cmp.certId",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_hashVal,
      { "hashVal", "cmp.hashVal",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_cmp_POPODecKeyChallContent_item,
      { "Challenge", "cmp.Challenge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_witness,
      { "witness", "cmp.witness",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_challenge,
      { "challenge", "cmp.challenge",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_POPODecKeyRespContent_item,
      { "POPODecKeyRespContent item", "cmp.POPODecKeyRespContent_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_caPubs,
      { "caPubs", "cmp.caPubs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CMPCertificate", HFILL }},
    { &hf_cmp_caPubs_item,
      { "CMPCertificate", "cmp.CMPCertificate",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_response,
      { "response", "cmp.response",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CertResponse", HFILL }},
    { &hf_cmp_response_item,
      { "CertResponse", "cmp.CertResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_certReqId,
      { "certReqId", "cmp.certReqId",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_pkistatusinf,
      { "status", "cmp.status",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIStatusInfo", HFILL }},
    { &hf_cmp_certifiedKeyPair,
      { "certifiedKeyPair", "cmp.certifiedKeyPair",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_rspInfo,
      { "rspInfo", "cmp.rspInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_certOrEncCert,
      { "certOrEncCert", "cmp.certOrEncCert",
        FT_UINT32, BASE_DEC, VALS(cmp_CertOrEncCert_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_privateKey,
      { "privateKey", "cmp.privateKey",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedValue", HFILL }},
    { &hf_cmp_publicationInfo,
      { "publicationInfo", "cmp.publicationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIPublicationInfo", HFILL }},
    { &hf_cmp_certificate,
      { "certificate", "cmp.certificate",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_encryptedCert,
      { "encryptedCert", "cmp.encryptedCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedValue", HFILL }},
    { &hf_cmp_newSigCert,
      { "newSigCert", "cmp.newSigCert",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_caCerts,
      { "caCerts", "cmp.caCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CMPCertificate", HFILL }},
    { &hf_cmp_caCerts_item,
      { "CMPCertificate", "cmp.CMPCertificate",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_keyPairHist,
      { "keyPairHist", "cmp.keyPairHist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair", HFILL }},
    { &hf_cmp_keyPairHist_item,
      { "CertifiedKeyPair", "cmp.CertifiedKeyPair",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_RevReqContent_item,
      { "RevDetails", "cmp.RevDetails",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_certDetails,
      { "certDetails", "cmp.certDetails",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertTemplate", HFILL }},
    { &hf_cmp_crlEntryDetails,
      { "crlEntryDetails", "cmp.crlEntryDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_cmp_rvrpcnt_status,
      { "status", "cmp.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo", HFILL }},
    { &hf_cmp_rvrpcnt_status_item,
      { "PKIStatusInfo", "cmp.PKIStatusInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_revCerts,
      { "revCerts", "cmp.revCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CertId", HFILL }},
    { &hf_cmp_revCerts_item,
      { "CertId", "cmp.CertId",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_crls,
      { "crls", "cmp.crls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CertificateList", HFILL }},
    { &hf_cmp_crls_item,
      { "CertificateList", "cmp.CertificateList",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_oldWithNew,
      { "oldWithNew", "cmp.oldWithNew",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_newWithOld,
      { "newWithOld", "cmp.newWithOld",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_newWithNew,
      { "newWithNew", "cmp.newWithNew",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_willBeRevokedAt,
      { "willBeRevokedAt", "cmp.willBeRevokedAt",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmp_badSinceDate,
      { "badSinceDate", "cmp.badSinceDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmp_crlDetails,
      { "crlDetails", "cmp.crlDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_cmp_CRLAnnContent_item,
      { "CertificateList", "cmp.CertificateList",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_CertConfirmContent_item,
      { "CertStatus", "cmp.CertStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_certHash,
      { "certHash", "cmp.certHash",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_statusInfo,
      { "statusInfo", "cmp.statusInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIStatusInfo", HFILL }},
    { &hf_cmp_infoType,
      { "infoType", "cmp.infoType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_infoValue,
      { "infoValue", "cmp.infoValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_SignKeyPairTypesValue_item,
      { "AlgorithmIdentifier", "cmp.AlgorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_EncKeyPairTypesValue_item,
      { "AlgorithmIdentifier", "cmp.AlgorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_UnsupportedOIDsValue_item,
      { "UnsupportedOIDsValue item", "cmp.UnsupportedOIDsValue_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmp_SuppLangTagsValue_item,
      { "SuppLangTagsValue item", "cmp.SuppLangTagsValue_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_cmp_GenMsgContent_item,
      { "InfoTypeAndValue", "cmp.InfoTypeAndValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_GenRepContent_item,
      { "InfoTypeAndValue", "cmp.InfoTypeAndValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_pKIStatusInfo,
      { "pKIStatusInfo", "cmp.pKIStatusInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_errorCode,
      { "errorCode", "cmp.errorCode",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_errorDetails,
      { "errorDetails", "cmp.errorDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIFreeText", HFILL }},
    { &hf_cmp_PollReqContent_item,
      { "PollReqContent item", "cmp.PollReqContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_PollRepContent_item,
      { "PollRepContent item", "cmp.PollRepContent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_checkAfter,
      { "checkAfter", "cmp.checkAfter",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_reason,
      { "reason", "cmp.reason",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIFreeText", HFILL }},
    { &hf_cmp_PKIFailureInfo_badAlg,
      { "badAlg", "cmp.badAlg",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badMessageCheck,
      { "badMessageCheck", "cmp.badMessageCheck",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badRequest,
      { "badRequest", "cmp.badRequest",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badTime,
      { "badTime", "cmp.badTime",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badCertId,
      { "badCertId", "cmp.badCertId",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badDataFormat,
      { "badDataFormat", "cmp.badDataFormat",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_wrongAuthority,
      { "wrongAuthority", "cmp.wrongAuthority",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_incorrectData,
      { "incorrectData", "cmp.incorrectData",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_missingTimeStamp,
      { "missingTimeStamp", "cmp.missingTimeStamp",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badPOP,
      { "badPOP", "cmp.badPOP",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_certRevoked,
      { "certRevoked", "cmp.certRevoked",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_certConfirmed,
      { "certConfirmed", "cmp.certConfirmed",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_wrongIntegrity,
      { "wrongIntegrity", "cmp.wrongIntegrity",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badRecipientNonce,
      { "badRecipientNonce", "cmp.badRecipientNonce",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_timeNotAvailable,
      { "timeNotAvailable", "cmp.timeNotAvailable",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_unacceptedPolicy,
      { "unacceptedPolicy", "cmp.unacceptedPolicy",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_unacceptedExtension,
      { "unacceptedExtension", "cmp.unacceptedExtension",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_addInfoNotAvailable,
      { "addInfoNotAvailable", "cmp.addInfoNotAvailable",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badSenderNonce,
      { "badSenderNonce", "cmp.badSenderNonce",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badCertTemplate,
      { "badCertTemplate", "cmp.badCertTemplate",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_signerNotTrusted,
      { "signerNotTrusted", "cmp.signerNotTrusted",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_transactionIdInUse,
      { "transactionIdInUse", "cmp.transactionIdInUse",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_unsupportedVersion,
      { "unsupportedVersion", "cmp.unsupportedVersion",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_notAuthorized,
      { "notAuthorized", "cmp.notAuthorized",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_systemUnavail,
      { "systemUnavail", "cmp.systemUnavail",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_systemFailure,
      { "systemFailure", "cmp.systemFailure",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_duplicateCertReq,
      { "duplicateCertReq", "cmp.duplicateCertReq",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},

/*--- End of included file: packet-cmp-hfarr.c ---*/
#line 338 "../../asn1/cmp/packet-cmp-template.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_cmp,

/*--- Included file: packet-cmp-ettarr.c ---*/
#line 1 "../../asn1/cmp/packet-cmp-ettarr.c"
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
#line 344 "../../asn1/cmp/packet-cmp-template.c"
	};
	module_t *cmp_module;

	/* Register protocol */
	proto_cmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_cmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	cmp_module = prefs_register_protocol(proto_cmp, proto_reg_handoff_cmp);
	prefs_register_bool_preference(cmp_module, "desegment",
			"Reassemble CMP-over-TCP messages spanning multiple TCP segments",
			"Whether the CMP-over-TCP dissector should reassemble messages spanning multiple TCP segments. "
			"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
			&cmp_desegment);

	prefs_register_uint_preference(cmp_module, "tcp_alternate_port",
			"Alternate TCP port",
			"Decode this TCP port\'s traffic as CMP. Set to \"0\" to disable.",
			10,
			&cmp_alternate_tcp_port);

	prefs_register_uint_preference(cmp_module, "http_alternate_port",
			"Alternate HTTP port",
			"Decode this TCP port\'s traffic as CMP-over-HTTP. Set to \"0\" to disable. "
			"Use this if the Content-Type is not set correctly.",
			10,
			&cmp_alternate_http_port);

	prefs_register_uint_preference(cmp_module, "tcp_style_http_alternate_port",
			"Alternate TCP-style-HTTP port",
			"Decode this TCP port\'s traffic as TCP-transport-style CMP-over-HTTP. Set to \"0\" to disable. "
			"Use this if the Content-Type is not set correctly.",
			10,
			&cmp_alternate_tcp_style_http_port);
}


/*--- proto_reg_handoff_cmp -------------------------------------------*/
void proto_reg_handoff_cmp(void) {
	static gboolean inited = FALSE;
	static dissector_handle_t cmp_http_handle;
	static dissector_handle_t cmp_tcp_style_http_handle;
	static dissector_handle_t cmp_tcp_handle;
	static guint cmp_alternate_tcp_port_prev = 0;
	static guint cmp_alternate_http_port_prev = 0;
	static guint cmp_alternate_tcp_style_http_port_prev = 0;

	if (!inited) {
		cmp_http_handle = new_create_dissector_handle(dissect_cmp_http, proto_cmp);
		dissector_add_string("media_type", "application/pkixcmp", cmp_http_handle);
		dissector_add_string("media_type", "application/x-pkixcmp", cmp_http_handle);

		cmp_tcp_style_http_handle = new_create_dissector_handle(dissect_cmp_tcp_pdu, proto_cmp);
		dissector_add_string("media_type", "application/pkixcmp-poll", cmp_tcp_style_http_handle);
		dissector_add_string("media_type", "application/x-pkixcmp-poll", cmp_tcp_style_http_handle);

		cmp_tcp_handle = new_create_dissector_handle(dissect_cmp_tcp, proto_cmp);
		dissector_add_uint("tcp.port", TCP_PORT_CMP, cmp_tcp_handle);

		oid_add_from_string("Cryptlib-presence-check","1.3.6.1.4.1.3029.3.1.1");
		oid_add_from_string("Cryptlib-PKIBoot","1.3.6.1.4.1.3029.3.1.2");

		oid_add_from_string("HMAC MD5","1.3.6.1.5.5.8.1.1");
		oid_add_from_string("HMAC SHA-1","1.3.6.1.5.5.8.1.2");
		oid_add_from_string("HMAC TIGER","1.3.6.1.5.5.8.1.3");
		oid_add_from_string("HMAC RIPEMD-160","1.3.6.1.5.5.8.1.4");

		oid_add_from_string("sha256WithRSAEncryption","1.2.840.113549.1.1.11");


/*--- Included file: packet-cmp-dis-tab.c ---*/
#line 1 "../../asn1/cmp/packet-cmp-dis-tab.c"
  register_ber_oid_dissector("1.2.840.113533.7.66.13", dissect_PBMParameter_PDU, proto_cmp, "id-PasswordBasedMac");
  register_ber_oid_dissector("1.2.640.113533.7.66.30", dissect_DHBMParameter_PDU, proto_cmp, "id-DHBasedMac");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.1", dissect_CAProtEncCertValue_PDU, proto_cmp, "id-it-caProtEncCert");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.2", dissect_SignKeyPairTypesValue_PDU, proto_cmp, "id-it-signKeyPairTypes");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.3", dissect_EncKeyPairTypesValue_PDU, proto_cmp, "id-it-encKeyPairTypes");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.4", dissect_PreferredSymmAlgValue_PDU, proto_cmp, "id-it-preferredSymmAlg");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.5", dissect_CAKeyUpdateInfoValue_PDU, proto_cmp, "id-it-caKeyUpdateInfo");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.6", dissect_CurrentCRLValue_PDU, proto_cmp, "id-it-currentCRL");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.7", dissect_UnsupportedOIDsValue_PDU, proto_cmp, "id-it-unsupportedOIDs");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.10", dissect_KeyPairParamReqValue_PDU, proto_cmp, "id-it-keyPairParamReq");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.11", dissect_KeyPairParamRepValue_PDU, proto_cmp, "id-it-keyPairParamRep");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.12", dissect_RevPassphraseValue_PDU, proto_cmp, "id-it-revPassphrase");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.13", dissect_ImplicitConfirmValue_PDU, proto_cmp, "id-it-implicitConfirm");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.14", dissect_ConfirmWaitTimeValue_PDU, proto_cmp, "id-it-confirmWaitTime");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.15", dissect_OrigPKIMessageValue_PDU, proto_cmp, "id-it-origPKIMessage");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.16", dissect_SuppLangTagsValue_PDU, proto_cmp, "id-it-suppLangTags");


/*--- End of included file: packet-cmp-dis-tab.c ---*/
#line 416 "../../asn1/cmp/packet-cmp-template.c"
		inited = TRUE;
	}

	/* change alternate TCP port if changed in the preferences */
	if (cmp_alternate_tcp_port != cmp_alternate_tcp_port_prev) {
		if (cmp_alternate_tcp_port_prev != 0)
			dissector_delete_uint("tcp.port", cmp_alternate_tcp_port_prev, cmp_tcp_handle);
		if (cmp_alternate_tcp_port != 0)
			dissector_add_uint("tcp.port", cmp_alternate_tcp_port, cmp_tcp_handle);
		cmp_alternate_tcp_port_prev = cmp_alternate_tcp_port;
	}

	/* change alternate HTTP port if changed in the preferences */
	if (cmp_alternate_http_port != cmp_alternate_http_port_prev) {
		if (cmp_alternate_http_port_prev != 0) {
			dissector_delete_uint("tcp.port", cmp_alternate_http_port_prev, NULL);
			dissector_delete_uint("http.port", cmp_alternate_http_port_prev, NULL);
		}
		if (cmp_alternate_http_port != 0)
			http_dissector_add( cmp_alternate_http_port, cmp_http_handle);
		cmp_alternate_http_port_prev = cmp_alternate_http_port;
	}

	/* change alternate TCP-style-HTTP port if changed in the preferences */
	if (cmp_alternate_tcp_style_http_port != cmp_alternate_tcp_style_http_port_prev) {
		if (cmp_alternate_tcp_style_http_port_prev != 0) {
			dissector_delete_uint("tcp.port", cmp_alternate_tcp_style_http_port_prev, NULL);
			dissector_delete_uint("http.port", cmp_alternate_tcp_style_http_port_prev, NULL);
		}
		if (cmp_alternate_tcp_style_http_port != 0)
			http_dissector_add( cmp_alternate_tcp_style_http_port, cmp_tcp_style_http_handle);
		cmp_alternate_tcp_style_http_port_prev = cmp_alternate_tcp_style_http_port;
	}

}

