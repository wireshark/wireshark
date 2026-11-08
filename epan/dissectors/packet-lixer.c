/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lixer.c                                                             */
/* asn2wrs.py -b -q -L -p lixer -c ./lixer.cnf -s ./packet-lixer-template -D . -O ../.. TS33128IdentityAssociation.asn */

/* packet-lixer.c
 * Routines for 3GPP TS 33.128 LI_XER (IEF to ICF) dissection
 *
 * See 3GPP TS 33.128 V19.8.0 (2026-09), clause 6.2.2A.2 and Annex F
 * (TS33128IdentityAssociation)
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
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-gsm_a_common.h"
#include "packet-tcp.h"
#include "packet-tls.h"

/* The start of the iEFRecordOID, the first component of an IEFMessage:
 * [1] IMPLICIT RELATIVE-OID with threeGPP(4) tS33128IdentityAssociation(20) */
#define LIXER_RECORD_OID_TAG    0x81
#define LIXER_RECORD_OID_PREFIX 0x0414

void proto_register_lixer(void);
void proto_reg_handoff_lixer(void);

static int proto_lixer;

static dissector_handle_t lixer_handle;

static bool lixer_desegment = true;

static int hf_lixer_IEFMessage_PDU;               /* IEFMessage */
static int hf_lixer_iEFRecordOID;                 /* RELATIVE_OID */
static int hf_lixer_record;                       /* IEFRecord */
static int hf_lixer_associationRecord;            /* IEFAssociationRecord */
static int hf_lixer_deassociationRecord;          /* IEFDeassociationRecord */
static int hf_lixer_keepalive;                    /* IEFKeepaliveMessage */
static int hf_lixer_keepaliveResponse;            /* IEFKeepaliveMessage */
static int hf_lixer_sUPI;                         /* SUPI */
static int hf_lixer_fiveGGUTI;                    /* FiveGGUTI */
static int hf_lixer_timestamp;                    /* GeneralizedTime */
static int hf_lixer_tAI;                          /* TAI */
static int hf_lixer_nCGI;                         /* NCGI */
static int hf_lixer_nCGITime;                     /* GeneralizedTime */
static int hf_lixer_sUCI;                         /* SUCI */
static int hf_lixer_pEI;                          /* PEI */
static int hf_lixer_fiveGSTAIList;                /* FiveGSTAIList */
static int hf_lixer_gPSI;                         /* GPSI */
static int hf_lixer_additionalCGIs;               /* AdditionalCGIs */
static int hf_lixer_sequenceNumber;               /* INTEGER */
static int hf_lixer_additionalNCGIList;           /* SEQUENCE_SIZE_1_MAX_OF_AdditionalNCGI */
static int hf_lixer_additionalNCGIList_item;      /* AdditionalNCGI */
static int hf_lixer_pLMNID;                       /* PLMNID */
static int hf_lixer_nCI;                          /* NCI */
static int hf_lixer_iMSI;                         /* IMSI */
static int hf_lixer_nAI;                          /* NAI */
static int hf_lixer_FiveGSTAIList_item;           /* TAI */
static int hf_lixer_iMEI;                         /* IMEI */
static int hf_lixer_iMEISV;                       /* IMEISV */
static int hf_lixer_mACAddress;                   /* MACAddress */
static int hf_lixer_eUI64;                        /* EUI64 */
static int hf_lixer_gPSIMSISDN;                   /* MSISDN */
static int hf_lixer_gPSINAI;                      /* NAI */
static int hf_lixer_aMFRegionID;
static int hf_lixer_aMFSetID;
static int hf_lixer_aMFPointer;
static int hf_lixer_fiveGTMSI;

static int ett_lixer;
static int ett_lixer_imsi;
static int ett_lixer_msisdn;
static int ett_lixer_plmnid;
static int ett_lixer_tai;
static int ett_lixer_fiveg_guti;
static int ett_lixer_suci;
static int ett_lixer_IEFMessage;
static int ett_lixer_IEFRecord;
static int ett_lixer_IEFAssociationRecord;
static int ett_lixer_IEFDeassociationRecord;
static int ett_lixer_IEFKeepaliveMessage;
static int ett_lixer_AdditionalCGIs;
static int ett_lixer_SEQUENCE_SIZE_1_MAX_OF_AdditionalNCGI;
static int ett_lixer_AdditionalNCGI;
static int ett_lixer_NCGI;
static int ett_lixer_SUPI;
static int ett_lixer_FiveGSTAIList;
static int ett_lixer_PEI;
static int ett_lixer_GPSI;

/* A 5G-GUTI as in TS 24.501 figure 9.11.3.4.1, without the first four
 * octets: MCC and MNC, AMF Region ID, AMF Set ID, AMF Pointer and 5G-TMSI */
static void
dissect_lixer_5g_guti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset;

  offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, E212_GUAMI, true);
  proto_tree_add_item(tree, hf_lixer_aMFRegionID, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_lixer_aMFSetID, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_lixer_aMFPointer, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_lixer_fiveGTMSI, tvb, offset, 4, ENC_BIG_ENDIAN);
}



static unsigned
dissect_lixer_RELATIVE_OID(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_relative_oid(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static unsigned
dissect_lixer_IMSI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *imsi_tvb = NULL;

  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        6, 15, hf_index, &imsi_tvb);

  if (imsi_tvb) {
    dissect_e212_utf8_imsi(imsi_tvb, actx->pinfo,
                           proto_item_add_subtree(actx->created_item, ett_lixer_imsi),
                           0, tvb_reported_length(imsi_tvb));
  }


  return offset;
}



static unsigned
dissect_lixer_NAI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string lixer_SUPI_vals[] = {
  {   1, "iMSI" },
  {   2, "nAI" },
  { 0, NULL }
};

static const ber_choice_t SUPI_choice[] = {
  {   1, &hf_lixer_iMSI          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lixer_IMSI },
  {   2, &hf_lixer_nAI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lixer_NAI },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_SUPI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SUPI_choice, hf_index, ett_lixer_SUPI,
                                 NULL);

  return offset;
}



static unsigned
dissect_lixer_FiveGGUTI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *guti_tvb = NULL;

  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   10, 10, hf_index, &guti_tvb);

  /* TS 24.501 figure 9.11.3.4.1, without the first four octets */
  if (guti_tvb && tvb_reported_length(guti_tvb) == 10) {
    dissect_lixer_5g_guti(guti_tvb, actx->pinfo,
                          proto_item_add_subtree(actx->created_item, ett_lixer_fiveg_guti));
  }


  return offset;
}



static unsigned
dissect_lixer_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static unsigned
dissect_lixer_TAI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *tai_tvb = NULL;

  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   6, 6, hf_index, &tai_tvb);

  /* TS 24.501 clause 9.11.3.8, without the IEI */
  if (tai_tvb && tvb_reported_length(tai_tvb) == 6) {
    nas_5gs_mm_elem_fcn[DE_NAS_5GS_MM_5GS_TA_ID](tai_tvb,
        proto_item_add_subtree(actx->created_item, ett_lixer_tai),
        actx->pinfo, 0, 6, NULL, 0);
  }


  return offset;
}



static unsigned
dissect_lixer_PLMNID(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *plmn_tvb = NULL;

  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   3, 3, hf_index, &plmn_tvb);

  /* TS 38.413 clause 9.3.3.5; PLMNID is only used in an NCGI */
  if (plmn_tvb && tvb_reported_length(plmn_tvb) == 3) {
    dissect_e212_mcc_mnc(plmn_tvb, actx->pinfo,
                         proto_item_add_subtree(actx->created_item, ett_lixer_plmnid),
                         0, E212_NRCGI, true);
  }


  return offset;
}



static unsigned
dissect_lixer_NCI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *nci_tvb = NULL;

  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                36, 36, NULL, 0, -1, -1,
                                                &nci_tvb);

  if (nci_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, nci_tvb, 0, 5, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const ber_sequence_t NCGI_sequence[] = {
  { &hf_lixer_pLMNID        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lixer_PLMNID },
  { &hf_lixer_nCI           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lixer_NCI },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_NCGI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NCGI_sequence, hf_index, ett_lixer_NCGI);

  return offset;
}



static unsigned
dissect_lixer_SUCI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *suci_tvb = NULL;

  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   8, 3008, hf_index, &suci_tvb);

  /* TS 24.501 clause 9.11.3.4, without the IEI and the length */
  if (suci_tvb && tvb_reported_length(suci_tvb) >= 8) {
    nas_5gs_mm_elem_fcn[DE_NAS_5GS_MM_5GS_MOBILE_ID](suci_tvb,
        proto_item_add_subtree(actx->created_item, ett_lixer_suci),
        actx->pinfo, 0, tvb_reported_length(suci_tvb), NULL, 0);
  }


  return offset;
}



static unsigned
dissect_lixer_IMEI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        14, 14, hf_index, NULL);

  return offset;
}



static unsigned
dissect_lixer_IMEISV(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        16, 16, hf_index, NULL);

  return offset;
}



static unsigned
dissect_lixer_MACAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   6, 6, hf_index, NULL);

  return offset;
}



static unsigned
dissect_lixer_EUI64(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   8, 8, hf_index, NULL);

  return offset;
}


static const value_string lixer_PEI_vals[] = {
  {   1, "iMEI" },
  {   2, "iMEISV" },
  {   3, "mACAddress" },
  {   4, "eUI64" },
  { 0, NULL }
};

static const ber_choice_t PEI_choice[] = {
  {   1, &hf_lixer_iMEI          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lixer_IMEI },
  {   2, &hf_lixer_iMEISV        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lixer_IMEISV },
  {   3, &hf_lixer_mACAddress    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lixer_MACAddress },
  {   4, &hf_lixer_eUI64         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lixer_EUI64 },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_PEI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PEI_choice, hf_index, ett_lixer_PEI,
                                 NULL);

  return offset;
}


static const ber_sequence_t FiveGSTAIList_sequence_of[1] = {
  { &hf_lixer_FiveGSTAIList_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_lixer_TAI },
};

static unsigned
dissect_lixer_FiveGSTAIList(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      FiveGSTAIList_sequence_of, hf_index, ett_lixer_FiveGSTAIList);

  return offset;
}



static unsigned
dissect_lixer_MSISDN(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *msisdn_tvb = NULL;

  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                                        actx, tree, tvb, offset,
                                                        1, 15, hf_index, &msisdn_tvb);

  if (msisdn_tvb) {
    dissect_e164_msisdn(msisdn_tvb, actx->pinfo,
                        proto_item_add_subtree(actx->created_item, ett_lixer_msisdn),
                        0, tvb_reported_length(msisdn_tvb), E164_ENC_UTF8);
  }


  return offset;
}


static const value_string lixer_GPSI_vals[] = {
  {   1, "gPSIMSISDN" },
  {   2, "gPSINAI" },
  { 0, NULL }
};

static const ber_choice_t GPSI_choice[] = {
  {   1, &hf_lixer_gPSIMSISDN    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lixer_MSISDN },
  {   2, &hf_lixer_gPSINAI       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lixer_NAI },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_GPSI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GPSI_choice, hf_index, ett_lixer_GPSI,
                                 NULL);

  return offset;
}


static const ber_sequence_t AdditionalNCGI_sequence[] = {
  { &hf_lixer_nCGI          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lixer_NCGI },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_AdditionalNCGI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AdditionalNCGI_sequence, hf_index, ett_lixer_AdditionalNCGI);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_AdditionalNCGI_sequence_of[1] = {
  { &hf_lixer_additionalNCGIList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lixer_AdditionalNCGI },
};

static unsigned
dissect_lixer_SEQUENCE_SIZE_1_MAX_OF_AdditionalNCGI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, NO_BOUND, SEQUENCE_SIZE_1_MAX_OF_AdditionalNCGI_sequence_of, hf_index, ett_lixer_SEQUENCE_SIZE_1_MAX_OF_AdditionalNCGI);

  return offset;
}


static const ber_sequence_t AdditionalCGIs_sequence[] = {
  { &hf_lixer_additionalNCGIList, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lixer_SEQUENCE_SIZE_1_MAX_OF_AdditionalNCGI },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_AdditionalCGIs(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AdditionalCGIs_sequence, hf_index, ett_lixer_AdditionalCGIs);

  return offset;
}


static const ber_sequence_t IEFAssociationRecord_sequence[] = {
  { &hf_lixer_sUPI          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lixer_SUPI },
  { &hf_lixer_fiveGGUTI     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lixer_FiveGGUTI },
  { &hf_lixer_timestamp     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lixer_GeneralizedTime },
  { &hf_lixer_tAI           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lixer_TAI },
  { &hf_lixer_nCGI          , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lixer_NCGI },
  { &hf_lixer_nCGITime      , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_lixer_GeneralizedTime },
  { &hf_lixer_sUCI          , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lixer_SUCI },
  { &hf_lixer_pEI           , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lixer_PEI },
  { &hf_lixer_fiveGSTAIList , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lixer_FiveGSTAIList },
  { &hf_lixer_gPSI          , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lixer_GPSI },
  { &hf_lixer_additionalCGIs, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lixer_AdditionalCGIs },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_IEFAssociationRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IEFAssociationRecord_sequence, hf_index, ett_lixer_IEFAssociationRecord);

  return offset;
}


static const ber_sequence_t IEFDeassociationRecord_sequence[] = {
  { &hf_lixer_sUPI          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lixer_SUPI },
  { &hf_lixer_fiveGGUTI     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lixer_FiveGGUTI },
  { &hf_lixer_timestamp     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lixer_GeneralizedTime },
  { &hf_lixer_nCGI          , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lixer_NCGI },
  { &hf_lixer_nCGITime      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_lixer_GeneralizedTime },
  { &hf_lixer_additionalCGIs, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lixer_AdditionalCGIs },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_IEFDeassociationRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IEFDeassociationRecord_sequence, hf_index, ett_lixer_IEFDeassociationRecord);

  return offset;
}



static unsigned
dissect_lixer_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t IEFKeepaliveMessage_sequence[] = {
  { &hf_lixer_sequenceNumber, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lixer_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_IEFKeepaliveMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IEFKeepaliveMessage_sequence, hf_index, ett_lixer_IEFKeepaliveMessage);

  return offset;
}


static const value_string lixer_IEFRecord_vals[] = {
  {   1, "associationRecord" },
  {   2, "deassociationRecord" },
  {   3, "keepalive" },
  {   4, "keepaliveResponse" },
  { 0, NULL }
};

static const ber_choice_t IEFRecord_choice[] = {
  {   1, &hf_lixer_associationRecord, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lixer_IEFAssociationRecord },
  {   2, &hf_lixer_deassociationRecord, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_lixer_IEFDeassociationRecord },
  {   3, &hf_lixer_keepalive     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lixer_IEFKeepaliveMessage },
  {   4, &hf_lixer_keepaliveResponse, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_lixer_IEFKeepaliveMessage },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_IEFRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int record = -1;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IEFRecord_choice, hf_index, ett_lixer_IEFRecord,
                                 &record);

  /* record is the index of the alternative in IEFRecord_choice */
  if (record != -1) {
    col_append_sep_str(actx->pinfo->cinfo, COL_INFO, ", ",
                       val_to_str_const(IEFRecord_choice[record].value, lixer_IEFRecord_vals, "Unknown"));
  }


  return offset;
}


static const ber_sequence_t IEFMessage_sequence[] = {
  { &hf_lixer_iEFRecordOID  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lixer_RELATIVE_OID },
  { &hf_lixer_record        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lixer_IEFRecord },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_lixer_IEFMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IEFMessage_sequence, hf_index, ett_lixer_IEFMessage);

  return offset;
}

/*--- PDUs ---*/

static int dissect_IEFMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_lixer_IEFMessage(false, tvb, offset, &asn1_ctx, tree, hf_lixer_IEFMessage_PDU);
  return offset;
}


/* One IEFMessage */
static int
dissect_lixer_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  proto_item *ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LI_XER");

  ti = proto_tree_add_item(tree, proto_lixer, tvb, 0, -1, ENC_NA);
  return dissect_IEFMessage_PDU(tvb, pinfo, proto_item_add_subtree(ti, ett_lixer), data);
}

/* The length of the BER encoded IEFMessage at offset, or 0 if it needs
 * more data */
static unsigned
get_lixer_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  volatile unsigned len = 0;
  unsigned ber_offset;
  uint32_t ber_len;

  TRY {
    ber_offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
    ber_offset = get_ber_length(tvb, ber_offset, &ber_len, NULL);
    /* get_ber_length() clamps ber_len to INT32_MAX */
    len = ber_offset - offset + ber_len;
  }
  CATCH_BOUNDS_ERRORS {
    len = 0;
  }
  ENDTRY;

  return len;
}

/* The IEFMessages of a TCP or TLS stream; the IEF transmits them over TLS
 * (TS 33.128 clause 6.2.2A.2.3) */
static int
dissect_lixer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  col_clear(pinfo->cinfo, COL_INFO);

  /* the shortest identifier and length are 2 octets */
  tcp_dissect_pdus(tvb, pinfo, tree, lixer_desegment, 2,
                   get_lixer_message_len, dissect_lixer_message, data);
  return tvb_captured_length(tvb);
}

static bool
dissect_lixer_heur_tls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct tlsinfo *tlsinfo = (struct tlsinfo *)data;
  unsigned offset = 2;
  uint8_t len_octet;
  uint8_t oid_len;

  /* an IEFMessage is a SEQUENCE */
  if (tvb_captured_length(tvb) < 2 || tvb_get_uint8(tvb, 0) != 0x30)
    return false;
  len_octet = tvb_get_uint8(tvb, 1);
  if (len_octet & 0x80) {
    /* the long form, or 0 octets for the indefinite form */
    if ((len_octet & 0x7f) > 4)
      return false;
    offset += len_octet & 0x7f;
  }

  /* its iEFRecordOID, with at least threeGPP(4) tS33128IdentityAssociation(20) */
  if (!tvb_bytes_exist(tvb, offset, 4))
    return false;
  if (tvb_get_uint8(tvb, offset) != LIXER_RECORD_OID_TAG)
    return false;
  oid_len = tvb_get_uint8(tvb, offset + 1);
  if (oid_len < 2 || (oid_len & 0x80))
    return false;
  if (tvb_get_ntohs(tvb, offset + 2) != LIXER_RECORD_OID_PREFIX)
    return false;

  /* TLS can keep it for this session */
  if (tlsinfo)
    *(tlsinfo->app_handle) = lixer_handle;
  dissect_lixer(tvb, pinfo, tree, data);

  return true;
}

/*--- proto_register_lixer --------------------------------------------------*/
void proto_register_lixer(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_lixer_IEFMessage_PDU,
      { "IEFMessage", "lixer.IEFMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_iEFRecordOID,
      { "iEFRecordOID", "lixer.iEFRecordOID",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_lixer_record,
      { "record", "lixer.record",
        FT_UINT32, BASE_DEC, VALS(lixer_IEFRecord_vals), 0,
        "IEFRecord", HFILL }},
    { &hf_lixer_associationRecord,
      { "associationRecord", "lixer.associationRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IEFAssociationRecord", HFILL }},
    { &hf_lixer_deassociationRecord,
      { "deassociationRecord", "lixer.deassociationRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IEFDeassociationRecord", HFILL }},
    { &hf_lixer_keepalive,
      { "keepalive", "lixer.keepalive_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IEFKeepaliveMessage", HFILL }},
    { &hf_lixer_keepaliveResponse,
      { "keepaliveResponse", "lixer.keepaliveResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IEFKeepaliveMessage", HFILL }},
    { &hf_lixer_sUPI,
      { "sUPI", "lixer.sUPI",
        FT_UINT32, BASE_DEC, VALS(lixer_SUPI_vals), 0,
        NULL, HFILL }},
    { &hf_lixer_fiveGGUTI,
      { "fiveGGUTI", "lixer.fiveGGUTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_timestamp,
      { "timestamp", "lixer.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_lixer_tAI,
      { "tAI", "lixer.tAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_nCGI,
      { "nCGI", "lixer.nCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_nCGITime,
      { "nCGITime", "lixer.nCGITime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_lixer_sUCI,
      { "sUCI", "lixer.sUCI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_pEI,
      { "pEI", "lixer.pEI",
        FT_UINT32, BASE_DEC, VALS(lixer_PEI_vals), 0,
        NULL, HFILL }},
    { &hf_lixer_fiveGSTAIList,
      { "fiveGSTAIList", "lixer.fiveGSTAIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_gPSI,
      { "gPSI", "lixer.gPSI",
        FT_UINT32, BASE_DEC, VALS(lixer_GPSI_vals), 0,
        NULL, HFILL }},
    { &hf_lixer_additionalCGIs,
      { "additionalCGIs", "lixer.additionalCGIs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_sequenceNumber,
      { "sequenceNumber", "lixer.sequenceNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_lixer_additionalNCGIList,
      { "additionalNCGIList", "lixer.additionalNCGIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_AdditionalNCGI", HFILL }},
    { &hf_lixer_additionalNCGIList_item,
      { "AdditionalNCGI", "lixer.AdditionalNCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_pLMNID,
      { "pLMNID", "lixer.pLMNID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_nCI,
      { "nCI", "lixer.nCI",
        FT_UINT40, BASE_HEX, NULL, 0xFFFFFFFFF0,
        NULL, HFILL }},
    { &hf_lixer_iMSI,
      { "iMSI", "lixer.iMSI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_nAI,
      { "nAI", "lixer.nAI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_FiveGSTAIList_item,
      { "TAI", "lixer.TAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_iMEI,
      { "iMEI", "lixer.iMEI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_iMEISV,
      { "iMEISV", "lixer.iMEISV",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_mACAddress,
      { "mACAddress", "lixer.mACAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_eUI64,
      { "eUI64", "lixer.eUI64",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_gPSIMSISDN,
      { "gPSIMSISDN", "lixer.gPSIMSISDN",
        FT_STRING, BASE_NONE, NULL, 0,
        "MSISDN", HFILL }},
    { &hf_lixer_gPSINAI,
      { "gPSINAI", "lixer.gPSINAI",
        FT_STRING, BASE_NONE, NULL, 0,
        "NAI", HFILL }},
    { &hf_lixer_aMFRegionID,
      { "AMF Region ID", "lixer.aMFRegionID",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_aMFSetID,
      { "AMF Set ID", "lixer.aMFSetID",
        FT_UINT16, BASE_DEC, NULL, 0xffc0,
        NULL, HFILL }},
    { &hf_lixer_aMFPointer,
      { "AMF Pointer", "lixer.aMFPointer",
        FT_UINT8, BASE_DEC, NULL, 0x3f,
        NULL, HFILL }},
    { &hf_lixer_fiveGTMSI,
      { "5G-TMSI", "lixer.fiveGTMSI",
        FT_UINT32, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_lixer,
    &ett_lixer_imsi,
    &ett_lixer_msisdn,
    &ett_lixer_plmnid,
    &ett_lixer_tai,
    &ett_lixer_fiveg_guti,
    &ett_lixer_suci,
    &ett_lixer_IEFMessage,
    &ett_lixer_IEFRecord,
    &ett_lixer_IEFAssociationRecord,
    &ett_lixer_IEFDeassociationRecord,
    &ett_lixer_IEFKeepaliveMessage,
    &ett_lixer_AdditionalCGIs,
    &ett_lixer_SEQUENCE_SIZE_1_MAX_OF_AdditionalNCGI,
    &ett_lixer_AdditionalNCGI,
    &ett_lixer_NCGI,
    &ett_lixer_SUPI,
    &ett_lixer_FiveGSTAIList,
    &ett_lixer_PEI,
    &ett_lixer_GPSI,
  };

  module_t *lixer_module;

  /* Register protocol */
  proto_lixer = proto_register_protocol("3GPP TS 33.128 LI_XER Identity Association", "LI_XER", "lixer");

  /* Register fields and subtrees */
  proto_register_field_array(proto_lixer, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  lixer_handle = register_dissector("lixer", dissect_lixer, proto_lixer);

  lixer_module = prefs_register_protocol(proto_lixer, NULL);
  prefs_register_bool_preference(lixer_module, "desegment",
                                 "Reassemble LI_XER messages spanning multiple TCP segments",
                                 "Whether the LI_XER dissector should reassemble messages spanning multiple TCP segments."
                                 " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                 &lixer_desegment);
}

/*--- proto_reg_handoff_lixer -----------------------------------------------*/
void proto_reg_handoff_lixer(void) {

  /* no port is assigned */
  dissector_add_uint_range_with_preference("tcp.port", "", lixer_handle);
  dissector_add_for_decode_as("tls.port", lixer_handle);
  heur_dissector_add("tls", dissect_lixer_heur_tls, "LI_XER over TLS", "lixer_tls", proto_lixer, HEURISTIC_ENABLE);
}
