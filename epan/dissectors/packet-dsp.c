/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-dsp.c                                                               */
/* asn2wrs.py -b -q -L -p dsp -c ./dsp.cnf -s ./packet-dsp-template -D . -O ../.. dsp.asn */

/* packet-dsp.c
 * Routines for X.518 (X.500 Distributed Operations)  packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"

#include "packet-x509if.h"
#include "packet-x509af.h"
#include "packet-x509sat.h"

#include "packet-dap.h"
#include "packet-dsp.h"


#define PNAME  "X.519 Directory System Protocol"
#define PSNAME "DSP"
#define PFNAME "dsp"

void proto_register_dsp(void);
void proto_reg_handoff_dsp(void);

/* Initialize the protocol and registered fields */
static int proto_dsp;

static int hf_dsp_AccessPoint_PDU;                /* AccessPoint */
static int hf_dsp_MasterAndShadowAccessPoints_PDU;  /* MasterAndShadowAccessPoints */
static int hf_dsp_DitBridgeKnowledge_PDU;         /* DitBridgeKnowledge */
static int hf_dsp_chainedArgument;                /* ChainingArguments */
static int hf_dsp_readArgument;                   /* ReadArgument */
static int hf_dsp_unsignedChainedReadArgument;    /* ChainedReadArgumentData */
static int hf_dsp_signedChainedReadArgument;      /* T_signedChainedReadArgument */
static int hf_dsp_chainedReadArgument;            /* ChainedReadArgumentData */
static int hf_dsp_algorithmIdentifier;            /* AlgorithmIdentifier */
static int hf_dsp_encrypted;                      /* BIT_STRING */
static int hf_dsp_chainedResults;                 /* ChainingResults */
static int hf_dsp_readResult;                     /* ReadResult */
static int hf_dsp_unsignedChainedReadResult;      /* ChainedReadResultData */
static int hf_dsp_signedChainedReadResult;        /* T_signedChainedReadResult */
static int hf_dsp_chainedReadResult;              /* ChainedReadResultData */
static int hf_dsp_compareArgument;                /* CompareArgument */
static int hf_dsp_unsignedChainedCompareArgument;  /* ChainedCompareArgumentData */
static int hf_dsp_signedChainedCompareArgument;   /* T_signedChainedCompareArgument */
static int hf_dsp_chainedCompareArgument;         /* ChainedCompareArgumentData */
static int hf_dsp_compareResult;                  /* CompareResult */
static int hf_dsp_unsignedChainedCompareResult;   /* ChainedCompareResultData */
static int hf_dsp_signedChainedCompareResult;     /* T_signedChainedCompareResult */
static int hf_dsp_chainedCompareResult;           /* ChainedCompareResultData */
static int hf_dsp_listArgument;                   /* ListArgument */
static int hf_dsp_unsignedChainedListArgument;    /* ChainedListArgumentData */
static int hf_dsp_signedChainedListArgument;      /* T_signedChainedListArgument */
static int hf_dsp_chainedListArgument;            /* ChainedListArgumentData */
static int hf_dsp_listResult;                     /* ListResult */
static int hf_dsp_unsignedChainedListResult;      /* ChainedListResultData */
static int hf_dsp_signedChainedListResult;        /* T_signedChainedListResult */
static int hf_dsp_chainedListResult;              /* ChainedListResultData */
static int hf_dsp_searchArgument;                 /* SearchArgument */
static int hf_dsp_unsignedChainedSearchArgument;  /* ChainedSearchArgumentData */
static int hf_dsp_signedChainedSearchArgument;    /* T_signedChainedSearchArgument */
static int hf_dsp_chainedSearchArgument;          /* ChainedSearchArgumentData */
static int hf_dsp_searchResult;                   /* SearchResult */
static int hf_dsp_unsignedChainedSearchResult;    /* ChainedSearchResultData */
static int hf_dsp_signedChainedSearchResult;      /* T_signedChainedSearchResult */
static int hf_dsp_chainedSearchResult;            /* ChainedSearchResultData */
static int hf_dsp_addEntryArgument;               /* AddEntryArgument */
static int hf_dsp_unsignedChainedAddEntryArgument;  /* ChainedAddEntryArgumentData */
static int hf_dsp_signedChainedAddEntryArgument;  /* T_signedChainedAddEntryArgument */
static int hf_dsp_chainedAddEntryArgument;        /* ChainedAddEntryArgumentData */
static int hf_dsp_addEntryResult;                 /* AddEntryResult */
static int hf_dsp_unsignedChainedAddEntryResult;  /* ChainedAddEntryResultData */
static int hf_dsp_signedChainedAddEntryResult;    /* T_signedChainedAddEntryResult */
static int hf_dsp_chainedAddEntryResult;          /* ChainedAddEntryResultData */
static int hf_dsp_removeEntryArgument;            /* RemoveEntryArgument */
static int hf_dsp_unsignedChainedRemoveEntryArgument;  /* ChainedRemoveEntryArgumentData */
static int hf_dsp_signedChainedRemoveEntryArgument;  /* T_signedChainedRemoveEntryArgument */
static int hf_dsp_chainedRemoveEntryArgument;     /* ChainedRemoveEntryArgumentData */
static int hf_dsp_removeEntryResult;              /* RemoveEntryResult */
static int hf_dsp_unsignedChainedRemoveEntryResult;  /* ChainedRemoveEntryResultData */
static int hf_dsp_signedChainedRemoveEntryResult;  /* T_signedChainedRemoveEntryResult */
static int hf_dsp_chainedRemoveEntryResult;       /* ChainedRemoveEntryResultData */
static int hf_dsp_modifyEntryArgument;            /* ModifyEntryArgument */
static int hf_dsp_unsignedChainedModifyEntryArgument;  /* ChainedModifyEntryArgumentData */
static int hf_dsp_signedChainedModifyEntryArgument;  /* T_signedChainedModifyEntryArgument */
static int hf_dsp_chainedModifyEntryArgument;     /* ChainedModifyEntryArgumentData */
static int hf_dsp_modifyEntryResult;              /* ModifyEntryResult */
static int hf_dsp_unsignedChainedModifyEntryResult;  /* ChainedModifyEntryResultData */
static int hf_dsp_signedChainedModifyEntryResult;  /* T_signedChainedModifyEntryResult */
static int hf_dsp_chainedModifyEntryResult;       /* ChainedModifyEntryResultData */
static int hf_dsp_modifyDNArgument;               /* ModifyDNArgument */
static int hf_dsp_unsignedChainedModifyDNArgument;  /* ChainedModifyDNArgumentData */
static int hf_dsp_signedChainedModifyDNArgument;  /* T_signedChainedModifyDNArgument */
static int hf_dsp_chainedModifyDNArgument;        /* ChainedModifyDNArgumentData */
static int hf_dsp_modifyDNResult;                 /* ModifyDNResult */
static int hf_dsp_unsignedChainedModifyDNResult;  /* ChainedModifyDNResultData */
static int hf_dsp_signedChainedModifyDNResult;    /* T_signedChainedModifyDNResult */
static int hf_dsp_chainedModifyDNResult;          /* ChainedModifyDNResultData */
static int hf_dsp_reference;                      /* ContinuationReference */
static int hf_dsp_contextPrefix;                  /* DistinguishedName */
static int hf_dsp_securityParameters;             /* SecurityParameters */
static int hf_dsp_performer;                      /* DistinguishedName */
static int hf_dsp_aliasDereferenced;              /* BOOLEAN */
static int hf_dsp_notification;                   /* SEQUENCE_OF_Attribute */
static int hf_dsp_notification_item;              /* Attribute */
static int hf_dsp_unsignedDSAReferral;            /* DSAReferralData */
static int hf_dsp_signedDSAReferral;              /* T_signedDSAReferral */
static int hf_dsp_dsaReferral;                    /* DSAReferralData */
static int hf_dsp_originator;                     /* DistinguishedName */
static int hf_dsp_targetObjectDN;                 /* DistinguishedName */
static int hf_dsp_operationProgress;              /* OperationProgress */
static int hf_dsp_traceInformation;               /* TraceInformation */
static int hf_dsp_aliasedRDNs;                    /* INTEGER */
static int hf_dsp_returnCrossRefs;                /* BOOLEAN */
static int hf_dsp_referenceType;                  /* ReferenceType */
static int hf_dsp_info;                           /* DomainInfo */
static int hf_dsp_timeLimit;                      /* Time */
static int hf_dsp_entryOnly;                      /* BOOLEAN */
static int hf_dsp_uniqueIdentifier;               /* UniqueIdentifier */
static int hf_dsp_authenticationLevel;            /* AuthenticationLevel */
static int hf_dsp_exclusions;                     /* Exclusions */
static int hf_dsp_excludeShadows;                 /* BOOLEAN */
static int hf_dsp_nameResolveOnMaster;            /* BOOLEAN */
static int hf_dsp_operationIdentifier;            /* INTEGER */
static int hf_dsp_searchRuleId;                   /* SearchRuleId */
static int hf_dsp_chainedRelaxation;              /* MRMapping */
static int hf_dsp_relatedEntry;                   /* INTEGER */
static int hf_dsp_dspPaging;                      /* BOOLEAN */
static int hf_dsp_nonDapPdu;                      /* T_nonDapPdu */
static int hf_dsp_streamedResults;                /* INTEGER */
static int hf_dsp_excludeWriteableCopies;         /* BOOLEAN */
static int hf_dsp_utcTime;                        /* UTCTime */
static int hf_dsp_generalizedTime;                /* GeneralizedTime */
static int hf_dsp_crossReferences;                /* SEQUENCE_OF_CrossReference */
static int hf_dsp_crossReferences_item;           /* CrossReference */
static int hf_dsp_alreadySearched;                /* Exclusions */
static int hf_dsp_accessPoint;                    /* AccessPointInformation */
static int hf_dsp_nameResolutionPhase;            /* T_nameResolutionPhase */
static int hf_dsp_nextRDNToBeResolved;            /* INTEGER */
static int hf_dsp_TraceInformation_item;          /* TraceItem */
static int hf_dsp_dsa;                            /* Name */
static int hf_dsp_targetObject;                   /* Name */
static int hf_dsp_ae_title;                       /* Name */
static int hf_dsp_address;                        /* PresentationAddress */
static int hf_dsp_protocolInformation;            /* SET_OF_ProtocolInformation */
static int hf_dsp_protocolInformation_item;       /* ProtocolInformation */
static int hf_dsp_labeledURI;                     /* LabeledURI */
static int hf_dsp_access_point_category;          /* APCategory */
static int hf_dsp_chainingRequired;               /* BOOLEAN */
static int hf_dsp_MasterAndShadowAccessPoints_item;  /* MasterOrShadowAccessPoint */
static int hf_dsp_category;                       /* T_category */
static int hf_dsp_additionalPoints;               /* MasterAndShadowAccessPoints */
static int hf_dsp_domainLocalID;                  /* DirectoryString */
static int hf_dsp_accessPoints;                   /* MasterAndShadowAccessPoints */
static int hf_dsp_Exclusions_item;                /* RDNSequence */
static int hf_dsp_rdnsResolved;                   /* INTEGER */
static int hf_dsp_accessPoints_01;                /* SET_OF_AccessPointInformation */
static int hf_dsp_accessPoints_item;              /* AccessPointInformation */
static int hf_dsp_returnToDUA;                    /* BOOLEAN */
static int hf_dsp_basicLevels;                    /* T_basicLevels */
static int hf_dsp_level;                          /* T_level */
static int hf_dsp_localQualifier;                 /* INTEGER */
static int hf_dsp_signed;                         /* BOOLEAN */
static int hf_dsp_other;                          /* EXTERNAL */

/* Initialize the subtree pointers */
static int ett_dsp;
static int ett_dsp_ChainedReadArgumentData;
static int ett_dsp_ChainedReadArgument;
static int ett_dsp_T_signedChainedReadArgument;
static int ett_dsp_ChainedReadResultData;
static int ett_dsp_ChainedReadResult;
static int ett_dsp_T_signedChainedReadResult;
static int ett_dsp_ChainedCompareArgumentData;
static int ett_dsp_ChainedCompareArgument;
static int ett_dsp_T_signedChainedCompareArgument;
static int ett_dsp_ChainedCompareResultData;
static int ett_dsp_ChainedCompareResult;
static int ett_dsp_T_signedChainedCompareResult;
static int ett_dsp_ChainedListArgumentData;
static int ett_dsp_ChainedListArgument;
static int ett_dsp_T_signedChainedListArgument;
static int ett_dsp_ChainedListResultData;
static int ett_dsp_ChainedListResult;
static int ett_dsp_T_signedChainedListResult;
static int ett_dsp_ChainedSearchArgumentData;
static int ett_dsp_ChainedSearchArgument;
static int ett_dsp_T_signedChainedSearchArgument;
static int ett_dsp_ChainedSearchResultData;
static int ett_dsp_ChainedSearchResult;
static int ett_dsp_T_signedChainedSearchResult;
static int ett_dsp_ChainedAddEntryArgumentData;
static int ett_dsp_ChainedAddEntryArgument;
static int ett_dsp_T_signedChainedAddEntryArgument;
static int ett_dsp_ChainedAddEntryResultData;
static int ett_dsp_ChainedAddEntryResult;
static int ett_dsp_T_signedChainedAddEntryResult;
static int ett_dsp_ChainedRemoveEntryArgumentData;
static int ett_dsp_ChainedRemoveEntryArgument;
static int ett_dsp_T_signedChainedRemoveEntryArgument;
static int ett_dsp_ChainedRemoveEntryResultData;
static int ett_dsp_ChainedRemoveEntryResult;
static int ett_dsp_T_signedChainedRemoveEntryResult;
static int ett_dsp_ChainedModifyEntryArgumentData;
static int ett_dsp_ChainedModifyEntryArgument;
static int ett_dsp_T_signedChainedModifyEntryArgument;
static int ett_dsp_ChainedModifyEntryResultData;
static int ett_dsp_ChainedModifyEntryResult;
static int ett_dsp_T_signedChainedModifyEntryResult;
static int ett_dsp_ChainedModifyDNArgumentData;
static int ett_dsp_ChainedModifyDNArgument;
static int ett_dsp_T_signedChainedModifyDNArgument;
static int ett_dsp_ChainedModifyDNResultData;
static int ett_dsp_ChainedModifyDNResult;
static int ett_dsp_T_signedChainedModifyDNResult;
static int ett_dsp_DSAReferralData;
static int ett_dsp_SEQUENCE_OF_Attribute;
static int ett_dsp_DSAReferral;
static int ett_dsp_T_signedDSAReferral;
static int ett_dsp_ChainingArguments;
static int ett_dsp_Time;
static int ett_dsp_ChainingResults;
static int ett_dsp_SEQUENCE_OF_CrossReference;
static int ett_dsp_CrossReference;
static int ett_dsp_OperationProgress;
static int ett_dsp_TraceInformation;
static int ett_dsp_TraceItem;
static int ett_dsp_AccessPoint;
static int ett_dsp_SET_OF_ProtocolInformation;
static int ett_dsp_MasterOrShadowAccessPoint;
static int ett_dsp_MasterAndShadowAccessPoints;
static int ett_dsp_AccessPointInformation;
static int ett_dsp_DitBridgeKnowledge;
static int ett_dsp_Exclusions;
static int ett_dsp_ContinuationReference;
static int ett_dsp_SET_OF_AccessPointInformation;
static int ett_dsp_AuthenticationLevel;
static int ett_dsp_T_basicLevels;

static expert_field ei_dsp_unsupported_opcode;
static expert_field ei_dsp_unsupported_errcode;
static expert_field ei_dsp_unsupported_pdu;
static expert_field ei_dsp_zero_pdu;



static int
dissect_dsp_DSASystemBindArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dsp_DSASystemBindResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dsp_DSASystemBindError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string dsp_T_nameResolutionPhase_vals[] = {
  {   1, "notStarted" },
  {   2, "proceeding" },
  {   3, "completed" },
  { 0, NULL }
};


static int
dissect_dsp_T_nameResolutionPhase(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dsp_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t OperationProgress_set[] = {
  { &hf_dsp_nameResolutionPhase, BER_CLASS_CON, 0, 0, dissect_dsp_T_nameResolutionPhase },
  { &hf_dsp_nextRDNToBeResolved, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dsp_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dsp_OperationProgress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              OperationProgress_set, hf_index, ett_dsp_OperationProgress);

  return offset;
}


static const ber_sequence_t TraceItem_set[] = {
  { &hf_dsp_dsa             , BER_CLASS_CON, 0, 0, dissect_x509if_Name },
  { &hf_dsp_targetObject    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_Name },
  { &hf_dsp_operationProgress, BER_CLASS_CON, 2, 0, dissect_dsp_OperationProgress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_TraceItem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              TraceItem_set, hf_index, ett_dsp_TraceItem);

  return offset;
}


static const ber_sequence_t TraceInformation_sequence_of[1] = {
  { &hf_dsp_TraceInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_TraceItem },
};

static int
dissect_dsp_TraceInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TraceInformation_sequence_of, hf_index, ett_dsp_TraceInformation);

  return offset;
}



static int
dissect_dsp_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


const value_string dsp_ReferenceType_vals[] = {
  {   1, "superior" },
  {   2, "subordinate" },
  {   3, "cross" },
  {   4, "nonSpecificSubordinate" },
  {   5, "supplier" },
  {   6, "master" },
  {   7, "immediateSuperior" },
  {   8, "self" },
  {   9, "ditBridge" },
  { 0, NULL }
};


int
dissect_dsp_ReferenceType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dsp_DomainInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_dsp_UTCTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index, NULL, NULL);

  return offset;
}



static int
dissect_dsp_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string dsp_Time_vals[] = {
  {   0, "utcTime" },
  {   1, "generalizedTime" },
  { 0, NULL }
};

static const ber_choice_t Time_choice[] = {
  {   0, &hf_dsp_utcTime         , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_dsp_UTCTime },
  {   1, &hf_dsp_generalizedTime , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_dsp_GeneralizedTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_Time(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Time_choice, hf_index, ett_dsp_Time,
                                 NULL);

  return offset;
}


static const value_string dsp_T_level_vals[] = {
  {   0, "none" },
  {   1, "simple" },
  {   2, "strong" },
  { 0, NULL }
};


static int
dissect_dsp_T_level(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_basicLevels_sequence[] = {
  { &hf_dsp_level           , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_dsp_T_level },
  { &hf_dsp_localQualifier  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dsp_INTEGER },
  { &hf_dsp_signed          , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dsp_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_basicLevels(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_basicLevels_sequence, hf_index, ett_dsp_T_basicLevels);

  return offset;
}



static int
dissect_dsp_EXTERNAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const value_string dsp_AuthenticationLevel_vals[] = {
  {   0, "basicLevels" },
  {   1, "other" },
  { 0, NULL }
};

static const ber_choice_t AuthenticationLevel_choice[] = {
  {   0, &hf_dsp_basicLevels     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_basicLevels },
  {   1, &hf_dsp_other           , BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_dsp_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_AuthenticationLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticationLevel_choice, hf_index, ett_dsp_AuthenticationLevel,
                                 NULL);

  return offset;
}


static const ber_sequence_t Exclusions_set_of[1] = {
  { &hf_dsp_Exclusions_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RDNSequence },
};

int
dissect_dsp_Exclusions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Exclusions_set_of, hf_index, ett_dsp_Exclusions);

  return offset;
}


static const value_string dsp_T_nonDapPdu_vals[] = {
  {   0, "ldap" },
  { 0, NULL }
};


static int
dissect_dsp_T_nonDapPdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ChainingArguments_set[] = {
  { &hf_dsp_originator      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dsp_targetObjectDN  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dsp_operationProgress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dsp_OperationProgress },
  { &hf_dsp_traceInformation, BER_CLASS_CON, 3, 0, dissect_dsp_TraceInformation },
  { &hf_dsp_aliasDereferenced, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_aliasedRDNs     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_dsp_INTEGER },
  { &hf_dsp_returnCrossRefs , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_referenceType   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_dsp_ReferenceType },
  { &hf_dsp_info            , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_dsp_DomainInfo },
  { &hf_dsp_timeLimit       , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dsp_Time },
  { &hf_dsp_securityParameters, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dsp_entryOnly       , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_uniqueIdentifier, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_x509sat_UniqueIdentifier },
  { &hf_dsp_authenticationLevel, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dsp_AuthenticationLevel },
  { &hf_dsp_exclusions      , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dsp_excludeShadows  , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_nameResolveOnMaster, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_operationIdentifier, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL, dissect_dsp_INTEGER },
  { &hf_dsp_searchRuleId    , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL, dissect_x509if_SearchRuleId },
  { &hf_dsp_chainedRelaxation, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_x509if_MRMapping },
  { &hf_dsp_relatedEntry    , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL, dissect_dsp_INTEGER },
  { &hf_dsp_dspPaging       , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_nonDapPdu       , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_dsp_T_nonDapPdu },
  { &hf_dsp_streamedResults , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_dsp_INTEGER },
  { &hf_dsp_excludeWriteableCopies, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainingArguments(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainingArguments_set, hf_index, ett_dsp_ChainingArguments);

  return offset;
}


static const ber_sequence_t ChainedReadArgumentData_set[] = {
  { &hf_dsp_chainedArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingArguments },
  { &hf_dsp_readArgument    , BER_CLASS_CON, 0, 0, dissect_dap_ReadArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedReadArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedReadArgumentData_set, hf_index, ett_dsp_ChainedReadArgumentData);

  return offset;
}



static int
dissect_dsp_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t T_signedChainedReadArgument_sequence[] = {
  { &hf_dsp_chainedReadArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedReadArgumentData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedReadArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedReadArgument_sequence, hf_index, ett_dsp_T_signedChainedReadArgument);

  return offset;
}


static const ber_choice_t ChainedReadArgument_choice[] = {
  {   0, &hf_dsp_unsignedChainedReadArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedReadArgumentData },
  {   1, &hf_dsp_signedChainedReadArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedReadArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedReadArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedReadArgument_choice, hf_index, ett_dsp_ChainedReadArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ProtocolInformation_set_of[1] = {
  { &hf_dsp_protocolInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_ProtocolInformation },
};

static int
dissect_dsp_SET_OF_ProtocolInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ProtocolInformation_set_of, hf_index, ett_dsp_SET_OF_ProtocolInformation);

  return offset;
}


static const value_string dsp_T_category_vals[] = {
  {   0, "master" },
  {   1, "shadow" },
  { 0, NULL }
};


static int
dissect_dsp_T_category(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string dsp_APCategory_vals[] = {
  {   0, "master" },
  {   1, "shadow" },
  { 0, NULL }
};


static int
dissect_dsp_APCategory(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MasterOrShadowAccessPoint_set[] = {
  { &hf_dsp_ae_title        , BER_CLASS_CON, 0, 0, dissect_x509if_Name },
  { &hf_dsp_address         , BER_CLASS_CON, 1, 0, dissect_x509sat_PresentationAddress },
  { &hf_dsp_protocolInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dsp_SET_OF_ProtocolInformation },
  { &hf_dsp_access_point_category, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dsp_APCategory },
  { &hf_dsp_chainingRequired, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_MasterOrShadowAccessPoint(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MasterOrShadowAccessPoint_set, hf_index, ett_dsp_MasterOrShadowAccessPoint);

  return offset;
}


static const ber_sequence_t MasterAndShadowAccessPoints_set_of[1] = {
  { &hf_dsp_MasterAndShadowAccessPoints_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_MasterOrShadowAccessPoint },
};

int
dissect_dsp_MasterAndShadowAccessPoints(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 MasterAndShadowAccessPoints_set_of, hf_index, ett_dsp_MasterAndShadowAccessPoints);

  return offset;
}


static const ber_sequence_t AccessPointInformation_set[] = {
  { &hf_dsp_ae_title        , BER_CLASS_CON, 0, 0, dissect_x509if_Name },
  { &hf_dsp_address         , BER_CLASS_CON, 1, 0, dissect_x509sat_PresentationAddress },
  { &hf_dsp_protocolInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dsp_SET_OF_ProtocolInformation },
  { &hf_dsp_category        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dsp_T_category },
  { &hf_dsp_chainingRequired, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_additionalPoints, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dsp_MasterAndShadowAccessPoints },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dsp_AccessPointInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AccessPointInformation_set, hf_index, ett_dsp_AccessPointInformation);

  return offset;
}


static const ber_sequence_t CrossReference_set[] = {
  { &hf_dsp_contextPrefix   , BER_CLASS_CON, 0, 0, dissect_x509if_DistinguishedName },
  { &hf_dsp_accessPoint     , BER_CLASS_CON, 1, 0, dissect_dsp_AccessPointInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_CrossReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CrossReference_set, hf_index, ett_dsp_CrossReference);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CrossReference_sequence_of[1] = {
  { &hf_dsp_crossReferences_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_CrossReference },
};

static int
dissect_dsp_SEQUENCE_OF_CrossReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CrossReference_sequence_of, hf_index, ett_dsp_SEQUENCE_OF_CrossReference);

  return offset;
}


static const ber_sequence_t ChainingResults_set[] = {
  { &hf_dsp_info            , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dsp_DomainInfo },
  { &hf_dsp_crossReferences , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dsp_SEQUENCE_OF_CrossReference },
  { &hf_dsp_securityParameters, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dsp_alreadySearched , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainingResults(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainingResults_set, hf_index, ett_dsp_ChainingResults);

  return offset;
}


static const ber_sequence_t ChainedReadResultData_set[] = {
  { &hf_dsp_chainedResults  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingResults },
  { &hf_dsp_readResult      , BER_CLASS_CON, 0, 0, dissect_dap_ReadResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedReadResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedReadResultData_set, hf_index, ett_dsp_ChainedReadResultData);

  return offset;
}


static const ber_sequence_t T_signedChainedReadResult_sequence[] = {
  { &hf_dsp_chainedReadResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedReadResultData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedReadResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedReadResult_sequence, hf_index, ett_dsp_T_signedChainedReadResult);

  return offset;
}


static const ber_choice_t ChainedReadResult_choice[] = {
  {   0, &hf_dsp_unsignedChainedReadResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedReadResultData },
  {   1, &hf_dsp_signedChainedReadResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedReadResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedReadResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedReadResult_choice, hf_index, ett_dsp_ChainedReadResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedCompareArgumentData_set[] = {
  { &hf_dsp_chainedArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingArguments },
  { &hf_dsp_compareArgument , BER_CLASS_CON, 0, 0, dissect_dap_CompareArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedCompareArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedCompareArgumentData_set, hf_index, ett_dsp_ChainedCompareArgumentData);

  return offset;
}


static const ber_sequence_t T_signedChainedCompareArgument_sequence[] = {
  { &hf_dsp_chainedCompareArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedCompareArgumentData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedCompareArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedCompareArgument_sequence, hf_index, ett_dsp_T_signedChainedCompareArgument);

  return offset;
}


static const ber_choice_t ChainedCompareArgument_choice[] = {
  {   0, &hf_dsp_unsignedChainedCompareArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedCompareArgumentData },
  {   1, &hf_dsp_signedChainedCompareArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedCompareArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedCompareArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedCompareArgument_choice, hf_index, ett_dsp_ChainedCompareArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedCompareResultData_set[] = {
  { &hf_dsp_chainedResults  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingResults },
  { &hf_dsp_compareResult   , BER_CLASS_CON, 0, 0, dissect_dap_CompareResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedCompareResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedCompareResultData_set, hf_index, ett_dsp_ChainedCompareResultData);

  return offset;
}


static const ber_sequence_t T_signedChainedCompareResult_sequence[] = {
  { &hf_dsp_chainedCompareResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedCompareResultData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedCompareResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedCompareResult_sequence, hf_index, ett_dsp_T_signedChainedCompareResult);

  return offset;
}


static const ber_choice_t ChainedCompareResult_choice[] = {
  {   0, &hf_dsp_unsignedChainedCompareResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedCompareResultData },
  {   1, &hf_dsp_signedChainedCompareResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedCompareResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedCompareResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedCompareResult_choice, hf_index, ett_dsp_ChainedCompareResult,
                                 NULL);

  return offset;
}



static int
dissect_dsp_ChainedAbandonArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_AbandonArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dsp_ChainedAbandonResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_AbandonResult(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ChainedListArgumentData_set[] = {
  { &hf_dsp_chainedArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingArguments },
  { &hf_dsp_listArgument    , BER_CLASS_CON, 0, 0, dissect_dap_ListArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedListArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedListArgumentData_set, hf_index, ett_dsp_ChainedListArgumentData);

  return offset;
}


static const ber_sequence_t T_signedChainedListArgument_sequence[] = {
  { &hf_dsp_chainedListArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedListArgumentData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedListArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedListArgument_sequence, hf_index, ett_dsp_T_signedChainedListArgument);

  return offset;
}


static const ber_choice_t ChainedListArgument_choice[] = {
  {   0, &hf_dsp_unsignedChainedListArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedListArgumentData },
  {   1, &hf_dsp_signedChainedListArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedListArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedListArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedListArgument_choice, hf_index, ett_dsp_ChainedListArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedListResultData_set[] = {
  { &hf_dsp_chainedResults  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingResults },
  { &hf_dsp_listResult      , BER_CLASS_CON, 0, 0, dissect_dap_ListResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedListResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedListResultData_set, hf_index, ett_dsp_ChainedListResultData);

  return offset;
}


static const ber_sequence_t T_signedChainedListResult_sequence[] = {
  { &hf_dsp_chainedListResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedListResultData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedListResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedListResult_sequence, hf_index, ett_dsp_T_signedChainedListResult);

  return offset;
}


static const ber_choice_t ChainedListResult_choice[] = {
  {   0, &hf_dsp_unsignedChainedListResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedListResultData },
  {   1, &hf_dsp_signedChainedListResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedListResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedListResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedListResult_choice, hf_index, ett_dsp_ChainedListResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedSearchArgumentData_set[] = {
  { &hf_dsp_chainedArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingArguments },
  { &hf_dsp_searchArgument  , BER_CLASS_CON, 0, 0, dissect_dap_SearchArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedSearchArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedSearchArgumentData_set, hf_index, ett_dsp_ChainedSearchArgumentData);

  return offset;
}


static const ber_sequence_t T_signedChainedSearchArgument_sequence[] = {
  { &hf_dsp_chainedSearchArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedSearchArgumentData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedSearchArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedSearchArgument_sequence, hf_index, ett_dsp_T_signedChainedSearchArgument);

  return offset;
}


static const ber_choice_t ChainedSearchArgument_choice[] = {
  {   0, &hf_dsp_unsignedChainedSearchArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedSearchArgumentData },
  {   1, &hf_dsp_signedChainedSearchArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedSearchArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedSearchArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedSearchArgument_choice, hf_index, ett_dsp_ChainedSearchArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedSearchResultData_set[] = {
  { &hf_dsp_chainedResults  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingResults },
  { &hf_dsp_searchResult    , BER_CLASS_CON, 0, 0, dissect_dap_SearchResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedSearchResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedSearchResultData_set, hf_index, ett_dsp_ChainedSearchResultData);

  return offset;
}


static const ber_sequence_t T_signedChainedSearchResult_sequence[] = {
  { &hf_dsp_chainedSearchResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedSearchResultData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedSearchResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedSearchResult_sequence, hf_index, ett_dsp_T_signedChainedSearchResult);

  return offset;
}


static const ber_choice_t ChainedSearchResult_choice[] = {
  {   0, &hf_dsp_unsignedChainedSearchResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedSearchResultData },
  {   1, &hf_dsp_signedChainedSearchResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedSearchResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedSearchResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedSearchResult_choice, hf_index, ett_dsp_ChainedSearchResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedAddEntryArgumentData_set[] = {
  { &hf_dsp_chainedArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingArguments },
  { &hf_dsp_addEntryArgument, BER_CLASS_CON, 0, 0, dissect_dap_AddEntryArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedAddEntryArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedAddEntryArgumentData_set, hf_index, ett_dsp_ChainedAddEntryArgumentData);

  return offset;
}


static const ber_sequence_t T_signedChainedAddEntryArgument_sequence[] = {
  { &hf_dsp_chainedAddEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedAddEntryArgumentData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedAddEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedAddEntryArgument_sequence, hf_index, ett_dsp_T_signedChainedAddEntryArgument);

  return offset;
}


static const ber_choice_t ChainedAddEntryArgument_choice[] = {
  {   0, &hf_dsp_unsignedChainedAddEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedAddEntryArgumentData },
  {   1, &hf_dsp_signedChainedAddEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedAddEntryArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedAddEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedAddEntryArgument_choice, hf_index, ett_dsp_ChainedAddEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedAddEntryResultData_set[] = {
  { &hf_dsp_chainedResults  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingResults },
  { &hf_dsp_addEntryResult  , BER_CLASS_CON, 0, 0, dissect_dap_AddEntryResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedAddEntryResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedAddEntryResultData_set, hf_index, ett_dsp_ChainedAddEntryResultData);

  return offset;
}


static const ber_sequence_t T_signedChainedAddEntryResult_sequence[] = {
  { &hf_dsp_chainedAddEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedAddEntryResultData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedAddEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedAddEntryResult_sequence, hf_index, ett_dsp_T_signedChainedAddEntryResult);

  return offset;
}


static const ber_choice_t ChainedAddEntryResult_choice[] = {
  {   0, &hf_dsp_unsignedChainedAddEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedAddEntryResultData },
  {   1, &hf_dsp_signedChainedAddEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedAddEntryResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedAddEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedAddEntryResult_choice, hf_index, ett_dsp_ChainedAddEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedRemoveEntryArgumentData_set[] = {
  { &hf_dsp_chainedArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingArguments },
  { &hf_dsp_removeEntryArgument, BER_CLASS_CON, 0, 0, dissect_dap_RemoveEntryArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedRemoveEntryArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedRemoveEntryArgumentData_set, hf_index, ett_dsp_ChainedRemoveEntryArgumentData);

  return offset;
}


static const ber_sequence_t T_signedChainedRemoveEntryArgument_sequence[] = {
  { &hf_dsp_chainedRemoveEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedRemoveEntryArgumentData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedRemoveEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedRemoveEntryArgument_sequence, hf_index, ett_dsp_T_signedChainedRemoveEntryArgument);

  return offset;
}


static const ber_choice_t ChainedRemoveEntryArgument_choice[] = {
  {   0, &hf_dsp_unsignedChainedRemoveEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedRemoveEntryArgumentData },
  {   1, &hf_dsp_signedChainedRemoveEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedRemoveEntryArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedRemoveEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedRemoveEntryArgument_choice, hf_index, ett_dsp_ChainedRemoveEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedRemoveEntryResultData_set[] = {
  { &hf_dsp_chainedResults  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingResults },
  { &hf_dsp_removeEntryResult, BER_CLASS_CON, 0, 0, dissect_dap_RemoveEntryResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedRemoveEntryResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedRemoveEntryResultData_set, hf_index, ett_dsp_ChainedRemoveEntryResultData);

  return offset;
}


static const ber_sequence_t T_signedChainedRemoveEntryResult_sequence[] = {
  { &hf_dsp_chainedRemoveEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedRemoveEntryResultData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedRemoveEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedRemoveEntryResult_sequence, hf_index, ett_dsp_T_signedChainedRemoveEntryResult);

  return offset;
}


static const ber_choice_t ChainedRemoveEntryResult_choice[] = {
  {   0, &hf_dsp_unsignedChainedRemoveEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedRemoveEntryResultData },
  {   1, &hf_dsp_signedChainedRemoveEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedRemoveEntryResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedRemoveEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedRemoveEntryResult_choice, hf_index, ett_dsp_ChainedRemoveEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedModifyEntryArgumentData_set[] = {
  { &hf_dsp_chainedArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingArguments },
  { &hf_dsp_modifyEntryArgument, BER_CLASS_CON, 0, 0, dissect_dap_ModifyEntryArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyEntryArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedModifyEntryArgumentData_set, hf_index, ett_dsp_ChainedModifyEntryArgumentData);

  return offset;
}


static const ber_sequence_t T_signedChainedModifyEntryArgument_sequence[] = {
  { &hf_dsp_chainedModifyEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedModifyEntryArgumentData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedModifyEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedModifyEntryArgument_sequence, hf_index, ett_dsp_T_signedChainedModifyEntryArgument);

  return offset;
}


static const ber_choice_t ChainedModifyEntryArgument_choice[] = {
  {   0, &hf_dsp_unsignedChainedModifyEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedModifyEntryArgumentData },
  {   1, &hf_dsp_signedChainedModifyEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedModifyEntryArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedModifyEntryArgument_choice, hf_index, ett_dsp_ChainedModifyEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedModifyEntryResultData_set[] = {
  { &hf_dsp_chainedResults  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingResults },
  { &hf_dsp_modifyEntryResult, BER_CLASS_CON, 0, 0, dissect_dap_ModifyEntryResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyEntryResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedModifyEntryResultData_set, hf_index, ett_dsp_ChainedModifyEntryResultData);

  return offset;
}


static const ber_sequence_t T_signedChainedModifyEntryResult_sequence[] = {
  { &hf_dsp_chainedModifyEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedModifyEntryResultData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedModifyEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedModifyEntryResult_sequence, hf_index, ett_dsp_T_signedChainedModifyEntryResult);

  return offset;
}


static const ber_choice_t ChainedModifyEntryResult_choice[] = {
  {   0, &hf_dsp_unsignedChainedModifyEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedModifyEntryResultData },
  {   1, &hf_dsp_signedChainedModifyEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedModifyEntryResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedModifyEntryResult_choice, hf_index, ett_dsp_ChainedModifyEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedModifyDNArgumentData_set[] = {
  { &hf_dsp_chainedArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingArguments },
  { &hf_dsp_modifyDNArgument, BER_CLASS_CON, 0, 0, dissect_dap_ModifyDNArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyDNArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedModifyDNArgumentData_set, hf_index, ett_dsp_ChainedModifyDNArgumentData);

  return offset;
}


static const ber_sequence_t T_signedChainedModifyDNArgument_sequence[] = {
  { &hf_dsp_chainedModifyDNArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedModifyDNArgumentData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedModifyDNArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedModifyDNArgument_sequence, hf_index, ett_dsp_T_signedChainedModifyDNArgument);

  return offset;
}


static const ber_choice_t ChainedModifyDNArgument_choice[] = {
  {   0, &hf_dsp_unsignedChainedModifyDNArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedModifyDNArgumentData },
  {   1, &hf_dsp_signedChainedModifyDNArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedModifyDNArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyDNArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedModifyDNArgument_choice, hf_index, ett_dsp_ChainedModifyDNArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedModifyDNResultData_set[] = {
  { &hf_dsp_chainedResults  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingResults },
  { &hf_dsp_modifyDNResult  , BER_CLASS_CON, 0, 0, dissect_dap_ModifyDNResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyDNResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedModifyDNResultData_set, hf_index, ett_dsp_ChainedModifyDNResultData);

  return offset;
}


static const ber_sequence_t T_signedChainedModifyDNResult_sequence[] = {
  { &hf_dsp_chainedModifyDNResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedModifyDNResultData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedModifyDNResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedChainedModifyDNResult_sequence, hf_index, ett_dsp_T_signedChainedModifyDNResult);

  return offset;
}


static const ber_choice_t ChainedModifyDNResult_choice[] = {
  {   0, &hf_dsp_unsignedChainedModifyDNResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainedModifyDNResultData },
  {   1, &hf_dsp_signedChainedModifyDNResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedChainedModifyDNResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyDNResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedModifyDNResult_choice, hf_index, ett_dsp_ChainedModifyDNResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_AccessPointInformation_set_of[1] = {
  { &hf_dsp_accessPoints_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_AccessPointInformation },
};

static int
dissect_dsp_SET_OF_AccessPointInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AccessPointInformation_set_of, hf_index, ett_dsp_SET_OF_AccessPointInformation);

  return offset;
}


static const ber_sequence_t ContinuationReference_set[] = {
  { &hf_dsp_targetObject    , BER_CLASS_CON, 0, 0, dissect_x509if_Name },
  { &hf_dsp_aliasedRDNs     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dsp_INTEGER },
  { &hf_dsp_operationProgress, BER_CLASS_CON, 2, 0, dissect_dsp_OperationProgress },
  { &hf_dsp_rdnsResolved    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dsp_INTEGER },
  { &hf_dsp_referenceType   , BER_CLASS_CON, 4, 0, dissect_dsp_ReferenceType },
  { &hf_dsp_accessPoints_01 , BER_CLASS_CON, 5, 0, dissect_dsp_SET_OF_AccessPointInformation },
  { &hf_dsp_entryOnly       , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_exclusions      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dsp_returnToDUA     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_nameResolveOnMaster, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dsp_ContinuationReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ContinuationReference_set, hf_index, ett_dsp_ContinuationReference);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Attribute_sequence_of[1] = {
  { &hf_dsp_notification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dsp_SEQUENCE_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Attribute_sequence_of, hf_index, ett_dsp_SEQUENCE_OF_Attribute);

  return offset;
}


static const ber_sequence_t DSAReferralData_set[] = {
  { &hf_dsp_reference       , BER_CLASS_CON, 0, 0, dissect_dsp_ContinuationReference },
  { &hf_dsp_contextPrefix   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dsp_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dsp_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dsp_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dsp_BOOLEAN },
  { &hf_dsp_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dsp_SEQUENCE_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_DSAReferralData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DSAReferralData_set, hf_index, ett_dsp_DSAReferralData);

  return offset;
}


static const ber_sequence_t T_signedDSAReferral_sequence[] = {
  { &hf_dsp_dsaReferral     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_DSAReferralData },
  { &hf_dsp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dsp_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dsp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedDSAReferral(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedDSAReferral_sequence, hf_index, ett_dsp_T_signedDSAReferral);

  return offset;
}


static const ber_choice_t DSAReferral_choice[] = {
  {   0, &hf_dsp_unsignedDSAReferral, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_DSAReferralData },
  {   1, &hf_dsp_signedDSAReferral, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dsp_T_signedDSAReferral },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_DSAReferral(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DSAReferral_choice, hf_index, ett_dsp_DSAReferral,
                                 NULL);

  return offset;
}



static int
dissect_dsp_LabeledURI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509sat_DirectoryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AccessPoint_set[] = {
  { &hf_dsp_ae_title        , BER_CLASS_CON, 0, 0, dissect_x509if_Name },
  { &hf_dsp_address         , BER_CLASS_CON, 1, 0, dissect_x509sat_PresentationAddress },
  { &hf_dsp_protocolInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dsp_SET_OF_ProtocolInformation },
  { &hf_dsp_labeledURI      , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_dsp_LabeledURI },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dsp_AccessPoint(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AccessPoint_set, hf_index, ett_dsp_AccessPoint);

  return offset;
}


static const ber_sequence_t DitBridgeKnowledge_sequence[] = {
  { &hf_dsp_domainLocalID   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509sat_DirectoryString },
  { &hf_dsp_accessPoints    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_MasterAndShadowAccessPoints },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_DitBridgeKnowledge(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DitBridgeKnowledge_sequence, hf_index, ett_dsp_DitBridgeKnowledge);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AccessPoint_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dsp_AccessPoint(false, tvb, offset, &asn1_ctx, tree, hf_dsp_AccessPoint_PDU);
  return offset;
}
static int dissect_MasterAndShadowAccessPoints_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dsp_MasterAndShadowAccessPoints(false, tvb, offset, &asn1_ctx, tree, hf_dsp_MasterAndShadowAccessPoints_PDU);
  return offset;
}
static int dissect_DitBridgeKnowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dsp_DitBridgeKnowledge(false, tvb, offset, &asn1_ctx, tree, hf_dsp_DitBridgeKnowledge_PDU);
  return offset;
}


static dissector_handle_t dsp_handle;

/*
* Dissect X518 PDUs inside a ROS PDUs
*/
static int
dissect_dsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	int offset = 0;
	int old_offset;
	proto_item *item;
	proto_tree *tree;
	struct SESSION_DATA_STRUCTURE* session;
	int (*dsp_dissector)(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	const char *dsp_op_name;
	asn1_ctx_t asn1_ctx;

	/* do we have operation information from the ROS dissector? */
	if (data == NULL)
		return 0;
	session  = (struct SESSION_DATA_STRUCTURE*)data;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	item = proto_tree_add_item(parent_tree, proto_dsp, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_dsp);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DAP");
  	col_clear(pinfo->cinfo, COL_INFO);

	asn1_ctx.private_data = session;

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  dsp_dissector = dissect_dsp_DSASystemBindArgument;
	  dsp_op_name = "System-Bind-Argument";
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  dsp_dissector = dissect_dsp_DSASystemBindResult;
	  dsp_op_name = "System-Bind-Result";
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  dsp_dissector = dissect_dsp_DSASystemBindError;
	  dsp_op_name = "System-Bind-Error";
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* read */
	    dsp_dissector = dissect_dsp_ChainedReadArgument;
	    dsp_op_name = "Chained-Read-Argument";
	    break;
	  case 2: /* compare */
	    dsp_dissector = dissect_dsp_ChainedCompareArgument;
	    dsp_op_name = "Chained-Compare-Argument";
	    break;
	  case 3: /* abandon */
	    dsp_dissector = dissect_dsp_ChainedAbandonArgument;
	    dsp_op_name = "Chained-Abandon-Argument";
	    break;
	  case 4: /* list */
	    dsp_dissector = dissect_dsp_ChainedListArgument;
	    dsp_op_name = "Chained-List-Argument";
	    break;
	  case 5: /* search */
	    dsp_dissector = dissect_dsp_ChainedSearchArgument;
	    dsp_op_name = "Chained-Search-Argument";
	    break;
	  case 6: /* addEntry */
	    dsp_dissector = dissect_dsp_ChainedAddEntryArgument;
	    dsp_op_name = "Chained-Add-Entry-Argument";
	    break;
	  case 7: /* removeEntry */
	    dsp_dissector = dissect_dsp_ChainedRemoveEntryArgument;
	    dsp_op_name = "Chained-Remove-Entry-Argument";
	    break;
	  case 8: /* modifyEntry */
	    dsp_dissector = dissect_dsp_ChainedModifyEntryArgument;
	    dsp_op_name = "ChainedModify-Entry-Argument";
	    break;
	  case 9: /* modifyDN */
	    dsp_dissector = dissect_dsp_ChainedModifyDNArgument;
	    dsp_op_name = "ChainedModify-DN-Argument";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_dsp_unsupported_opcode, tvb, offset, -1,
	        "Unsupported DSP opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* read */
	    dsp_dissector = dissect_dsp_ChainedReadResult;
	    dsp_op_name = "Chained-Read-Result";
	    break;
	  case 2: /* compare */
	    dsp_dissector = dissect_dsp_ChainedCompareResult;
	    dsp_op_name = "Chained-Compare-Result";
	    break;
	  case 3: /* abandon */
	    dsp_dissector = dissect_dsp_ChainedAbandonResult;
	    dsp_op_name = "Chained-Abandon-Result";
	    break;
	  case 4: /* list */
	    dsp_dissector = dissect_dsp_ChainedListResult;
	    dsp_op_name = "Chained-List-Result";
	    break;
	  case 5: /* search */
	    dsp_dissector = dissect_dsp_ChainedSearchResult;
	    dsp_op_name = "Chained-Search-Result";
	    break;
	  case 6: /* addEntry */
	    dsp_dissector = dissect_dsp_ChainedAddEntryResult;
	    dsp_op_name = "Chained-Add-Entry-Result";
	    break;
	  case 7: /* removeEntry */
	    dsp_dissector = dissect_dsp_ChainedRemoveEntryResult;
	    dsp_op_name = "Chained-Remove-Entry-Result";
	    break;
	  case 8: /* modifyEntry */
	    dsp_dissector = dissect_dsp_ChainedModifyEntryResult;
	    dsp_op_name = "Chained-Modify-Entry-Result";
	    break;
	  case 9: /* modifyDN */
	    dsp_dissector = dissect_dsp_ChainedModifyDNResult;
	    dsp_op_name = "ChainedModify-DN-Result";
	    break;
	  default:
	    proto_tree_add_expert(tree, pinfo, &ei_dsp_unsupported_opcode, tvb, offset, -1);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* attributeError */
	    dsp_dissector = dissect_dap_AttributeError;
	    dsp_op_name = "Attribute-Error";
	    break;
	  case 2: /* nameError */
	    dsp_dissector = dissect_dap_NameError;
	    dsp_op_name = "Name-Error";
	    break;
	  case 3: /* serviceError */
	    dsp_dissector = dissect_dap_ServiceError;
	    dsp_op_name = "Service-Error";
	    break;
	  case 4: /* referral */
	    dsp_dissector = dissect_dap_Referral;
	    dsp_op_name = "Referral";
	    break;
	  case 5: /* abandoned */
	    dsp_dissector = dissect_dap_Abandoned;
	    dsp_op_name = "Abandoned";
	    break;
	  case 6: /* securityError */
	    dsp_dissector = dissect_dap_SecurityError;
	    dsp_op_name = "Security-Error";
	    break;
	  case 7: /* abandonFailed */
	    dsp_dissector = dissect_dap_AbandonFailedError;
	    dsp_op_name = "Abandon-Failed-Error";
	    break;
	  case 8: /* updateError */
	    dsp_dissector = dissect_dap_UpdateError;
	    dsp_op_name = "Update-Error";
	    break;
	  case 9: /* DSAReferral */
	    dsp_dissector = dissect_dsp_DSAReferral;
	    dsp_op_name = "DSA-Referral";
	    break;
	  default:
	    proto_tree_add_expert(tree, pinfo, &ei_dsp_unsupported_errcode, tvb, offset, -1);
	    break;
	  }
	  break;
	default:
	  proto_tree_add_expert(tree, pinfo, &ei_dsp_unsupported_pdu, tvb, offset, -1);
	  return tvb_captured_length(tvb);
	}

	if(dsp_dissector) {
    col_set_str(pinfo->cinfo, COL_INFO, dsp_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dsp_dissector)(false, tvb, offset, &asn1_ctx, tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_expert(tree, pinfo, &ei_dsp_zero_pdu, tvb, offset, -1);
	      break;
	    }
	  }
	}

	return tvb_captured_length(tvb);
}


/*--- proto_register_dsp -------------------------------------------*/
void proto_register_dsp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    { &hf_dsp_AccessPoint_PDU,
      { "AccessPoint", "dsp.AccessPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_MasterAndShadowAccessPoints_PDU,
      { "MasterAndShadowAccessPoints", "dsp.MasterAndShadowAccessPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_DitBridgeKnowledge_PDU,
      { "DitBridgeKnowledge", "dsp.DitBridgeKnowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedArgument,
      { "chainedArgument", "dsp.chainedArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainingArguments", HFILL }},
    { &hf_dsp_readArgument,
      { "readArgument", "dsp.readArgument",
        FT_UINT32, BASE_DEC, VALS(dap_ReadArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedReadArgument,
      { "unsignedChainedReadArgument", "dsp.unsignedChainedReadArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadArgumentData", HFILL }},
    { &hf_dsp_signedChainedReadArgument,
      { "signedChainedReadArgument", "dsp.signedChainedReadArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedReadArgument,
      { "chainedReadArgument", "dsp.chainedReadArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadArgumentData", HFILL }},
    { &hf_dsp_algorithmIdentifier,
      { "algorithmIdentifier", "dsp.algorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_encrypted,
      { "encrypted", "dsp.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_dsp_chainedResults,
      { "chainedResults", "dsp.chainedResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainingResults", HFILL }},
    { &hf_dsp_readResult,
      { "readResult", "dsp.readResult",
        FT_UINT32, BASE_DEC, VALS(dap_ReadResult_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedReadResult,
      { "unsignedChainedReadResult", "dsp.unsignedChainedReadResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadResultData", HFILL }},
    { &hf_dsp_signedChainedReadResult,
      { "signedChainedReadResult", "dsp.signedChainedReadResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedReadResult,
      { "chainedReadResult", "dsp.chainedReadResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadResultData", HFILL }},
    { &hf_dsp_compareArgument,
      { "compareArgument", "dsp.compareArgument",
        FT_UINT32, BASE_DEC, VALS(dap_CompareArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedCompareArgument,
      { "unsignedChainedCompareArgument", "dsp.unsignedChainedCompareArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareArgumentData", HFILL }},
    { &hf_dsp_signedChainedCompareArgument,
      { "signedChainedCompareArgument", "dsp.signedChainedCompareArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedCompareArgument,
      { "chainedCompareArgument", "dsp.chainedCompareArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareArgumentData", HFILL }},
    { &hf_dsp_compareResult,
      { "compareResult", "dsp.compareResult",
        FT_UINT32, BASE_DEC, VALS(dap_CompareResult_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedCompareResult,
      { "unsignedChainedCompareResult", "dsp.unsignedChainedCompareResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareResultData", HFILL }},
    { &hf_dsp_signedChainedCompareResult,
      { "signedChainedCompareResult", "dsp.signedChainedCompareResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedCompareResult,
      { "chainedCompareResult", "dsp.chainedCompareResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareResultData", HFILL }},
    { &hf_dsp_listArgument,
      { "listArgument", "dsp.listArgument",
        FT_UINT32, BASE_DEC, VALS(dap_ListArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedListArgument,
      { "unsignedChainedListArgument", "dsp.unsignedChainedListArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListArgumentData", HFILL }},
    { &hf_dsp_signedChainedListArgument,
      { "signedChainedListArgument", "dsp.signedChainedListArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedListArgument,
      { "chainedListArgument", "dsp.chainedListArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListArgumentData", HFILL }},
    { &hf_dsp_listResult,
      { "listResult", "dsp.listResult",
        FT_UINT32, BASE_DEC, VALS(dap_ListResult_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedListResult,
      { "unsignedChainedListResult", "dsp.unsignedChainedListResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListResultData", HFILL }},
    { &hf_dsp_signedChainedListResult,
      { "signedChainedListResult", "dsp.signedChainedListResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedListResult,
      { "chainedListResult", "dsp.chainedListResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListResultData", HFILL }},
    { &hf_dsp_searchArgument,
      { "searchArgument", "dsp.searchArgument",
        FT_UINT32, BASE_DEC, VALS(dap_SearchArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedSearchArgument,
      { "unsignedChainedSearchArgument", "dsp.unsignedChainedSearchArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchArgumentData", HFILL }},
    { &hf_dsp_signedChainedSearchArgument,
      { "signedChainedSearchArgument", "dsp.signedChainedSearchArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedSearchArgument,
      { "chainedSearchArgument", "dsp.chainedSearchArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchArgumentData", HFILL }},
    { &hf_dsp_searchResult,
      { "searchResult", "dsp.searchResult",
        FT_UINT32, BASE_DEC, VALS(dap_SearchResult_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedSearchResult,
      { "unsignedChainedSearchResult", "dsp.unsignedChainedSearchResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchResultData", HFILL }},
    { &hf_dsp_signedChainedSearchResult,
      { "signedChainedSearchResult", "dsp.signedChainedSearchResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedSearchResult,
      { "chainedSearchResult", "dsp.chainedSearchResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchResultData", HFILL }},
    { &hf_dsp_addEntryArgument,
      { "addEntryArgument", "dsp.addEntryArgument",
        FT_UINT32, BASE_DEC, VALS(dap_AddEntryArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedAddEntryArgument,
      { "unsignedChainedAddEntryArgument", "dsp.unsignedChainedAddEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryArgumentData", HFILL }},
    { &hf_dsp_signedChainedAddEntryArgument,
      { "signedChainedAddEntryArgument", "dsp.signedChainedAddEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedAddEntryArgument,
      { "chainedAddEntryArgument", "dsp.chainedAddEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryArgumentData", HFILL }},
    { &hf_dsp_addEntryResult,
      { "addEntryResult", "dsp.addEntryResult",
        FT_UINT32, BASE_DEC, VALS(dap_AddEntryResult_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedAddEntryResult,
      { "unsignedChainedAddEntryResult", "dsp.unsignedChainedAddEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryResultData", HFILL }},
    { &hf_dsp_signedChainedAddEntryResult,
      { "signedChainedAddEntryResult", "dsp.signedChainedAddEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedAddEntryResult,
      { "chainedAddEntryResult", "dsp.chainedAddEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryResultData", HFILL }},
    { &hf_dsp_removeEntryArgument,
      { "removeEntryArgument", "dsp.removeEntryArgument",
        FT_UINT32, BASE_DEC, VALS(dap_RemoveEntryArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedRemoveEntryArgument,
      { "unsignedChainedRemoveEntryArgument", "dsp.unsignedChainedRemoveEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryArgumentData", HFILL }},
    { &hf_dsp_signedChainedRemoveEntryArgument,
      { "signedChainedRemoveEntryArgument", "dsp.signedChainedRemoveEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedRemoveEntryArgument,
      { "chainedRemoveEntryArgument", "dsp.chainedRemoveEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryArgumentData", HFILL }},
    { &hf_dsp_removeEntryResult,
      { "removeEntryResult", "dsp.removeEntryResult",
        FT_UINT32, BASE_DEC, VALS(dap_RemoveEntryResult_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedRemoveEntryResult,
      { "unsignedChainedRemoveEntryResult", "dsp.unsignedChainedRemoveEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryResultData", HFILL }},
    { &hf_dsp_signedChainedRemoveEntryResult,
      { "signedChainedRemoveEntryResult", "dsp.signedChainedRemoveEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedRemoveEntryResult,
      { "chainedRemoveEntryResult", "dsp.chainedRemoveEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryResultData", HFILL }},
    { &hf_dsp_modifyEntryArgument,
      { "modifyEntryArgument", "dsp.modifyEntryArgument",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyEntryArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedModifyEntryArgument,
      { "unsignedChainedModifyEntryArgument", "dsp.unsignedChainedModifyEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryArgumentData", HFILL }},
    { &hf_dsp_signedChainedModifyEntryArgument,
      { "signedChainedModifyEntryArgument", "dsp.signedChainedModifyEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedModifyEntryArgument,
      { "chainedModifyEntryArgument", "dsp.chainedModifyEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryArgumentData", HFILL }},
    { &hf_dsp_modifyEntryResult,
      { "modifyEntryResult", "dsp.modifyEntryResult",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyEntryResult_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedModifyEntryResult,
      { "unsignedChainedModifyEntryResult", "dsp.unsignedChainedModifyEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryResultData", HFILL }},
    { &hf_dsp_signedChainedModifyEntryResult,
      { "signedChainedModifyEntryResult", "dsp.signedChainedModifyEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedModifyEntryResult,
      { "chainedModifyEntryResult", "dsp.chainedModifyEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryResultData", HFILL }},
    { &hf_dsp_modifyDNArgument,
      { "modifyDNArgument", "dsp.modifyDNArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedModifyDNArgument,
      { "unsignedChainedModifyDNArgument", "dsp.unsignedChainedModifyDNArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNArgumentData", HFILL }},
    { &hf_dsp_signedChainedModifyDNArgument,
      { "signedChainedModifyDNArgument", "dsp.signedChainedModifyDNArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedModifyDNArgument,
      { "chainedModifyDNArgument", "dsp.chainedModifyDNArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNArgumentData", HFILL }},
    { &hf_dsp_modifyDNResult,
      { "modifyDNResult", "dsp.modifyDNResult",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyDNResult_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedChainedModifyDNResult,
      { "unsignedChainedModifyDNResult", "dsp.unsignedChainedModifyDNResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNResultData", HFILL }},
    { &hf_dsp_signedChainedModifyDNResult,
      { "signedChainedModifyDNResult", "dsp.signedChainedModifyDNResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedModifyDNResult,
      { "chainedModifyDNResult", "dsp.chainedModifyDNResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNResultData", HFILL }},
    { &hf_dsp_reference,
      { "reference", "dsp.reference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContinuationReference", HFILL }},
    { &hf_dsp_contextPrefix,
      { "contextPrefix", "dsp.contextPrefix",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dsp_securityParameters,
      { "securityParameters", "dsp.securityParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_performer,
      { "performer", "dsp.performer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dsp_aliasDereferenced,
      { "aliasDereferenced", "dsp.aliasDereferenced",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_notification,
      { "notification", "dsp.notification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Attribute", HFILL }},
    { &hf_dsp_notification_item,
      { "Attribute", "dsp.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_unsignedDSAReferral,
      { "unsignedDSAReferral", "dsp.unsignedDSAReferral_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DSAReferralData", HFILL }},
    { &hf_dsp_signedDSAReferral,
      { "signedDSAReferral", "dsp.signedDSAReferral_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_dsaReferral,
      { "dsaReferral", "dsp.dsaReferral_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DSAReferralData", HFILL }},
    { &hf_dsp_originator,
      { "originator", "dsp.originator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dsp_targetObjectDN,
      { "targetObject", "dsp.targetObject",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dsp_operationProgress,
      { "operationProgress", "dsp.operationProgress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_traceInformation,
      { "traceInformation", "dsp.traceInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_aliasedRDNs,
      { "aliasedRDNs", "dsp.aliasedRDNs",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dsp_returnCrossRefs,
      { "returnCrossRefs", "dsp.returnCrossRefs",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_referenceType,
      { "referenceType", "dsp.referenceType",
        FT_UINT32, BASE_DEC, VALS(dsp_ReferenceType_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_info,
      { "info", "dsp.info",
        FT_OID, BASE_NONE, NULL, 0,
        "DomainInfo", HFILL }},
    { &hf_dsp_timeLimit,
      { "timeLimit", "dsp.timeLimit",
        FT_UINT32, BASE_DEC, VALS(dsp_Time_vals), 0,
        "Time", HFILL }},
    { &hf_dsp_entryOnly,
      { "entryOnly", "dsp.entryOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_uniqueIdentifier,
      { "uniqueIdentifier", "dsp.uniqueIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_authenticationLevel,
      { "authenticationLevel", "dsp.authenticationLevel",
        FT_UINT32, BASE_DEC, VALS(dsp_AuthenticationLevel_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_exclusions,
      { "exclusions", "dsp.exclusions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_excludeShadows,
      { "excludeShadows", "dsp.excludeShadows",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_nameResolveOnMaster,
      { "nameResolveOnMaster", "dsp.nameResolveOnMaster",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_operationIdentifier,
      { "operationIdentifier", "dsp.operationIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dsp_searchRuleId,
      { "searchRuleId", "dsp.searchRuleId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_chainedRelaxation,
      { "chainedRelaxation", "dsp.chainedRelaxation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MRMapping", HFILL }},
    { &hf_dsp_relatedEntry,
      { "relatedEntry", "dsp.relatedEntry",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dsp_dspPaging,
      { "dspPaging", "dsp.dspPaging",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_nonDapPdu,
      { "nonDapPdu", "dsp.nonDapPdu",
        FT_UINT32, BASE_DEC, VALS(dsp_T_nonDapPdu_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_streamedResults,
      { "streamedResults", "dsp.streamedResults",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dsp_excludeWriteableCopies,
      { "excludeWriteableCopies", "dsp.excludeWriteableCopies",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_utcTime,
      { "utcTime", "dsp.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_generalizedTime,
      { "generalizedTime", "dsp.generalizedTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_crossReferences,
      { "crossReferences", "dsp.crossReferences",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CrossReference", HFILL }},
    { &hf_dsp_crossReferences_item,
      { "CrossReference", "dsp.CrossReference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_alreadySearched,
      { "alreadySearched", "dsp.alreadySearched",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Exclusions", HFILL }},
    { &hf_dsp_accessPoint,
      { "accessPoint", "dsp.accessPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessPointInformation", HFILL }},
    { &hf_dsp_nameResolutionPhase,
      { "nameResolutionPhase", "dsp.nameResolutionPhase",
        FT_UINT32, BASE_DEC, VALS(dsp_T_nameResolutionPhase_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_nextRDNToBeResolved,
      { "nextRDNToBeResolved", "dsp.nextRDNToBeResolved",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dsp_TraceInformation_item,
      { "TraceItem", "dsp.TraceItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_dsa,
      { "dsa", "dsp.dsa",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dsp_targetObject,
      { "targetObject", "dsp.targetObject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dsp_ae_title,
      { "ae-title", "dsp.ae_title",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dsp_address,
      { "address", "dsp.address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentationAddress", HFILL }},
    { &hf_dsp_protocolInformation,
      { "protocolInformation", "dsp.protocolInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ProtocolInformation", HFILL }},
    { &hf_dsp_protocolInformation_item,
      { "ProtocolInformation", "dsp.ProtocolInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_labeledURI,
      { "labeledURI", "dsp.labeledURI",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_access_point_category,
      { "category", "dsp.category",
        FT_UINT32, BASE_DEC, VALS(dsp_APCategory_vals), 0,
        "APCategory", HFILL }},
    { &hf_dsp_chainingRequired,
      { "chainingRequired", "dsp.chainingRequired",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_MasterAndShadowAccessPoints_item,
      { "MasterOrShadowAccessPoint", "dsp.MasterOrShadowAccessPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_category,
      { "category", "dsp.category",
        FT_UINT32, BASE_DEC, VALS(dsp_T_category_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_additionalPoints,
      { "additionalPoints", "dsp.additionalPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MasterAndShadowAccessPoints", HFILL }},
    { &hf_dsp_domainLocalID,
      { "domainLocalID", "dsp.domainLocalID",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_dsp_accessPoints,
      { "accessPoints", "dsp.accessPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MasterAndShadowAccessPoints", HFILL }},
    { &hf_dsp_Exclusions_item,
      { "RDNSequence", "dsp.RDNSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_rdnsResolved,
      { "rdnsResolved", "dsp.rdnsResolved",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dsp_accessPoints_01,
      { "accessPoints", "dsp.accessPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AccessPointInformation", HFILL }},
    { &hf_dsp_accessPoints_item,
      { "AccessPointInformation", "dsp.AccessPointInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_returnToDUA,
      { "returnToDUA", "dsp.returnToDUA",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_basicLevels,
      { "basicLevels", "dsp.basicLevels_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dsp_level,
      { "level", "dsp.level",
        FT_UINT32, BASE_DEC, VALS(dsp_T_level_vals), 0,
        NULL, HFILL }},
    { &hf_dsp_localQualifier,
      { "localQualifier", "dsp.localQualifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dsp_signed,
      { "signed", "dsp.signed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dsp_other,
      { "other", "dsp.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_dsp,
    &ett_dsp_ChainedReadArgumentData,
    &ett_dsp_ChainedReadArgument,
    &ett_dsp_T_signedChainedReadArgument,
    &ett_dsp_ChainedReadResultData,
    &ett_dsp_ChainedReadResult,
    &ett_dsp_T_signedChainedReadResult,
    &ett_dsp_ChainedCompareArgumentData,
    &ett_dsp_ChainedCompareArgument,
    &ett_dsp_T_signedChainedCompareArgument,
    &ett_dsp_ChainedCompareResultData,
    &ett_dsp_ChainedCompareResult,
    &ett_dsp_T_signedChainedCompareResult,
    &ett_dsp_ChainedListArgumentData,
    &ett_dsp_ChainedListArgument,
    &ett_dsp_T_signedChainedListArgument,
    &ett_dsp_ChainedListResultData,
    &ett_dsp_ChainedListResult,
    &ett_dsp_T_signedChainedListResult,
    &ett_dsp_ChainedSearchArgumentData,
    &ett_dsp_ChainedSearchArgument,
    &ett_dsp_T_signedChainedSearchArgument,
    &ett_dsp_ChainedSearchResultData,
    &ett_dsp_ChainedSearchResult,
    &ett_dsp_T_signedChainedSearchResult,
    &ett_dsp_ChainedAddEntryArgumentData,
    &ett_dsp_ChainedAddEntryArgument,
    &ett_dsp_T_signedChainedAddEntryArgument,
    &ett_dsp_ChainedAddEntryResultData,
    &ett_dsp_ChainedAddEntryResult,
    &ett_dsp_T_signedChainedAddEntryResult,
    &ett_dsp_ChainedRemoveEntryArgumentData,
    &ett_dsp_ChainedRemoveEntryArgument,
    &ett_dsp_T_signedChainedRemoveEntryArgument,
    &ett_dsp_ChainedRemoveEntryResultData,
    &ett_dsp_ChainedRemoveEntryResult,
    &ett_dsp_T_signedChainedRemoveEntryResult,
    &ett_dsp_ChainedModifyEntryArgumentData,
    &ett_dsp_ChainedModifyEntryArgument,
    &ett_dsp_T_signedChainedModifyEntryArgument,
    &ett_dsp_ChainedModifyEntryResultData,
    &ett_dsp_ChainedModifyEntryResult,
    &ett_dsp_T_signedChainedModifyEntryResult,
    &ett_dsp_ChainedModifyDNArgumentData,
    &ett_dsp_ChainedModifyDNArgument,
    &ett_dsp_T_signedChainedModifyDNArgument,
    &ett_dsp_ChainedModifyDNResultData,
    &ett_dsp_ChainedModifyDNResult,
    &ett_dsp_T_signedChainedModifyDNResult,
    &ett_dsp_DSAReferralData,
    &ett_dsp_SEQUENCE_OF_Attribute,
    &ett_dsp_DSAReferral,
    &ett_dsp_T_signedDSAReferral,
    &ett_dsp_ChainingArguments,
    &ett_dsp_Time,
    &ett_dsp_ChainingResults,
    &ett_dsp_SEQUENCE_OF_CrossReference,
    &ett_dsp_CrossReference,
    &ett_dsp_OperationProgress,
    &ett_dsp_TraceInformation,
    &ett_dsp_TraceItem,
    &ett_dsp_AccessPoint,
    &ett_dsp_SET_OF_ProtocolInformation,
    &ett_dsp_MasterOrShadowAccessPoint,
    &ett_dsp_MasterAndShadowAccessPoints,
    &ett_dsp_AccessPointInformation,
    &ett_dsp_DitBridgeKnowledge,
    &ett_dsp_Exclusions,
    &ett_dsp_ContinuationReference,
    &ett_dsp_SET_OF_AccessPointInformation,
    &ett_dsp_AuthenticationLevel,
    &ett_dsp_T_basicLevels,
  };
  static ei_register_info ei[] = {
    { &ei_dsp_unsupported_opcode, { "dsp.unsupported_opcode", PI_UNDECODED, PI_WARN, "Unsupported DSP opcode", EXPFILL }},
    { &ei_dsp_unsupported_errcode, { "dsp.unsupported_errcode", PI_UNDECODED, PI_WARN, "Unsupported DSP errcode", EXPFILL }},
    { &ei_dsp_unsupported_pdu, { "dsp.unsupported_pdu", PI_UNDECODED, PI_WARN, "Unsupported DSP PDU", EXPFILL }},
    { &ei_dsp_zero_pdu, { "dsp.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte DSP PDU", EXPFILL }},
  };

  module_t *dsp_module;
  expert_module_t* expert_dsp;

  /* Register protocol */
  proto_dsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  dsp_handle = register_dissector("dsp", dissect_dsp, proto_dsp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dsp = expert_register_protocol(proto_dsp);
  expert_register_field_array(expert_dsp, ei, array_length(ei));

  /* Register our configuration options for DSP, particularly our port */

  dsp_module = prefs_register_protocol_subtree("OSI/X.500", proto_dsp, NULL);

  prefs_register_obsolete_preference(dsp_module, "tcp.port");

  prefs_register_static_text_preference(dsp_module, "tcp_port_info",
            "The TCP ports used by the DSP protocol should be added to the TPKT preference \"TPKT TCP ports\", or by selecting \"TPKT\" as the \"Transport\" protocol in the \"Decode As\" dialog.",
            "DSP TCP Port preference moved information");

}


/*--- proto_reg_handoff_dsp --- */
void proto_reg_handoff_dsp(void) {
  register_ber_oid_dissector("2.5.12.1", dissect_AccessPoint_PDU, proto_dsp, "id-doa-myAccessPoint");
  register_ber_oid_dissector("2.5.12.2", dissect_AccessPoint_PDU, proto_dsp, "id-doa-superiorKnowledge");
  register_ber_oid_dissector("2.5.12.3", dissect_MasterAndShadowAccessPoints_PDU, proto_dsp, "id-doa-specificKnowledge");
  register_ber_oid_dissector("2.5.12.4", dissect_MasterAndShadowAccessPoints_PDU, proto_dsp, "id-doa-nonSpecificKnowledge");
  register_ber_oid_dissector("2.5.12.8", dissect_DitBridgeKnowledge_PDU, proto_dsp, "id-doa-ditBridgeKnowledge");


  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-directory-system","2.5.3.2");

  /* ABSTRACT SYNTAXES */

  /* Register DSP with ROS (with no use of RTSE) */
  register_ros_oid_dissector_handle("2.5.9.2", dsp_handle, 0, "id-as-directory-system", false);

}
