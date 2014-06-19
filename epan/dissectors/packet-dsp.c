/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-dsp.c                                                               */
/* ../../tools/asn2wrs.py -b -p dsp -c ./dsp.cnf -s ./packet-dsp-template -D . -O ../../epan/dissectors dsp.asn */

/* Input file: packet-dsp-template.c */

#line 1 "../../asn1/dsp/packet-dsp-template.c"
/* packet-dsp.c
 * Routines for X.518 (X.500 Distributed Operations)  packet dissection
 * Graeme Lunt 2005
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
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

static guint global_dsp_tcp_port = 102;
static dissector_handle_t tpkt_handle;
static void prefs_register_dsp(void); /* forward declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
static int proto_dsp = -1;


/*--- Included file: packet-dsp-hf.c ---*/
#line 1 "../../asn1/dsp/packet-dsp-hf.c"
static int hf_dsp_AccessPoint_PDU = -1;           /* AccessPoint */
static int hf_dsp_MasterAndShadowAccessPoints_PDU = -1;  /* MasterAndShadowAccessPoints */
static int hf_dsp_DitBridgeKnowledge_PDU = -1;    /* DitBridgeKnowledge */
static int hf_dsp_chainedArgument = -1;           /* ChainingArguments */
static int hf_dsp_readArgument = -1;              /* ReadArgument */
static int hf_dsp_unsignedChainedReadArgument = -1;  /* ChainedReadArgumentData */
static int hf_dsp_signedChainedReadArgument = -1;  /* T_signedChainedReadArgument */
static int hf_dsp_chainedReadArgument = -1;       /* ChainedReadArgumentData */
static int hf_dsp_algorithmIdentifier = -1;       /* AlgorithmIdentifier */
static int hf_dsp_encrypted = -1;                 /* BIT_STRING */
static int hf_dsp_chainedResults = -1;            /* ChainingResults */
static int hf_dsp_readResult = -1;                /* ReadResult */
static int hf_dsp_unsignedChainedReadResult = -1;  /* ChainedReadResultData */
static int hf_dsp_signedChainedReadResult = -1;   /* T_signedChainedReadResult */
static int hf_dsp_chainedReadResult = -1;         /* ChainedReadResultData */
static int hf_dsp_compareArgument = -1;           /* CompareArgument */
static int hf_dsp_unsignedChainedCompareArgument = -1;  /* ChainedCompareArgumentData */
static int hf_dsp_signedChainedCompareArgument = -1;  /* T_signedChainedCompareArgument */
static int hf_dsp_chainedCompareArgument = -1;    /* ChainedCompareArgumentData */
static int hf_dsp_compareResult = -1;             /* CompareResult */
static int hf_dsp_unsignedChainedCompareResult = -1;  /* ChainedCompareResultData */
static int hf_dsp_signedChainedCompareResult = -1;  /* T_signedChainedCompareResult */
static int hf_dsp_chainedCompareResult = -1;      /* ChainedCompareResultData */
static int hf_dsp_listArgument = -1;              /* ListArgument */
static int hf_dsp_unsignedChainedListArgument = -1;  /* ChainedListArgumentData */
static int hf_dsp_signedChainedListArgument = -1;  /* T_signedChainedListArgument */
static int hf_dsp_chainedListArgument = -1;       /* ChainedListArgumentData */
static int hf_dsp_listResult = -1;                /* ListResult */
static int hf_dsp_unsignedChainedListResult = -1;  /* ChainedListResultData */
static int hf_dsp_signedChainedListResult = -1;   /* T_signedChainedListResult */
static int hf_dsp_chainedListResult = -1;         /* ChainedListResultData */
static int hf_dsp_searchArgument = -1;            /* SearchArgument */
static int hf_dsp_unsignedChainedSearchArgument = -1;  /* ChainedSearchArgumentData */
static int hf_dsp_signedChainedSearchArgument = -1;  /* T_signedChainedSearchArgument */
static int hf_dsp_chainedSearchArgument = -1;     /* ChainedSearchArgumentData */
static int hf_dsp_searchResult = -1;              /* SearchResult */
static int hf_dsp_unsignedChainedSearchResult = -1;  /* ChainedSearchResultData */
static int hf_dsp_signedChainedSearchResult = -1;  /* T_signedChainedSearchResult */
static int hf_dsp_chainedSearchResult = -1;       /* ChainedSearchResultData */
static int hf_dsp_addEntryArgument = -1;          /* AddEntryArgument */
static int hf_dsp_unsignedChainedAddEntryArgument = -1;  /* ChainedAddEntryArgumentData */
static int hf_dsp_signedChainedAddEntryArgument = -1;  /* T_signedChainedAddEntryArgument */
static int hf_dsp_chainedAddEntryArgument = -1;   /* ChainedAddEntryArgumentData */
static int hf_dsp_addEntryResult = -1;            /* AddEntryResult */
static int hf_dsp_unsignedChainedAddEntryResult = -1;  /* ChainedAddEntryResultData */
static int hf_dsp_signedChainedAddEntryResult = -1;  /* T_signedChainedAddEntryResult */
static int hf_dsp_chainedAddEntryResult = -1;     /* ChainedAddEntryResultData */
static int hf_dsp_removeEntryArgument = -1;       /* RemoveEntryArgument */
static int hf_dsp_unsignedChainedRemoveEntryArgument = -1;  /* ChainedRemoveEntryArgumentData */
static int hf_dsp_signedChainedRemoveEntryArgument = -1;  /* T_signedChainedRemoveEntryArgument */
static int hf_dsp_chainedRemoveEntryArgument = -1;  /* ChainedRemoveEntryArgumentData */
static int hf_dsp_removeEntryResult = -1;         /* RemoveEntryResult */
static int hf_dsp_unsignedChainedRemoveEntryResult = -1;  /* ChainedRemoveEntryResultData */
static int hf_dsp_signedChainedRemoveEntryResult = -1;  /* T_signedChainedRemoveEntryResult */
static int hf_dsp_chainedRemoveEntryResult = -1;  /* ChainedRemoveEntryResultData */
static int hf_dsp_modifyEntryArgument = -1;       /* ModifyEntryArgument */
static int hf_dsp_unsignedChainedModifyEntryArgument = -1;  /* ChainedModifyEntryArgumentData */
static int hf_dsp_signedChainedModifyEntryArgument = -1;  /* T_signedChainedModifyEntryArgument */
static int hf_dsp_chainedModifyEntryArgument = -1;  /* ChainedModifyEntryArgumentData */
static int hf_dsp_modifyEntryResult = -1;         /* ModifyEntryResult */
static int hf_dsp_unsignedChainedModifyEntryResult = -1;  /* ChainedModifyEntryResultData */
static int hf_dsp_signedChainedModifyEntryResult = -1;  /* T_signedChainedModifyEntryResult */
static int hf_dsp_chainedModifyEntryResult = -1;  /* ChainedModifyEntryResultData */
static int hf_dsp_modifyDNArgument = -1;          /* ModifyDNArgument */
static int hf_dsp_unsignedChainedModifyDNArgument = -1;  /* ChainedModifyDNArgumentData */
static int hf_dsp_signedChainedModifyDNArgument = -1;  /* T_signedChainedModifyDNArgument */
static int hf_dsp_chainedModifyDNArgument = -1;   /* ChainedModifyDNArgumentData */
static int hf_dsp_modifyDNResult = -1;            /* ModifyDNResult */
static int hf_dsp_unsignedChainedModifyDNResult = -1;  /* ChainedModifyDNResultData */
static int hf_dsp_signedChainedModifyDNResult = -1;  /* T_signedChainedModifyDNResult */
static int hf_dsp_chainedModifyDNResult = -1;     /* ChainedModifyDNResultData */
static int hf_dsp_reference = -1;                 /* ContinuationReference */
static int hf_dsp_contextPrefix = -1;             /* DistinguishedName */
static int hf_dsp_securityParameters = -1;        /* SecurityParameters */
static int hf_dsp_performer = -1;                 /* DistinguishedName */
static int hf_dsp_aliasDereferenced = -1;         /* BOOLEAN */
static int hf_dsp_notification = -1;              /* SEQUENCE_OF_Attribute */
static int hf_dsp_notification_item = -1;         /* Attribute */
static int hf_dsp_unsignedDSAReferral = -1;       /* DSAReferralData */
static int hf_dsp_signedDSAReferral = -1;         /* T_signedDSAReferral */
static int hf_dsp_dsaReferral = -1;               /* DSAReferralData */
static int hf_dsp_originator = -1;                /* DistinguishedName */
static int hf_dsp_targetObjectDN = -1;            /* DistinguishedName */
static int hf_dsp_operationProgress = -1;         /* OperationProgress */
static int hf_dsp_traceInformation = -1;          /* TraceInformation */
static int hf_dsp_aliasedRDNs = -1;               /* INTEGER */
static int hf_dsp_returnCrossRefs = -1;           /* BOOLEAN */
static int hf_dsp_referenceType = -1;             /* ReferenceType */
static int hf_dsp_info = -1;                      /* DomainInfo */
static int hf_dsp_timeLimit = -1;                 /* Time */
static int hf_dsp_entryOnly = -1;                 /* BOOLEAN */
static int hf_dsp_uniqueIdentifier = -1;          /* UniqueIdentifier */
static int hf_dsp_authenticationLevel = -1;       /* AuthenticationLevel */
static int hf_dsp_exclusions = -1;                /* Exclusions */
static int hf_dsp_excludeShadows = -1;            /* BOOLEAN */
static int hf_dsp_nameResolveOnMaster = -1;       /* BOOLEAN */
static int hf_dsp_operationIdentifier = -1;       /* INTEGER */
static int hf_dsp_searchRuleId = -1;              /* SearchRuleId */
static int hf_dsp_chainedRelaxation = -1;         /* MRMapping */
static int hf_dsp_relatedEntry = -1;              /* INTEGER */
static int hf_dsp_dspPaging = -1;                 /* BOOLEAN */
static int hf_dsp_nonDapPdu = -1;                 /* T_nonDapPdu */
static int hf_dsp_streamedResults = -1;           /* INTEGER */
static int hf_dsp_excludeWriteableCopies = -1;    /* BOOLEAN */
static int hf_dsp_utcTime = -1;                   /* UTCTime */
static int hf_dsp_generalizedTime = -1;           /* GeneralizedTime */
static int hf_dsp_crossReferences = -1;           /* SEQUENCE_OF_CrossReference */
static int hf_dsp_crossReferences_item = -1;      /* CrossReference */
static int hf_dsp_alreadySearched = -1;           /* Exclusions */
static int hf_dsp_accessPoint = -1;               /* AccessPointInformation */
static int hf_dsp_nameResolutionPhase = -1;       /* T_nameResolutionPhase */
static int hf_dsp_nextRDNToBeResolved = -1;       /* INTEGER */
static int hf_dsp_TraceInformation_item = -1;     /* TraceItem */
static int hf_dsp_dsa = -1;                       /* Name */
static int hf_dsp_targetObject = -1;              /* Name */
static int hf_dsp_ae_title = -1;                  /* Name */
static int hf_dsp_address = -1;                   /* PresentationAddress */
static int hf_dsp_protocolInformation = -1;       /* SET_OF_ProtocolInformation */
static int hf_dsp_protocolInformation_item = -1;  /* ProtocolInformation */
static int hf_dsp_labeledURI = -1;                /* LabeledURI */
static int hf_dsp_access_point_category = -1;     /* APCategory */
static int hf_dsp_chainingRequired = -1;          /* BOOLEAN */
static int hf_dsp_MasterAndShadowAccessPoints_item = -1;  /* MasterOrShadowAccessPoint */
static int hf_dsp_category = -1;                  /* T_category */
static int hf_dsp_additionalPoints = -1;          /* MasterAndShadowAccessPoints */
static int hf_dsp_domainLocalID = -1;             /* DirectoryString */
static int hf_dsp_accessPoints = -1;              /* MasterAndShadowAccessPoints */
static int hf_dsp_Exclusions_item = -1;           /* RDNSequence */
static int hf_dsp_rdnsResolved = -1;              /* INTEGER */
static int hf_dsp_accessPoints_01 = -1;           /* SET_OF_AccessPointInformation */
static int hf_dsp_accessPoints_item = -1;         /* AccessPointInformation */
static int hf_dsp_returnToDUA = -1;               /* BOOLEAN */
static int hf_dsp_basicLevels = -1;               /* T_basicLevels */
static int hf_dsp_level = -1;                     /* T_level */
static int hf_dsp_localQualifier = -1;            /* INTEGER */
static int hf_dsp_signed = -1;                    /* BOOLEAN */
static int hf_dsp_other = -1;                     /* EXTERNAL */

/*--- End of included file: packet-dsp-hf.c ---*/
#line 60 "../../asn1/dsp/packet-dsp-template.c"

/* Initialize the subtree pointers */
static gint ett_dsp = -1;

/*--- Included file: packet-dsp-ett.c ---*/
#line 1 "../../asn1/dsp/packet-dsp-ett.c"
static gint ett_dsp_ChainedReadArgumentData = -1;
static gint ett_dsp_ChainedReadArgument = -1;
static gint ett_dsp_T_signedChainedReadArgument = -1;
static gint ett_dsp_ChainedReadResultData = -1;
static gint ett_dsp_ChainedReadResult = -1;
static gint ett_dsp_T_signedChainedReadResult = -1;
static gint ett_dsp_ChainedCompareArgumentData = -1;
static gint ett_dsp_ChainedCompareArgument = -1;
static gint ett_dsp_T_signedChainedCompareArgument = -1;
static gint ett_dsp_ChainedCompareResultData = -1;
static gint ett_dsp_ChainedCompareResult = -1;
static gint ett_dsp_T_signedChainedCompareResult = -1;
static gint ett_dsp_ChainedListArgumentData = -1;
static gint ett_dsp_ChainedListArgument = -1;
static gint ett_dsp_T_signedChainedListArgument = -1;
static gint ett_dsp_ChainedListResultData = -1;
static gint ett_dsp_ChainedListResult = -1;
static gint ett_dsp_T_signedChainedListResult = -1;
static gint ett_dsp_ChainedSearchArgumentData = -1;
static gint ett_dsp_ChainedSearchArgument = -1;
static gint ett_dsp_T_signedChainedSearchArgument = -1;
static gint ett_dsp_ChainedSearchResultData = -1;
static gint ett_dsp_ChainedSearchResult = -1;
static gint ett_dsp_T_signedChainedSearchResult = -1;
static gint ett_dsp_ChainedAddEntryArgumentData = -1;
static gint ett_dsp_ChainedAddEntryArgument = -1;
static gint ett_dsp_T_signedChainedAddEntryArgument = -1;
static gint ett_dsp_ChainedAddEntryResultData = -1;
static gint ett_dsp_ChainedAddEntryResult = -1;
static gint ett_dsp_T_signedChainedAddEntryResult = -1;
static gint ett_dsp_ChainedRemoveEntryArgumentData = -1;
static gint ett_dsp_ChainedRemoveEntryArgument = -1;
static gint ett_dsp_T_signedChainedRemoveEntryArgument = -1;
static gint ett_dsp_ChainedRemoveEntryResultData = -1;
static gint ett_dsp_ChainedRemoveEntryResult = -1;
static gint ett_dsp_T_signedChainedRemoveEntryResult = -1;
static gint ett_dsp_ChainedModifyEntryArgumentData = -1;
static gint ett_dsp_ChainedModifyEntryArgument = -1;
static gint ett_dsp_T_signedChainedModifyEntryArgument = -1;
static gint ett_dsp_ChainedModifyEntryResultData = -1;
static gint ett_dsp_ChainedModifyEntryResult = -1;
static gint ett_dsp_T_signedChainedModifyEntryResult = -1;
static gint ett_dsp_ChainedModifyDNArgumentData = -1;
static gint ett_dsp_ChainedModifyDNArgument = -1;
static gint ett_dsp_T_signedChainedModifyDNArgument = -1;
static gint ett_dsp_ChainedModifyDNResultData = -1;
static gint ett_dsp_ChainedModifyDNResult = -1;
static gint ett_dsp_T_signedChainedModifyDNResult = -1;
static gint ett_dsp_DSAReferralData = -1;
static gint ett_dsp_SEQUENCE_OF_Attribute = -1;
static gint ett_dsp_DSAReferral = -1;
static gint ett_dsp_T_signedDSAReferral = -1;
static gint ett_dsp_ChainingArguments = -1;
static gint ett_dsp_Time = -1;
static gint ett_dsp_ChainingResults = -1;
static gint ett_dsp_SEQUENCE_OF_CrossReference = -1;
static gint ett_dsp_CrossReference = -1;
static gint ett_dsp_OperationProgress = -1;
static gint ett_dsp_TraceInformation = -1;
static gint ett_dsp_TraceItem = -1;
static gint ett_dsp_AccessPoint = -1;
static gint ett_dsp_SET_OF_ProtocolInformation = -1;
static gint ett_dsp_MasterOrShadowAccessPoint = -1;
static gint ett_dsp_MasterAndShadowAccessPoints = -1;
static gint ett_dsp_AccessPointInformation = -1;
static gint ett_dsp_DitBridgeKnowledge = -1;
static gint ett_dsp_Exclusions = -1;
static gint ett_dsp_ContinuationReference = -1;
static gint ett_dsp_SET_OF_AccessPointInformation = -1;
static gint ett_dsp_AuthenticationLevel = -1;
static gint ett_dsp_T_basicLevels = -1;

/*--- End of included file: packet-dsp-ett.c ---*/
#line 64 "../../asn1/dsp/packet-dsp-template.c"


/*--- Included file: packet-dsp-fn.c ---*/
#line 1 "../../asn1/dsp/packet-dsp-fn.c"


static int
dissect_dsp_DSASystemBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dsp_DSASystemBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dsp_DSASystemBindError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_nameResolutionPhase(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dsp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_OperationProgress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_TraceItem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              TraceItem_set, hf_index, ett_dsp_TraceItem);

  return offset;
}


static const ber_sequence_t TraceInformation_sequence_of[1] = {
  { &hf_dsp_TraceInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_TraceItem },
};

static int
dissect_dsp_TraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TraceInformation_sequence_of, hf_index, ett_dsp_TraceInformation);

  return offset;
}



static int
dissect_dsp_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ReferenceType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dsp_DomainInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_dsp_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_dsp_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_Time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_level(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_basicLevels(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_basicLevels_sequence, hf_index, ett_dsp_T_basicLevels);

  return offset;
}



static int
dissect_dsp_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_AuthenticationLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticationLevel_choice, hf_index, ett_dsp_AuthenticationLevel,
                                 NULL);

  return offset;
}


static const ber_sequence_t Exclusions_set_of[1] = {
  { &hf_dsp_Exclusions_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RDNSequence },
};

int
dissect_dsp_Exclusions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Exclusions_set_of, hf_index, ett_dsp_Exclusions);

  return offset;
}


static const value_string dsp_T_nonDapPdu_vals[] = {
  {   0, "ldap" },
  { 0, NULL }
};


static int
dissect_dsp_T_nonDapPdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainingArguments(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedReadArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ChainedReadArgumentData_set, hf_index, ett_dsp_ChainedReadArgumentData);

  return offset;
}



static int
dissect_dsp_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
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
dissect_dsp_T_signedChainedReadArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedReadArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedReadArgument_choice, hf_index, ett_dsp_ChainedReadArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ProtocolInformation_set_of[1] = {
  { &hf_dsp_protocolInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_ProtocolInformation },
};

static int
dissect_dsp_SET_OF_ProtocolInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_category(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_APCategory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_MasterOrShadowAccessPoint(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MasterOrShadowAccessPoint_set, hf_index, ett_dsp_MasterOrShadowAccessPoint);

  return offset;
}


static const ber_sequence_t MasterAndShadowAccessPoints_set_of[1] = {
  { &hf_dsp_MasterAndShadowAccessPoints_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_MasterOrShadowAccessPoint },
};

int
dissect_dsp_MasterAndShadowAccessPoints(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_AccessPointInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_CrossReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CrossReference_set, hf_index, ett_dsp_CrossReference);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CrossReference_sequence_of[1] = {
  { &hf_dsp_crossReferences_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_CrossReference },
};

static int
dissect_dsp_SEQUENCE_OF_CrossReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainingResults(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedReadResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedReadResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedReadResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedCompareArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedCompareArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedCompareArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedCompareResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedCompareResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedCompareResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedCompareResult_choice, hf_index, ett_dsp_ChainedCompareResult,
                                 NULL);

  return offset;
}



static int
dissect_dsp_ChainedAbandonArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_AbandonArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dsp_ChainedAbandonResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_AbandonResult(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ChainedListArgumentData_set[] = {
  { &hf_dsp_chainedArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ChainingArguments },
  { &hf_dsp_listArgument    , BER_CLASS_CON, 0, 0, dissect_dap_ListArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedListArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedListArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedListArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedListResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedListResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedListResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedSearchArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedSearchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedSearchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedSearchResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedSearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedSearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedAddEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedAddEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedAddEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedAddEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedAddEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedAddEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedRemoveEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedRemoveEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedRemoveEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedRemoveEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedRemoveEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedRemoveEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedModifyEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedModifyEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedModifyEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedModifyEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedModifyEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedModifyEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedModifyDNArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedModifyDNArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedModifyDNArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedModifyDNResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedChainedModifyDNResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ChainedModifyDNResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChainedModifyDNResult_choice, hf_index, ett_dsp_ChainedModifyDNResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_AccessPointInformation_set_of[1] = {
  { &hf_dsp_accessPoints_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_AccessPointInformation },
};

static int
dissect_dsp_SET_OF_AccessPointInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_ContinuationReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ContinuationReference_set, hf_index, ett_dsp_ContinuationReference);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Attribute_sequence_of[1] = {
  { &hf_dsp_notification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dsp_SEQUENCE_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_DSAReferralData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_T_signedDSAReferral(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_DSAReferral(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DSAReferral_choice, hf_index, ett_dsp_DSAReferral,
                                 NULL);

  return offset;
}



static int
dissect_dsp_LabeledURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_AccessPoint(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dsp_DitBridgeKnowledge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DitBridgeKnowledge_sequence, hf_index, ett_dsp_DitBridgeKnowledge);

  return offset;
}

/*--- PDUs ---*/

static void dissect_AccessPoint_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dsp_AccessPoint(FALSE, tvb, 0, &asn1_ctx, tree, hf_dsp_AccessPoint_PDU);
}
static void dissect_MasterAndShadowAccessPoints_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dsp_MasterAndShadowAccessPoints(FALSE, tvb, 0, &asn1_ctx, tree, hf_dsp_MasterAndShadowAccessPoints_PDU);
}
static void dissect_DitBridgeKnowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dsp_DitBridgeKnowledge(FALSE, tvb, 0, &asn1_ctx, tree, hf_dsp_DitBridgeKnowledge_PDU);
}


/*--- End of included file: packet-dsp-fn.c ---*/
#line 66 "../../asn1/dsp/packet-dsp-template.c"

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
	int (*dsp_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	const char *dsp_op_name;
	asn1_ctx_t asn1_ctx;

	/* do we have operation information from the ROS dissector? */
	if (data == NULL)
		return 0;
	session  = (struct SESSION_DATA_STRUCTURE*)data;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DSP opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
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
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DSP opcode");
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
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DSP errcode");
	    break;
	  }
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DSP PDU");
	  return tvb_captured_length(tvb);
	}

	if(dsp_dissector) {
    col_set_str(pinfo->cinfo, COL_INFO, dsp_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dsp_dissector)(FALSE, tvb, offset, &asn1_ctx, tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DSP PDU");
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

/*--- Included file: packet-dsp-hfarr.c ---*/
#line 1 "../../asn1/dsp/packet-dsp-hfarr.c"
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
        FT_STRING, BASE_NONE, NULL, 0,
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

/*--- End of included file: packet-dsp-hfarr.c ---*/
#line 269 "../../asn1/dsp/packet-dsp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_dsp,

/*--- Included file: packet-dsp-ettarr.c ---*/
#line 1 "../../asn1/dsp/packet-dsp-ettarr.c"
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

/*--- End of included file: packet-dsp-ettarr.c ---*/
#line 275 "../../asn1/dsp/packet-dsp-template.c"
  };
  module_t *dsp_module;

  /* Register protocol */
  proto_dsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  new_register_dissector("dsp", dissect_dsp, proto_dsp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DSP, particularly our port */

  dsp_module = prefs_register_protocol_subtree("OSI/X.500", proto_dsp, prefs_register_dsp);

  prefs_register_uint_preference(dsp_module, "tcp.port", "DSP TCP Port",
				 "Set the port for DSP operations (if other"
				 " than the default of 102)",
				 10, &global_dsp_tcp_port);


}


/*--- proto_reg_handoff_dsp --- */
void proto_reg_handoff_dsp(void) {
  dissector_handle_t dsp_handle;


/*--- Included file: packet-dsp-dis-tab.c ---*/
#line 1 "../../asn1/dsp/packet-dsp-dis-tab.c"
  register_ber_oid_dissector("2.5.12.1", dissect_AccessPoint_PDU, proto_dsp, "id-doa-myAccessPoint");
  register_ber_oid_dissector("2.5.12.2", dissect_AccessPoint_PDU, proto_dsp, "id-doa-superiorKnowledge");
  register_ber_oid_dissector("2.5.12.3", dissect_MasterAndShadowAccessPoints_PDU, proto_dsp, "id-doa-specificKnowledge");
  register_ber_oid_dissector("2.5.12.4", dissect_MasterAndShadowAccessPoints_PDU, proto_dsp, "id-doa-nonSpecificKnowledge");
  register_ber_oid_dissector("2.5.12.8", dissect_DitBridgeKnowledge_PDU, proto_dsp, "id-doa-ditBridgeKnowledge");


/*--- End of included file: packet-dsp-dis-tab.c ---*/
#line 305 "../../asn1/dsp/packet-dsp-template.c"

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-directory-system","2.5.3.2");

  /* ABSTRACT SYNTAXES */

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");

  /* Register DSP with ROS (with no use of RTSE) */
  dsp_handle = find_dissector("dsp");
  register_ros_oid_dissector_handle("2.5.9.2", dsp_handle, 0, "id-as-directory-system", FALSE);

}

static void
prefs_register_dsp(void)
{
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete_uint("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_dsp_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add_uint("tcp.port", global_dsp_tcp_port, tpkt_handle);

}
