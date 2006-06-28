/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-dsp.c                                                             */
/* ../../tools/asn2wrs.py -b -e -p dsp -c dsp.cnf -s packet-dsp-template dsp.asn */

/* Input file: packet-dsp-template.c */

#line 1 "packet-dsp-template.c"
/* packet-dsp.c
 * Routines for X.518 (X.500 Distributed Operations)  packet dissection
 * Graeme Lunt 2005
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
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/oid_resolv.h>

#include <stdio.h>
#include <string.h>

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

static guint global_dsp_tcp_port = 102;
static guint tcp_port = 0;
static dissector_handle_t tpkt_handle = NULL;
void prefs_register_dsp(void); /* forwad declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
int proto_dsp = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;


/*--- Included file: packet-dsp-hf.c ---*/
#line 1 "packet-dsp-hf.c"
static int hf_dsp_AccessPoint_PDU = -1;           /* AccessPoint */
static int hf_dsp_MasterAndShadowAccessPoints_PDU = -1;  /* MasterAndShadowAccessPoints */
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
static int hf_dsp_access_point_category = -1;     /* APCategory */
static int hf_dsp_chainingRequired = -1;          /* BOOLEAN */
static int hf_dsp_MasterAndShadowAccessPoints_item = -1;  /* MasterOrShadowAccessPoint */
static int hf_dsp_category = -1;                  /* T_category */
static int hf_dsp_additionalPoints = -1;          /* MasterAndShadowAccessPoints */
static int hf_dsp_Exclusions_item = -1;           /* RDNSequence */
static int hf_dsp_rdnsResolved = -1;              /* INTEGER */
static int hf_dsp_accessPoints = -1;              /* SET_OF_AccessPointInformation */
static int hf_dsp_accessPoints_item = -1;         /* AccessPointInformation */
static int hf_dsp_returnToDUA = -1;               /* BOOLEAN */
static int hf_dsp_basicLevels = -1;               /* T_basicLevels */
static int hf_dsp_level = -1;                     /* T_level */
static int hf_dsp_localQualifier = -1;            /* INTEGER */
static int hf_dsp_signed = -1;                    /* BOOLEAN */
static int hf_dsp_other = -1;                     /* EXTERNAL */

/*--- End of included file: packet-dsp-hf.c ---*/
#line 67 "packet-dsp-template.c"

/* Initialize the subtree pointers */
static gint ett_dsp = -1;

/*--- Included file: packet-dsp-ett.c ---*/
#line 1 "packet-dsp-ett.c"
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
static gint ett_dsp_Exclusions = -1;
static gint ett_dsp_ContinuationReference = -1;
static gint ett_dsp_SET_OF_AccessPointInformation = -1;
static gint ett_dsp_AuthenticationLevel = -1;
static gint ett_dsp_T_basicLevels = -1;

/*--- End of included file: packet-dsp-ett.c ---*/
#line 71 "packet-dsp-template.c"


/*--- Included file: packet-dsp-fn.c ---*/
#line 1 "packet-dsp-fn.c"
/*--- Fields for imported types ---*/

static int dissect_readArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ReadArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_readArgument);
}
static int dissect_algorithmIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_dsp_algorithmIdentifier);
}
static int dissect_readResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ReadResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_readResult);
}
static int dissect_compareArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_CompareArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_compareArgument);
}
static int dissect_compareResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_CompareResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_compareResult);
}
static int dissect_listArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ListArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_listArgument);
}
static int dissect_listResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ListResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_listResult);
}
static int dissect_searchArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SearchArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_searchArgument);
}
static int dissect_searchResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SearchResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_searchResult);
}
static int dissect_addEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AddEntryArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_addEntryArgument);
}
static int dissect_addEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AddEntryResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_addEntryResult);
}
static int dissect_removeEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_RemoveEntryArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_removeEntryArgument);
}
static int dissect_removeEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_RemoveEntryResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_removeEntryResult);
}
static int dissect_modifyEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyEntryArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_modifyEntryArgument);
}
static int dissect_modifyEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyEntryResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_modifyEntryResult);
}
static int dissect_modifyDNArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyDNArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_modifyDNArgument);
}
static int dissect_modifyDNResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyDNResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_modifyDNResult);
}
static int dissect_contextPrefix(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dsp_contextPrefix);
}
static int dissect_securityParameters(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SecurityParameters(FALSE, tvb, offset, pinfo, tree, hf_dsp_securityParameters);
}
static int dissect_performer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dsp_performer);
}
static int dissect_notification_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dsp_notification_item);
}
static int dissect_originator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dsp_originator);
}
static int dissect_targetObjectDN(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dsp_targetObjectDN);
}
static int dissect_uniqueIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_UniqueIdentifier(FALSE, tvb, offset, pinfo, tree, hf_dsp_uniqueIdentifier);
}
static int dissect_searchRuleId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SearchRuleId(FALSE, tvb, offset, pinfo, tree, hf_dsp_searchRuleId);
}
static int dissect_chainedRelaxation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_MRMapping(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedRelaxation);
}
static int dissect_dsa(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_dsp_dsa);
}
static int dissect_targetObject(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_dsp_targetObject);
}
static int dissect_ae_title(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_dsp_ae_title);
}
static int dissect_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PresentationAddress(FALSE, tvb, offset, pinfo, tree, hf_dsp_address);
}
static int dissect_protocolInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_ProtocolInformation(FALSE, tvb, offset, pinfo, tree, hf_dsp_protocolInformation_item);
}
static int dissect_Exclusions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RDNSequence(FALSE, tvb, offset, pinfo, tree, hf_dsp_Exclusions_item);
}
static int dissect_other(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(FALSE, tvb, offset, pinfo, tree, hf_dsp_other);
}



static int
dissect_dsp_DSASystemBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_dsp_DSASystemBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_dsp_DSASystemBindError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindError(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string dsp_T_nameResolutionPhase_vals[] = {
  {   1, "notStarted" },
  {   2, "proceeding" },
  {   3, "completed" },
  { 0, NULL }
};


static int
dissect_dsp_T_nameResolutionPhase(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_nameResolutionPhase(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_nameResolutionPhase(FALSE, tvb, offset, pinfo, tree, hf_dsp_nameResolutionPhase);
}



static int
dissect_dsp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_aliasedRDNs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dsp_aliasedRDNs);
}
static int dissect_operationIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dsp_operationIdentifier);
}
static int dissect_relatedEntry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dsp_relatedEntry);
}
static int dissect_nextRDNToBeResolved(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dsp_nextRDNToBeResolved);
}
static int dissect_rdnsResolved(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dsp_rdnsResolved);
}
static int dissect_localQualifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dsp_localQualifier);
}


static const ber_sequence_t OperationProgress_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_nameResolutionPhase },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_nextRDNToBeResolved },
  { 0, 0, 0, NULL }
};

int
dissect_dsp_OperationProgress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OperationProgress_set, hf_index, ett_dsp_OperationProgress);

  return offset;
}
static int dissect_operationProgress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_OperationProgress(FALSE, tvb, offset, pinfo, tree, hf_dsp_operationProgress);
}


static const ber_sequence_t TraceItem_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_dsa },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_targetObject },
  { BER_CLASS_CON, 2, 0, dissect_operationProgress },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_TraceItem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TraceItem_set, hf_index, ett_dsp_TraceItem);

  return offset;
}
static int dissect_TraceInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_TraceItem(FALSE, tvb, offset, pinfo, tree, hf_dsp_TraceInformation_item);
}


static const ber_sequence_t TraceInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_TraceInformation_item },
};

static int
dissect_dsp_TraceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      TraceInformation_sequence_of, hf_index, ett_dsp_TraceInformation);

  return offset;
}
static int dissect_traceInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_TraceInformation(FALSE, tvb, offset, pinfo, tree, hf_dsp_traceInformation);
}



static int
dissect_dsp_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_aliasDereferenced(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dsp_aliasDereferenced);
}
static int dissect_returnCrossRefs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dsp_returnCrossRefs);
}
static int dissect_entryOnly(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dsp_entryOnly);
}
static int dissect_excludeShadows(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dsp_excludeShadows);
}
static int dissect_nameResolveOnMaster(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dsp_nameResolveOnMaster);
}
static int dissect_chainingRequired(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainingRequired);
}
static int dissect_returnToDUA(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dsp_returnToDUA);
}
static int dissect_signed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dsp_signed);
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
  { 0, NULL }
};


int
dissect_dsp_ReferenceType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_referenceType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ReferenceType(FALSE, tvb, offset, pinfo, tree, hf_dsp_referenceType);
}



static int
dissect_dsp_DomainInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_info(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_DomainInfo(FALSE, tvb, offset, pinfo, tree, hf_dsp_info);
}



static int
dissect_dsp_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_utcTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_UTCTime(FALSE, tvb, offset, pinfo, tree, hf_dsp_utcTime);
}



static int
dissect_dsp_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_generalizedTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_dsp_generalizedTime);
}


static const value_string dsp_Time_vals[] = {
  {   0, "utcTime" },
  {   1, "generalizedTime" },
  { 0, NULL }
};

static const ber_choice_t Time_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_utcTime },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_generalizedTime },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_Time(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Time_choice, hf_index, ett_dsp_Time,
                                 NULL);

  return offset;
}
static int dissect_timeLimit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_Time(FALSE, tvb, offset, pinfo, tree, hf_dsp_timeLimit);
}


static const value_string dsp_T_level_vals[] = {
  {   0, "none" },
  {   1, "simple" },
  {   2, "strong" },
  { 0, NULL }
};


static int
dissect_dsp_T_level(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_level(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_level(FALSE, tvb, offset, pinfo, tree, hf_dsp_level);
}


static const ber_sequence_t T_basicLevels_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_level },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_localQualifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_signed },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_basicLevels(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_basicLevels_sequence, hf_index, ett_dsp_T_basicLevels);

  return offset;
}
static int dissect_basicLevels(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_basicLevels(FALSE, tvb, offset, pinfo, tree, hf_dsp_basicLevels);
}


static const value_string dsp_AuthenticationLevel_vals[] = {
  {   0, "basicLevels" },
  {   1, "other" },
  { 0, NULL }
};

static const ber_choice_t AuthenticationLevel_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_basicLevels },
  {   1, BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_other },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_AuthenticationLevel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AuthenticationLevel_choice, hf_index, ett_dsp_AuthenticationLevel,
                                 NULL);

  return offset;
}
static int dissect_authenticationLevel(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_AuthenticationLevel(FALSE, tvb, offset, pinfo, tree, hf_dsp_authenticationLevel);
}


static const ber_sequence_t Exclusions_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Exclusions_item },
};

static int
dissect_dsp_Exclusions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 Exclusions_set_of, hf_index, ett_dsp_Exclusions);

  return offset;
}
static int dissect_exclusions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_Exclusions(FALSE, tvb, offset, pinfo, tree, hf_dsp_exclusions);
}
static int dissect_alreadySearched(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_Exclusions(FALSE, tvb, offset, pinfo, tree, hf_dsp_alreadySearched);
}


static const ber_sequence_t ChainingArguments_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_originator },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_targetObjectDN },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_operationProgress },
  { BER_CLASS_CON, 3, 0, dissect_traceInformation },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_returnCrossRefs },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_referenceType },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_info },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_timeLimit },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_uniqueIdentifier },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_authenticationLevel },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_exclusions },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL, dissect_excludeShadows },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL, dissect_operationIdentifier },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL, dissect_searchRuleId },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_chainedRelaxation },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL, dissect_relatedEntry },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainingArguments(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainingArguments_set, hf_index, ett_dsp_ChainingArguments);

  return offset;
}
static int dissect_chainedArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainingArguments(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedArgument);
}


static const ber_sequence_t ChainedReadArgumentData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedArgument },
  { BER_CLASS_CON, 0, 0, dissect_readArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedReadArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedReadArgumentData_set, hf_index, ett_dsp_ChainedReadArgumentData);

  return offset;
}
static int dissect_unsignedChainedReadArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedReadArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedReadArgument);
}
static int dissect_chainedReadArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedReadArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedReadArgument);
}



static int
dissect_dsp_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_encrypted(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_dsp_encrypted);
}


static const ber_sequence_t T_signedChainedReadArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedReadArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedReadArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedReadArgument_sequence, hf_index, ett_dsp_T_signedChainedReadArgument);

  return offset;
}
static int dissect_signedChainedReadArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedReadArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedReadArgument);
}


static const value_string dsp_ChainedReadArgument_vals[] = {
  {   0, "unsignedChainedReadArgument" },
  {   1, "signedChainedReadArgument" },
  { 0, NULL }
};

static const ber_choice_t ChainedReadArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedReadArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedReadArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedReadArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedReadArgument_choice, hf_index, ett_dsp_ChainedReadArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ProtocolInformation_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_protocolInformation_item },
};

static int
dissect_dsp_SET_OF_ProtocolInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ProtocolInformation_set_of, hf_index, ett_dsp_SET_OF_ProtocolInformation);

  return offset;
}
static int dissect_protocolInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_SET_OF_ProtocolInformation(FALSE, tvb, offset, pinfo, tree, hf_dsp_protocolInformation);
}


static const value_string dsp_T_category_vals[] = {
  {   0, "master" },
  {   1, "shadow" },
  { 0, NULL }
};


static int
dissect_dsp_T_category(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_category(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_category(FALSE, tvb, offset, pinfo, tree, hf_dsp_category);
}


static const value_string dsp_APCategory_vals[] = {
  {   0, "master" },
  {   1, "shadow" },
  { 0, NULL }
};


static int
dissect_dsp_APCategory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_access_point_category(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_APCategory(FALSE, tvb, offset, pinfo, tree, hf_dsp_access_point_category);
}


static const ber_sequence_t MasterOrShadowAccessPoint_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_ae_title },
  { BER_CLASS_CON, 1, 0, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_protocolInformation },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_access_point_category },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_chainingRequired },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_MasterOrShadowAccessPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MasterOrShadowAccessPoint_set, hf_index, ett_dsp_MasterOrShadowAccessPoint);

  return offset;
}
static int dissect_MasterAndShadowAccessPoints_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_MasterOrShadowAccessPoint(FALSE, tvb, offset, pinfo, tree, hf_dsp_MasterAndShadowAccessPoints_item);
}


static const ber_sequence_t MasterAndShadowAccessPoints_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_MasterAndShadowAccessPoints_item },
};

int
dissect_dsp_MasterAndShadowAccessPoints(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 MasterAndShadowAccessPoints_set_of, hf_index, ett_dsp_MasterAndShadowAccessPoints);

  return offset;
}
static int dissect_additionalPoints(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_MasterAndShadowAccessPoints(FALSE, tvb, offset, pinfo, tree, hf_dsp_additionalPoints);
}


static const ber_sequence_t AccessPointInformation_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_ae_title },
  { BER_CLASS_CON, 1, 0, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_protocolInformation },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_category },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_chainingRequired },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_additionalPoints },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_AccessPointInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AccessPointInformation_set, hf_index, ett_dsp_AccessPointInformation);

  return offset;
}
static int dissect_accessPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_AccessPointInformation(FALSE, tvb, offset, pinfo, tree, hf_dsp_accessPoint);
}
static int dissect_accessPoints_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_AccessPointInformation(FALSE, tvb, offset, pinfo, tree, hf_dsp_accessPoints_item);
}


static const ber_sequence_t CrossReference_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_contextPrefix },
  { BER_CLASS_CON, 1, 0, dissect_accessPoint },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_CrossReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CrossReference_set, hf_index, ett_dsp_CrossReference);

  return offset;
}
static int dissect_crossReferences_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_CrossReference(FALSE, tvb, offset, pinfo, tree, hf_dsp_crossReferences_item);
}


static const ber_sequence_t SEQUENCE_OF_CrossReference_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_crossReferences_item },
};

static int
dissect_dsp_SEQUENCE_OF_CrossReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_CrossReference_sequence_of, hf_index, ett_dsp_SEQUENCE_OF_CrossReference);

  return offset;
}
static int dissect_crossReferences(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_SEQUENCE_OF_CrossReference(FALSE, tvb, offset, pinfo, tree, hf_dsp_crossReferences);
}


static const ber_sequence_t ChainingResults_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_info },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_crossReferences },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_alreadySearched },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainingResults(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainingResults_set, hf_index, ett_dsp_ChainingResults);

  return offset;
}
static int dissect_chainedResults(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainingResults(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedResults);
}


static const ber_sequence_t ChainedReadResultData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedResults },
  { BER_CLASS_CON, 0, 0, dissect_readResult },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedReadResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedReadResultData_set, hf_index, ett_dsp_ChainedReadResultData);

  return offset;
}
static int dissect_unsignedChainedReadResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedReadResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedReadResult);
}
static int dissect_chainedReadResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedReadResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedReadResult);
}


static const ber_sequence_t T_signedChainedReadResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedReadResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedReadResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedReadResult_sequence, hf_index, ett_dsp_T_signedChainedReadResult);

  return offset;
}
static int dissect_signedChainedReadResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedReadResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedReadResult);
}


static const value_string dsp_ChainedReadResult_vals[] = {
  {   0, "unsignedChainedReadResult" },
  {   1, "signedChainedReadResult" },
  { 0, NULL }
};

static const ber_choice_t ChainedReadResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedReadResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedReadResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedReadResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedReadResult_choice, hf_index, ett_dsp_ChainedReadResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedCompareArgumentData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedArgument },
  { BER_CLASS_CON, 0, 0, dissect_compareArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedCompareArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedCompareArgumentData_set, hf_index, ett_dsp_ChainedCompareArgumentData);

  return offset;
}
static int dissect_unsignedChainedCompareArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedCompareArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedCompareArgument);
}
static int dissect_chainedCompareArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedCompareArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedCompareArgument);
}


static const ber_sequence_t T_signedChainedCompareArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedCompareArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedCompareArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedCompareArgument_sequence, hf_index, ett_dsp_T_signedChainedCompareArgument);

  return offset;
}
static int dissect_signedChainedCompareArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedCompareArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedCompareArgument);
}


static const value_string dsp_ChainedCompareArgument_vals[] = {
  {   0, "unsignedChainedCompareArgument" },
  {   1, "signedChainedCompareArgument" },
  { 0, NULL }
};

static const ber_choice_t ChainedCompareArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedCompareArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedCompareArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedCompareArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedCompareArgument_choice, hf_index, ett_dsp_ChainedCompareArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedCompareResultData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedResults },
  { BER_CLASS_CON, 0, 0, dissect_compareResult },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedCompareResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedCompareResultData_set, hf_index, ett_dsp_ChainedCompareResultData);

  return offset;
}
static int dissect_unsignedChainedCompareResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedCompareResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedCompareResult);
}
static int dissect_chainedCompareResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedCompareResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedCompareResult);
}


static const ber_sequence_t T_signedChainedCompareResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedCompareResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedCompareResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedCompareResult_sequence, hf_index, ett_dsp_T_signedChainedCompareResult);

  return offset;
}
static int dissect_signedChainedCompareResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedCompareResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedCompareResult);
}


static const value_string dsp_ChainedCompareResult_vals[] = {
  {   0, "unsignedChainedCompareResult" },
  {   1, "signedChainedCompareResult" },
  { 0, NULL }
};

static const ber_choice_t ChainedCompareResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedCompareResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedCompareResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedCompareResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedCompareResult_choice, hf_index, ett_dsp_ChainedCompareResult,
                                 NULL);

  return offset;
}



static int
dissect_dsp_ChainedAbandonArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dap_AbandonArgument(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_dsp_ChainedAbandonResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dap_AbandonResult(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t ChainedListArgumentData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedArgument },
  { BER_CLASS_CON, 0, 0, dissect_listArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedListArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedListArgumentData_set, hf_index, ett_dsp_ChainedListArgumentData);

  return offset;
}
static int dissect_unsignedChainedListArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedListArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedListArgument);
}
static int dissect_chainedListArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedListArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedListArgument);
}


static const ber_sequence_t T_signedChainedListArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedListArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedListArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedListArgument_sequence, hf_index, ett_dsp_T_signedChainedListArgument);

  return offset;
}
static int dissect_signedChainedListArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedListArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedListArgument);
}


static const value_string dsp_ChainedListArgument_vals[] = {
  {   0, "unsignedChainedListArgument" },
  {   1, "signedChainedListArgument" },
  { 0, NULL }
};

static const ber_choice_t ChainedListArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedListArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedListArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedListArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedListArgument_choice, hf_index, ett_dsp_ChainedListArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedListResultData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedResults },
  { BER_CLASS_CON, 0, 0, dissect_listResult },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedListResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedListResultData_set, hf_index, ett_dsp_ChainedListResultData);

  return offset;
}
static int dissect_unsignedChainedListResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedListResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedListResult);
}
static int dissect_chainedListResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedListResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedListResult);
}


static const ber_sequence_t T_signedChainedListResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedListResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedListResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedListResult_sequence, hf_index, ett_dsp_T_signedChainedListResult);

  return offset;
}
static int dissect_signedChainedListResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedListResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedListResult);
}


static const value_string dsp_ChainedListResult_vals[] = {
  {   0, "unsignedChainedListResult" },
  {   1, "signedChainedListResult" },
  { 0, NULL }
};

static const ber_choice_t ChainedListResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedListResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedListResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedListResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedListResult_choice, hf_index, ett_dsp_ChainedListResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedSearchArgumentData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedArgument },
  { BER_CLASS_CON, 0, 0, dissect_searchArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedSearchArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedSearchArgumentData_set, hf_index, ett_dsp_ChainedSearchArgumentData);

  return offset;
}
static int dissect_unsignedChainedSearchArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedSearchArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedSearchArgument);
}
static int dissect_chainedSearchArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedSearchArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedSearchArgument);
}


static const ber_sequence_t T_signedChainedSearchArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedSearchArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedSearchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedSearchArgument_sequence, hf_index, ett_dsp_T_signedChainedSearchArgument);

  return offset;
}
static int dissect_signedChainedSearchArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedSearchArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedSearchArgument);
}


static const value_string dsp_ChainedSearchArgument_vals[] = {
  {   0, "unsignedChainedSearchArgument" },
  {   1, "signedChainedSearchArgument" },
  { 0, NULL }
};

static const ber_choice_t ChainedSearchArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedSearchArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedSearchArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedSearchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedSearchArgument_choice, hf_index, ett_dsp_ChainedSearchArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedSearchResultData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedResults },
  { BER_CLASS_CON, 0, 0, dissect_searchResult },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedSearchResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedSearchResultData_set, hf_index, ett_dsp_ChainedSearchResultData);

  return offset;
}
static int dissect_unsignedChainedSearchResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedSearchResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedSearchResult);
}
static int dissect_chainedSearchResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedSearchResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedSearchResult);
}


static const ber_sequence_t T_signedChainedSearchResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedSearchResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedSearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedSearchResult_sequence, hf_index, ett_dsp_T_signedChainedSearchResult);

  return offset;
}
static int dissect_signedChainedSearchResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedSearchResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedSearchResult);
}


static const value_string dsp_ChainedSearchResult_vals[] = {
  {   0, "unsignedChainedSearchResult" },
  {   1, "signedChainedSearchResult" },
  { 0, NULL }
};

static const ber_choice_t ChainedSearchResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedSearchResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedSearchResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedSearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedSearchResult_choice, hf_index, ett_dsp_ChainedSearchResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedAddEntryArgumentData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedArgument },
  { BER_CLASS_CON, 0, 0, dissect_addEntryArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedAddEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedAddEntryArgumentData_set, hf_index, ett_dsp_ChainedAddEntryArgumentData);

  return offset;
}
static int dissect_unsignedChainedAddEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedAddEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedAddEntryArgument);
}
static int dissect_chainedAddEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedAddEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedAddEntryArgument);
}


static const ber_sequence_t T_signedChainedAddEntryArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedAddEntryArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedAddEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedAddEntryArgument_sequence, hf_index, ett_dsp_T_signedChainedAddEntryArgument);

  return offset;
}
static int dissect_signedChainedAddEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedAddEntryArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedAddEntryArgument);
}


static const value_string dsp_ChainedAddEntryArgument_vals[] = {
  {   0, "unsignedChainedAddEntryArgument" },
  {   1, "signedChainedAddEntryArgument" },
  { 0, NULL }
};

static const ber_choice_t ChainedAddEntryArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedAddEntryArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedAddEntryArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedAddEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedAddEntryArgument_choice, hf_index, ett_dsp_ChainedAddEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedAddEntryResultData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedResults },
  { BER_CLASS_CON, 0, 0, dissect_addEntryResult },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedAddEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedAddEntryResultData_set, hf_index, ett_dsp_ChainedAddEntryResultData);

  return offset;
}
static int dissect_unsignedChainedAddEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedAddEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedAddEntryResult);
}
static int dissect_chainedAddEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedAddEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedAddEntryResult);
}


static const ber_sequence_t T_signedChainedAddEntryResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedAddEntryResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedAddEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedAddEntryResult_sequence, hf_index, ett_dsp_T_signedChainedAddEntryResult);

  return offset;
}
static int dissect_signedChainedAddEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedAddEntryResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedAddEntryResult);
}


static const value_string dsp_ChainedAddEntryResult_vals[] = {
  {   0, "unsignedChainedAddEntryResult" },
  {   1, "signedChainedAddEntryResult" },
  { 0, NULL }
};

static const ber_choice_t ChainedAddEntryResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedAddEntryResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedAddEntryResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedAddEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedAddEntryResult_choice, hf_index, ett_dsp_ChainedAddEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedRemoveEntryArgumentData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedArgument },
  { BER_CLASS_CON, 0, 0, dissect_removeEntryArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedRemoveEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedRemoveEntryArgumentData_set, hf_index, ett_dsp_ChainedRemoveEntryArgumentData);

  return offset;
}
static int dissect_unsignedChainedRemoveEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedRemoveEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedRemoveEntryArgument);
}
static int dissect_chainedRemoveEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedRemoveEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedRemoveEntryArgument);
}


static const ber_sequence_t T_signedChainedRemoveEntryArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedRemoveEntryArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedRemoveEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedRemoveEntryArgument_sequence, hf_index, ett_dsp_T_signedChainedRemoveEntryArgument);

  return offset;
}
static int dissect_signedChainedRemoveEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedRemoveEntryArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedRemoveEntryArgument);
}


static const value_string dsp_ChainedRemoveEntryArgument_vals[] = {
  {   0, "unsignedChainedRemoveEntryArgument" },
  {   1, "signedChainedRemoveEntryArgument" },
  { 0, NULL }
};

static const ber_choice_t ChainedRemoveEntryArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedRemoveEntryArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedRemoveEntryArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedRemoveEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedRemoveEntryArgument_choice, hf_index, ett_dsp_ChainedRemoveEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedRemoveEntryResultData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedResults },
  { BER_CLASS_CON, 0, 0, dissect_removeEntryResult },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedRemoveEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedRemoveEntryResultData_set, hf_index, ett_dsp_ChainedRemoveEntryResultData);

  return offset;
}
static int dissect_unsignedChainedRemoveEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedRemoveEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedRemoveEntryResult);
}
static int dissect_chainedRemoveEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedRemoveEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedRemoveEntryResult);
}


static const ber_sequence_t T_signedChainedRemoveEntryResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedRemoveEntryResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedRemoveEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedRemoveEntryResult_sequence, hf_index, ett_dsp_T_signedChainedRemoveEntryResult);

  return offset;
}
static int dissect_signedChainedRemoveEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedRemoveEntryResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedRemoveEntryResult);
}


static const value_string dsp_ChainedRemoveEntryResult_vals[] = {
  {   0, "unsignedChainedRemoveEntryResult" },
  {   1, "signedChainedRemoveEntryResult" },
  { 0, NULL }
};

static const ber_choice_t ChainedRemoveEntryResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedRemoveEntryResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedRemoveEntryResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedRemoveEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedRemoveEntryResult_choice, hf_index, ett_dsp_ChainedRemoveEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedModifyEntryArgumentData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedArgument },
  { BER_CLASS_CON, 0, 0, dissect_modifyEntryArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedModifyEntryArgumentData_set, hf_index, ett_dsp_ChainedModifyEntryArgumentData);

  return offset;
}
static int dissect_unsignedChainedModifyEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedModifyEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedModifyEntryArgument);
}
static int dissect_chainedModifyEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedModifyEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedModifyEntryArgument);
}


static const ber_sequence_t T_signedChainedModifyEntryArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedModifyEntryArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedModifyEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedModifyEntryArgument_sequence, hf_index, ett_dsp_T_signedChainedModifyEntryArgument);

  return offset;
}
static int dissect_signedChainedModifyEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedModifyEntryArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedModifyEntryArgument);
}


static const value_string dsp_ChainedModifyEntryArgument_vals[] = {
  {   0, "unsignedChainedModifyEntryArgument" },
  {   1, "signedChainedModifyEntryArgument" },
  { 0, NULL }
};

static const ber_choice_t ChainedModifyEntryArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedModifyEntryArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedModifyEntryArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedModifyEntryArgument_choice, hf_index, ett_dsp_ChainedModifyEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedModifyEntryResultData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedResults },
  { BER_CLASS_CON, 0, 0, dissect_modifyEntryResult },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedModifyEntryResultData_set, hf_index, ett_dsp_ChainedModifyEntryResultData);

  return offset;
}
static int dissect_unsignedChainedModifyEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedModifyEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedModifyEntryResult);
}
static int dissect_chainedModifyEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedModifyEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedModifyEntryResult);
}


static const ber_sequence_t T_signedChainedModifyEntryResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedModifyEntryResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedModifyEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedModifyEntryResult_sequence, hf_index, ett_dsp_T_signedChainedModifyEntryResult);

  return offset;
}
static int dissect_signedChainedModifyEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedModifyEntryResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedModifyEntryResult);
}


static const value_string dsp_ChainedModifyEntryResult_vals[] = {
  {   0, "unsignedChainedModifyEntryResult" },
  {   1, "signedChainedModifyEntryResult" },
  { 0, NULL }
};

static const ber_choice_t ChainedModifyEntryResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedModifyEntryResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedModifyEntryResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedModifyEntryResult_choice, hf_index, ett_dsp_ChainedModifyEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedModifyDNArgumentData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedArgument },
  { BER_CLASS_CON, 0, 0, dissect_modifyDNArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyDNArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedModifyDNArgumentData_set, hf_index, ett_dsp_ChainedModifyDNArgumentData);

  return offset;
}
static int dissect_unsignedChainedModifyDNArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedModifyDNArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedModifyDNArgument);
}
static int dissect_chainedModifyDNArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedModifyDNArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedModifyDNArgument);
}


static const ber_sequence_t T_signedChainedModifyDNArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedModifyDNArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedModifyDNArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedModifyDNArgument_sequence, hf_index, ett_dsp_T_signedChainedModifyDNArgument);

  return offset;
}
static int dissect_signedChainedModifyDNArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedModifyDNArgument(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedModifyDNArgument);
}


static const value_string dsp_ChainedModifyDNArgument_vals[] = {
  {   0, "unsignedChainedModifyDNArgument" },
  {   1, "signedChainedModifyDNArgument" },
  { 0, NULL }
};

static const ber_choice_t ChainedModifyDNArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedModifyDNArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedModifyDNArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyDNArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedModifyDNArgument_choice, hf_index, ett_dsp_ChainedModifyDNArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChainedModifyDNResultData_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedResults },
  { BER_CLASS_CON, 0, 0, dissect_modifyDNResult },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyDNResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChainedModifyDNResultData_set, hf_index, ett_dsp_ChainedModifyDNResultData);

  return offset;
}
static int dissect_unsignedChainedModifyDNResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedModifyDNResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedChainedModifyDNResult);
}
static int dissect_chainedModifyDNResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ChainedModifyDNResultData(FALSE, tvb, offset, pinfo, tree, hf_dsp_chainedModifyDNResult);
}


static const ber_sequence_t T_signedChainedModifyDNResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_chainedModifyDNResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedChainedModifyDNResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedChainedModifyDNResult_sequence, hf_index, ett_dsp_T_signedChainedModifyDNResult);

  return offset;
}
static int dissect_signedChainedModifyDNResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedChainedModifyDNResult(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedChainedModifyDNResult);
}


static const value_string dsp_ChainedModifyDNResult_vals[] = {
  {   0, "unsignedChainedModifyDNResult" },
  {   1, "signedChainedModifyDNResult" },
  { 0, NULL }
};

static const ber_choice_t ChainedModifyDNResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedChainedModifyDNResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedChainedModifyDNResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_ChainedModifyDNResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChainedModifyDNResult_choice, hf_index, ett_dsp_ChainedModifyDNResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_AccessPointInformation_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_accessPoints_item },
};

static int
dissect_dsp_SET_OF_AccessPointInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AccessPointInformation_set_of, hf_index, ett_dsp_SET_OF_AccessPointInformation);

  return offset;
}
static int dissect_accessPoints(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_SET_OF_AccessPointInformation(FALSE, tvb, offset, pinfo, tree, hf_dsp_accessPoints);
}


static const ber_sequence_t ContinuationReference_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_targetObject },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 2, 0, dissect_operationProgress },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_rdnsResolved },
  { BER_CLASS_CON, 4, 0, dissect_referenceType },
  { BER_CLASS_CON, 5, 0, dissect_accessPoints },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_exclusions },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_returnToDUA },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { 0, 0, 0, NULL }
};

int
dissect_dsp_ContinuationReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ContinuationReference_set, hf_index, ett_dsp_ContinuationReference);

  return offset;
}
static int dissect_reference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ContinuationReference(FALSE, tvb, offset, pinfo, tree, hf_dsp_reference);
}


static const ber_sequence_t SEQUENCE_OF_Attribute_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_notification_item },
};

static int
dissect_dsp_SEQUENCE_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Attribute_sequence_of, hf_index, ett_dsp_SEQUENCE_OF_Attribute);

  return offset;
}
static int dissect_notification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_SEQUENCE_OF_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dsp_notification);
}


static const ber_sequence_t DSAReferralData_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_reference },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_contextPrefix },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_DSAReferralData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DSAReferralData_set, hf_index, ett_dsp_DSAReferralData);

  return offset;
}
static int dissect_unsignedDSAReferral(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_DSAReferralData(FALSE, tvb, offset, pinfo, tree, hf_dsp_unsignedDSAReferral);
}
static int dissect_dsaReferral(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_DSAReferralData(FALSE, tvb, offset, pinfo, tree, hf_dsp_dsaReferral);
}


static const ber_sequence_t T_signedDSAReferral_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsaReferral },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dsp_T_signedDSAReferral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedDSAReferral_sequence, hf_index, ett_dsp_T_signedDSAReferral);

  return offset;
}
static int dissect_signedDSAReferral(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_T_signedDSAReferral(FALSE, tvb, offset, pinfo, tree, hf_dsp_signedDSAReferral);
}


static const value_string dsp_DSAReferral_vals[] = {
  {   0, "unsignedDSAReferral" },
  {   1, "signedDSAReferral" },
  { 0, NULL }
};

static const ber_choice_t DSAReferral_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedDSAReferral },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedDSAReferral },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dsp_DSAReferral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DSAReferral_choice, hf_index, ett_dsp_DSAReferral,
                                 NULL);

  return offset;
}


static const ber_sequence_t AccessPoint_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_ae_title },
  { BER_CLASS_CON, 1, 0, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_protocolInformation },
  { 0, 0, 0, NULL }
};

int
dissect_dsp_AccessPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AccessPoint_set, hf_index, ett_dsp_AccessPoint);

  return offset;
}

/*--- PDUs ---*/

static void dissect_AccessPoint_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dsp_AccessPoint(FALSE, tvb, 0, pinfo, tree, hf_dsp_AccessPoint_PDU);
}
static void dissect_MasterAndShadowAccessPoints_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dsp_MasterAndShadowAccessPoints(FALSE, tvb, 0, pinfo, tree, hf_dsp_MasterAndShadowAccessPoints_PDU);
}


/*--- End of included file: packet-dsp-fn.c ---*/
#line 73 "packet-dsp-template.c"

/*
* Dissect X518 PDUs inside a ROS PDUs
*/
static void
dissect_dsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*dsp_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *dsp_op_name;

	/* do we have operation information from the ROS dissector?  */
	if( !pinfo->private_data ){
		if(parent_tree){
			proto_tree_add_text(parent_tree, tvb, offset, -1,
				"Internal error: can't get operation information from ROS dissector.");
		} 
		return  ;
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );
	}

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_dsp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_dsp);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DAP");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

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
	  return;
	}

	if(dsp_dissector) {
	  if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_str(pinfo->cinfo, COL_INFO, dsp_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dsp_dissector)(FALSE, tvb, offset, pinfo , tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DSP PDU");
	      offset = tvb_length(tvb);
	      break;
	    }
	  }
	}
}


/*--- proto_register_dsp -------------------------------------------*/
void proto_register_dsp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-dsp-hfarr.c ---*/
#line 1 "packet-dsp-hfarr.c"
    { &hf_dsp_AccessPoint_PDU,
      { "AccessPoint", "dsp.AccessPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessPoint", HFILL }},
    { &hf_dsp_MasterAndShadowAccessPoints_PDU,
      { "MasterAndShadowAccessPoints", "dsp.MasterAndShadowAccessPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MasterAndShadowAccessPoints", HFILL }},
    { &hf_dsp_chainedArgument,
      { "chainedArgument", "dsp.chainedArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dsp_readArgument,
      { "readArgument", "dsp.readArgument",
        FT_UINT32, BASE_DEC, VALS(dap_ReadArgument_vals), 0,
        "ChainedReadArgumentData/readArgument", HFILL }},
    { &hf_dsp_unsignedChainedReadArgument,
      { "unsignedChainedReadArgument", "dsp.unsignedChainedReadArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadArgument/unsignedChainedReadArgument", HFILL }},
    { &hf_dsp_signedChainedReadArgument,
      { "signedChainedReadArgument", "dsp.signedChainedReadArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadArgument/signedChainedReadArgument", HFILL }},
    { &hf_dsp_chainedReadArgument,
      { "chainedReadArgument", "dsp.chainedReadArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadArgument/signedChainedReadArgument/chainedReadArgument", HFILL }},
    { &hf_dsp_algorithmIdentifier,
      { "algorithmIdentifier", "dsp.algorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dsp_encrypted,
      { "encrypted", "dsp.encrypted",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_dsp_chainedResults,
      { "chainedResults", "dsp.chainedResults",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dsp_readResult,
      { "readResult", "dsp.readResult",
        FT_UINT32, BASE_DEC, VALS(dap_ReadResult_vals), 0,
        "ChainedReadResultData/readResult", HFILL }},
    { &hf_dsp_unsignedChainedReadResult,
      { "unsignedChainedReadResult", "dsp.unsignedChainedReadResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadResult/unsignedChainedReadResult", HFILL }},
    { &hf_dsp_signedChainedReadResult,
      { "signedChainedReadResult", "dsp.signedChainedReadResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadResult/signedChainedReadResult", HFILL }},
    { &hf_dsp_chainedReadResult,
      { "chainedReadResult", "dsp.chainedReadResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedReadResult/signedChainedReadResult/chainedReadResult", HFILL }},
    { &hf_dsp_compareArgument,
      { "compareArgument", "dsp.compareArgument",
        FT_UINT32, BASE_DEC, VALS(dap_CompareArgument_vals), 0,
        "ChainedCompareArgumentData/compareArgument", HFILL }},
    { &hf_dsp_unsignedChainedCompareArgument,
      { "unsignedChainedCompareArgument", "dsp.unsignedChainedCompareArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareArgument/unsignedChainedCompareArgument", HFILL }},
    { &hf_dsp_signedChainedCompareArgument,
      { "signedChainedCompareArgument", "dsp.signedChainedCompareArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareArgument/signedChainedCompareArgument", HFILL }},
    { &hf_dsp_chainedCompareArgument,
      { "chainedCompareArgument", "dsp.chainedCompareArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareArgument/signedChainedCompareArgument/chainedCompareArgument", HFILL }},
    { &hf_dsp_compareResult,
      { "compareResult", "dsp.compareResult",
        FT_UINT32, BASE_DEC, VALS(dap_CompareResult_vals), 0,
        "ChainedCompareResultData/compareResult", HFILL }},
    { &hf_dsp_unsignedChainedCompareResult,
      { "unsignedChainedCompareResult", "dsp.unsignedChainedCompareResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareResult/unsignedChainedCompareResult", HFILL }},
    { &hf_dsp_signedChainedCompareResult,
      { "signedChainedCompareResult", "dsp.signedChainedCompareResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareResult/signedChainedCompareResult", HFILL }},
    { &hf_dsp_chainedCompareResult,
      { "chainedCompareResult", "dsp.chainedCompareResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedCompareResult/signedChainedCompareResult/chainedCompareResult", HFILL }},
    { &hf_dsp_listArgument,
      { "listArgument", "dsp.listArgument",
        FT_UINT32, BASE_DEC, VALS(dap_ListArgument_vals), 0,
        "ChainedListArgumentData/listArgument", HFILL }},
    { &hf_dsp_unsignedChainedListArgument,
      { "unsignedChainedListArgument", "dsp.unsignedChainedListArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListArgument/unsignedChainedListArgument", HFILL }},
    { &hf_dsp_signedChainedListArgument,
      { "signedChainedListArgument", "dsp.signedChainedListArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListArgument/signedChainedListArgument", HFILL }},
    { &hf_dsp_chainedListArgument,
      { "chainedListArgument", "dsp.chainedListArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListArgument/signedChainedListArgument/chainedListArgument", HFILL }},
    { &hf_dsp_listResult,
      { "listResult", "dsp.listResult",
        FT_UINT32, BASE_DEC, VALS(dap_ListResult_vals), 0,
        "ChainedListResultData/listResult", HFILL }},
    { &hf_dsp_unsignedChainedListResult,
      { "unsignedChainedListResult", "dsp.unsignedChainedListResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListResult/unsignedChainedListResult", HFILL }},
    { &hf_dsp_signedChainedListResult,
      { "signedChainedListResult", "dsp.signedChainedListResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListResult/signedChainedListResult", HFILL }},
    { &hf_dsp_chainedListResult,
      { "chainedListResult", "dsp.chainedListResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedListResult/signedChainedListResult/chainedListResult", HFILL }},
    { &hf_dsp_searchArgument,
      { "searchArgument", "dsp.searchArgument",
        FT_UINT32, BASE_DEC, VALS(dap_SearchArgument_vals), 0,
        "ChainedSearchArgumentData/searchArgument", HFILL }},
    { &hf_dsp_unsignedChainedSearchArgument,
      { "unsignedChainedSearchArgument", "dsp.unsignedChainedSearchArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchArgument/unsignedChainedSearchArgument", HFILL }},
    { &hf_dsp_signedChainedSearchArgument,
      { "signedChainedSearchArgument", "dsp.signedChainedSearchArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchArgument/signedChainedSearchArgument", HFILL }},
    { &hf_dsp_chainedSearchArgument,
      { "chainedSearchArgument", "dsp.chainedSearchArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchArgument/signedChainedSearchArgument/chainedSearchArgument", HFILL }},
    { &hf_dsp_searchResult,
      { "searchResult", "dsp.searchResult",
        FT_UINT32, BASE_DEC, VALS(dap_SearchResult_vals), 0,
        "ChainedSearchResultData/searchResult", HFILL }},
    { &hf_dsp_unsignedChainedSearchResult,
      { "unsignedChainedSearchResult", "dsp.unsignedChainedSearchResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchResult/unsignedChainedSearchResult", HFILL }},
    { &hf_dsp_signedChainedSearchResult,
      { "signedChainedSearchResult", "dsp.signedChainedSearchResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchResult/signedChainedSearchResult", HFILL }},
    { &hf_dsp_chainedSearchResult,
      { "chainedSearchResult", "dsp.chainedSearchResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedSearchResult/signedChainedSearchResult/chainedSearchResult", HFILL }},
    { &hf_dsp_addEntryArgument,
      { "addEntryArgument", "dsp.addEntryArgument",
        FT_UINT32, BASE_DEC, VALS(dap_AddEntryArgument_vals), 0,
        "ChainedAddEntryArgumentData/addEntryArgument", HFILL }},
    { &hf_dsp_unsignedChainedAddEntryArgument,
      { "unsignedChainedAddEntryArgument", "dsp.unsignedChainedAddEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryArgument/unsignedChainedAddEntryArgument", HFILL }},
    { &hf_dsp_signedChainedAddEntryArgument,
      { "signedChainedAddEntryArgument", "dsp.signedChainedAddEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryArgument/signedChainedAddEntryArgument", HFILL }},
    { &hf_dsp_chainedAddEntryArgument,
      { "chainedAddEntryArgument", "dsp.chainedAddEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryArgument/signedChainedAddEntryArgument/chainedAddEntryArgument", HFILL }},
    { &hf_dsp_addEntryResult,
      { "addEntryResult", "dsp.addEntryResult",
        FT_UINT32, BASE_DEC, VALS(dap_AddEntryResult_vals), 0,
        "ChainedAddEntryResultData/addEntryResult", HFILL }},
    { &hf_dsp_unsignedChainedAddEntryResult,
      { "unsignedChainedAddEntryResult", "dsp.unsignedChainedAddEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryResult/unsignedChainedAddEntryResult", HFILL }},
    { &hf_dsp_signedChainedAddEntryResult,
      { "signedChainedAddEntryResult", "dsp.signedChainedAddEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryResult/signedChainedAddEntryResult", HFILL }},
    { &hf_dsp_chainedAddEntryResult,
      { "chainedAddEntryResult", "dsp.chainedAddEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedAddEntryResult/signedChainedAddEntryResult/chainedAddEntryResult", HFILL }},
    { &hf_dsp_removeEntryArgument,
      { "removeEntryArgument", "dsp.removeEntryArgument",
        FT_UINT32, BASE_DEC, VALS(dap_RemoveEntryArgument_vals), 0,
        "ChainedRemoveEntryArgumentData/removeEntryArgument", HFILL }},
    { &hf_dsp_unsignedChainedRemoveEntryArgument,
      { "unsignedChainedRemoveEntryArgument", "dsp.unsignedChainedRemoveEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryArgument/unsignedChainedRemoveEntryArgument", HFILL }},
    { &hf_dsp_signedChainedRemoveEntryArgument,
      { "signedChainedRemoveEntryArgument", "dsp.signedChainedRemoveEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryArgument/signedChainedRemoveEntryArgument", HFILL }},
    { &hf_dsp_chainedRemoveEntryArgument,
      { "chainedRemoveEntryArgument", "dsp.chainedRemoveEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryArgument/signedChainedRemoveEntryArgument/chainedRemoveEntryArgument", HFILL }},
    { &hf_dsp_removeEntryResult,
      { "removeEntryResult", "dsp.removeEntryResult",
        FT_UINT32, BASE_DEC, VALS(dap_RemoveEntryResult_vals), 0,
        "ChainedRemoveEntryResultData/removeEntryResult", HFILL }},
    { &hf_dsp_unsignedChainedRemoveEntryResult,
      { "unsignedChainedRemoveEntryResult", "dsp.unsignedChainedRemoveEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryResult/unsignedChainedRemoveEntryResult", HFILL }},
    { &hf_dsp_signedChainedRemoveEntryResult,
      { "signedChainedRemoveEntryResult", "dsp.signedChainedRemoveEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryResult/signedChainedRemoveEntryResult", HFILL }},
    { &hf_dsp_chainedRemoveEntryResult,
      { "chainedRemoveEntryResult", "dsp.chainedRemoveEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedRemoveEntryResult/signedChainedRemoveEntryResult/chainedRemoveEntryResult", HFILL }},
    { &hf_dsp_modifyEntryArgument,
      { "modifyEntryArgument", "dsp.modifyEntryArgument",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyEntryArgument_vals), 0,
        "ChainedModifyEntryArgumentData/modifyEntryArgument", HFILL }},
    { &hf_dsp_unsignedChainedModifyEntryArgument,
      { "unsignedChainedModifyEntryArgument", "dsp.unsignedChainedModifyEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryArgument/unsignedChainedModifyEntryArgument", HFILL }},
    { &hf_dsp_signedChainedModifyEntryArgument,
      { "signedChainedModifyEntryArgument", "dsp.signedChainedModifyEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryArgument/signedChainedModifyEntryArgument", HFILL }},
    { &hf_dsp_chainedModifyEntryArgument,
      { "chainedModifyEntryArgument", "dsp.chainedModifyEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryArgument/signedChainedModifyEntryArgument/chainedModifyEntryArgument", HFILL }},
    { &hf_dsp_modifyEntryResult,
      { "modifyEntryResult", "dsp.modifyEntryResult",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyEntryResult_vals), 0,
        "ChainedModifyEntryResultData/modifyEntryResult", HFILL }},
    { &hf_dsp_unsignedChainedModifyEntryResult,
      { "unsignedChainedModifyEntryResult", "dsp.unsignedChainedModifyEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryResult/unsignedChainedModifyEntryResult", HFILL }},
    { &hf_dsp_signedChainedModifyEntryResult,
      { "signedChainedModifyEntryResult", "dsp.signedChainedModifyEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryResult/signedChainedModifyEntryResult", HFILL }},
    { &hf_dsp_chainedModifyEntryResult,
      { "chainedModifyEntryResult", "dsp.chainedModifyEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyEntryResult/signedChainedModifyEntryResult/chainedModifyEntryResult", HFILL }},
    { &hf_dsp_modifyDNArgument,
      { "modifyDNArgument", "dsp.modifyDNArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNArgumentData/modifyDNArgument", HFILL }},
    { &hf_dsp_unsignedChainedModifyDNArgument,
      { "unsignedChainedModifyDNArgument", "dsp.unsignedChainedModifyDNArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNArgument/unsignedChainedModifyDNArgument", HFILL }},
    { &hf_dsp_signedChainedModifyDNArgument,
      { "signedChainedModifyDNArgument", "dsp.signedChainedModifyDNArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNArgument/signedChainedModifyDNArgument", HFILL }},
    { &hf_dsp_chainedModifyDNArgument,
      { "chainedModifyDNArgument", "dsp.chainedModifyDNArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNArgument/signedChainedModifyDNArgument/chainedModifyDNArgument", HFILL }},
    { &hf_dsp_modifyDNResult,
      { "modifyDNResult", "dsp.modifyDNResult",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyDNResult_vals), 0,
        "ChainedModifyDNResultData/modifyDNResult", HFILL }},
    { &hf_dsp_unsignedChainedModifyDNResult,
      { "unsignedChainedModifyDNResult", "dsp.unsignedChainedModifyDNResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNResult/unsignedChainedModifyDNResult", HFILL }},
    { &hf_dsp_signedChainedModifyDNResult,
      { "signedChainedModifyDNResult", "dsp.signedChainedModifyDNResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNResult/signedChainedModifyDNResult", HFILL }},
    { &hf_dsp_chainedModifyDNResult,
      { "chainedModifyDNResult", "dsp.chainedModifyDNResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainedModifyDNResult/signedChainedModifyDNResult/chainedModifyDNResult", HFILL }},
    { &hf_dsp_reference,
      { "reference", "dsp.reference",
        FT_NONE, BASE_NONE, NULL, 0,
        "DSAReferralData/reference", HFILL }},
    { &hf_dsp_contextPrefix,
      { "contextPrefix", "dsp.contextPrefix",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dsp_securityParameters,
      { "securityParameters", "dsp.securityParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dsp_performer,
      { "performer", "dsp.performer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DSAReferralData/performer", HFILL }},
    { &hf_dsp_aliasDereferenced,
      { "aliasDereferenced", "dsp.aliasDereferenced",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_dsp_notification,
      { "notification", "dsp.notification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DSAReferralData/notification", HFILL }},
    { &hf_dsp_notification_item,
      { "Item", "dsp.notification_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DSAReferralData/notification/_item", HFILL }},
    { &hf_dsp_unsignedDSAReferral,
      { "unsignedDSAReferral", "dsp.unsignedDSAReferral",
        FT_NONE, BASE_NONE, NULL, 0,
        "DSAReferral/unsignedDSAReferral", HFILL }},
    { &hf_dsp_signedDSAReferral,
      { "signedDSAReferral", "dsp.signedDSAReferral",
        FT_NONE, BASE_NONE, NULL, 0,
        "DSAReferral/signedDSAReferral", HFILL }},
    { &hf_dsp_dsaReferral,
      { "dsaReferral", "dsp.dsaReferral",
        FT_NONE, BASE_NONE, NULL, 0,
        "DSAReferral/signedDSAReferral/dsaReferral", HFILL }},
    { &hf_dsp_originator,
      { "originator", "dsp.originator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChainingArguments/originator", HFILL }},
    { &hf_dsp_targetObjectDN,
      { "targetObject", "dsp.targetObject",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChainingArguments/targetObject", HFILL }},
    { &hf_dsp_operationProgress,
      { "operationProgress", "dsp.operationProgress",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dsp_traceInformation,
      { "traceInformation", "dsp.traceInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChainingArguments/traceInformation", HFILL }},
    { &hf_dsp_aliasedRDNs,
      { "aliasedRDNs", "dsp.aliasedRDNs",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dsp_returnCrossRefs,
      { "returnCrossRefs", "dsp.returnCrossRefs",
        FT_BOOLEAN, 8, NULL, 0,
        "ChainingArguments/returnCrossRefs", HFILL }},
    { &hf_dsp_referenceType,
      { "referenceType", "dsp.referenceType",
        FT_UINT32, BASE_DEC, VALS(dsp_ReferenceType_vals), 0,
        "", HFILL }},
    { &hf_dsp_info,
      { "info", "dsp.info",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dsp_timeLimit,
      { "timeLimit", "dsp.timeLimit",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "ChainingArguments/timeLimit", HFILL }},
    { &hf_dsp_entryOnly,
      { "entryOnly", "dsp.entryOnly",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_dsp_uniqueIdentifier,
      { "uniqueIdentifier", "dsp.uniqueIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ChainingArguments/uniqueIdentifier", HFILL }},
    { &hf_dsp_authenticationLevel,
      { "authenticationLevel", "dsp.authenticationLevel",
        FT_UINT32, BASE_DEC, VALS(dsp_AuthenticationLevel_vals), 0,
        "ChainingArguments/authenticationLevel", HFILL }},
    { &hf_dsp_exclusions,
      { "exclusions", "dsp.exclusions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dsp_excludeShadows,
      { "excludeShadows", "dsp.excludeShadows",
        FT_BOOLEAN, 8, NULL, 0,
        "ChainingArguments/excludeShadows", HFILL }},
    { &hf_dsp_nameResolveOnMaster,
      { "nameResolveOnMaster", "dsp.nameResolveOnMaster",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_dsp_operationIdentifier,
      { "operationIdentifier", "dsp.operationIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "ChainingArguments/operationIdentifier", HFILL }},
    { &hf_dsp_searchRuleId,
      { "searchRuleId", "dsp.searchRuleId",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainingArguments/searchRuleId", HFILL }},
    { &hf_dsp_chainedRelaxation,
      { "chainedRelaxation", "dsp.chainedRelaxation",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainingArguments/chainedRelaxation", HFILL }},
    { &hf_dsp_relatedEntry,
      { "relatedEntry", "dsp.relatedEntry",
        FT_INT32, BASE_DEC, NULL, 0,
        "ChainingArguments/relatedEntry", HFILL }},
    { &hf_dsp_utcTime,
      { "utcTime", "dsp.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time/utcTime", HFILL }},
    { &hf_dsp_generalizedTime,
      { "generalizedTime", "dsp.generalizedTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time/generalizedTime", HFILL }},
    { &hf_dsp_crossReferences,
      { "crossReferences", "dsp.crossReferences",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChainingResults/crossReferences", HFILL }},
    { &hf_dsp_crossReferences_item,
      { "Item", "dsp.crossReferences_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChainingResults/crossReferences/_item", HFILL }},
    { &hf_dsp_alreadySearched,
      { "alreadySearched", "dsp.alreadySearched",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChainingResults/alreadySearched", HFILL }},
    { &hf_dsp_accessPoint,
      { "accessPoint", "dsp.accessPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "CrossReference/accessPoint", HFILL }},
    { &hf_dsp_nameResolutionPhase,
      { "nameResolutionPhase", "dsp.nameResolutionPhase",
        FT_UINT32, BASE_DEC, VALS(dsp_T_nameResolutionPhase_vals), 0,
        "OperationProgress/nameResolutionPhase", HFILL }},
    { &hf_dsp_nextRDNToBeResolved,
      { "nextRDNToBeResolved", "dsp.nextRDNToBeResolved",
        FT_INT32, BASE_DEC, NULL, 0,
        "OperationProgress/nextRDNToBeResolved", HFILL }},
    { &hf_dsp_TraceInformation_item,
      { "Item", "dsp.TraceInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "TraceInformation/_item", HFILL }},
    { &hf_dsp_dsa,
      { "dsa", "dsp.dsa",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "TraceItem/dsa", HFILL }},
    { &hf_dsp_targetObject,
      { "targetObject", "dsp.targetObject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "", HFILL }},
    { &hf_dsp_ae_title,
      { "ae-title", "dsp.ae_title",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "", HFILL }},
    { &hf_dsp_address,
      { "address", "dsp.address",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dsp_protocolInformation,
      { "protocolInformation", "dsp.protocolInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dsp_protocolInformation_item,
      { "Item", "dsp.protocolInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dsp_access_point_category,
      { "category", "dsp.category",
        FT_UINT32, BASE_DEC, VALS(dsp_APCategory_vals), 0,
        "MasterOrShadowAccessPoint/category", HFILL }},
    { &hf_dsp_chainingRequired,
      { "chainingRequired", "dsp.chainingRequired",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_dsp_MasterAndShadowAccessPoints_item,
      { "Item", "dsp.MasterAndShadowAccessPoints_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MasterAndShadowAccessPoints/_item", HFILL }},
    { &hf_dsp_category,
      { "category", "dsp.category",
        FT_UINT32, BASE_DEC, VALS(dsp_T_category_vals), 0,
        "AccessPointInformation/category", HFILL }},
    { &hf_dsp_additionalPoints,
      { "additionalPoints", "dsp.additionalPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AccessPointInformation/additionalPoints", HFILL }},
    { &hf_dsp_Exclusions_item,
      { "Item", "dsp.Exclusions_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Exclusions/_item", HFILL }},
    { &hf_dsp_rdnsResolved,
      { "rdnsResolved", "dsp.rdnsResolved",
        FT_INT32, BASE_DEC, NULL, 0,
        "ContinuationReference/rdnsResolved", HFILL }},
    { &hf_dsp_accessPoints,
      { "accessPoints", "dsp.accessPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContinuationReference/accessPoints", HFILL }},
    { &hf_dsp_accessPoints_item,
      { "Item", "dsp.accessPoints_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContinuationReference/accessPoints/_item", HFILL }},
    { &hf_dsp_returnToDUA,
      { "returnToDUA", "dsp.returnToDUA",
        FT_BOOLEAN, 8, NULL, 0,
        "ContinuationReference/returnToDUA", HFILL }},
    { &hf_dsp_basicLevels,
      { "basicLevels", "dsp.basicLevels",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationLevel/basicLevels", HFILL }},
    { &hf_dsp_level,
      { "level", "dsp.level",
        FT_UINT32, BASE_DEC, VALS(dsp_T_level_vals), 0,
        "AuthenticationLevel/basicLevels/level", HFILL }},
    { &hf_dsp_localQualifier,
      { "localQualifier", "dsp.localQualifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AuthenticationLevel/basicLevels/localQualifier", HFILL }},
    { &hf_dsp_signed,
      { "signed", "dsp.signed",
        FT_BOOLEAN, 8, NULL, 0,
        "AuthenticationLevel/basicLevels/signed", HFILL }},
    { &hf_dsp_other,
      { "other", "dsp.other",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationLevel/other", HFILL }},

/*--- End of included file: packet-dsp-hfarr.c ---*/
#line 279 "packet-dsp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_dsp,

/*--- Included file: packet-dsp-ettarr.c ---*/
#line 1 "packet-dsp-ettarr.c"
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
    &ett_dsp_Exclusions,
    &ett_dsp_ContinuationReference,
    &ett_dsp_SET_OF_AccessPointInformation,
    &ett_dsp_AuthenticationLevel,
    &ett_dsp_T_basicLevels,

/*--- End of included file: packet-dsp-ettarr.c ---*/
#line 285 "packet-dsp-template.c"
  };
  module_t *dsp_module;

  /* Register protocol */
  proto_dsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* initially disable the protocol */
  proto_set_decoding(proto_dsp, FALSE);

  register_dissector("dsp", dissect_dsp, proto_dsp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DSP, particularly our port */

#ifdef PREFERENCE_GROUPING
  dsp_module = prefs_register_protocol_subtree("OSI/X.500", proto_dsp, prefs_register_dsp);
#else
  dsp_module = prefs_register_protocol(proto_dsp, prefs_register_dsp);
#endif

  prefs_register_uint_preference(dsp_module, "tcp.port", "DSP TCP Port",
				 "Set the port for DSP operations (if other"
				 " than the default of 102)",
				 10, &global_dsp_tcp_port);


}


/*--- proto_reg_handoff_dsp --- */
void proto_reg_handoff_dsp(void) {
  dissector_handle_t handle = NULL;


/*--- Included file: packet-dsp-dis-tab.c ---*/
#line 1 "packet-dsp-dis-tab.c"
  register_ber_oid_dissector("2.5.12.1", dissect_AccessPoint_PDU, proto_dsp, "id-doa-myAccessPoint");
  register_ber_oid_dissector("2.5.12.2", dissect_AccessPoint_PDU, proto_dsp, "id-doa-superiorKnowledge");
  register_ber_oid_dissector("2.5.12.3", dissect_MasterAndShadowAccessPoints_PDU, proto_dsp, "id-doa-specificKnowledge");
  register_ber_oid_dissector("2.5.12.4", dissect_MasterAndShadowAccessPoints_PDU, proto_dsp, "id-doa-nonSpecificKnowledge");


/*--- End of included file: packet-dsp-dis-tab.c ---*/
#line 322 "packet-dsp-template.c"

  /* APPLICATION CONTEXT */

  add_oid_str_name("2.5.3.2", "id-ac-directory-system");

  /* ABSTRACT SYNTAXES */
    
  /* Register DSP with ROS (with no use of RTSE) */
  if((handle = find_dissector("dsp"))) {
    register_ros_oid_dissector_handle("2.5.9.2", handle, 0, "id-as-directory-system", FALSE); 
  }


}

void prefs_register_dsp(void) {

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port != 102) && tpkt_handle)
    dissector_delete("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_dsp_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add("tcp.port", global_dsp_tcp_port, tpkt_handle);

}
