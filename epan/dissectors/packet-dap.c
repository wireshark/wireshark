/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-dap.c                                                             */
/* ../../tools/asn2eth.py -X -b -e -p dap -c dap.cnf -s packet-dap-template dap.asn */

/* Input file: packet-dap-template.c */

#line 1 "packet-dap-template.c"
/* packet-dap.c
 * Routines for X.511 (X.500 Directory Asbtract Service) and X.519 DAP  packet dissection
 * Graeme Lunt 2005
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
#include <epan/prefs.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"

#include "packet-x509if.h"
#include "packet-x509af.h"
#include "packet-x509sat.h"
#include "packet-crmf.h"

#include "packet-dsp.h"
#include "packet-disp.h"
#include "packet-dap.h"
#include <epan/strutil.h>

/* we don't have a separate dissector for X519 - 
   most of DAP is defined in X511 */
#define PNAME  "X.519 Directory Access Protocol"
#define PSNAME "DAP"
#define PFNAME "dap"

static guint global_dap_tcp_port = 102;
static guint tcp_port = 0;
static dissector_handle_t tpkt_handle = NULL;
void prefs_register_dap(void); /* forwad declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
int proto_dap = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;


/*--- Included file: packet-dap-hf.c ---*/
#line 1 "packet-dap-hf.c"
static int hf_dap_securityParameters = -1;        /* SecurityParameters */
static int hf_dap_performer = -1;                 /* DistinguishedName */
static int hf_dap_aliasDereferenced = -1;         /* BOOLEAN */
static int hf_dap_notification = -1;              /* SEQUENCE_OF_Attribute */
static int hf_dap_notification_item = -1;         /* Attribute */
static int hf_dap_options = -1;                   /* ServiceControlOptions */
static int hf_dap_priority = -1;                  /* T_priority */
static int hf_dap_timeLimit = -1;                 /* INTEGER */
static int hf_dap_sizeLimit = -1;                 /* INTEGER */
static int hf_dap_scopeOfReferral = -1;           /* T_scopeOfReferral */
static int hf_dap_attributeSizeLimit = -1;        /* INTEGER */
static int hf_dap_manageDSAITPlaneRef = -1;       /* T_manageDSAITPlaneRef */
static int hf_dap_dsaName = -1;                   /* Name */
static int hf_dap_agreementID = -1;               /* AgreementID */
static int hf_dap_serviceType = -1;               /* OBJECT_IDENTIFIER */
static int hf_dap_userClass = -1;                 /* INTEGER */
static int hf_dap_attributes = -1;                /* T_attributes */
static int hf_dap_allUserAttributes = -1;         /* NULL */
static int hf_dap_select = -1;                    /* SET_OF_AttributeType */
static int hf_dap_select_item = -1;               /* AttributeType */
static int hf_dap_infoTypes = -1;                 /* T_infoTypes */
static int hf_dap_extraAttributes = -1;           /* T_extraAttributes */
static int hf_dap_allOperationalAttributes = -1;  /* NULL */
static int hf_dap_contextSelection = -1;          /* ContextSelection */
static int hf_dap_returnContexts = -1;            /* BOOLEAN */
static int hf_dap_familyReturn = -1;              /* FamilyReturn */
static int hf_dap_allContexts = -1;               /* NULL */
static int hf_dap_selectedContexts = -1;          /* SET_OF_TypeAndContextAssertion */
static int hf_dap_selectedContexts_item = -1;     /* TypeAndContextAssertion */
static int hf_dap_type = -1;                      /* AttributeType */
static int hf_dap_contextAssertions = -1;         /* T_contextAssertions */
static int hf_dap_preference = -1;                /* SEQUENCE_OF_ContextAssertion */
static int hf_dap_preference_item = -1;           /* ContextAssertion */
static int hf_dap_all = -1;                       /* SET_OF_ContextAssertion */
static int hf_dap_all_item = -1;                  /* ContextAssertion */
static int hf_dap_memberSelect = -1;              /* T_memberSelect */
static int hf_dap_familySelect = -1;              /* T_familySelect */
static int hf_dap_familySelect_item = -1;         /* OBJECT_IDENTIFIER */
static int hf_dap_name = -1;                      /* Name */
static int hf_dap_fromEntry = -1;                 /* BOOLEAN */
static int hf_dap_entry_information = -1;         /* T_information */
static int hf_dap_entry_information_item = -1;    /* EntryInformationItem */
static int hf_dap_attributeType = -1;             /* AttributeType */
static int hf_dap_attribute = -1;                 /* Attribute */
static int hf_dap_incompleteEntry = -1;           /* BOOLEAN */
static int hf_dap_partialName = -1;               /* BOOLEAN */
static int hf_dap_derivedEntry = -1;              /* BOOLEAN */
static int hf_dap_family_class = -1;              /* OBJECT_IDENTIFIER */
static int hf_dap_familyEntries = -1;             /* SEQUENCE_OF_FamilyEntry */
static int hf_dap_familyEntries_item = -1;        /* FamilyEntry */
static int hf_dap_rdn = -1;                       /* RelativeDistinguishedName */
static int hf_dap_family_information = -1;        /* FamilyInformation */
static int hf_dap_information_item = -1;          /* T_information_item */
static int hf_dap_family_info = -1;               /* SEQUENCE_OF_FamilyEntries */
static int hf_dap_family_info_item = -1;          /* FamilyEntries */
static int hf_dap_filter_item = -1;               /* FilterItem */
static int hf_dap_and = -1;                       /* SetOfFilter */
static int hf_dap_or = -1;                        /* SetOfFilter */
static int hf_dap_not = -1;                       /* Filter */
static int hf_dap_SetOfFilter_item = -1;          /* Filter */
static int hf_dap_equality = -1;                  /* AttributeValueAssertion */
static int hf_dap_substrings = -1;                /* T_substrings */
static int hf_dap_sunstringType = -1;             /* OBJECT_IDENTIFIER */
static int hf_dap_strings = -1;                   /* T_strings */
static int hf_dap_strings_item = -1;              /* T_strings_item */
static int hf_dap_initial = -1;                   /* T_initial */
static int hf_dap_any = -1;                       /* T_any */
static int hf_dap_final = -1;                     /* T_final */
static int hf_dap_control = -1;                   /* Attribute */
static int hf_dap_greaterOrEqual = -1;            /* AttributeValueAssertion */
static int hf_dap_lessOrEqual = -1;               /* AttributeValueAssertion */
static int hf_dap_present = -1;                   /* AttributeType */
static int hf_dap_approximateMatch = -1;          /* AttributeValueAssertion */
static int hf_dap_extensibleMatch = -1;           /* MatchingRuleAssertion */
static int hf_dap_contextPresent = -1;            /* AttributeTypeAssertion */
static int hf_dap_matchingRule = -1;              /* T_matchingRule */
static int hf_dap_matchingRule_item = -1;         /* OBJECT_IDENTIFIER */
static int hf_dap_matchValue = -1;                /* T_matchValue */
static int hf_dap_dnAttributes = -1;              /* BOOLEAN */
static int hf_dap_newRequest = -1;                /* T_newRequest */
static int hf_dap_pageSize = -1;                  /* INTEGER */
static int hf_dap_sortKeys = -1;                  /* SEQUENCE_OF_SortKey */
static int hf_dap_sortKeys_item = -1;             /* SortKey */
static int hf_dap_reverse = -1;                   /* BOOLEAN */
static int hf_dap_unmerged = -1;                  /* BOOLEAN */
static int hf_dap_queryReference = -1;            /* OCTET_STRING */
static int hf_dap_orderingRule = -1;              /* OBJECT_IDENTIFIER */
static int hf_dap_certification_path = -1;        /* CertificationPath */
static int hf_dap_distinguished_name = -1;        /* DistinguishedName */
static int hf_dap_time = -1;                      /* Time */
static int hf_dap_random = -1;                    /* BIT_STRING */
static int hf_dap_target = -1;                    /* ProtectionRequest */
static int hf_dap_response = -1;                  /* BIT_STRING */
static int hf_dap_operationCode = -1;             /* Code */
static int hf_dap_attributeCertificationPath = -1;  /* AttributeCertificationPath */
static int hf_dap_errorProtection = -1;           /* ErrorProtectionRequest */
static int hf_dap_errorCode = -1;                 /* Code */
static int hf_dap_utcTime = -1;                   /* UTCTime */
static int hf_dap_generalizedTime = -1;           /* GeneralizedTime */
static int hf_dap_credentials = -1;               /* Credentials */
static int hf_dap_versions = -1;                  /* Versions */
static int hf_dap_simple = -1;                    /* SimpleCredentials */
static int hf_dap_strong = -1;                    /* StrongCredentials */
static int hf_dap_externalProcedure = -1;         /* EXTERNAL */
static int hf_dap_spkm = -1;                      /* SpkmCredentials */
static int hf_dap_validity = -1;                  /* T_validity */
static int hf_dap_time1 = -1;                     /* T_time1 */
static int hf_dap_utc = -1;                       /* UTCTime */
static int hf_dap_gt = -1;                        /* GeneralizedTime */
static int hf_dap_time2 = -1;                     /* T_time2 */
static int hf_dap_random1 = -1;                   /* BIT_STRING */
static int hf_dap_random2 = -1;                   /* BIT_STRING */
static int hf_dap_password = -1;                  /* T_password */
static int hf_dap_unprotected = -1;               /* OCTET_STRING */
static int hf_dap_protected = -1;                 /* T_protected */
static int hf_dap_protectedPassword = -1;         /* OCTET_STRING */
static int hf_dap_algorithmIdentifier = -1;       /* AlgorithmIdentifier */
static int hf_dap_encrypted = -1;                 /* BIT_STRING */
static int hf_dap_bind_token = -1;                /* T_bind_token */
static int hf_dap_req = -1;                       /* T_req */
static int hf_dap_rep = -1;                       /* T_rep */
static int hf_dap_error = -1;                     /* T_error */
static int hf_dap_serviceProblem = -1;            /* ServiceProblem */
static int hf_dap_securityProblem = -1;           /* SecurityProblem */
static int hf_dap_unsignedDirectoryBindError = -1;  /* DirectoryBindErrorData */
static int hf_dap_signedDirectoryBindError = -1;  /* T_signedDirectoryBindError */
static int hf_dap_directoryBindError = -1;        /* DirectoryBindErrorData */
static int hf_dap_object = -1;                    /* Name */
static int hf_dap_selection = -1;                 /* EntryInformationSelection */
static int hf_dap_modifyRightsRequest = -1;       /* BOOLEAN */
static int hf_dap_serviceControls = -1;           /* ServiceControls */
static int hf_dap_requestor = -1;                 /* DistinguishedName */
static int hf_dap_operationProgress = -1;         /* OperationProgress */
static int hf_dap_aliasedRDNs = -1;               /* INTEGER */
static int hf_dap_criticalExtensions = -1;        /* BIT_STRING */
static int hf_dap_referenceType = -1;             /* ReferenceType */
static int hf_dap_entryOnly = -1;                 /* BOOLEAN */
static int hf_dap_nameResolveOnMaster = -1;       /* BOOLEAN */
static int hf_dap_operationContexts = -1;         /* ContextSelection */
static int hf_dap_familyGrouping = -1;            /* FamilyGrouping */
static int hf_dap_rdnSequence = -1;               /* RDNSequence */
static int hf_dap_unsignedReadArgument = -1;      /* ReadArgumentData */
static int hf_dap_signedReadArgument = -1;        /* T_signedReadArgument */
static int hf_dap_readArgument = -1;              /* ReadArgumentData */
static int hf_dap_entry = -1;                     /* EntryInformation */
static int hf_dap_modifyRights = -1;              /* ModifyRights */
static int hf_dap_unsignedReadResult = -1;        /* ReadResultData */
static int hf_dap_signedReadResult = -1;          /* T_signedReadResult */
static int hf_dap_readResult = -1;                /* ReadResultData */
static int hf_dap_ModifyRights_item = -1;         /* ModifyRights_item */
static int hf_dap_item = -1;                      /* T_item */
static int hf_dap_item_entry = -1;                /* NULL */
static int hf_dap_attribute_type = -1;            /* AttributeType */
static int hf_dap_value_assertion = -1;           /* AttributeValueAssertion */
static int hf_dap_permission = -1;                /* T_permission */
static int hf_dap_purported = -1;                 /* AttributeValueAssertion */
static int hf_dap_unsignedCompareArgument = -1;   /* CompareArgumentData */
static int hf_dap_signedCompareArgument = -1;     /* T_signedCompareArgument */
static int hf_dap_compareArgument = -1;           /* CompareArgumentData */
static int hf_dap_matched = -1;                   /* BOOLEAN */
static int hf_dap_matchedSubtype = -1;            /* AttributeType */
static int hf_dap_unsignedCompareResult = -1;     /* CompareResultData */
static int hf_dap_signedCompareResult = -1;       /* T_signedCompareResult */
static int hf_dap_compareResult = -1;             /* CompareResultData */
static int hf_dap_invokeID = -1;                  /* InvokeId */
static int hf_dap_unsignedAbandonArgument = -1;   /* AbandonArgumentData */
static int hf_dap_signedAbandonArgument = -1;     /* T_signedAbandonArgument */
static int hf_dap_abandonArgument = -1;           /* AbandonArgumentData */
static int hf_dap_null = -1;                      /* NULL */
static int hf_dap_abandon_information = -1;       /* AbandonInformation */
static int hf_dap_unsignedAbandonResult = -1;     /* AbandonResultData */
static int hf_dap_signedAbandonResult = -1;       /* T_signedAbandonResult */
static int hf_dap_abandonResult = -1;             /* AbandonResultData */
static int hf_dap_pagedResults = -1;              /* PagedResultsRequest */
static int hf_dap_listFamily = -1;                /* BOOLEAN */
static int hf_dap_unsignedListArgument = -1;      /* ListArgumentData */
static int hf_dap_signedListArgument = -1;        /* T_signedListArgument */
static int hf_dap_listArgument = -1;              /* ListArgumentData */
static int hf_dap_listInfo = -1;                  /* T_listInfo */
static int hf_dap_subordinates = -1;              /* T_subordinates */
static int hf_dap_subordinates_item = -1;         /* T_subordinates_item */
static int hf_dap_aliasEntry = -1;                /* BOOLEAN */
static int hf_dap_partialOutcomeQualifier = -1;   /* PartialOutcomeQualifier */
static int hf_dap_uncorrelatedListInfo = -1;      /* SET_OF_ListResult */
static int hf_dap_uncorrelatedListInfo_item = -1;  /* ListResult */
static int hf_dap_unsignedListResult = -1;        /* ListResultData */
static int hf_dap_signedListResult = -1;          /* T_signedListResult */
static int hf_dap_listResult = -1;                /* ListResultData */
static int hf_dap_limitProblem = -1;              /* LimitProblem */
static int hf_dap_unexplored = -1;                /* SET_OF_ContinuationReference */
static int hf_dap_unexplored_item = -1;           /* ContinuationReference */
static int hf_dap_unavailableCriticalExtensions = -1;  /* BOOLEAN */
static int hf_dap_unknownErrors = -1;             /* T_unknownErrors */
static int hf_dap_unknownErrors_item = -1;        /* OBJECT_IDENTIFIER */
static int hf_dap_overspecFilter = -1;            /* Filter */
static int hf_dap_entryCount = -1;                /* T_entryCount */
static int hf_dap_bestEstimate = -1;              /* INTEGER */
static int hf_dap_lowEstimate = -1;               /* INTEGER */
static int hf_dap_baseObject = -1;                /* Name */
static int hf_dap_subset = -1;                    /* T_subset */
static int hf_dap_filter = -1;                    /* Filter */
static int hf_dap_searchAliases = -1;             /* BOOLEAN */
static int hf_dap_matchedValuesOnly = -1;         /* BOOLEAN */
static int hf_dap_extendedFilter = -1;            /* Filter */
static int hf_dap_checkOverspecified = -1;        /* BOOLEAN */
static int hf_dap_relaxation = -1;                /* RelaxationPolicy */
static int hf_dap_extendedArea = -1;              /* INTEGER */
static int hf_dap_hierarchySelections = -1;       /* HierarchySelections */
static int hf_dap_searchControlOptions = -1;      /* SearchControlOptions */
static int hf_dap_joinArguments = -1;             /* SEQUENCE_SIZE_1_MAX_OF_JoinArgument */
static int hf_dap_joinArguments_item = -1;        /* JoinArgument */
static int hf_dap_joinType = -1;                  /* T_joinType */
static int hf_dap_unsignedSearchArgument = -1;    /* SearchArgumentData */
static int hf_dap_signedSearchArgument = -1;      /* T_signedSearchArgument */
static int hf_dap_searchArgument = -1;            /* SearchArgumentData */
static int hf_dap_joinBaseObject = -1;            /* Name */
static int hf_dap_domainLocalID = -1;             /* DomainLocalID */
static int hf_dap_joinSubset = -1;                /* T_joinSubset */
static int hf_dap_joinFilter = -1;                /* Filter */
static int hf_dap_joinAttributes = -1;            /* SEQUENCE_OF_JoinAttPair */
static int hf_dap_joinAttributes_item = -1;       /* JoinAttPair */
static int hf_dap_joinSelection = -1;             /* EntryInformationSelection */
static int hf_dap_baseAtt = -1;                   /* AttributeType */
static int hf_dap_joinAtt = -1;                   /* AttributeType */
static int hf_dap_joinContext = -1;               /* SEQUENCE_OF_JoinContextType */
static int hf_dap_joinContext_item = -1;          /* JoinContextType */
static int hf_dap_searchInfo = -1;                /* T_searchInfo */
static int hf_dap_entries = -1;                   /* SET_OF_EntryInformation */
static int hf_dap_entries_item = -1;              /* EntryInformation */
static int hf_dap_altMatching = -1;               /* BOOLEAN */
static int hf_dap_uncorrelatedSearchInfo = -1;    /* SET_OF_SearchResult */
static int hf_dap_uncorrelatedSearchInfo_item = -1;  /* SearchResult */
static int hf_dap_unsignedSearchResult = -1;      /* SearchResultData */
static int hf_dap_signedSearchResult = -1;        /* T_signedSearchResult */
static int hf_dap_searchResult = -1;              /* SearchResultData */
static int hf_dap_add_entry = -1;                 /* SET_OF_Attribute */
static int hf_dap_entry_item = -1;                /* Attribute */
static int hf_dap_targetSystem = -1;              /* AccessPoint */
static int hf_dap_unsignedAddEntryArgument = -1;  /* AddEntryArgumentData */
static int hf_dap_signedAddEntryArgument = -1;    /* T_signedAddEntryArgument */
static int hf_dap_addEntryArgument = -1;          /* AddEntryArgumentData */
static int hf_dap_add_entry_information = -1;     /* AddEntryInformation */
static int hf_dap_unsignedAddEntryResult = -1;    /* AddEntryResultData */
static int hf_dap_signedAddEntryResult = -1;      /* T_signedAddEntryResult */
static int hf_dap_addEntryResult = -1;            /* AddEntryResultData */
static int hf_dap_unsignedRemoveEntryArgument = -1;  /* RemoveEntryArgumentData */
static int hf_dap_signedRemoveEntryArgument = -1;  /* T_signedRemoveEntryArgument */
static int hf_dap_removeEntryArgument = -1;       /* RemoveEntryArgumentData */
static int hf_dap_remove_entry_information = -1;  /* RemoveEntryInformation */
static int hf_dap_unsignedRemoveEntryResult = -1;  /* RemoveEntryResultData */
static int hf_dap_signedRemoveEntryResult = -1;   /* T_signedRemoveEntryResult */
static int hf_dap_removeEntryResult = -1;         /* RemoveEntryResultData */
static int hf_dap_changes = -1;                   /* SEQUENCE_OF_EntryModification */
static int hf_dap_changes_item = -1;              /* EntryModification */
static int hf_dap_unsignedModifyEntryArgument = -1;  /* ModifyEntryArgumentData */
static int hf_dap_signedModifyEntryArgument = -1;  /* T_signedModifyEntryArgument */
static int hf_dap_modifyEntryArgument = -1;       /* ModifyEntryArgumentData */
static int hf_dap_modify_entry_information = -1;  /* ModifyEntryInformation */
static int hf_dap_unsignedModifyEntryResult = -1;  /* ModifyEntryResultData */
static int hf_dap_signedModifyEntryResult = -1;   /* T_signedModifyEntryResult */
static int hf_dap_modifyEntryResult = -1;         /* ModifyEntryResultData */
static int hf_dap_addAttribute = -1;              /* Attribute */
static int hf_dap_removeAttribute = -1;           /* AttributeType */
static int hf_dap_addValues = -1;                 /* Attribute */
static int hf_dap_removeValues = -1;              /* Attribute */
static int hf_dap_alterValues = -1;               /* AttributeTypeAndValue */
static int hf_dap_resetValue = -1;                /* AttributeType */
static int hf_dap_newRDN = -1;                    /* RelativeDistinguishedName */
static int hf_dap_deleteOldRDN = -1;              /* BOOLEAN */
static int hf_dap_newSuperior = -1;               /* DistinguishedName */
static int hf_dap_modify_dn_information = -1;     /* ModifyDNInformation */
static int hf_dap_unsignedModifyDNResult = -1;    /* ModifyDNResultData */
static int hf_dap_signedModifyDNResult = -1;      /* T_signedModifyDNResult */
static int hf_dap_modifyDNResult = -1;            /* ModifyDNResultData */
static int hf_dap_unsignedAbandoned = -1;         /* AbandonedData */
static int hf_dap_signedAbandoned = -1;           /* T_signedAbandoned */
static int hf_dap_abandoned = -1;                 /* AbandonedData */
static int hf_dap_abandon_failed_problem = -1;    /* AbandonProblem */
static int hf_dap_operation = -1;                 /* InvokeId */
static int hf_dap_unsignedAbandonFailedError = -1;  /* AbandonFailedErrorData */
static int hf_dap_signedAbandonFailedError = -1;  /* T_signedAbandonFailedError */
static int hf_dap_abandonFailedError = -1;        /* AbandonFailedErrorData */
static int hf_dap_problems = -1;                  /* T_problems */
static int hf_dap_problems_item = -1;             /* T_problems_item */
static int hf_dap_attribute_error_problem = -1;   /* AttributeProblem */
static int hf_dap_value = -1;                     /* AttributeValue */
static int hf_dap_unsignedAttributeError = -1;    /* AttributeErrorData */
static int hf_dap_signedAttributeError = -1;      /* T_signedAttributeError */
static int hf_dap_attributeError = -1;            /* AttributeErrorData */
static int hf_dap_name_error_problem = -1;        /* NameProblem */
static int hf_dap_matched_name = -1;              /* Name */
static int hf_dap_unsignedNameError = -1;         /* NameErrorData */
static int hf_dap_signedNameError = -1;           /* T_signedNameError */
static int hf_dap_nameError = -1;                 /* NameErrorData */
static int hf_dap_candidate = -1;                 /* ContinuationReference */
static int hf_dap_unsignedReferral = -1;          /* ReferralData */
static int hf_dap_signedReferral = -1;            /* T_signedReferral */
static int hf_dap_referral = -1;                  /* ReferralData */
static int hf_dap_security_error_problem = -1;    /* SecurityProblem */
static int hf_dap_spkmInfo = -1;                  /* T_spkmInfo */
static int hf_dap_unsignedSecurityError = -1;     /* SecurityErrorData */
static int hf_dap_signedSecurityError = -1;       /* T_signedSecurityError */
static int hf_dap_securityErrorData = -1;         /* SecurityErrorData */
static int hf_dap_service_error_problem = -1;     /* ServiceProblem */
static int hf_dap_unsignedServiceError = -1;      /* ServiceErrorData */
static int hf_dap_signedServiceError = -1;        /* T_signedServiceError */
static int hf_dap_serviceError = -1;              /* ServiceErrorData */
static int hf_dap_update_error_problem = -1;      /* UpdateProblem */
static int hf_dap_attributeInfo = -1;             /* T_attributeInfo */
static int hf_dap_attributeInfo_item = -1;        /* T_attributeInfo_item */
static int hf_dap_unsignedUpdateError = -1;       /* UpdateErrorData */
static int hf_dap_signedUpdateError = -1;         /* T_signedUpdateError */
static int hf_dap_updateError = -1;               /* UpdateErrorData */
/* named bits */
static int hf_dap_ServiceControlOptions_preferChaining = -1;
static int hf_dap_ServiceControlOptions_chainingProhibited = -1;
static int hf_dap_ServiceControlOptions_localScope = -1;
static int hf_dap_ServiceControlOptions_dontUseCopy = -1;
static int hf_dap_ServiceControlOptions_dontDereferenceAliases = -1;
static int hf_dap_ServiceControlOptions_subentries = -1;
static int hf_dap_ServiceControlOptions_copyShallDo = -1;
static int hf_dap_ServiceControlOptions_partialNameResolution = -1;
static int hf_dap_ServiceControlOptions_manageDSAIT = -1;
static int hf_dap_ServiceControlOptions_noSubtypeMatch = -1;
static int hf_dap_ServiceControlOptions_noSubtypeSelection = -1;
static int hf_dap_ServiceControlOptions_countFamily = -1;
static int hf_dap_Versions_v1 = -1;
static int hf_dap_Versions_v2 = -1;
static int hf_dap_T_permission_add = -1;
static int hf_dap_T_permission_remove = -1;
static int hf_dap_T_permission_rename = -1;
static int hf_dap_T_permission_move = -1;
static int hf_dap_HierarchySelections_self = -1;
static int hf_dap_HierarchySelections_children = -1;
static int hf_dap_HierarchySelections_parent = -1;
static int hf_dap_HierarchySelections_hierarchy = -1;
static int hf_dap_HierarchySelections_top = -1;
static int hf_dap_HierarchySelections_subtree = -1;
static int hf_dap_HierarchySelections_siblings = -1;
static int hf_dap_HierarchySelections_siblingChildren = -1;
static int hf_dap_HierarchySelections_siblingSubtree = -1;
static int hf_dap_HierarchySelections_all = -1;
static int hf_dap_SearchControlOptions_searchAliases = -1;
static int hf_dap_SearchControlOptions_matchedValuesOnly = -1;
static int hf_dap_SearchControlOptions_checkOverspecified = -1;
static int hf_dap_SearchControlOptions_performExactly = -1;
static int hf_dap_SearchControlOptions_includeAllAreas = -1;
static int hf_dap_SearchControlOptions_noSystemRelaxation = -1;
static int hf_dap_SearchControlOptions_dnAttribute = -1;
static int hf_dap_SearchControlOptions_matchOnResidualName = -1;
static int hf_dap_SearchControlOptions_entryCount = -1;
static int hf_dap_SearchControlOptions_useSubset = -1;
static int hf_dap_SearchControlOptions_separateFamilyMembers = -1;
static int hf_dap_SearchControlOptions_searchFamily = -1;

/*--- End of included file: packet-dap-hf.c ---*/
#line 70 "packet-dap-template.c"

/* Initialize the subtree pointers */
static gint ett_dap = -1;

/*--- Included file: packet-dap-ett.c ---*/
#line 1 "packet-dap-ett.c"
static gint ett_dap_CommonResults = -1;
static gint ett_dap_SEQUENCE_OF_Attribute = -1;
static gint ett_dap_ServiceControls = -1;
static gint ett_dap_T_manageDSAITPlaneRef = -1;
static gint ett_dap_ServiceControlOptions = -1;
static gint ett_dap_EntryInformationSelection = -1;
static gint ett_dap_T_attributes = -1;
static gint ett_dap_SET_OF_AttributeType = -1;
static gint ett_dap_T_extraAttributes = -1;
static gint ett_dap_ContextSelection = -1;
static gint ett_dap_SET_OF_TypeAndContextAssertion = -1;
static gint ett_dap_TypeAndContextAssertion = -1;
static gint ett_dap_T_contextAssertions = -1;
static gint ett_dap_SEQUENCE_OF_ContextAssertion = -1;
static gint ett_dap_SET_OF_ContextAssertion = -1;
static gint ett_dap_FamilyReturn = -1;
static gint ett_dap_T_familySelect = -1;
static gint ett_dap_EntryInformation = -1;
static gint ett_dap_T_information = -1;
static gint ett_dap_EntryInformationItem = -1;
static gint ett_dap_FamilyEntries = -1;
static gint ett_dap_SEQUENCE_OF_FamilyEntry = -1;
static gint ett_dap_FamilyEntry = -1;
static gint ett_dap_FamilyInformation = -1;
static gint ett_dap_T_information_item = -1;
static gint ett_dap_SEQUENCE_OF_FamilyEntries = -1;
static gint ett_dap_Filter = -1;
static gint ett_dap_SetOfFilter = -1;
static gint ett_dap_FilterItem = -1;
static gint ett_dap_T_substrings = -1;
static gint ett_dap_T_strings = -1;
static gint ett_dap_T_strings_item = -1;
static gint ett_dap_MatchingRuleAssertion = -1;
static gint ett_dap_T_matchingRule = -1;
static gint ett_dap_PagedResultsRequest = -1;
static gint ett_dap_T_newRequest = -1;
static gint ett_dap_SEQUENCE_OF_SortKey = -1;
static gint ett_dap_SortKey = -1;
static gint ett_dap_SecurityParameters = -1;
static gint ett_dap_Time = -1;
static gint ett_dap_DirectoryBindArgument = -1;
static gint ett_dap_Credentials = -1;
static gint ett_dap_SimpleCredentials = -1;
static gint ett_dap_T_validity = -1;
static gint ett_dap_T_time1 = -1;
static gint ett_dap_T_time2 = -1;
static gint ett_dap_T_password = -1;
static gint ett_dap_T_protected = -1;
static gint ett_dap_StrongCredentials = -1;
static gint ett_dap_SpkmCredentials = -1;
static gint ett_dap_Versions = -1;
static gint ett_dap_DirectoryBindErrorData = -1;
static gint ett_dap_T_error = -1;
static gint ett_dap_DirectoryBindError = -1;
static gint ett_dap_T_signedDirectoryBindError = -1;
static gint ett_dap_ReadArgumentData = -1;
static gint ett_dap_Name = -1;
static gint ett_dap_ReadArgument = -1;
static gint ett_dap_T_signedReadArgument = -1;
static gint ett_dap_ReadResultData = -1;
static gint ett_dap_ReadResult = -1;
static gint ett_dap_T_signedReadResult = -1;
static gint ett_dap_ModifyRights = -1;
static gint ett_dap_ModifyRights_item = -1;
static gint ett_dap_T_item = -1;
static gint ett_dap_T_permission = -1;
static gint ett_dap_CompareArgumentData = -1;
static gint ett_dap_CompareArgument = -1;
static gint ett_dap_T_signedCompareArgument = -1;
static gint ett_dap_CompareResultData = -1;
static gint ett_dap_CompareResult = -1;
static gint ett_dap_T_signedCompareResult = -1;
static gint ett_dap_AbandonArgumentData = -1;
static gint ett_dap_AbandonArgument = -1;
static gint ett_dap_T_signedAbandonArgument = -1;
static gint ett_dap_AbandonResultData = -1;
static gint ett_dap_AbandonResult = -1;
static gint ett_dap_AbandonInformation = -1;
static gint ett_dap_T_signedAbandonResult = -1;
static gint ett_dap_ListArgumentData = -1;
static gint ett_dap_ListArgument = -1;
static gint ett_dap_T_signedListArgument = -1;
static gint ett_dap_ListResultData = -1;
static gint ett_dap_T_listInfo = -1;
static gint ett_dap_T_subordinates = -1;
static gint ett_dap_T_subordinates_item = -1;
static gint ett_dap_SET_OF_ListResult = -1;
static gint ett_dap_ListResult = -1;
static gint ett_dap_T_signedListResult = -1;
static gint ett_dap_PartialOutcomeQualifier = -1;
static gint ett_dap_SET_OF_ContinuationReference = -1;
static gint ett_dap_T_unknownErrors = -1;
static gint ett_dap_T_entryCount = -1;
static gint ett_dap_SearchArgumentData = -1;
static gint ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument = -1;
static gint ett_dap_SearchArgument = -1;
static gint ett_dap_T_signedSearchArgument = -1;
static gint ett_dap_HierarchySelections = -1;
static gint ett_dap_SearchControlOptions = -1;
static gint ett_dap_JoinArgument = -1;
static gint ett_dap_SEQUENCE_OF_JoinAttPair = -1;
static gint ett_dap_JoinAttPair = -1;
static gint ett_dap_SEQUENCE_OF_JoinContextType = -1;
static gint ett_dap_SearchResultData = -1;
static gint ett_dap_T_searchInfo = -1;
static gint ett_dap_SET_OF_EntryInformation = -1;
static gint ett_dap_SET_OF_SearchResult = -1;
static gint ett_dap_SearchResult = -1;
static gint ett_dap_T_signedSearchResult = -1;
static gint ett_dap_AddEntryArgumentData = -1;
static gint ett_dap_SET_OF_Attribute = -1;
static gint ett_dap_AddEntryArgument = -1;
static gint ett_dap_T_signedAddEntryArgument = -1;
static gint ett_dap_AddEntryResultData = -1;
static gint ett_dap_AddEntryResult = -1;
static gint ett_dap_AddEntryInformation = -1;
static gint ett_dap_T_signedAddEntryResult = -1;
static gint ett_dap_RemoveEntryArgumentData = -1;
static gint ett_dap_RemoveEntryArgument = -1;
static gint ett_dap_T_signedRemoveEntryArgument = -1;
static gint ett_dap_RemoveEntryResultData = -1;
static gint ett_dap_RemoveEntryResult = -1;
static gint ett_dap_RemoveEntryInformation = -1;
static gint ett_dap_T_signedRemoveEntryResult = -1;
static gint ett_dap_ModifyEntryArgumentData = -1;
static gint ett_dap_SEQUENCE_OF_EntryModification = -1;
static gint ett_dap_ModifyEntryArgument = -1;
static gint ett_dap_T_signedModifyEntryArgument = -1;
static gint ett_dap_ModifyEntryResultData = -1;
static gint ett_dap_ModifyEntryResult = -1;
static gint ett_dap_ModifyEntryInformation = -1;
static gint ett_dap_T_signedModifyEntryResult = -1;
static gint ett_dap_EntryModification = -1;
static gint ett_dap_ModifyDNArgument = -1;
static gint ett_dap_ModifyDNResultData = -1;
static gint ett_dap_ModifyDNResult = -1;
static gint ett_dap_ModifyDNInformation = -1;
static gint ett_dap_T_signedModifyDNResult = -1;
static gint ett_dap_AbandonedData = -1;
static gint ett_dap_Abandoned = -1;
static gint ett_dap_T_signedAbandoned = -1;
static gint ett_dap_AbandonFailedErrorData = -1;
static gint ett_dap_AbandonFailedError = -1;
static gint ett_dap_T_signedAbandonFailedError = -1;
static gint ett_dap_AttributeErrorData = -1;
static gint ett_dap_T_problems = -1;
static gint ett_dap_T_problems_item = -1;
static gint ett_dap_AttributeError = -1;
static gint ett_dap_T_signedAttributeError = -1;
static gint ett_dap_NameErrorData = -1;
static gint ett_dap_NameError = -1;
static gint ett_dap_T_signedNameError = -1;
static gint ett_dap_ReferralData = -1;
static gint ett_dap_Referral = -1;
static gint ett_dap_T_signedReferral = -1;
static gint ett_dap_SecurityErrorData = -1;
static gint ett_dap_SecurityError = -1;
static gint ett_dap_T_signedSecurityError = -1;
static gint ett_dap_ServiceErrorData = -1;
static gint ett_dap_ServiceError = -1;
static gint ett_dap_T_signedServiceError = -1;
static gint ett_dap_UpdateErrorData = -1;
static gint ett_dap_T_attributeInfo = -1;
static gint ett_dap_T_attributeInfo_item = -1;
static gint ett_dap_UpdateError = -1;
static gint ett_dap_T_signedUpdateError = -1;

/*--- End of included file: packet-dap-ett.c ---*/
#line 74 "packet-dap-template.c"


/*--- Included file: packet-dap-fn.c ---*/
#line 1 "packet-dap-fn.c"
/*--- Cyclic dependencies ---*/

/* FamilyEntries -> FamilyEntries/familyEntries -> FamilyEntry -> FamilyEntry/family-info -> FamilyEntries */
static int dissect_dap_FamilyEntries(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_family_info_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_FamilyEntries(FALSE, tvb, offset, pinfo, tree, hf_dap_family_info_item);
}

/* Filter -> SetOfFilter -> Filter */
/* Filter -> Filter */
static int dissect_dap_Filter(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_not(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Filter(FALSE, tvb, offset, pinfo, tree, hf_dap_not);
}
static int dissect_SetOfFilter_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Filter(FALSE, tvb, offset, pinfo, tree, hf_dap_SetOfFilter_item);
}
static int dissect_overspecFilter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Filter(FALSE, tvb, offset, pinfo, tree, hf_dap_overspecFilter);
}
static int dissect_filter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Filter(FALSE, tvb, offset, pinfo, tree, hf_dap_filter);
}
static int dissect_extendedFilter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Filter(FALSE, tvb, offset, pinfo, tree, hf_dap_extendedFilter);
}
static int dissect_joinFilter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Filter(FALSE, tvb, offset, pinfo, tree, hf_dap_joinFilter);
}

/* ListResultData -> ListResultData/uncorrelatedListInfo -> ListResult -> ListResultData */
/* ListResultData -> ListResultData/uncorrelatedListInfo -> ListResult -> ListResult/signedListResult -> ListResultData */
static int dissect_dap_ListResultData(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_unsignedListResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ListResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedListResult);
}
static int dissect_listResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ListResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_listResult);
}

/* SearchResultData -> SearchResultData/uncorrelatedSearchInfo -> SearchResult -> SearchResultData */
/* SearchResultData -> SearchResultData/uncorrelatedSearchInfo -> SearchResult -> SearchResult/signedSearchResult -> SearchResultData */
static int dissect_dap_SearchResultData(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_unsignedSearchResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SearchResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedSearchResult);
}
static int dissect_searchResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SearchResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_searchResult);
}


/*--- Fields for imported types ---*/

static int dissect_performer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dap_performer);
}
static int dissect_notification_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dap_notification_item);
}
static int dissect_agreementID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_disp_AgreementID(FALSE, tvb, offset, pinfo, tree, hf_dap_agreementID);
}
static int dissect_select_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_select_item);
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_type);
}
static int dissect_preference_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_preference_item);
}
static int dissect_all_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_all_item);
}
static int dissect_attributeType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_attributeType);
}
static int dissect_attribute(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dap_attribute);
}
static int dissect_rdn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RelativeDistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dap_rdn);
}
static int dissect_equality(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_equality);
}
static int dissect_control(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dap_control);
}
static int dissect_greaterOrEqual(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_greaterOrEqual);
}
static int dissect_lessOrEqual(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_lessOrEqual);
}
static int dissect_present(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_present);
}
static int dissect_approximateMatch(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_approximateMatch);
}
static int dissect_contextPresent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeTypeAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_contextPresent);
}
static int dissect_certification_path(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificationPath(FALSE, tvb, offset, pinfo, tree, hf_dap_certification_path);
}
static int dissect_distinguished_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dap_distinguished_name);
}
static int dissect_operationCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_Code(FALSE, tvb, offset, pinfo, tree, hf_dap_operationCode);
}
static int dissect_attributeCertificationPath(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AttributeCertificationPath(FALSE, tvb, offset, pinfo, tree, hf_dap_attributeCertificationPath);
}
static int dissect_errorCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_Code(FALSE, tvb, offset, pinfo, tree, hf_dap_errorCode);
}
static int dissect_externalProcedure(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(FALSE, tvb, offset, pinfo, tree, hf_dap_externalProcedure);
}
static int dissect_algorithmIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_dap_algorithmIdentifier);
}
static int dissect_requestor(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dap_requestor);
}
static int dissect_operationProgress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_OperationProgress(FALSE, tvb, offset, pinfo, tree, hf_dap_operationProgress);
}
static int dissect_referenceType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ReferenceType(FALSE, tvb, offset, pinfo, tree, hf_dap_referenceType);
}
static int dissect_rdnSequence(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RDNSequence(FALSE, tvb, offset, pinfo, tree, hf_dap_rdnSequence);
}
static int dissect_attribute_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_attribute_type);
}
static int dissect_value_assertion(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_value_assertion);
}
static int dissect_purported(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_purported);
}
static int dissect_matchedSubtype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_matchedSubtype);
}
static int dissect_invokeID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_InvokeId(FALSE, tvb, offset, pinfo, tree, hf_dap_invokeID);
}
static int dissect_unexplored_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ContinuationReference(FALSE, tvb, offset, pinfo, tree, hf_dap_unexplored_item);
}
static int dissect_relaxation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RelaxationPolicy(FALSE, tvb, offset, pinfo, tree, hf_dap_relaxation);
}
static int dissect_baseAtt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_baseAtt);
}
static int dissect_joinAtt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_joinAtt);
}
static int dissect_entry_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dap_entry_item);
}
static int dissect_targetSystem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_AccessPoint(FALSE, tvb, offset, pinfo, tree, hf_dap_targetSystem);
}
static int dissect_addAttribute(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dap_addAttribute);
}
static int dissect_removeAttribute(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_removeAttribute);
}
static int dissect_addValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dap_addValues);
}
static int dissect_removeValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dap_removeValues);
}
static int dissect_alterValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_AttributeTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_dap_alterValues);
}
static int dissect_resetValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_resetValue);
}
static int dissect_newRDN(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RelativeDistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dap_newRDN);
}
static int dissect_newSuperior(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dap_newSuperior);
}
static int dissect_operation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ros_InvokeId(FALSE, tvb, offset, pinfo, tree, hf_dap_operation);
}
static int dissect_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_dap_value);
}
static int dissect_candidate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_ContinuationReference(FALSE, tvb, offset, pinfo, tree, hf_dap_candidate);
}


static const value_string dap_FamilyGrouping_vals[] = {
  {   1, "entryOnly" },
  {   2, "compoundEntry" },
  {   3, "strands" },
  {   4, "multiStrand" },
  { 0, NULL }
};


static int
dissect_dap_FamilyGrouping(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_familyGrouping(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_FamilyGrouping(FALSE, tvb, offset, pinfo, tree, hf_dap_familyGrouping);
}



static int
dissect_dap_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_utcTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_UTCTime(FALSE, tvb, offset, pinfo, tree, hf_dap_utcTime);
}
static int dissect_utc(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_UTCTime(FALSE, tvb, offset, pinfo, tree, hf_dap_utc);
}



static int
dissect_dap_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_generalizedTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_dap_generalizedTime);
}
static int dissect_gt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_dap_gt);
}


static const value_string dap_Time_vals[] = {
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
dissect_dap_Time(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Time_choice, hf_index, ett_dap_Time,
                                 NULL);

  return offset;
}
static int dissect_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Time(FALSE, tvb, offset, pinfo, tree, hf_dap_time);
}



static int
dissect_dap_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_random(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_dap_random);
}
static int dissect_response(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_dap_response);
}
static int dissect_random1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_dap_random1);
}
static int dissect_random2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_dap_random2);
}
static int dissect_encrypted(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_dap_encrypted);
}
static int dissect_criticalExtensions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_dap_criticalExtensions);
}


static const value_string dap_ProtectionRequest_vals[] = {
  {   0, "none" },
  {   1, "signed" },
  {   2, "encrypted" },
  {   3, "signed-encrypted" },
  { 0, NULL }
};


static int
dissect_dap_ProtectionRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_target(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ProtectionRequest(FALSE, tvb, offset, pinfo, tree, hf_dap_target);
}


static const value_string dap_ErrorProtectionRequest_vals[] = {
  {   0, "none" },
  {   1, "signed" },
  {   2, "encrypted" },
  {   3, "signed-encrypted" },
  { 0, NULL }
};


static int
dissect_dap_ErrorProtectionRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_errorProtection(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ErrorProtectionRequest(FALSE, tvb, offset, pinfo, tree, hf_dap_errorProtection);
}


static const ber_sequence_t SecurityParameters_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_certification_path },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_distinguished_name },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_time },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_random },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_target },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_response },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_operationCode },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_attributeCertificationPath },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_errorProtection },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_errorCode },
  { 0, 0, 0, NULL }
};

int
dissect_dap_SecurityParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SecurityParameters_set, hf_index, ett_dap_SecurityParameters);

  return offset;
}
static int dissect_securityParameters(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SecurityParameters(FALSE, tvb, offset, pinfo, tree, hf_dap_securityParameters);
}



static int
dissect_dap_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_aliasDereferenced(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_aliasDereferenced);
}
static int dissect_returnContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_returnContexts);
}
static int dissect_fromEntry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_fromEntry);
}
static int dissect_incompleteEntry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_incompleteEntry);
}
static int dissect_partialName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_partialName);
}
static int dissect_derivedEntry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_derivedEntry);
}
static int dissect_dnAttributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_dnAttributes);
}
static int dissect_reverse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_reverse);
}
static int dissect_unmerged(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_unmerged);
}
static int dissect_modifyRightsRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_modifyRightsRequest);
}
static int dissect_entryOnly(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_entryOnly);
}
static int dissect_nameResolveOnMaster(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_nameResolveOnMaster);
}
static int dissect_matched(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_matched);
}
static int dissect_listFamily(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_listFamily);
}
static int dissect_aliasEntry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_aliasEntry);
}
static int dissect_unavailableCriticalExtensions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_unavailableCriticalExtensions);
}
static int dissect_searchAliases(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_searchAliases);
}
static int dissect_matchedValuesOnly(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_matchedValuesOnly);
}
static int dissect_checkOverspecified(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_checkOverspecified);
}
static int dissect_altMatching(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_altMatching);
}
static int dissect_deleteOldRDN(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dap_deleteOldRDN);
}


static const ber_sequence_t SEQUENCE_OF_Attribute_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_notification_item },
};

static int
dissect_dap_SEQUENCE_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Attribute_sequence_of, hf_index, ett_dap_SEQUENCE_OF_Attribute);

  return offset;
}
static int dissect_notification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SEQUENCE_OF_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dap_notification);
}


static const ber_sequence_t CommonResults_set[] = {
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

int
dissect_dap_CommonResults(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CommonResults_set, hf_index, ett_dap_CommonResults);

  return offset;
}


static const asn_namedbit ServiceControlOptions_bits[] = {
  {  0, &hf_dap_ServiceControlOptions_preferChaining, -1, -1, "preferChaining", NULL },
  {  1, &hf_dap_ServiceControlOptions_chainingProhibited, -1, -1, "chainingProhibited", NULL },
  {  2, &hf_dap_ServiceControlOptions_localScope, -1, -1, "localScope", NULL },
  {  3, &hf_dap_ServiceControlOptions_dontUseCopy, -1, -1, "dontUseCopy", NULL },
  {  4, &hf_dap_ServiceControlOptions_dontDereferenceAliases, -1, -1, "dontDereferenceAliases", NULL },
  {  5, &hf_dap_ServiceControlOptions_subentries, -1, -1, "subentries", NULL },
  {  6, &hf_dap_ServiceControlOptions_copyShallDo, -1, -1, "copyShallDo", NULL },
  {  7, &hf_dap_ServiceControlOptions_partialNameResolution, -1, -1, "partialNameResolution", NULL },
  {  8, &hf_dap_ServiceControlOptions_manageDSAIT, -1, -1, "manageDSAIT", NULL },
  {  9, &hf_dap_ServiceControlOptions_noSubtypeMatch, -1, -1, "noSubtypeMatch", NULL },
  { 10, &hf_dap_ServiceControlOptions_noSubtypeSelection, -1, -1, "noSubtypeSelection", NULL },
  { 11, &hf_dap_ServiceControlOptions_countFamily, -1, -1, "countFamily", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_dap_ServiceControlOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    ServiceControlOptions_bits, hf_index, ett_dap_ServiceControlOptions,
                                    NULL);

  return offset;
}
static int dissect_options(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ServiceControlOptions(FALSE, tvb, offset, pinfo, tree, hf_dap_options);
}


static const value_string dap_T_priority_vals[] = {
  {   0, "low" },
  {   1, "medium" },
  {   2, "high" },
  { 0, NULL }
};


static int
dissect_dap_T_priority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_priority(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_priority(FALSE, tvb, offset, pinfo, tree, hf_dap_priority);
}



static int
dissect_dap_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_timeLimit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dap_timeLimit);
}
static int dissect_sizeLimit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dap_sizeLimit);
}
static int dissect_attributeSizeLimit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dap_attributeSizeLimit);
}
static int dissect_userClass(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dap_userClass);
}
static int dissect_pageSize(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dap_pageSize);
}
static int dissect_aliasedRDNs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dap_aliasedRDNs);
}
static int dissect_bestEstimate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dap_bestEstimate);
}
static int dissect_lowEstimate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dap_lowEstimate);
}
static int dissect_extendedArea(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dap_extendedArea);
}


static const value_string dap_T_scopeOfReferral_vals[] = {
  {   0, "dmd" },
  {   1, "country" },
  { 0, NULL }
};


static int
dissect_dap_T_scopeOfReferral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_scopeOfReferral(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_scopeOfReferral(FALSE, tvb, offset, pinfo, tree, hf_dap_scopeOfReferral);
}


static const value_string dap_Name_vals[] = {
  {   0, "rdnSequence" },
  { 0, NULL }
};

static const ber_choice_t Name_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_rdnSequence },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_Name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 257 "dap.cnf"
	const char *dn;

	  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Name_choice, hf_index, ett_dap_Name,
                                 NULL);


	if(check_col(pinfo->cinfo, COL_INFO)) {
		dn = x509if_get_last_dn();
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", (dn && *dn) ? dn : "(root)");
	}



  return offset;
}
static int dissect_dsaName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Name(FALSE, tvb, offset, pinfo, tree, hf_dap_dsaName);
}
static int dissect_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Name(FALSE, tvb, offset, pinfo, tree, hf_dap_name);
}
static int dissect_object(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Name(FALSE, tvb, offset, pinfo, tree, hf_dap_object);
}
static int dissect_baseObject(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Name(FALSE, tvb, offset, pinfo, tree, hf_dap_baseObject);
}
static int dissect_joinBaseObject(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Name(FALSE, tvb, offset, pinfo, tree, hf_dap_joinBaseObject);
}
static int dissect_matched_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Name(FALSE, tvb, offset, pinfo, tree, hf_dap_matched_name);
}


static const ber_sequence_t T_manageDSAITPlaneRef_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dsaName },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_agreementID },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_manageDSAITPlaneRef(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_manageDSAITPlaneRef_sequence, hf_index, ett_dap_T_manageDSAITPlaneRef);

  return offset;
}
static int dissect_manageDSAITPlaneRef(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_manageDSAITPlaneRef(FALSE, tvb, offset, pinfo, tree, hf_dap_manageDSAITPlaneRef);
}



static int
dissect_dap_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_serviceType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_dap_serviceType);
}
static int dissect_familySelect_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_dap_familySelect_item);
}
static int dissect_family_class(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_dap_family_class);
}
static int dissect_sunstringType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_dap_sunstringType);
}
static int dissect_matchingRule_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_dap_matchingRule_item);
}
static int dissect_orderingRule(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_dap_orderingRule);
}
static int dissect_unknownErrors_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_dap_unknownErrors_item);
}


static const ber_sequence_t ServiceControls_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_options },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_priority },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_timeLimit },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_sizeLimit },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_scopeOfReferral },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_attributeSizeLimit },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_manageDSAITPlaneRef },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_serviceType },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_userClass },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ServiceControls(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ServiceControls_set, hf_index, ett_dap_ServiceControls);

  return offset;
}
static int dissect_serviceControls(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ServiceControls(FALSE, tvb, offset, pinfo, tree, hf_dap_serviceControls);
}



static int
dissect_dap_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_allUserAttributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_NULL(FALSE, tvb, offset, pinfo, tree, hf_dap_allUserAttributes);
}
static int dissect_allOperationalAttributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_NULL(FALSE, tvb, offset, pinfo, tree, hf_dap_allOperationalAttributes);
}
static int dissect_allContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_NULL(FALSE, tvb, offset, pinfo, tree, hf_dap_allContexts);
}
static int dissect_item_entry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_NULL(FALSE, tvb, offset, pinfo, tree, hf_dap_item_entry);
}
static int dissect_null(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_NULL(FALSE, tvb, offset, pinfo, tree, hf_dap_null);
}


static const ber_sequence_t SET_OF_AttributeType_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_select_item },
};

static int
dissect_dap_SET_OF_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AttributeType_set_of, hf_index, ett_dap_SET_OF_AttributeType);

  return offset;
}
static int dissect_select(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SET_OF_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dap_select);
}


static const value_string dap_T_attributes_vals[] = {
  {   0, "allUserAttributes" },
  {   1, "select" },
  { 0, NULL }
};

static const ber_choice_t T_attributes_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_allUserAttributes },
  {   1, BER_CLASS_CON, 1, 0, dissect_select },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_attributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_attributes_choice, hf_index, ett_dap_T_attributes,
                                 NULL);

  return offset;
}
static int dissect_attributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_attributes(FALSE, tvb, offset, pinfo, tree, hf_dap_attributes);
}


static const value_string dap_T_infoTypes_vals[] = {
  {   0, "attributeTypesOnly" },
  {   1, "attributeTypesAndValues" },
  { 0, NULL }
};


static int
dissect_dap_T_infoTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_infoTypes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_infoTypes(FALSE, tvb, offset, pinfo, tree, hf_dap_infoTypes);
}


static const value_string dap_T_extraAttributes_vals[] = {
  {   3, "allOperationalAttributes" },
  {   4, "select" },
  { 0, NULL }
};

static const ber_choice_t T_extraAttributes_choice[] = {
  {   3, BER_CLASS_CON, 3, 0, dissect_allOperationalAttributes },
  {   4, BER_CLASS_CON, 4, 0, dissect_select },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_extraAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_extraAttributes_choice, hf_index, ett_dap_T_extraAttributes,
                                 NULL);

  return offset;
}
static int dissect_extraAttributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_extraAttributes(FALSE, tvb, offset, pinfo, tree, hf_dap_extraAttributes);
}


static const ber_sequence_t SEQUENCE_OF_ContextAssertion_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_preference_item },
};

static int
dissect_dap_SEQUENCE_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_ContextAssertion_sequence_of, hf_index, ett_dap_SEQUENCE_OF_ContextAssertion);

  return offset;
}
static int dissect_preference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SEQUENCE_OF_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_preference);
}


static const ber_sequence_t SET_OF_ContextAssertion_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_all_item },
};

static int
dissect_dap_SET_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ContextAssertion_set_of, hf_index, ett_dap_SET_OF_ContextAssertion);

  return offset;
}
static int dissect_all(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SET_OF_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_all);
}


static const value_string dap_T_contextAssertions_vals[] = {
  {   0, "preference" },
  {   1, "all" },
  { 0, NULL }
};

static const ber_choice_t T_contextAssertions_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_preference },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_all },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_contextAssertions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_contextAssertions_choice, hf_index, ett_dap_T_contextAssertions,
                                 NULL);

  return offset;
}
static int dissect_contextAssertions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_contextAssertions(FALSE, tvb, offset, pinfo, tree, hf_dap_contextAssertions);
}


static const ber_sequence_t TypeAndContextAssertion_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_contextAssertions },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_TypeAndContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TypeAndContextAssertion_sequence, hf_index, ett_dap_TypeAndContextAssertion);

  return offset;
}
static int dissect_selectedContexts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_TypeAndContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_selectedContexts_item);
}


static const ber_sequence_t SET_OF_TypeAndContextAssertion_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_selectedContexts_item },
};

static int
dissect_dap_SET_OF_TypeAndContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_TypeAndContextAssertion_set_of, hf_index, ett_dap_SET_OF_TypeAndContextAssertion);

  return offset;
}
static int dissect_selectedContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SET_OF_TypeAndContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_selectedContexts);
}


const value_string dap_ContextSelection_vals[] = {
  {   0, "allContexts" },
  {   1, "selectedContexts" },
  { 0, NULL }
};

static const ber_choice_t ContextSelection_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_allContexts },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_selectedContexts },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_ContextSelection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ContextSelection_choice, hf_index, ett_dap_ContextSelection,
                                 NULL);

  return offset;
}
static int dissect_contextSelection(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ContextSelection(FALSE, tvb, offset, pinfo, tree, hf_dap_contextSelection);
}
static int dissect_operationContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ContextSelection(FALSE, tvb, offset, pinfo, tree, hf_dap_operationContexts);
}


static const value_string dap_T_memberSelect_vals[] = {
  {   1, "contributingEntriesOnly" },
  {   2, "participatingEntriesOnly" },
  {   3, "compoundEntry" },
  { 0, NULL }
};


static int
dissect_dap_T_memberSelect(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_memberSelect(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_memberSelect(FALSE, tvb, offset, pinfo, tree, hf_dap_memberSelect);
}


static const ber_sequence_t T_familySelect_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_familySelect_item },
};

static int
dissect_dap_T_familySelect(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_familySelect_sequence_of, hf_index, ett_dap_T_familySelect);

  return offset;
}
static int dissect_familySelect(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_familySelect(FALSE, tvb, offset, pinfo, tree, hf_dap_familySelect);
}


static const ber_sequence_t FamilyReturn_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_memberSelect },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_familySelect },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_FamilyReturn(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FamilyReturn_sequence, hf_index, ett_dap_FamilyReturn);

  return offset;
}
static int dissect_familyReturn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_FamilyReturn(FALSE, tvb, offset, pinfo, tree, hf_dap_familyReturn);
}


static const ber_sequence_t EntryInformationSelection_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_attributes },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_infoTypes },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extraAttributes },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_contextSelection },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_returnContexts },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_familyReturn },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_EntryInformationSelection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              EntryInformationSelection_set, hf_index, ett_dap_EntryInformationSelection);

  return offset;
}
static int dissect_selection(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_EntryInformationSelection(FALSE, tvb, offset, pinfo, tree, hf_dap_selection);
}
static int dissect_joinSelection(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_EntryInformationSelection(FALSE, tvb, offset, pinfo, tree, hf_dap_joinSelection);
}


static const value_string dap_EntryInformationItem_vals[] = {
  {   0, "attributeType" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t EntryInformationItem_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attributeType },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_attribute },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_EntryInformationItem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 EntryInformationItem_choice, hf_index, ett_dap_EntryInformationItem,
                                 NULL);

  return offset;
}
static int dissect_entry_information_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_EntryInformationItem(FALSE, tvb, offset, pinfo, tree, hf_dap_entry_information_item);
}


static const ber_sequence_t T_information_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_entry_information_item },
};

static int
dissect_dap_T_information(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_information_set_of, hf_index, ett_dap_T_information);

  return offset;
}
static int dissect_entry_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_information(FALSE, tvb, offset, pinfo, tree, hf_dap_entry_information);
}


static const ber_sequence_t EntryInformation_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_name },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_fromEntry },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_entry_information },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_incompleteEntry },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_partialName },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_derivedEntry },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_EntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EntryInformation_sequence, hf_index, ett_dap_EntryInformation);

  return offset;
}
static int dissect_entry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_EntryInformation(FALSE, tvb, offset, pinfo, tree, hf_dap_entry);
}
static int dissect_entries_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_EntryInformation(FALSE, tvb, offset, pinfo, tree, hf_dap_entries_item);
}


static const value_string dap_T_information_item_vals[] = {
  {   0, "attributeType" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t T_information_item_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attributeType },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_attribute },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_information_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_information_item_choice, hf_index, ett_dap_T_information_item,
                                 NULL);

  return offset;
}
static int dissect_information_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_information_item(FALSE, tvb, offset, pinfo, tree, hf_dap_information_item);
}


static const ber_sequence_t FamilyInformation_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_information_item },
};

static int
dissect_dap_FamilyInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      FamilyInformation_sequence_of, hf_index, ett_dap_FamilyInformation);

  return offset;
}
static int dissect_family_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_FamilyInformation(FALSE, tvb, offset, pinfo, tree, hf_dap_family_information);
}


static const ber_sequence_t SEQUENCE_OF_FamilyEntries_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_family_info_item },
};

static int
dissect_dap_SEQUENCE_OF_FamilyEntries(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_FamilyEntries_sequence_of, hf_index, ett_dap_SEQUENCE_OF_FamilyEntries);

  return offset;
}
static int dissect_family_info(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SEQUENCE_OF_FamilyEntries(FALSE, tvb, offset, pinfo, tree, hf_dap_family_info);
}


static const ber_sequence_t FamilyEntry_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_rdn },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_family_information },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_family_info },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_FamilyEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FamilyEntry_sequence, hf_index, ett_dap_FamilyEntry);

  return offset;
}
static int dissect_familyEntries_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_FamilyEntry(FALSE, tvb, offset, pinfo, tree, hf_dap_familyEntries_item);
}


static const ber_sequence_t SEQUENCE_OF_FamilyEntry_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_familyEntries_item },
};

static int
dissect_dap_SEQUENCE_OF_FamilyEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_FamilyEntry_sequence_of, hf_index, ett_dap_SEQUENCE_OF_FamilyEntry);

  return offset;
}
static int dissect_familyEntries(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SEQUENCE_OF_FamilyEntry(FALSE, tvb, offset, pinfo, tree, hf_dap_familyEntries);
}


static const ber_sequence_t FamilyEntries_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_family_class },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_familyEntries },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_FamilyEntries(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FamilyEntries_sequence, hf_index, ett_dap_FamilyEntries);

  return offset;
}



static int
dissect_dap_T_initial(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 117 "dap.cnf"
	proto_item *it;
	it = proto_tree_add_item(tree, hf_index, tvb, offset, -1, FALSE);
	proto_item_append_text(it," XXX: Not yet implemented!");



  return offset;
}
static int dissect_initial(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_initial(FALSE, tvb, offset, pinfo, tree, hf_dap_initial);
}



static int
dissect_dap_T_any(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 122 "dap.cnf"
	/* XXX: not yet implemented */



  return offset;
}
static int dissect_any(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_any(FALSE, tvb, offset, pinfo, tree, hf_dap_any);
}



static int
dissect_dap_T_final(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 125 "dap.cnf"
	/* XXX: not yet implemented */



  return offset;
}
static int dissect_final(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_final(FALSE, tvb, offset, pinfo, tree, hf_dap_final);
}


static const value_string dap_T_strings_item_vals[] = {
  {   0, "initial" },
  {   1, "any" },
  {   2, "final" },
  {   3, "control" },
  { 0, NULL }
};

static const ber_choice_t T_strings_item_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_initial },
  {   1, BER_CLASS_CON, 1, 0, dissect_any },
  {   2, BER_CLASS_CON, 2, 0, dissect_final },
  {   3, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_control },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_strings_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_strings_item_choice, hf_index, ett_dap_T_strings_item,
                                 NULL);

  return offset;
}
static int dissect_strings_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_strings_item(FALSE, tvb, offset, pinfo, tree, hf_dap_strings_item);
}


static const ber_sequence_t T_strings_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_strings_item },
};

static int
dissect_dap_T_strings(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_strings_sequence_of, hf_index, ett_dap_T_strings);

  return offset;
}
static int dissect_strings(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_strings(FALSE, tvb, offset, pinfo, tree, hf_dap_strings);
}


static const ber_sequence_t T_substrings_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_sunstringType },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_strings },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_substrings(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_substrings_sequence, hf_index, ett_dap_T_substrings);

  return offset;
}
static int dissect_substrings(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_substrings(FALSE, tvb, offset, pinfo, tree, hf_dap_substrings);
}


static const ber_sequence_t T_matchingRule_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_matchingRule_item },
};

static int
dissect_dap_T_matchingRule(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_matchingRule_set_of, hf_index, ett_dap_T_matchingRule);

  return offset;
}
static int dissect_matchingRule(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_matchingRule(FALSE, tvb, offset, pinfo, tree, hf_dap_matchingRule);
}



static int
dissect_dap_T_matchValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 128 "dap.cnf"
	/* XXX: not yet implemented */



  return offset;
}
static int dissect_matchValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_matchValue(FALSE, tvb, offset, pinfo, tree, hf_dap_matchValue);
}


static const ber_sequence_t MatchingRuleAssertion_sequence[] = {
  { BER_CLASS_CON, 1, 0, dissect_matchingRule },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_type },
  { BER_CLASS_CON, 3, 0, dissect_matchValue },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dnAttributes },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_MatchingRuleAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MatchingRuleAssertion_sequence, hf_index, ett_dap_MatchingRuleAssertion);

  return offset;
}
static int dissect_extensibleMatch(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_MatchingRuleAssertion(FALSE, tvb, offset, pinfo, tree, hf_dap_extensibleMatch);
}


static const value_string dap_FilterItem_vals[] = {
  {   0, "equality" },
  {   1, "substrings" },
  {   2, "greaterOrEqual" },
  {   3, "lessOrEqual" },
  {   4, "present" },
  {   5, "approximateMatch" },
  {   6, "extensibleMatch" },
  {   7, "contextPresent" },
  { 0, NULL }
};

static const ber_choice_t FilterItem_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_equality },
  {   1, BER_CLASS_CON, 1, 0, dissect_substrings },
  {   2, BER_CLASS_CON, 2, 0, dissect_greaterOrEqual },
  {   3, BER_CLASS_CON, 3, 0, dissect_lessOrEqual },
  {   4, BER_CLASS_CON, 4, 0, dissect_present },
  {   5, BER_CLASS_CON, 5, 0, dissect_approximateMatch },
  {   6, BER_CLASS_CON, 6, 0, dissect_extensibleMatch },
  {   7, BER_CLASS_CON, 7, 0, dissect_contextPresent },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_FilterItem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 FilterItem_choice, hf_index, ett_dap_FilterItem,
                                 NULL);

  return offset;
}
static int dissect_filter_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_FilterItem(FALSE, tvb, offset, pinfo, tree, hf_dap_filter_item);
}


static const ber_sequence_t SetOfFilter_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_SetOfFilter_item },
};

static int
dissect_dap_SetOfFilter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SetOfFilter_set_of, hf_index, ett_dap_SetOfFilter);

  return offset;
}
static int dissect_and(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SetOfFilter(FALSE, tvb, offset, pinfo, tree, hf_dap_and);
}
static int dissect_or(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SetOfFilter(FALSE, tvb, offset, pinfo, tree, hf_dap_or);
}


static const value_string dap_Filter_vals[] = {
  {   0, "item" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t Filter_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_filter_item },
  {   1, BER_CLASS_CON, 1, 0, dissect_and },
  {   2, BER_CLASS_CON, 2, 0, dissect_or },
  {   3, BER_CLASS_CON, 3, 0, dissect_not },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_Filter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Filter_choice, hf_index, ett_dap_Filter,
                                 NULL);

  return offset;
}


static const ber_sequence_t SortKey_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_orderingRule },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_SortKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SortKey_sequence, hf_index, ett_dap_SortKey);

  return offset;
}
static int dissect_sortKeys_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SortKey(FALSE, tvb, offset, pinfo, tree, hf_dap_sortKeys_item);
}


static const ber_sequence_t SEQUENCE_OF_SortKey_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sortKeys_item },
};

static int
dissect_dap_SEQUENCE_OF_SortKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_SortKey_sequence_of, hf_index, ett_dap_SEQUENCE_OF_SortKey);

  return offset;
}
static int dissect_sortKeys(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SEQUENCE_OF_SortKey(FALSE, tvb, offset, pinfo, tree, hf_dap_sortKeys);
}


static const ber_sequence_t T_newRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pageSize },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sortKeys },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_reverse },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_unmerged },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_newRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_newRequest_sequence, hf_index, ett_dap_T_newRequest);

  return offset;
}
static int dissect_newRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_newRequest(FALSE, tvb, offset, pinfo, tree, hf_dap_newRequest);
}



static int
dissect_dap_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 172 "dap.cnf"
	tvbuff_t *out_tvb;
	int 	i;
	int	len;
	proto_item	*oct_item;

    	  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &out_tvb);


	len = tvb_length(out_tvb);
	/* now see if we can add a string representation */
	for(i=0; i<len; i++)
		if(!g_ascii_isprint(tvb_get_guint8(out_tvb, i)))
			break;
	
	if(i == len) {
		if((oct_item = get_ber_last_created_item())) {

			proto_item_append_text(oct_item," (");
			for(i=0; i<len; i++)
				proto_item_append_text(oct_item,"%c",tvb_get_guint8(out_tvb,i));
			proto_item_append_text(oct_item,")");
		}
	}
	


  return offset;
}
static int dissect_queryReference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_dap_queryReference);
}
static int dissect_unprotected(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_dap_unprotected);
}
static int dissect_protectedPassword(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_dap_protectedPassword);
}


static const value_string dap_PagedResultsRequest_vals[] = {
  {   0, "newRequest" },
  {   1, "queryReference" },
  { 0, NULL }
};

static const ber_choice_t PagedResultsRequest_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_newRequest },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_queryReference },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_PagedResultsRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PagedResultsRequest_choice, hf_index, ett_dap_PagedResultsRequest,
                                 NULL);

  return offset;
}
static int dissect_pagedResults(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_PagedResultsRequest(FALSE, tvb, offset, pinfo, tree, hf_dap_pagedResults);
}


static const value_string dap_T_time1_vals[] = {
  {   0, "utc" },
  {   1, "gt" },
  { 0, NULL }
};

static const ber_choice_t T_time1_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_utc },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_gt },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_time1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_time1_choice, hf_index, ett_dap_T_time1,
                                 NULL);

  return offset;
}
static int dissect_time1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_time1(FALSE, tvb, offset, pinfo, tree, hf_dap_time1);
}


static const value_string dap_T_time2_vals[] = {
  {   0, "utc" },
  {   1, "gt" },
  { 0, NULL }
};

static const ber_choice_t T_time2_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_utc },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_gt },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_time2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_time2_choice, hf_index, ett_dap_T_time2,
                                 NULL);

  return offset;
}
static int dissect_time2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_time2(FALSE, tvb, offset, pinfo, tree, hf_dap_time2);
}


static const ber_sequence_t T_validity_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_time1 },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_time2 },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_random1 },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_random2 },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_validity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              T_validity_set, hf_index, ett_dap_T_validity);

  return offset;
}
static int dissect_validity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_validity(FALSE, tvb, offset, pinfo, tree, hf_dap_validity);
}


static const ber_sequence_t T_protected_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_protectedPassword },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_protected(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_protected_sequence, hf_index, ett_dap_T_protected);

  return offset;
}
static int dissect_protected(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_protected(FALSE, tvb, offset, pinfo, tree, hf_dap_protected);
}


static const value_string dap_T_password_vals[] = {
  {   0, "unprotected" },
  {   1, "protected" },
  { 0, NULL }
};

static const ber_choice_t T_password_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_unprotected },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_protected },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_password(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_password_choice, hf_index, ett_dap_T_password,
                                 NULL);

  return offset;
}
static int dissect_password(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_password(FALSE, tvb, offset, pinfo, tree, hf_dap_password);
}


static const ber_sequence_t SimpleCredentials_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_distinguished_name },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_validity },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_password },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_SimpleCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 162 "dap.cnf"

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SimpleCredentials_sequence, hf_index, ett_dap_SimpleCredentials);


	if(check_col(pinfo->cinfo, COL_INFO))	
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", x509if_get_last_dn());



  return offset;
}
static int dissect_simple(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SimpleCredentials(FALSE, tvb, offset, pinfo, tree, hf_dap_simple);
}



static int
dissect_dap_T_bind_token(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 131 "dap.cnf"
	/* XXX: not yet implemented */



  return offset;
}
static int dissect_bind_token(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_bind_token(FALSE, tvb, offset, pinfo, tree, hf_dap_bind_token);
}


static const ber_sequence_t StrongCredentials_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_certification_path },
  { BER_CLASS_CON, 1, 0, dissect_bind_token },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_distinguished_name },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_attributeCertificationPath },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_StrongCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              StrongCredentials_set, hf_index, ett_dap_StrongCredentials);

  return offset;
}
static int dissect_strong(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_StrongCredentials(FALSE, tvb, offset, pinfo, tree, hf_dap_strong);
}



static int
dissect_dap_T_req(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 134 "dap.cnf"
	/* XXX: not yet implemented */



  return offset;
}
static int dissect_req(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_req(FALSE, tvb, offset, pinfo, tree, hf_dap_req);
}



static int
dissect_dap_T_rep(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 137 "dap.cnf"
	/* XXX: not yet implemented */



  return offset;
}
static int dissect_rep(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_rep(FALSE, tvb, offset, pinfo, tree, hf_dap_rep);
}


static const value_string dap_SpkmCredentials_vals[] = {
  {   0, "req" },
  {   1, "rep" },
  { 0, NULL }
};

static const ber_choice_t SpkmCredentials_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_req },
  {   1, BER_CLASS_CON, 1, 0, dissect_rep },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_SpkmCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SpkmCredentials_choice, hf_index, ett_dap_SpkmCredentials,
                                 NULL);

  return offset;
}
static int dissect_spkm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SpkmCredentials(FALSE, tvb, offset, pinfo, tree, hf_dap_spkm);
}


static const value_string dap_Credentials_vals[] = {
  {   0, "simple" },
  {   1, "strong" },
  {   2, "externalProcedure" },
  {   3, "spkm" },
  { 0, NULL }
};

static const ber_choice_t Credentials_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_simple },
  {   1, BER_CLASS_CON, 1, 0, dissect_strong },
  {   2, BER_CLASS_CON, 2, 0, dissect_externalProcedure },
  {   3, BER_CLASS_CON, 3, 0, dissect_spkm },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_Credentials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Credentials_choice, hf_index, ett_dap_Credentials,
                                 NULL);

  return offset;
}
static int dissect_credentials(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Credentials(FALSE, tvb, offset, pinfo, tree, hf_dap_credentials);
}


static const asn_namedbit Versions_bits[] = {
  {  0, &hf_dap_Versions_v1, -1, -1, "v1", NULL },
  {  1, &hf_dap_Versions_v2, -1, -1, "v2", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_dap_Versions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    Versions_bits, hf_index, ett_dap_Versions,
                                    NULL);

  return offset;
}
static int dissect_versions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Versions(FALSE, tvb, offset, pinfo, tree, hf_dap_versions);
}


static const ber_sequence_t DirectoryBindArgument_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_credentials },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_versions },
  { 0, 0, 0, NULL }
};

int
dissect_dap_DirectoryBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 143 "dap.cnf"

	guint32 len;

	/* check and see if this is an empty set */
	dissect_ber_length(pinfo, tree, tvb, offset+1, &len, NULL);

	if(len == 0) {
		/* its an empty set - i.e anonymous  (assuming version is DEFAULTed) */
		proto_tree_add_text(tree, tvb, offset, -1,"Anonymous");

		if(check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " anonymous");

	}
	/* do the default thing */

	  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DirectoryBindArgument_set, hf_index, ett_dap_DirectoryBindArgument);
	



  return offset;
}



static int
dissect_dap_DirectoryBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string dap_ServiceProblem_vals[] = {
  {   1, "busy" },
  {   2, "unavailable" },
  {   3, "unwillingToPerform" },
  {   4, "chainingRequired" },
  {   5, "unableToProceed" },
  {   6, "invalidReference" },
  {   7, "timeLimitExceeded" },
  {   8, "administrativeLimitExceeded" },
  {   9, "loopDetected" },
  {  10, "unavailableCriticalExtension" },
  {  11, "outOfScope" },
  {  12, "ditError" },
  {  13, "invalidQueryReference" },
  {  14, "requestedServiceNotAvailable" },
  {  15, "relaxationNotSupported" },
  {  16, "unsupportedMatchingUse" },
  { 0, NULL }
};


static int
dissect_dap_ServiceProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 211 "dap.cnf"
  guint32 problem;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &problem);


  if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, dap_ServiceProblem_vals, "ServiceProblem(%d)"));
  }



  return offset;
}
static int dissect_serviceProblem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ServiceProblem(FALSE, tvb, offset, pinfo, tree, hf_dap_serviceProblem);
}
static int dissect_service_error_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ServiceProblem(FALSE, tvb, offset, pinfo, tree, hf_dap_service_error_problem);
}


static const value_string dap_SecurityProblem_vals[] = {
  {   1, "inappropriateAuthentication" },
  {   2, "invalidCredentials" },
  {   3, "insufficientAccessRights" },
  {   4, "invalidSignature" },
  {   5, "protectionRequired" },
  {   6, "noInformation" },
  {   7, "blockedCredentials" },
  {   8, "invalidQOPMatch" },
  {   9, "spkmError" },
  { 0, NULL }
};


static int
dissect_dap_SecurityProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 199 "dap.cnf"
  guint32 problem;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &problem);


  if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, dap_SecurityProblem_vals, "SecurityProblem(%d)"));
  }



  return offset;
}
static int dissect_securityProblem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SecurityProblem(FALSE, tvb, offset, pinfo, tree, hf_dap_securityProblem);
}
static int dissect_security_error_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SecurityProblem(FALSE, tvb, offset, pinfo, tree, hf_dap_security_error_problem);
}


static const value_string dap_T_error_vals[] = {
  {   1, "serviceError" },
  {   2, "securityError" },
  { 0, NULL }
};

static const ber_choice_t T_error_choice[] = {
  {   1, BER_CLASS_CON, 1, 0, dissect_serviceProblem },
  {   2, BER_CLASS_CON, 2, 0, dissect_securityProblem },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_error_choice, hf_index, ett_dap_T_error,
                                 NULL);

  return offset;
}
static int dissect_error(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_error(FALSE, tvb, offset, pinfo, tree, hf_dap_error);
}


static const ber_sequence_t DirectoryBindErrorData_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_versions },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_error },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_DirectoryBindErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DirectoryBindErrorData_set, hf_index, ett_dap_DirectoryBindErrorData);

  return offset;
}
static int dissect_unsignedDirectoryBindError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_DirectoryBindErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedDirectoryBindError);
}
static int dissect_directoryBindError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_DirectoryBindErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_directoryBindError);
}


static const ber_sequence_t T_signedDirectoryBindError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_directoryBindError },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedDirectoryBindError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedDirectoryBindError_sequence, hf_index, ett_dap_T_signedDirectoryBindError);

  return offset;
}
static int dissect_signedDirectoryBindError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedDirectoryBindError(FALSE, tvb, offset, pinfo, tree, hf_dap_signedDirectoryBindError);
}


const value_string dap_DirectoryBindError_vals[] = {
  {   0, "unsignedDirectoryBindError" },
  {   1, "signedDirectoryBindError" },
  { 0, NULL }
};

static const ber_choice_t DirectoryBindError_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedDirectoryBindError },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedDirectoryBindError },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_DirectoryBindError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DirectoryBindError_choice, hf_index, ett_dap_DirectoryBindError,
                                 NULL);

  return offset;
}


static const ber_sequence_t ReadArgumentData_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_object },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_selection },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_modifyRightsRequest },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_serviceControls },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_requestor },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_operationProgress },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_criticalExtensions },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_referenceType },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_operationContexts },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_familyGrouping },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ReadArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ReadArgumentData_set, hf_index, ett_dap_ReadArgumentData);

  return offset;
}
static int dissect_unsignedReadArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ReadArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedReadArgument);
}
static int dissect_readArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ReadArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_readArgument);
}


static const ber_sequence_t T_signedReadArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_readArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedReadArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedReadArgument_sequence, hf_index, ett_dap_T_signedReadArgument);

  return offset;
}
static int dissect_signedReadArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedReadArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_signedReadArgument);
}


const value_string dap_ReadArgument_vals[] = {
  {   0, "unsignedReadArgument" },
  {   1, "signedReadArgument" },
  { 0, NULL }
};

static const ber_choice_t ReadArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedReadArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedReadArgument },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_ReadArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ReadArgument_choice, hf_index, ett_dap_ReadArgument,
                                 NULL);

  return offset;
}


static const value_string dap_T_item_vals[] = {
  {   0, "entry" },
  {   1, "attribute" },
  {   2, "value" },
  { 0, NULL }
};

static const ber_choice_t T_item_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_item_entry },
  {   1, BER_CLASS_CON, 1, 0, dissect_attribute_type },
  {   2, BER_CLASS_CON, 2, 0, dissect_value_assertion },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_item_choice, hf_index, ett_dap_T_item,
                                 NULL);

  return offset;
}
static int dissect_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_item(FALSE, tvb, offset, pinfo, tree, hf_dap_item);
}


static const asn_namedbit T_permission_bits[] = {
  {  0, &hf_dap_T_permission_add, -1, -1, "add", NULL },
  {  1, &hf_dap_T_permission_remove, -1, -1, "remove", NULL },
  {  2, &hf_dap_T_permission_rename, -1, -1, "rename", NULL },
  {  3, &hf_dap_T_permission_move, -1, -1, "move", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_dap_T_permission(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    T_permission_bits, hf_index, ett_dap_T_permission,
                                    NULL);

  return offset;
}
static int dissect_permission(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_permission(FALSE, tvb, offset, pinfo, tree, hf_dap_permission);
}


static const ber_sequence_t ModifyRights_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_item },
  { BER_CLASS_CON, 3, 0, dissect_permission },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyRights_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModifyRights_item_sequence, hf_index, ett_dap_ModifyRights_item);

  return offset;
}
static int dissect_ModifyRights_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyRights_item(FALSE, tvb, offset, pinfo, tree, hf_dap_ModifyRights_item);
}


static const ber_sequence_t ModifyRights_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ModifyRights_item },
};

static int
dissect_dap_ModifyRights(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 ModifyRights_set_of, hf_index, ett_dap_ModifyRights);

  return offset;
}
static int dissect_modifyRights(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyRights(FALSE, tvb, offset, pinfo, tree, hf_dap_modifyRights);
}


static const ber_sequence_t ReadResultData_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_entry },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_modifyRights },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ReadResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ReadResultData_set, hf_index, ett_dap_ReadResultData);

  return offset;
}
static int dissect_unsignedReadResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ReadResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedReadResult);
}
static int dissect_readResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ReadResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_readResult);
}


static const ber_sequence_t T_signedReadResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_readResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedReadResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedReadResult_sequence, hf_index, ett_dap_T_signedReadResult);

  return offset;
}
static int dissect_signedReadResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedReadResult(FALSE, tvb, offset, pinfo, tree, hf_dap_signedReadResult);
}


const value_string dap_ReadResult_vals[] = {
  {   0, "unsignedReadResult" },
  {   1, "signedReadResult" },
  { 0, NULL }
};

static const ber_choice_t ReadResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedReadResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedReadResult },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_ReadResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ReadResult_choice, hf_index, ett_dap_ReadResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t CompareArgumentData_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_object },
  { BER_CLASS_CON, 1, 0, dissect_purported },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_serviceControls },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_requestor },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_operationProgress },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_criticalExtensions },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_referenceType },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_operationContexts },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_familyGrouping },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_CompareArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CompareArgumentData_set, hf_index, ett_dap_CompareArgumentData);

  return offset;
}
static int dissect_unsignedCompareArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_CompareArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedCompareArgument);
}
static int dissect_compareArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_CompareArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_compareArgument);
}


static const ber_sequence_t T_signedCompareArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_compareArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedCompareArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedCompareArgument_sequence, hf_index, ett_dap_T_signedCompareArgument);

  return offset;
}
static int dissect_signedCompareArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedCompareArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_signedCompareArgument);
}


const value_string dap_CompareArgument_vals[] = {
  {   0, "unsignedCompareArgument" },
  {   1, "signedCompareArgument" },
  { 0, NULL }
};

static const ber_choice_t CompareArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedCompareArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedCompareArgument },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_CompareArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CompareArgument_choice, hf_index, ett_dap_CompareArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t CompareResultData_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_name },
  { BER_CLASS_CON, 0, 0, dissect_matched },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_fromEntry },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_matchedSubtype },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_CompareResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CompareResultData_set, hf_index, ett_dap_CompareResultData);

  return offset;
}
static int dissect_unsignedCompareResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_CompareResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedCompareResult);
}
static int dissect_compareResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_CompareResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_compareResult);
}


static const ber_sequence_t T_signedCompareResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_compareResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedCompareResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedCompareResult_sequence, hf_index, ett_dap_T_signedCompareResult);

  return offset;
}
static int dissect_signedCompareResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedCompareResult(FALSE, tvb, offset, pinfo, tree, hf_dap_signedCompareResult);
}


const value_string dap_CompareResult_vals[] = {
  {   0, "unsignedCompareResult" },
  {   1, "signedCompareResult" },
  { 0, NULL }
};

static const ber_choice_t CompareResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedCompareResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedCompareResult },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_CompareResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CompareResult_choice, hf_index, ett_dap_CompareResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t AbandonArgumentData_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_invokeID },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AbandonArgumentData_sequence, hf_index, ett_dap_AbandonArgumentData);

  return offset;
}
static int dissect_unsignedAbandonArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedAbandonArgument);
}
static int dissect_abandonArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_abandonArgument);
}


static const ber_sequence_t T_signedAbandonArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_abandonArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAbandonArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedAbandonArgument_sequence, hf_index, ett_dap_T_signedAbandonArgument);

  return offset;
}
static int dissect_signedAbandonArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedAbandonArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_signedAbandonArgument);
}


const value_string dap_AbandonArgument_vals[] = {
  {   0, "unsignedAbandonArgument" },
  {   1, "signedAbandonArgument" },
  { 0, NULL }
};

static const ber_choice_t AbandonArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_unsignedAbandonArgument },
  {   1, BER_CLASS_CON, 0, 0, dissect_signedAbandonArgument },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_AbandonArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AbandonArgument_choice, hf_index, ett_dap_AbandonArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t AbandonResultData_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AbandonResultData_sequence, hf_index, ett_dap_AbandonResultData);

  return offset;
}
static int dissect_unsignedAbandonResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedAbandonResult);
}
static int dissect_abandonResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_abandonResult);
}


static const ber_sequence_t T_signedAbandonResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_abandonResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAbandonResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedAbandonResult_sequence, hf_index, ett_dap_T_signedAbandonResult);

  return offset;
}
static int dissect_signedAbandonResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedAbandonResult(FALSE, tvb, offset, pinfo, tree, hf_dap_signedAbandonResult);
}


static const value_string dap_AbandonInformation_vals[] = {
  {   0, "unsignedAbandonResult" },
  {   1, "signedAbandonResult" },
  { 0, NULL }
};

static const ber_choice_t AbandonInformation_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_unsignedAbandonResult },
  {   1, BER_CLASS_CON, 0, 0, dissect_signedAbandonResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AbandonInformation_choice, hf_index, ett_dap_AbandonInformation,
                                 NULL);

  return offset;
}
static int dissect_abandon_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonInformation(FALSE, tvb, offset, pinfo, tree, hf_dap_abandon_information);
}


const value_string dap_AbandonResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t AbandonResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_abandon_information },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_AbandonResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AbandonResult_choice, hf_index, ett_dap_AbandonResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ListArgumentData_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_object },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_pagedResults },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_listFamily },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_serviceControls },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_requestor },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_operationProgress },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_criticalExtensions },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_referenceType },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_operationContexts },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_familyGrouping },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ListArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ListArgumentData_set, hf_index, ett_dap_ListArgumentData);

  return offset;
}
static int dissect_unsignedListArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ListArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedListArgument);
}
static int dissect_listArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ListArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_listArgument);
}


static const ber_sequence_t T_signedListArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_listArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedListArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedListArgument_sequence, hf_index, ett_dap_T_signedListArgument);

  return offset;
}
static int dissect_signedListArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedListArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_signedListArgument);
}


const value_string dap_ListArgument_vals[] = {
  {   0, "unsignedListArgument" },
  {   1, "signedListArgument" },
  { 0, NULL }
};

static const ber_choice_t ListArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedListArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedListArgument },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_ListArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ListArgument_choice, hf_index, ett_dap_ListArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_subordinates_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_rdn },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_aliasEntry },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_fromEntry },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_subordinates_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 267 "dap.cnf"
	proto_item *sub_item;

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_subordinates_item_sequence, hf_index, ett_dap_T_subordinates_item);


	if((sub_item = get_ber_last_created_item())) {
		
		proto_item_append_text(sub_item," (%s)", x509if_get_last_dn());
	}



  return offset;
}
static int dissect_subordinates_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_subordinates_item(FALSE, tvb, offset, pinfo, tree, hf_dap_subordinates_item);
}


static const ber_sequence_t T_subordinates_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_subordinates_item },
};

static int
dissect_dap_T_subordinates(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_subordinates_set_of, hf_index, ett_dap_T_subordinates);

  return offset;
}
static int dissect_subordinates(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_subordinates(FALSE, tvb, offset, pinfo, tree, hf_dap_subordinates);
}


static const value_string dap_LimitProblem_vals[] = {
  {   0, "timeLimitExceeded" },
  {   1, "sizeLimitExceeded" },
  {   2, "administrativeLimitExceeded" },
  { 0, NULL }
};


static int
dissect_dap_LimitProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 235 "dap.cnf"
  guint32 problem;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &problem);


  if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, dap_LimitProblem_vals, "LimitProblem(%d)"));
  }



  return offset;
}
static int dissect_limitProblem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_LimitProblem(FALSE, tvb, offset, pinfo, tree, hf_dap_limitProblem);
}


static const ber_sequence_t SET_OF_ContinuationReference_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unexplored_item },
};

static int
dissect_dap_SET_OF_ContinuationReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ContinuationReference_set_of, hf_index, ett_dap_SET_OF_ContinuationReference);

  return offset;
}
static int dissect_unexplored(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SET_OF_ContinuationReference(FALSE, tvb, offset, pinfo, tree, hf_dap_unexplored);
}


static const ber_sequence_t T_unknownErrors_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_unknownErrors_item },
};

static int
dissect_dap_T_unknownErrors(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_unknownErrors_set_of, hf_index, ett_dap_T_unknownErrors);

  return offset;
}
static int dissect_unknownErrors(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_unknownErrors(FALSE, tvb, offset, pinfo, tree, hf_dap_unknownErrors);
}


static const value_string dap_T_entryCount_vals[] = {
  {   7, "bestEstimate" },
  {   8, "lowEstimate" },
  { 0, NULL }
};

static const ber_choice_t T_entryCount_choice[] = {
  {   7, BER_CLASS_CON, 7, 0, dissect_bestEstimate },
  {   8, BER_CLASS_CON, 8, 0, dissect_lowEstimate },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_entryCount(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_entryCount_choice, hf_index, ett_dap_T_entryCount,
                                 NULL);

  return offset;
}
static int dissect_entryCount(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_entryCount(FALSE, tvb, offset, pinfo, tree, hf_dap_entryCount);
}


static const ber_sequence_t PartialOutcomeQualifier_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_limitProblem },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_unexplored },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_unavailableCriticalExtensions },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_unknownErrors },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_queryReference },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_overspecFilter },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_notification },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_entryCount },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_PartialOutcomeQualifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PartialOutcomeQualifier_set, hf_index, ett_dap_PartialOutcomeQualifier);

  return offset;
}
static int dissect_partialOutcomeQualifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_PartialOutcomeQualifier(FALSE, tvb, offset, pinfo, tree, hf_dap_partialOutcomeQualifier);
}


static const ber_sequence_t T_listInfo_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_name },
  { BER_CLASS_CON, 1, 0, dissect_subordinates },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_partialOutcomeQualifier },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_listInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              T_listInfo_set, hf_index, ett_dap_T_listInfo);

  return offset;
}
static int dissect_listInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_listInfo(FALSE, tvb, offset, pinfo, tree, hf_dap_listInfo);
}


static const ber_sequence_t T_signedListResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_listResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedListResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedListResult_sequence, hf_index, ett_dap_T_signedListResult);

  return offset;
}
static int dissect_signedListResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedListResult(FALSE, tvb, offset, pinfo, tree, hf_dap_signedListResult);
}


const value_string dap_ListResult_vals[] = {
  {   0, "unsignedListResult" },
  {   1, "signedListResult" },
  { 0, NULL }
};

static const ber_choice_t ListResult_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_unsignedListResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedListResult },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_ListResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ListResult_choice, hf_index, ett_dap_ListResult,
                                 NULL);

  return offset;
}
static int dissect_uncorrelatedListInfo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ListResult(FALSE, tvb, offset, pinfo, tree, hf_dap_uncorrelatedListInfo_item);
}


static const ber_sequence_t SET_OF_ListResult_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_uncorrelatedListInfo_item },
};

static int
dissect_dap_SET_OF_ListResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ListResult_set_of, hf_index, ett_dap_SET_OF_ListResult);

  return offset;
}
static int dissect_uncorrelatedListInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SET_OF_ListResult(FALSE, tvb, offset, pinfo, tree, hf_dap_uncorrelatedListInfo);
}


static const value_string dap_ListResultData_vals[] = {
  {   0, "listInfo" },
  {   1, "uncorrelatedListInfo" },
  { 0, NULL }
};

static const ber_choice_t ListResultData_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_listInfo },
  {   1, BER_CLASS_CON, 0, 0, dissect_uncorrelatedListInfo },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_ListResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ListResultData_choice, hf_index, ett_dap_ListResultData,
                                 NULL);

  return offset;
}


static const value_string dap_T_subset_vals[] = {
  {   0, "baseObject" },
  {   1, "oneLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_dap_T_subset(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 247 "dap.cnf"
  guint32 subset;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &subset);


  if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(subset, dap_T_subset_vals, "Subset(%d)"));
  }




  return offset;
}
static int dissect_subset(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_subset(FALSE, tvb, offset, pinfo, tree, hf_dap_subset);
}


static const asn_namedbit HierarchySelections_bits[] = {
  {  0, &hf_dap_HierarchySelections_self, -1, -1, "self", NULL },
  {  1, &hf_dap_HierarchySelections_children, -1, -1, "children", NULL },
  {  2, &hf_dap_HierarchySelections_parent, -1, -1, "parent", NULL },
  {  3, &hf_dap_HierarchySelections_hierarchy, -1, -1, "hierarchy", NULL },
  {  4, &hf_dap_HierarchySelections_top, -1, -1, "top", NULL },
  {  5, &hf_dap_HierarchySelections_subtree, -1, -1, "subtree", NULL },
  {  6, &hf_dap_HierarchySelections_siblings, -1, -1, "siblings", NULL },
  {  7, &hf_dap_HierarchySelections_siblingChildren, -1, -1, "siblingChildren", NULL },
  {  8, &hf_dap_HierarchySelections_siblingSubtree, -1, -1, "siblingSubtree", NULL },
  {  9, &hf_dap_HierarchySelections_all, -1, -1, "all", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_dap_HierarchySelections(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    HierarchySelections_bits, hf_index, ett_dap_HierarchySelections,
                                    NULL);

  return offset;
}
static int dissect_hierarchySelections(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_HierarchySelections(FALSE, tvb, offset, pinfo, tree, hf_dap_hierarchySelections);
}


static const asn_namedbit SearchControlOptions_bits[] = {
  {  0, &hf_dap_SearchControlOptions_searchAliases, -1, -1, "searchAliases", NULL },
  {  1, &hf_dap_SearchControlOptions_matchedValuesOnly, -1, -1, "matchedValuesOnly", NULL },
  {  2, &hf_dap_SearchControlOptions_checkOverspecified, -1, -1, "checkOverspecified", NULL },
  {  3, &hf_dap_SearchControlOptions_performExactly, -1, -1, "performExactly", NULL },
  {  4, &hf_dap_SearchControlOptions_includeAllAreas, -1, -1, "includeAllAreas", NULL },
  {  5, &hf_dap_SearchControlOptions_noSystemRelaxation, -1, -1, "noSystemRelaxation", NULL },
  {  6, &hf_dap_SearchControlOptions_dnAttribute, -1, -1, "dnAttribute", NULL },
  {  7, &hf_dap_SearchControlOptions_matchOnResidualName, -1, -1, "matchOnResidualName", NULL },
  {  8, &hf_dap_SearchControlOptions_entryCount, -1, -1, "entryCount", NULL },
  {  9, &hf_dap_SearchControlOptions_useSubset, -1, -1, "useSubset", NULL },
  { 10, &hf_dap_SearchControlOptions_separateFamilyMembers, -1, -1, "separateFamilyMembers", NULL },
  { 11, &hf_dap_SearchControlOptions_searchFamily, -1, -1, "searchFamily", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_dap_SearchControlOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    SearchControlOptions_bits, hf_index, ett_dap_SearchControlOptions,
                                    NULL);

  return offset;
}
static int dissect_searchControlOptions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SearchControlOptions(FALSE, tvb, offset, pinfo, tree, hf_dap_searchControlOptions);
}



static int
dissect_dap_DomainLocalID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509sat_DirectoryString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_domainLocalID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_DomainLocalID(FALSE, tvb, offset, pinfo, tree, hf_dap_domainLocalID);
}


static const value_string dap_T_joinSubset_vals[] = {
  {   0, "baseObject" },
  {   1, "oneLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_dap_T_joinSubset(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_joinSubset(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_joinSubset(FALSE, tvb, offset, pinfo, tree, hf_dap_joinSubset);
}



static int
dissect_dap_JoinContextType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_joinContext_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_JoinContextType(FALSE, tvb, offset, pinfo, tree, hf_dap_joinContext_item);
}


static const ber_sequence_t SEQUENCE_OF_JoinContextType_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_joinContext_item },
};

static int
dissect_dap_SEQUENCE_OF_JoinContextType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_JoinContextType_sequence_of, hf_index, ett_dap_SEQUENCE_OF_JoinContextType);

  return offset;
}
static int dissect_joinContext(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SEQUENCE_OF_JoinContextType(FALSE, tvb, offset, pinfo, tree, hf_dap_joinContext);
}


static const ber_sequence_t JoinAttPair_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_baseAtt },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_joinAtt },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_joinContext },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_JoinAttPair(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   JoinAttPair_sequence, hf_index, ett_dap_JoinAttPair);

  return offset;
}
static int dissect_joinAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_JoinAttPair(FALSE, tvb, offset, pinfo, tree, hf_dap_joinAttributes_item);
}


static const ber_sequence_t SEQUENCE_OF_JoinAttPair_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_joinAttributes_item },
};

static int
dissect_dap_SEQUENCE_OF_JoinAttPair(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_JoinAttPair_sequence_of, hf_index, ett_dap_SEQUENCE_OF_JoinAttPair);

  return offset;
}
static int dissect_joinAttributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SEQUENCE_OF_JoinAttPair(FALSE, tvb, offset, pinfo, tree, hf_dap_joinAttributes);
}


static const ber_sequence_t JoinArgument_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_joinBaseObject },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_domainLocalID },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_joinSubset },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_joinFilter },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_joinAttributes },
  { BER_CLASS_CON, 5, 0, dissect_joinSelection },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_JoinArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   JoinArgument_sequence, hf_index, ett_dap_JoinArgument);

  return offset;
}
static int dissect_joinArguments_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_JoinArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_joinArguments_item);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_JoinArgument_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_joinArguments_item },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_JoinArgument_sequence_of, hf_index, ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument);

  return offset;
}
static int dissect_joinArguments(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_joinArguments);
}


static const value_string dap_T_joinType_vals[] = {
  {   0, "innerJoin" },
  {   1, "leftOuterJoin" },
  {   2, "fullOuterJoin" },
  { 0, NULL }
};


static int
dissect_dap_T_joinType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_joinType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_joinType(FALSE, tvb, offset, pinfo, tree, hf_dap_joinType);
}


static const ber_sequence_t SearchArgumentData_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_baseObject },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_subset },
  { BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_filter },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_searchAliases },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_selection },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_pagedResults },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_matchedValuesOnly },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_extendedFilter },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_checkOverspecified },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_relaxation },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_extendedArea },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_hierarchySelections },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_searchControlOptions },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_joinArguments },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_joinType },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_serviceControls },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_requestor },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_operationProgress },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_criticalExtensions },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_referenceType },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_operationContexts },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_familyGrouping },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_SearchArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SearchArgumentData_set, hf_index, ett_dap_SearchArgumentData);

  return offset;
}
static int dissect_unsignedSearchArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SearchArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedSearchArgument);
}
static int dissect_searchArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SearchArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_searchArgument);
}


static const ber_sequence_t T_signedSearchArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_searchArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedSearchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedSearchArgument_sequence, hf_index, ett_dap_T_signedSearchArgument);

  return offset;
}
static int dissect_signedSearchArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedSearchArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_signedSearchArgument);
}


const value_string dap_SearchArgument_vals[] = {
  {   0, "unsignedSearchArgument" },
  {   1, "signedSearchArgument" },
  { 0, NULL }
};

static const ber_choice_t SearchArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedSearchArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedSearchArgument },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_SearchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SearchArgument_choice, hf_index, ett_dap_SearchArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_EntryInformation_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_entries_item },
};

static int
dissect_dap_SET_OF_EntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_EntryInformation_set_of, hf_index, ett_dap_SET_OF_EntryInformation);

  return offset;
}
static int dissect_entries(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SET_OF_EntryInformation(FALSE, tvb, offset, pinfo, tree, hf_dap_entries);
}


static const ber_sequence_t T_searchInfo_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_name },
  { BER_CLASS_CON, 0, 0, dissect_entries },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_partialOutcomeQualifier },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_altMatching },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_searchInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              T_searchInfo_set, hf_index, ett_dap_T_searchInfo);

  return offset;
}
static int dissect_searchInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_searchInfo(FALSE, tvb, offset, pinfo, tree, hf_dap_searchInfo);
}


static const ber_sequence_t T_signedSearchResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_searchResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedSearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedSearchResult_sequence, hf_index, ett_dap_T_signedSearchResult);

  return offset;
}
static int dissect_signedSearchResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedSearchResult(FALSE, tvb, offset, pinfo, tree, hf_dap_signedSearchResult);
}


const value_string dap_SearchResult_vals[] = {
  {   0, "unsignedSearchResult" },
  {   1, "signedSearchResult" },
  { 0, NULL }
};

static const ber_choice_t SearchResult_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_unsignedSearchResult },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedSearchResult },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_SearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SearchResult_choice, hf_index, ett_dap_SearchResult,
                                 NULL);

  return offset;
}
static int dissect_uncorrelatedSearchInfo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SearchResult(FALSE, tvb, offset, pinfo, tree, hf_dap_uncorrelatedSearchInfo_item);
}


static const ber_sequence_t SET_OF_SearchResult_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_uncorrelatedSearchInfo_item },
};

static int
dissect_dap_SET_OF_SearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_SearchResult_set_of, hf_index, ett_dap_SET_OF_SearchResult);

  return offset;
}
static int dissect_uncorrelatedSearchInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SET_OF_SearchResult(FALSE, tvb, offset, pinfo, tree, hf_dap_uncorrelatedSearchInfo);
}


static const value_string dap_SearchResultData_vals[] = {
  {   0, "searchInfo" },
  {   1, "uncorrelatedSearchInfo" },
  { 0, NULL }
};

static const ber_choice_t SearchResultData_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_searchInfo },
  {   1, BER_CLASS_CON, 0, 0, dissect_uncorrelatedSearchInfo },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_SearchResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SearchResultData_choice, hf_index, ett_dap_SearchResultData,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_entry_item },
};

static int
dissect_dap_SET_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Attribute_set_of, hf_index, ett_dap_SET_OF_Attribute);

  return offset;
}
static int dissect_add_entry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SET_OF_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dap_add_entry);
}


static const ber_sequence_t AddEntryArgumentData_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_object },
  { BER_CLASS_CON, 1, 0, dissect_add_entry },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_targetSystem },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_serviceControls },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_requestor },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_operationProgress },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_criticalExtensions },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_referenceType },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_operationContexts },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_familyGrouping },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_AddEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AddEntryArgumentData_set, hf_index, ett_dap_AddEntryArgumentData);

  return offset;
}
static int dissect_unsignedAddEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AddEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedAddEntryArgument);
}
static int dissect_addEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AddEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_addEntryArgument);
}


static const ber_sequence_t T_signedAddEntryArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_addEntryArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAddEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedAddEntryArgument_sequence, hf_index, ett_dap_T_signedAddEntryArgument);

  return offset;
}
static int dissect_signedAddEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedAddEntryArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_signedAddEntryArgument);
}


const value_string dap_AddEntryArgument_vals[] = {
  {   0, "unsignedAddEntryArgument" },
  {   1, "signedAddEntryArgument" },
  { 0, NULL }
};

static const ber_choice_t AddEntryArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedAddEntryArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedAddEntryArgument },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_AddEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AddEntryArgument_choice, hf_index, ett_dap_AddEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t AddEntryResultData_sequence[] = {
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_AddEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AddEntryResultData_sequence, hf_index, ett_dap_AddEntryResultData);

  return offset;
}
static int dissect_unsignedAddEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AddEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedAddEntryResult);
}
static int dissect_addEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AddEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_addEntryResult);
}


static const ber_sequence_t T_signedAddEntryResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_addEntryResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAddEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedAddEntryResult_sequence, hf_index, ett_dap_T_signedAddEntryResult);

  return offset;
}
static int dissect_signedAddEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedAddEntryResult(FALSE, tvb, offset, pinfo, tree, hf_dap_signedAddEntryResult);
}


static const value_string dap_AddEntryInformation_vals[] = {
  {   0, "unsignedAddEntryResult" },
  {   1, "signedAddEntryResult" },
  { 0, NULL }
};

static const ber_choice_t AddEntryInformation_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_unsignedAddEntryResult },
  {   1, BER_CLASS_CON, 0, 0, dissect_signedAddEntryResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_AddEntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AddEntryInformation_choice, hf_index, ett_dap_AddEntryInformation,
                                 NULL);

  return offset;
}
static int dissect_add_entry_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AddEntryInformation(FALSE, tvb, offset, pinfo, tree, hf_dap_add_entry_information);
}


const value_string dap_AddEntryResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t AddEntryResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_add_entry_information },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_AddEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AddEntryResult_choice, hf_index, ett_dap_AddEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t RemoveEntryArgumentData_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_object },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_serviceControls },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_requestor },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_operationProgress },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_criticalExtensions },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_referenceType },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_operationContexts },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_familyGrouping },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_RemoveEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RemoveEntryArgumentData_set, hf_index, ett_dap_RemoveEntryArgumentData);

  return offset;
}
static int dissect_unsignedRemoveEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_RemoveEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedRemoveEntryArgument);
}
static int dissect_removeEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_RemoveEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_removeEntryArgument);
}


static const ber_sequence_t T_signedRemoveEntryArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_removeEntryArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedRemoveEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedRemoveEntryArgument_sequence, hf_index, ett_dap_T_signedRemoveEntryArgument);

  return offset;
}
static int dissect_signedRemoveEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedRemoveEntryArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_signedRemoveEntryArgument);
}


const value_string dap_RemoveEntryArgument_vals[] = {
  {   0, "unsignedRemoveEntryArgument" },
  {   1, "signedRemoveEntryArgument" },
  { 0, NULL }
};

static const ber_choice_t RemoveEntryArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedRemoveEntryArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedRemoveEntryArgument },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_RemoveEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RemoveEntryArgument_choice, hf_index, ett_dap_RemoveEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t RemoveEntryResultData_sequence[] = {
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_RemoveEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RemoveEntryResultData_sequence, hf_index, ett_dap_RemoveEntryResultData);

  return offset;
}
static int dissect_unsignedRemoveEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_RemoveEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedRemoveEntryResult);
}
static int dissect_removeEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_RemoveEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_removeEntryResult);
}


static const ber_sequence_t T_signedRemoveEntryResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_removeEntryResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedRemoveEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedRemoveEntryResult_sequence, hf_index, ett_dap_T_signedRemoveEntryResult);

  return offset;
}
static int dissect_signedRemoveEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedRemoveEntryResult(FALSE, tvb, offset, pinfo, tree, hf_dap_signedRemoveEntryResult);
}


static const value_string dap_RemoveEntryInformation_vals[] = {
  {   0, "unsignedRemoveEntryResult" },
  {   1, "signedRemoveEntryResult" },
  { 0, NULL }
};

static const ber_choice_t RemoveEntryInformation_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_unsignedRemoveEntryResult },
  {   1, BER_CLASS_CON, 0, 0, dissect_signedRemoveEntryResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_RemoveEntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RemoveEntryInformation_choice, hf_index, ett_dap_RemoveEntryInformation,
                                 NULL);

  return offset;
}
static int dissect_remove_entry_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_RemoveEntryInformation(FALSE, tvb, offset, pinfo, tree, hf_dap_remove_entry_information);
}


const value_string dap_RemoveEntryResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t RemoveEntryResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_remove_entry_information },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_RemoveEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RemoveEntryResult_choice, hf_index, ett_dap_RemoveEntryResult,
                                 NULL);

  return offset;
}


const value_string dap_EntryModification_vals[] = {
  {   0, "addAttribute" },
  {   1, "removeAttribute" },
  {   2, "addValues" },
  {   3, "removeValues" },
  {   4, "alterValues" },
  {   5, "resetValue" },
  { 0, NULL }
};

static const ber_choice_t EntryModification_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_addAttribute },
  {   1, BER_CLASS_CON, 1, 0, dissect_removeAttribute },
  {   2, BER_CLASS_CON, 2, 0, dissect_addValues },
  {   3, BER_CLASS_CON, 3, 0, dissect_removeValues },
  {   4, BER_CLASS_CON, 4, 0, dissect_alterValues },
  {   5, BER_CLASS_CON, 5, 0, dissect_resetValue },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_EntryModification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 EntryModification_choice, hf_index, ett_dap_EntryModification,
                                 NULL);

  return offset;
}
static int dissect_changes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_EntryModification(FALSE, tvb, offset, pinfo, tree, hf_dap_changes_item);
}


static const ber_sequence_t SEQUENCE_OF_EntryModification_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_changes_item },
};

static int
dissect_dap_SEQUENCE_OF_EntryModification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_EntryModification_sequence_of, hf_index, ett_dap_SEQUENCE_OF_EntryModification);

  return offset;
}
static int dissect_changes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SEQUENCE_OF_EntryModification(FALSE, tvb, offset, pinfo, tree, hf_dap_changes);
}


static const ber_sequence_t ModifyEntryArgumentData_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_object },
  { BER_CLASS_CON, 1, 0, dissect_changes },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_selection },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_serviceControls },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_requestor },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_operationProgress },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_criticalExtensions },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_referenceType },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_operationContexts },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_familyGrouping },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ModifyEntryArgumentData_set, hf_index, ett_dap_ModifyEntryArgumentData);

  return offset;
}
static int dissect_unsignedModifyEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedModifyEntryArgument);
}
static int dissect_modifyEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyEntryArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dap_modifyEntryArgument);
}


static const ber_sequence_t T_signedModifyEntryArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_modifyEntryArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedModifyEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedModifyEntryArgument_sequence, hf_index, ett_dap_T_signedModifyEntryArgument);

  return offset;
}
static int dissect_signedModifyEntryArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedModifyEntryArgument(FALSE, tvb, offset, pinfo, tree, hf_dap_signedModifyEntryArgument);
}


const value_string dap_ModifyEntryArgument_vals[] = {
  {   0, "unsignedModifyEntryArgument" },
  {   1, "signedModifyEntryArgument" },
  { 0, NULL }
};

static const ber_choice_t ModifyEntryArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedModifyEntryArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedModifyEntryArgument },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_ModifyEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ModifyEntryArgument_choice, hf_index, ett_dap_ModifyEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ModifyEntryResultData_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_entry },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModifyEntryResultData_sequence, hf_index, ett_dap_ModifyEntryResultData);

  return offset;
}
static int dissect_unsignedModifyEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedModifyEntryResult);
}
static int dissect_modifyEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyEntryResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_modifyEntryResult);
}


static const ber_sequence_t T_signedModifyEntryResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_modifyEntryResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedModifyEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedModifyEntryResult_sequence, hf_index, ett_dap_T_signedModifyEntryResult);

  return offset;
}
static int dissect_signedModifyEntryResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedModifyEntryResult(FALSE, tvb, offset, pinfo, tree, hf_dap_signedModifyEntryResult);
}


static const value_string dap_ModifyEntryInformation_vals[] = {
  {   0, "unsignedModifyEntryResult" },
  {   1, "signedModifyEntryResult" },
  { 0, NULL }
};

static const ber_choice_t ModifyEntryInformation_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_unsignedModifyEntryResult },
  {   1, BER_CLASS_CON, 0, 0, dissect_signedModifyEntryResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyEntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ModifyEntryInformation_choice, hf_index, ett_dap_ModifyEntryInformation,
                                 NULL);

  return offset;
}
static int dissect_modify_entry_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyEntryInformation(FALSE, tvb, offset, pinfo, tree, hf_dap_modify_entry_information);
}


const value_string dap_ModifyEntryResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t ModifyEntryResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_modify_entry_information },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_ModifyEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ModifyEntryResult_choice, hf_index, ett_dap_ModifyEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ModifyDNArgument_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_distinguished_name },
  { BER_CLASS_CON, 1, 0, dissect_newRDN },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_deleteOldRDN },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_newSuperior },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_serviceControls },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_requestor },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_operationProgress },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_aliasedRDNs },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_criticalExtensions },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_referenceType },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_entryOnly },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_nameResolveOnMaster },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_operationContexts },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_familyGrouping },
  { 0, 0, 0, NULL }
};

int
dissect_dap_ModifyDNArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ModifyDNArgument_set, hf_index, ett_dap_ModifyDNArgument);

  return offset;
}


static const ber_sequence_t ModifyDNResultData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_newRDN },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyDNResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModifyDNResultData_sequence, hf_index, ett_dap_ModifyDNResultData);

  return offset;
}
static int dissect_unsignedModifyDNResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyDNResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedModifyDNResult);
}
static int dissect_modifyDNResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyDNResultData(FALSE, tvb, offset, pinfo, tree, hf_dap_modifyDNResult);
}


static const ber_sequence_t T_signedModifyDNResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_modifyDNResult },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedModifyDNResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedModifyDNResult_sequence, hf_index, ett_dap_T_signedModifyDNResult);

  return offset;
}
static int dissect_signedModifyDNResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedModifyDNResult(FALSE, tvb, offset, pinfo, tree, hf_dap_signedModifyDNResult);
}


static const value_string dap_ModifyDNInformation_vals[] = {
  {   0, "unsignedModifyDNResult" },
  {   1, "signedModifyDNResult" },
  { 0, NULL }
};

static const ber_choice_t ModifyDNInformation_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_unsignedModifyDNResult },
  {   1, BER_CLASS_CON, 0, 0, dissect_signedModifyDNResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyDNInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ModifyDNInformation_choice, hf_index, ett_dap_ModifyDNInformation,
                                 NULL);

  return offset;
}
static int dissect_modify_dn_information(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ModifyDNInformation(FALSE, tvb, offset, pinfo, tree, hf_dap_modify_dn_information);
}


const value_string dap_ModifyDNResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t ModifyDNResult_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_modify_dn_information },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_ModifyDNResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ModifyDNResult_choice, hf_index, ett_dap_ModifyDNResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t AbandonedData_set[] = {
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AbandonedData_set, hf_index, ett_dap_AbandonedData);

  return offset;
}
static int dissect_unsignedAbandoned(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonedData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedAbandoned);
}
static int dissect_abandoned(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonedData(FALSE, tvb, offset, pinfo, tree, hf_dap_abandoned);
}


static const ber_sequence_t T_signedAbandoned_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_abandoned },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAbandoned(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedAbandoned_sequence, hf_index, ett_dap_T_signedAbandoned);

  return offset;
}
static int dissect_signedAbandoned(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedAbandoned(FALSE, tvb, offset, pinfo, tree, hf_dap_signedAbandoned);
}


const value_string dap_Abandoned_vals[] = {
  {   0, "unsignedAbandoned" },
  {   1, "signedAbandoned" },
  { 0, NULL }
};

static const ber_choice_t Abandoned_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedAbandoned },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedAbandoned },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_Abandoned(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Abandoned_choice, hf_index, ett_dap_Abandoned,
                                 NULL);

  return offset;
}


static const value_string dap_AbandonProblem_vals[] = {
  {   1, "noSuchOperation" },
  {   2, "tooLate" },
  {   3, "cannotAbandon" },
  { 0, NULL }
};


static int
dissect_dap_AbandonProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_abandon_failed_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonProblem(FALSE, tvb, offset, pinfo, tree, hf_dap_abandon_failed_problem);
}


static const ber_sequence_t AbandonFailedErrorData_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_abandon_failed_problem },
  { BER_CLASS_CON, 1, 0, dissect_operation },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonFailedErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AbandonFailedErrorData_set, hf_index, ett_dap_AbandonFailedErrorData);

  return offset;
}
static int dissect_unsignedAbandonFailedError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonFailedErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedAbandonFailedError);
}
static int dissect_abandonFailedError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AbandonFailedErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_abandonFailedError);
}


static const ber_sequence_t T_signedAbandonFailedError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_abandonFailedError },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAbandonFailedError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedAbandonFailedError_sequence, hf_index, ett_dap_T_signedAbandonFailedError);

  return offset;
}
static int dissect_signedAbandonFailedError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedAbandonFailedError(FALSE, tvb, offset, pinfo, tree, hf_dap_signedAbandonFailedError);
}


const value_string dap_AbandonFailedError_vals[] = {
  {   0, "unsignedAbandonFailedError" },
  {   1, "signedAbandonFailedError" },
  { 0, NULL }
};

static const ber_choice_t AbandonFailedError_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedAbandonFailedError },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedAbandonFailedError },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_AbandonFailedError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AbandonFailedError_choice, hf_index, ett_dap_AbandonFailedError,
                                 NULL);

  return offset;
}


static const value_string dap_AttributeProblem_vals[] = {
  {   1, "noSuchAttributeOrValue" },
  {   2, "invalidAttributeSyntax" },
  {   3, "undefinedAttributeType" },
  {   4, "inappropriateMatching" },
  {   5, "constraintViolation" },
  {   6, "attributeOrValueAlreadyExists" },
  {   7, "contextViolation" },
  { 0, NULL }
};


static int
dissect_dap_AttributeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_attribute_error_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AttributeProblem(FALSE, tvb, offset, pinfo, tree, hf_dap_attribute_error_problem);
}


static const ber_sequence_t T_problems_item_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_attribute_error_problem },
  { BER_CLASS_CON, 1, 0, dissect_type },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_value },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_problems_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_problems_item_sequence, hf_index, ett_dap_T_problems_item);

  return offset;
}
static int dissect_problems_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_problems_item(FALSE, tvb, offset, pinfo, tree, hf_dap_problems_item);
}


static const ber_sequence_t T_problems_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_problems_item },
};

static int
dissect_dap_T_problems(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_problems_set_of, hf_index, ett_dap_T_problems);

  return offset;
}
static int dissect_problems(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_problems(FALSE, tvb, offset, pinfo, tree, hf_dap_problems);
}


static const ber_sequence_t AttributeErrorData_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_object },
  { BER_CLASS_CON, 1, 0, dissect_problems },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_AttributeErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AttributeErrorData_set, hf_index, ett_dap_AttributeErrorData);

  return offset;
}
static int dissect_unsignedAttributeError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AttributeErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedAttributeError);
}
static int dissect_attributeError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_AttributeErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_attributeError);
}


static const ber_sequence_t T_signedAttributeError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_attributeError },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAttributeError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedAttributeError_sequence, hf_index, ett_dap_T_signedAttributeError);

  return offset;
}
static int dissect_signedAttributeError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedAttributeError(FALSE, tvb, offset, pinfo, tree, hf_dap_signedAttributeError);
}


const value_string dap_AttributeError_vals[] = {
  {   0, "unsignedAttributeError" },
  {   1, "signedAttributeError" },
  { 0, NULL }
};

static const ber_choice_t AttributeError_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedAttributeError },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedAttributeError },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_AttributeError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AttributeError_choice, hf_index, ett_dap_AttributeError,
                                 NULL);

  return offset;
}


static const value_string dap_NameProblem_vals[] = {
  {   1, "noSuchObject" },
  {   2, "aliasProblem" },
  {   3, "invalidAttributeSyntax" },
  {   4, "aliasDereferencingProblem" },
  {   5, "contextProblem" },
  { 0, NULL }
};


static int
dissect_dap_NameProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_name_error_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_NameProblem(FALSE, tvb, offset, pinfo, tree, hf_dap_name_error_problem);
}


static const ber_sequence_t NameErrorData_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_name_error_problem },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_matched_name },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_NameErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              NameErrorData_set, hf_index, ett_dap_NameErrorData);

  return offset;
}
static int dissect_unsignedNameError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_NameErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedNameError);
}
static int dissect_nameError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_NameErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_nameError);
}


static const ber_sequence_t T_signedNameError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_nameError },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedNameError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedNameError_sequence, hf_index, ett_dap_T_signedNameError);

  return offset;
}
static int dissect_signedNameError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedNameError(FALSE, tvb, offset, pinfo, tree, hf_dap_signedNameError);
}


const value_string dap_NameError_vals[] = {
  {   0, "unsignedNameError" },
  {   1, "signedNameError" },
  { 0, NULL }
};

static const ber_choice_t NameError_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedNameError },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedNameError },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_NameError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 NameError_choice, hf_index, ett_dap_NameError,
                                 NULL);

  return offset;
}


static const ber_sequence_t ReferralData_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_candidate },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ReferralData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ReferralData_set, hf_index, ett_dap_ReferralData);

  return offset;
}
static int dissect_unsignedReferral(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ReferralData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedReferral);
}
static int dissect_referral(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ReferralData(FALSE, tvb, offset, pinfo, tree, hf_dap_referral);
}


static const ber_sequence_t T_signedReferral_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_referral },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedReferral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedReferral_sequence, hf_index, ett_dap_T_signedReferral);

  return offset;
}
static int dissect_signedReferral(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedReferral(FALSE, tvb, offset, pinfo, tree, hf_dap_signedReferral);
}


const value_string dap_Referral_vals[] = {
  {   0, "unsignedReferral" },
  {   1, "signedReferral" },
  { 0, NULL }
};

static const ber_choice_t Referral_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedReferral },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedReferral },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_Referral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Referral_choice, hf_index, ett_dap_Referral,
                                 NULL);

  return offset;
}



static int
dissect_dap_T_spkmInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 140 "dap.cnf"
	/* XXX: not yet implemented */



  return offset;
}
static int dissect_spkmInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_spkmInfo(FALSE, tvb, offset, pinfo, tree, hf_dap_spkmInfo);
}


static const ber_sequence_t SecurityErrorData_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_security_error_problem },
  { BER_CLASS_CON, 1, 0, dissect_spkmInfo },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_SecurityErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SecurityErrorData_set, hf_index, ett_dap_SecurityErrorData);

  return offset;
}
static int dissect_unsignedSecurityError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SecurityErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedSecurityError);
}
static int dissect_securityErrorData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SecurityErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_securityErrorData);
}


static const ber_sequence_t T_signedSecurityError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_securityErrorData },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedSecurityError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedSecurityError_sequence, hf_index, ett_dap_T_signedSecurityError);

  return offset;
}
static int dissect_signedSecurityError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedSecurityError(FALSE, tvb, offset, pinfo, tree, hf_dap_signedSecurityError);
}


const value_string dap_SecurityError_vals[] = {
  {   0, "unsignedSecurityError" },
  {   1, "signedSecurityError" },
  { 0, NULL }
};

static const ber_choice_t SecurityError_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedSecurityError },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedSecurityError },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_SecurityError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SecurityError_choice, hf_index, ett_dap_SecurityError,
                                 NULL);

  return offset;
}


static const ber_sequence_t ServiceErrorData_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_service_error_problem },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_ServiceErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ServiceErrorData_set, hf_index, ett_dap_ServiceErrorData);

  return offset;
}
static int dissect_unsignedServiceError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ServiceErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedServiceError);
}
static int dissect_serviceError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_ServiceErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_serviceError);
}


static const ber_sequence_t T_signedServiceError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_serviceError },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedServiceError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedServiceError_sequence, hf_index, ett_dap_T_signedServiceError);

  return offset;
}
static int dissect_signedServiceError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedServiceError(FALSE, tvb, offset, pinfo, tree, hf_dap_signedServiceError);
}


const value_string dap_ServiceError_vals[] = {
  {   0, "unsignedServiceError" },
  {   1, "signedServiceError" },
  { 0, NULL }
};

static const ber_choice_t ServiceError_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedServiceError },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedServiceError },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_ServiceError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ServiceError_choice, hf_index, ett_dap_ServiceError,
                                 NULL);

  return offset;
}


static const value_string dap_UpdateProblem_vals[] = {
  {   1, "namingViolation" },
  {   2, "objectClassViolation" },
  {   3, "notAllowedOnNonLeaf" },
  {   4, "notAllowedOnRDN" },
  {   5, "entryAlreadyExists" },
  {   6, "affectsMultipleDSAs" },
  {   7, "objectClassModificationProhibited" },
  {   8, "noSuchSuperior" },
  {   9, "notAncestor" },
  {  10, "parentNotAncestor" },
  {  11, "hierarchyRuleViolation" },
  {  12, "familyRuleViolation" },
  { 0, NULL }
};


static int
dissect_dap_UpdateProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 223 "dap.cnf"
  guint32 problem;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &problem);


  if (check_col(pinfo->cinfo, COL_INFO)) {
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, dap_UpdateProblem_vals, "UpdateProblem(%d)"));
  }



  return offset;
}
static int dissect_update_error_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_UpdateProblem(FALSE, tvb, offset, pinfo, tree, hf_dap_update_error_problem);
}


static const value_string dap_T_attributeInfo_item_vals[] = {
  {   0, "attributeType" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t T_attributeInfo_item_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attributeType },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_attribute },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dap_T_attributeInfo_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_attributeInfo_item_choice, hf_index, ett_dap_T_attributeInfo_item,
                                 NULL);

  return offset;
}
static int dissect_attributeInfo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_attributeInfo_item(FALSE, tvb, offset, pinfo, tree, hf_dap_attributeInfo_item);
}


static const ber_sequence_t T_attributeInfo_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_attributeInfo_item },
};

static int
dissect_dap_T_attributeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_attributeInfo_set_of, hf_index, ett_dap_T_attributeInfo);

  return offset;
}
static int dissect_attributeInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_attributeInfo(FALSE, tvb, offset, pinfo, tree, hf_dap_attributeInfo);
}


static const ber_sequence_t UpdateErrorData_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_update_error_problem },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_attributeInfo },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_UpdateErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              UpdateErrorData_set, hf_index, ett_dap_UpdateErrorData);

  return offset;
}
static int dissect_unsignedUpdateError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_UpdateErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_unsignedUpdateError);
}
static int dissect_updateError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_UpdateErrorData(FALSE, tvb, offset, pinfo, tree, hf_dap_updateError);
}


static const ber_sequence_t T_signedUpdateError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_updateError },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedUpdateError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedUpdateError_sequence, hf_index, ett_dap_T_signedUpdateError);

  return offset;
}
static int dissect_signedUpdateError(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_T_signedUpdateError(FALSE, tvb, offset, pinfo, tree, hf_dap_signedUpdateError);
}


const value_string dap_UpdateError_vals[] = {
  {   0, "unsignedUpdateError" },
  {   1, "signedUpdateError" },
  { 0, NULL }
};

static const ber_choice_t UpdateError_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_unsignedUpdateError },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedUpdateError },
  { 0, 0, 0, 0, NULL }
};

int
dissect_dap_UpdateError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 UpdateError_choice, hf_index, ett_dap_UpdateError,
                                 NULL);

  return offset;
}


/*--- End of included file: packet-dap-fn.c ---*/
#line 76 "packet-dap-template.c"

/*
* Dissect DAP PDUs inside a ROS PDUs
*/
static void
dissect_dap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*dap_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *dap_op_name;

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
		item = proto_tree_add_item(parent_tree, proto_dap, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_dap);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DAP");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  dap_dissector = dissect_dap_DirectoryBindArgument;
	  dap_op_name = "Bind-Argument";
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  dap_dissector = dissect_dap_DirectoryBindResult;
	  dap_op_name = "Bind-Result";
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  dap_dissector = dissect_dap_DirectoryBindError;
	  dap_op_name = "Bind-Error";
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* read */
	    dap_dissector = dissect_dap_ReadArgument;
	    dap_op_name = "Read-Argument";
	    break;
	  case 2: /* compare */
	    dap_dissector = dissect_dap_CompareArgument;
	    dap_op_name = "Compare-Argument";
	    break;
	  case 3: /* abandon */
	    dap_dissector = dissect_dap_AbandonArgument;
	    dap_op_name = "Abandon-Argument";
	    break;
	  case 4: /* list */
	    dap_dissector = dissect_dap_ListArgument;
	    dap_op_name = "List-Argument";
	    break;
	  case 5: /* search */
	    dap_dissector = dissect_dap_SearchArgument;
	    dap_op_name = "Search-Argument";
	    break;
	  case 6: /* addEntry */
	    dap_dissector = dissect_dap_AddEntryArgument;
	    dap_op_name = "Add-Entry-Argument";
	    break;
	  case 7: /* removeEntry */
	    dap_dissector = dissect_dap_RemoveEntryArgument;
	    dap_op_name = "Remove-Entry-Argument";
	    break;
	  case 8: /* modifyEntry */
	    dap_dissector = dissect_dap_ModifyEntryArgument;
	    dap_op_name = "Modify-Entry-Argument";
	    break;
	  case 9: /* modifyDN */
	    dap_dissector = dissect_dap_ModifyDNArgument;
	    dap_op_name = "Modify-DN-Argument";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DAP opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* read */
	    dap_dissector = dissect_dap_ReadResult;
	    dap_op_name = "Read-Result";
	    break;
	  case 2: /* compare */
	    dap_dissector = dissect_dap_CompareResult;
	    dap_op_name = "Compare-Result";
	    break;
	  case 3: /* abandon */
	    dap_dissector = dissect_dap_AbandonResult;
	    dap_op_name = "Abandon-Result";
	    break;
	  case 4: /* list */
	    dap_dissector = dissect_dap_ListResult;
	    dap_op_name = "List-Result";
	    break;
	  case 5: /* search */
	    dap_dissector = dissect_dap_SearchResult;
	    dap_op_name = "Search-Result";
	    break;
	  case 6: /* addEntry */
	    dap_dissector = dissect_dap_AddEntryResult;
	    dap_op_name = "Add-Entry-Result";
	    break;
	  case 7: /* removeEntry */
	    dap_dissector = dissect_dap_RemoveEntryResult;
	    dap_op_name = "Remove-Entry-Result";
	    break;
	  case 8: /* modifyEntry */
	    dap_dissector = dissect_dap_ModifyEntryResult;
	    dap_op_name = "Modify-Entry-Result";
	    break;
	  case 9: /* modifyDN */
	    dap_dissector = dissect_dap_ModifyDNResult;
	    dap_op_name = "Modify-DN-Result";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DAP opcode");
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* attributeError */
	    dap_dissector = dissect_dap_AttributeError;
	    dap_op_name = "Attribute-Error";
	    break;
	  case 2: /* nameError */
	    dap_dissector = dissect_dap_NameError;
	    dap_op_name = "Name-Error";
	    break;
	  case 3: /* serviceError */
	    dap_dissector = dissect_dap_ServiceError;
	    dap_op_name = "Service-Error";
	    break;
	  case 4: /* referral */
	    dap_dissector = dissect_dap_Referral;
	    dap_op_name = "Referral";
	    break;
	  case 5: /* abandoned */
	    dap_dissector = dissect_dap_Abandoned;
	    dap_op_name = "Abandoned";
	    break;
	  case 6: /* securityError */
	    dap_dissector = dissect_dap_SecurityError;
	    dap_op_name = "Security-Error";
	    break;
	  case 7: /* abandonFailed */
	    dap_dissector = dissect_dap_AbandonFailedError;
	    dap_op_name = "Abandon-Failed-Error";
	    break;
	  case 8: /* updateError */
	    dap_dissector = dissect_dap_UpdateError;
	    dap_op_name = "Update-Error";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DAP errcode");
	    break;
	  }
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DAP PDU");
	  return;
	}

	if(dap_dissector) {
	  if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_str(pinfo->cinfo, COL_INFO, dap_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dap_dissector)(FALSE, tvb, offset, pinfo , tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DAP PDU");
	      offset = tvb_length(tvb);
	      break;
	    }
	  }
	}
}


/*--- proto_register_dap -------------------------------------------*/
void proto_register_dap(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-dap-hfarr.c ---*/
#line 1 "packet-dap-hfarr.c"
    { &hf_dap_securityParameters,
      { "securityParameters", "dap.securityParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_performer,
      { "performer", "dap.performer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dap_aliasDereferenced,
      { "aliasDereferenced", "dap.aliasDereferenced",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_dap_notification,
      { "notification", "dap.notification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dap_notification_item,
      { "Item", "dap.notification_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_options,
      { "options", "dap.options",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ServiceControls/options", HFILL }},
    { &hf_dap_priority,
      { "priority", "dap.priority",
        FT_INT32, BASE_DEC, VALS(dap_T_priority_vals), 0,
        "ServiceControls/priority", HFILL }},
    { &hf_dap_timeLimit,
      { "timeLimit", "dap.timeLimit",
        FT_INT32, BASE_DEC, NULL, 0,
        "ServiceControls/timeLimit", HFILL }},
    { &hf_dap_sizeLimit,
      { "sizeLimit", "dap.sizeLimit",
        FT_INT32, BASE_DEC, NULL, 0,
        "ServiceControls/sizeLimit", HFILL }},
    { &hf_dap_scopeOfReferral,
      { "scopeOfReferral", "dap.scopeOfReferral",
        FT_INT32, BASE_DEC, VALS(dap_T_scopeOfReferral_vals), 0,
        "ServiceControls/scopeOfReferral", HFILL }},
    { &hf_dap_attributeSizeLimit,
      { "attributeSizeLimit", "dap.attributeSizeLimit",
        FT_INT32, BASE_DEC, NULL, 0,
        "ServiceControls/attributeSizeLimit", HFILL }},
    { &hf_dap_manageDSAITPlaneRef,
      { "manageDSAITPlaneRef", "dap.manageDSAITPlaneRef",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControls/manageDSAITPlaneRef", HFILL }},
    { &hf_dap_dsaName,
      { "dsaName", "dap.dsaName",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "ServiceControls/manageDSAITPlaneRef/dsaName", HFILL }},
    { &hf_dap_agreementID,
      { "agreementID", "dap.agreementID",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControls/manageDSAITPlaneRef/agreementID", HFILL }},
    { &hf_dap_serviceType,
      { "serviceType", "dap.serviceType",
        FT_OID, BASE_NONE, NULL, 0,
        "ServiceControls/serviceType", HFILL }},
    { &hf_dap_userClass,
      { "userClass", "dap.userClass",
        FT_INT32, BASE_DEC, NULL, 0,
        "ServiceControls/userClass", HFILL }},
    { &hf_dap_attributes,
      { "attributes", "dap.attributes",
        FT_UINT32, BASE_DEC, VALS(dap_T_attributes_vals), 0,
        "EntryInformationSelection/attributes", HFILL }},
    { &hf_dap_allUserAttributes,
      { "allUserAttributes", "dap.allUserAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryInformationSelection/attributes/allUserAttributes", HFILL }},
    { &hf_dap_select,
      { "select", "dap.select",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dap_select_item,
      { "Item", "dap.select_item",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_infoTypes,
      { "infoTypes", "dap.infoTypes",
        FT_INT32, BASE_DEC, VALS(dap_T_infoTypes_vals), 0,
        "EntryInformationSelection/infoTypes", HFILL }},
    { &hf_dap_extraAttributes,
      { "extraAttributes", "dap.extraAttributes",
        FT_UINT32, BASE_DEC, VALS(dap_T_extraAttributes_vals), 0,
        "EntryInformationSelection/extraAttributes", HFILL }},
    { &hf_dap_allOperationalAttributes,
      { "allOperationalAttributes", "dap.allOperationalAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryInformationSelection/extraAttributes/allOperationalAttributes", HFILL }},
    { &hf_dap_contextSelection,
      { "contextSelection", "dap.contextSelection",
        FT_UINT32, BASE_DEC, VALS(dap_ContextSelection_vals), 0,
        "EntryInformationSelection/contextSelection", HFILL }},
    { &hf_dap_returnContexts,
      { "returnContexts", "dap.returnContexts",
        FT_BOOLEAN, 8, NULL, 0,
        "EntryInformationSelection/returnContexts", HFILL }},
    { &hf_dap_familyReturn,
      { "familyReturn", "dap.familyReturn",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryInformationSelection/familyReturn", HFILL }},
    { &hf_dap_allContexts,
      { "allContexts", "dap.allContexts",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContextSelection/allContexts", HFILL }},
    { &hf_dap_selectedContexts,
      { "selectedContexts", "dap.selectedContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContextSelection/selectedContexts", HFILL }},
    { &hf_dap_selectedContexts_item,
      { "Item", "dap.selectedContexts_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContextSelection/selectedContexts/_item", HFILL }},
    { &hf_dap_type,
      { "type", "dap.type",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_contextAssertions,
      { "contextAssertions", "dap.contextAssertions",
        FT_UINT32, BASE_DEC, VALS(dap_T_contextAssertions_vals), 0,
        "TypeAndContextAssertion/contextAssertions", HFILL }},
    { &hf_dap_preference,
      { "preference", "dap.preference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TypeAndContextAssertion/contextAssertions/preference", HFILL }},
    { &hf_dap_preference_item,
      { "Item", "dap.preference_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "TypeAndContextAssertion/contextAssertions/preference/_item", HFILL }},
    { &hf_dap_all,
      { "all", "dap.all",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TypeAndContextAssertion/contextAssertions/all", HFILL }},
    { &hf_dap_all_item,
      { "Item", "dap.all_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "TypeAndContextAssertion/contextAssertions/all/_item", HFILL }},
    { &hf_dap_memberSelect,
      { "memberSelect", "dap.memberSelect",
        FT_UINT32, BASE_DEC, VALS(dap_T_memberSelect_vals), 0,
        "FamilyReturn/memberSelect", HFILL }},
    { &hf_dap_familySelect,
      { "familySelect", "dap.familySelect",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FamilyReturn/familySelect", HFILL }},
    { &hf_dap_familySelect_item,
      { "Item", "dap.familySelect_item",
        FT_OID, BASE_NONE, NULL, 0,
        "FamilyReturn/familySelect/_item", HFILL }},
    { &hf_dap_name,
      { "name", "dap.name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "", HFILL }},
    { &hf_dap_fromEntry,
      { "fromEntry", "dap.fromEntry",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_dap_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EntryInformation/information", HFILL }},
    { &hf_dap_entry_information_item,
      { "Item", "dap.information_item",
        FT_UINT32, BASE_DEC, VALS(dap_EntryInformationItem_vals), 0,
        "EntryInformation/information/_item", HFILL }},
    { &hf_dap_attributeType,
      { "attributeType", "dap.attributeType",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_attribute,
      { "attribute", "dap.attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_incompleteEntry,
      { "incompleteEntry", "dap.incompleteEntry",
        FT_BOOLEAN, 8, NULL, 0,
        "EntryInformation/incompleteEntry", HFILL }},
    { &hf_dap_partialName,
      { "partialName", "dap.partialName",
        FT_BOOLEAN, 8, NULL, 0,
        "EntryInformation/partialName", HFILL }},
    { &hf_dap_derivedEntry,
      { "derivedEntry", "dap.derivedEntry",
        FT_BOOLEAN, 8, NULL, 0,
        "EntryInformation/derivedEntry", HFILL }},
    { &hf_dap_family_class,
      { "family-class", "dap.family_class",
        FT_OID, BASE_NONE, NULL, 0,
        "FamilyEntries/family-class", HFILL }},
    { &hf_dap_familyEntries,
      { "familyEntries", "dap.familyEntries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FamilyEntries/familyEntries", HFILL }},
    { &hf_dap_familyEntries_item,
      { "Item", "dap.familyEntries_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "FamilyEntries/familyEntries/_item", HFILL }},
    { &hf_dap_rdn,
      { "rdn", "dap.rdn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dap_family_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FamilyEntry/information", HFILL }},
    { &hf_dap_information_item,
      { "Item", "dap.information_item",
        FT_UINT32, BASE_DEC, VALS(dap_T_information_item_vals), 0,
        "FamilyEntry/information/_item", HFILL }},
    { &hf_dap_family_info,
      { "family-info", "dap.family_info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FamilyEntry/family-info", HFILL }},
    { &hf_dap_family_info_item,
      { "Item", "dap.family_info_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "FamilyEntry/family-info/_item", HFILL }},
    { &hf_dap_filter_item,
      { "item", "dap.item",
        FT_UINT32, BASE_DEC, VALS(dap_FilterItem_vals), 0,
        "Filter/item", HFILL }},
    { &hf_dap_and,
      { "and", "dap.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Filter/and", HFILL }},
    { &hf_dap_or,
      { "or", "dap.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Filter/or", HFILL }},
    { &hf_dap_not,
      { "not", "dap.not",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "Filter/not", HFILL }},
    { &hf_dap_SetOfFilter_item,
      { "Item", "dap.SetOfFilter_item",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "SetOfFilter/_item", HFILL }},
    { &hf_dap_equality,
      { "equality", "dap.equality",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/equality", HFILL }},
    { &hf_dap_substrings,
      { "substrings", "dap.substrings",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/substrings", HFILL }},
    { &hf_dap_sunstringType,
      { "type", "dap.type",
        FT_OID, BASE_NONE, NULL, 0,
        "FilterItem/substrings/type", HFILL }},
    { &hf_dap_strings,
      { "strings", "dap.strings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FilterItem/substrings/strings", HFILL }},
    { &hf_dap_strings_item,
      { "Item", "dap.strings_item",
        FT_UINT32, BASE_DEC, VALS(dap_T_strings_item_vals), 0,
        "FilterItem/substrings/strings/_item", HFILL }},
    { &hf_dap_initial,
      { "initial", "dap.initial",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/substrings/strings/_item/initial", HFILL }},
    { &hf_dap_any,
      { "any", "dap.any",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/substrings/strings/_item/any", HFILL }},
    { &hf_dap_final,
      { "final", "dap.final",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/substrings/strings/_item/final", HFILL }},
    { &hf_dap_control,
      { "control", "dap.control",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/substrings/strings/_item/control", HFILL }},
    { &hf_dap_greaterOrEqual,
      { "greaterOrEqual", "dap.greaterOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/greaterOrEqual", HFILL }},
    { &hf_dap_lessOrEqual,
      { "lessOrEqual", "dap.lessOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/lessOrEqual", HFILL }},
    { &hf_dap_present,
      { "present", "dap.present",
        FT_OID, BASE_NONE, NULL, 0,
        "FilterItem/present", HFILL }},
    { &hf_dap_approximateMatch,
      { "approximateMatch", "dap.approximateMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/approximateMatch", HFILL }},
    { &hf_dap_extensibleMatch,
      { "extensibleMatch", "dap.extensibleMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/extensibleMatch", HFILL }},
    { &hf_dap_contextPresent,
      { "contextPresent", "dap.contextPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/contextPresent", HFILL }},
    { &hf_dap_matchingRule,
      { "matchingRule", "dap.matchingRule",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MatchingRuleAssertion/matchingRule", HFILL }},
    { &hf_dap_matchingRule_item,
      { "Item", "dap.matchingRule_item",
        FT_OID, BASE_NONE, NULL, 0,
        "MatchingRuleAssertion/matchingRule/_item", HFILL }},
    { &hf_dap_matchValue,
      { "matchValue", "dap.matchValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "MatchingRuleAssertion/matchValue", HFILL }},
    { &hf_dap_dnAttributes,
      { "dnAttributes", "dap.dnAttributes",
        FT_BOOLEAN, 8, NULL, 0,
        "MatchingRuleAssertion/dnAttributes", HFILL }},
    { &hf_dap_newRequest,
      { "newRequest", "dap.newRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "PagedResultsRequest/newRequest", HFILL }},
    { &hf_dap_pageSize,
      { "pageSize", "dap.pageSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "PagedResultsRequest/newRequest/pageSize", HFILL }},
    { &hf_dap_sortKeys,
      { "sortKeys", "dap.sortKeys",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PagedResultsRequest/newRequest/sortKeys", HFILL }},
    { &hf_dap_sortKeys_item,
      { "Item", "dap.sortKeys_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PagedResultsRequest/newRequest/sortKeys/_item", HFILL }},
    { &hf_dap_reverse,
      { "reverse", "dap.reverse",
        FT_BOOLEAN, 8, NULL, 0,
        "PagedResultsRequest/newRequest/reverse", HFILL }},
    { &hf_dap_unmerged,
      { "unmerged", "dap.unmerged",
        FT_BOOLEAN, 8, NULL, 0,
        "PagedResultsRequest/newRequest/unmerged", HFILL }},
    { &hf_dap_queryReference,
      { "queryReference", "dap.queryReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_dap_orderingRule,
      { "orderingRule", "dap.orderingRule",
        FT_OID, BASE_NONE, NULL, 0,
        "SortKey/orderingRule", HFILL }},
    { &hf_dap_certification_path,
      { "certification-path", "dap.certification_path",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_distinguished_name,
      { "name", "dap.name",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dap_time,
      { "time", "dap.time",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "SecurityParameters/time", HFILL }},
    { &hf_dap_random,
      { "random", "dap.random",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SecurityParameters/random", HFILL }},
    { &hf_dap_target,
      { "target", "dap.target",
        FT_INT32, BASE_DEC, VALS(dap_ProtectionRequest_vals), 0,
        "SecurityParameters/target", HFILL }},
    { &hf_dap_response,
      { "response", "dap.response",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SecurityParameters/response", HFILL }},
    { &hf_dap_operationCode,
      { "operationCode", "dap.operationCode",
        FT_UINT32, BASE_DEC, VALS(ros_Code_vals), 0,
        "SecurityParameters/operationCode", HFILL }},
    { &hf_dap_attributeCertificationPath,
      { "attributeCertificationPath", "dap.attributeCertificationPath",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_errorProtection,
      { "errorProtection", "dap.errorProtection",
        FT_INT32, BASE_DEC, VALS(dap_ErrorProtectionRequest_vals), 0,
        "SecurityParameters/errorProtection", HFILL }},
    { &hf_dap_errorCode,
      { "errorCode", "dap.errorCode",
        FT_UINT32, BASE_DEC, VALS(ros_Code_vals), 0,
        "SecurityParameters/errorCode", HFILL }},
    { &hf_dap_utcTime,
      { "utcTime", "dap.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time/utcTime", HFILL }},
    { &hf_dap_generalizedTime,
      { "generalizedTime", "dap.generalizedTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time/generalizedTime", HFILL }},
    { &hf_dap_credentials,
      { "credentials", "dap.credentials",
        FT_UINT32, BASE_DEC, VALS(dap_Credentials_vals), 0,
        "DirectoryBindArgument/credentials", HFILL }},
    { &hf_dap_versions,
      { "versions", "dap.versions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_dap_simple,
      { "simple", "dap.simple",
        FT_NONE, BASE_NONE, NULL, 0,
        "Credentials/simple", HFILL }},
    { &hf_dap_strong,
      { "strong", "dap.strong",
        FT_NONE, BASE_NONE, NULL, 0,
        "Credentials/strong", HFILL }},
    { &hf_dap_externalProcedure,
      { "externalProcedure", "dap.externalProcedure",
        FT_NONE, BASE_NONE, NULL, 0,
        "Credentials/externalProcedure", HFILL }},
    { &hf_dap_spkm,
      { "spkm", "dap.spkm",
        FT_UINT32, BASE_DEC, VALS(dap_SpkmCredentials_vals), 0,
        "Credentials/spkm", HFILL }},
    { &hf_dap_validity,
      { "validity", "dap.validity",
        FT_NONE, BASE_NONE, NULL, 0,
        "SimpleCredentials/validity", HFILL }},
    { &hf_dap_time1,
      { "time1", "dap.time1",
        FT_UINT32, BASE_DEC, VALS(dap_T_time1_vals), 0,
        "SimpleCredentials/validity/time1", HFILL }},
    { &hf_dap_utc,
      { "utc", "dap.utc",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_gt,
      { "gt", "dap.gt",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_time2,
      { "time2", "dap.time2",
        FT_UINT32, BASE_DEC, VALS(dap_T_time2_vals), 0,
        "SimpleCredentials/validity/time2", HFILL }},
    { &hf_dap_random1,
      { "random1", "dap.random1",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SimpleCredentials/validity/random1", HFILL }},
    { &hf_dap_random2,
      { "random2", "dap.random2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SimpleCredentials/validity/random2", HFILL }},
    { &hf_dap_password,
      { "password", "dap.password",
        FT_UINT32, BASE_DEC, VALS(dap_T_password_vals), 0,
        "SimpleCredentials/password", HFILL }},
    { &hf_dap_unprotected,
      { "unprotected", "dap.unprotected",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SimpleCredentials/password/unprotected", HFILL }},
    { &hf_dap_protected,
      { "protected", "dap.protected",
        FT_NONE, BASE_NONE, NULL, 0,
        "SimpleCredentials/password/protected", HFILL }},
    { &hf_dap_protectedPassword,
      { "protectedPassword", "dap.protectedPassword",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SimpleCredentials/password/protected/protectedPassword", HFILL }},
    { &hf_dap_algorithmIdentifier,
      { "algorithmIdentifier", "dap.algorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_encrypted,
      { "encrypted", "dap.encrypted",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_dap_bind_token,
      { "bind-token", "dap.bind_token",
        FT_NONE, BASE_NONE, NULL, 0,
        "StrongCredentials/bind-token", HFILL }},
    { &hf_dap_req,
      { "req", "dap.req",
        FT_NONE, BASE_NONE, NULL, 0,
        "SpkmCredentials/req", HFILL }},
    { &hf_dap_rep,
      { "rep", "dap.rep",
        FT_NONE, BASE_NONE, NULL, 0,
        "SpkmCredentials/rep", HFILL }},
    { &hf_dap_error,
      { "error", "dap.error",
        FT_UINT32, BASE_DEC, VALS(dap_T_error_vals), 0,
        "DirectoryBindErrorData/error", HFILL }},
    { &hf_dap_serviceProblem,
      { "serviceError", "dap.serviceError",
        FT_INT32, BASE_DEC, VALS(dap_ServiceProblem_vals), 0,
        "DirectoryBindErrorData/error/serviceError", HFILL }},
    { &hf_dap_securityProblem,
      { "securityError", "dap.securityError",
        FT_INT32, BASE_DEC, VALS(dap_SecurityProblem_vals), 0,
        "DirectoryBindErrorData/error/securityError", HFILL }},
    { &hf_dap_unsignedDirectoryBindError,
      { "unsignedDirectoryBindError", "dap.unsignedDirectoryBindError",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectoryBindError/unsignedDirectoryBindError", HFILL }},
    { &hf_dap_signedDirectoryBindError,
      { "signedDirectoryBindError", "dap.signedDirectoryBindError",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectoryBindError/signedDirectoryBindError", HFILL }},
    { &hf_dap_directoryBindError,
      { "directoryBindError", "dap.directoryBindError",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectoryBindError/signedDirectoryBindError/directoryBindError", HFILL }},
    { &hf_dap_object,
      { "object", "dap.object",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "", HFILL }},
    { &hf_dap_selection,
      { "selection", "dap.selection",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_modifyRightsRequest,
      { "modifyRightsRequest", "dap.modifyRightsRequest",
        FT_BOOLEAN, 8, NULL, 0,
        "ReadArgumentData/modifyRightsRequest", HFILL }},
    { &hf_dap_serviceControls,
      { "serviceControls", "dap.serviceControls",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_requestor,
      { "requestor", "dap.requestor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dap_operationProgress,
      { "operationProgress", "dap.operationProgress",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_aliasedRDNs,
      { "aliasedRDNs", "dap.aliasedRDNs",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dap_criticalExtensions,
      { "criticalExtensions", "dap.criticalExtensions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_dap_referenceType,
      { "referenceType", "dap.referenceType",
        FT_UINT32, BASE_DEC, VALS(dsp_ReferenceType_vals), 0,
        "", HFILL }},
    { &hf_dap_entryOnly,
      { "entryOnly", "dap.entryOnly",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_dap_nameResolveOnMaster,
      { "nameResolveOnMaster", "dap.nameResolveOnMaster",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_dap_operationContexts,
      { "operationContexts", "dap.operationContexts",
        FT_UINT32, BASE_DEC, VALS(dap_ContextSelection_vals), 0,
        "", HFILL }},
    { &hf_dap_familyGrouping,
      { "familyGrouping", "dap.familyGrouping",
        FT_UINT32, BASE_DEC, VALS(dap_FamilyGrouping_vals), 0,
        "", HFILL }},
    { &hf_dap_rdnSequence,
      { "rdnSequence", "dap.rdnSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name/rdnSequence", HFILL }},
    { &hf_dap_unsignedReadArgument,
      { "unsignedReadArgument", "dap.unsignedReadArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadArgument/unsignedReadArgument", HFILL }},
    { &hf_dap_signedReadArgument,
      { "signedReadArgument", "dap.signedReadArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadArgument/signedReadArgument", HFILL }},
    { &hf_dap_readArgument,
      { "readArgument", "dap.readArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadArgument/signedReadArgument/readArgument", HFILL }},
    { &hf_dap_entry,
      { "entry", "dap.entry",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_modifyRights,
      { "modifyRights", "dap.modifyRights",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReadResultData/modifyRights", HFILL }},
    { &hf_dap_unsignedReadResult,
      { "unsignedReadResult", "dap.unsignedReadResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadResult/unsignedReadResult", HFILL }},
    { &hf_dap_signedReadResult,
      { "signedReadResult", "dap.signedReadResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadResult/signedReadResult", HFILL }},
    { &hf_dap_readResult,
      { "readResult", "dap.readResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadResult/signedReadResult/readResult", HFILL }},
    { &hf_dap_ModifyRights_item,
      { "Item", "dap.ModifyRights_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyRights/_item", HFILL }},
    { &hf_dap_item,
      { "item", "dap.item",
        FT_UINT32, BASE_DEC, VALS(dap_T_item_vals), 0,
        "ModifyRights/_item/item", HFILL }},
    { &hf_dap_item_entry,
      { "entry", "dap.entry",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyRights/_item/item/entry", HFILL }},
    { &hf_dap_attribute_type,
      { "attribute", "dap.attribute",
        FT_OID, BASE_NONE, NULL, 0,
        "ModifyRights/_item/item/attribute", HFILL }},
    { &hf_dap_value_assertion,
      { "value", "dap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyRights/_item/item/value", HFILL }},
    { &hf_dap_permission,
      { "permission", "dap.permission",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ModifyRights/_item/permission", HFILL }},
    { &hf_dap_purported,
      { "purported", "dap.purported",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareArgumentData/purported", HFILL }},
    { &hf_dap_unsignedCompareArgument,
      { "unsignedCompareArgument", "dap.unsignedCompareArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareArgument/unsignedCompareArgument", HFILL }},
    { &hf_dap_signedCompareArgument,
      { "signedCompareArgument", "dap.signedCompareArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareArgument/signedCompareArgument", HFILL }},
    { &hf_dap_compareArgument,
      { "compareArgument", "dap.compareArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareArgument/signedCompareArgument/compareArgument", HFILL }},
    { &hf_dap_matched,
      { "matched", "dap.matched",
        FT_BOOLEAN, 8, NULL, 0,
        "CompareResultData/matched", HFILL }},
    { &hf_dap_matchedSubtype,
      { "matchedSubtype", "dap.matchedSubtype",
        FT_OID, BASE_NONE, NULL, 0,
        "CompareResultData/matchedSubtype", HFILL }},
    { &hf_dap_unsignedCompareResult,
      { "unsignedCompareResult", "dap.unsignedCompareResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareResult/unsignedCompareResult", HFILL }},
    { &hf_dap_signedCompareResult,
      { "signedCompareResult", "dap.signedCompareResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareResult/signedCompareResult", HFILL }},
    { &hf_dap_compareResult,
      { "compareResult", "dap.compareResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareResult/signedCompareResult/compareResult", HFILL }},
    { &hf_dap_invokeID,
      { "invokeID", "dap.invokeID",
        FT_UINT32, BASE_DEC, VALS(ros_InvokeId_vals), 0,
        "", HFILL }},
    { &hf_dap_unsignedAbandonArgument,
      { "unsignedAbandonArgument", "dap.unsignedAbandonArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonArgument/unsignedAbandonArgument", HFILL }},
    { &hf_dap_signedAbandonArgument,
      { "signedAbandonArgument", "dap.signedAbandonArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonArgument/signedAbandonArgument", HFILL }},
    { &hf_dap_abandonArgument,
      { "abandonArgument", "dap.abandonArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonArgument/signedAbandonArgument/abandonArgument", HFILL }},
    { &hf_dap_null,
      { "null", "dap.null",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_abandon_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_AbandonInformation_vals), 0,
        "AbandonResult/information", HFILL }},
    { &hf_dap_unsignedAbandonResult,
      { "unsignedAbandonResult", "dap.unsignedAbandonResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonResult/information/unsignedAbandonResult", HFILL }},
    { &hf_dap_signedAbandonResult,
      { "signedAbandonResult", "dap.signedAbandonResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonResult/information/signedAbandonResult", HFILL }},
    { &hf_dap_abandonResult,
      { "abandonResult", "dap.abandonResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonResult/information/signedAbandonResult/abandonResult", HFILL }},
    { &hf_dap_pagedResults,
      { "pagedResults", "dap.pagedResults",
        FT_UINT32, BASE_DEC, VALS(dap_PagedResultsRequest_vals), 0,
        "", HFILL }},
    { &hf_dap_listFamily,
      { "listFamily", "dap.listFamily",
        FT_BOOLEAN, 8, NULL, 0,
        "ListArgumentData/listFamily", HFILL }},
    { &hf_dap_unsignedListArgument,
      { "unsignedListArgument", "dap.unsignedListArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListArgument/unsignedListArgument", HFILL }},
    { &hf_dap_signedListArgument,
      { "signedListArgument", "dap.signedListArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListArgument/signedListArgument", HFILL }},
    { &hf_dap_listArgument,
      { "listArgument", "dap.listArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListArgument/signedListArgument/listArgument", HFILL }},
    { &hf_dap_listInfo,
      { "listInfo", "dap.listInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListResultData/listInfo", HFILL }},
    { &hf_dap_subordinates,
      { "subordinates", "dap.subordinates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ListResultData/listInfo/subordinates", HFILL }},
    { &hf_dap_subordinates_item,
      { "Item", "dap.subordinates_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListResultData/listInfo/subordinates/_item", HFILL }},
    { &hf_dap_aliasEntry,
      { "aliasEntry", "dap.aliasEntry",
        FT_BOOLEAN, 8, NULL, 0,
        "ListResultData/listInfo/subordinates/_item/aliasEntry", HFILL }},
    { &hf_dap_partialOutcomeQualifier,
      { "partialOutcomeQualifier", "dap.partialOutcomeQualifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dap_uncorrelatedListInfo,
      { "uncorrelatedListInfo", "dap.uncorrelatedListInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ListResultData/uncorrelatedListInfo", HFILL }},
    { &hf_dap_uncorrelatedListInfo_item,
      { "Item", "dap.uncorrelatedListInfo_item",
        FT_UINT32, BASE_DEC, VALS(dap_ListResult_vals), 0,
        "ListResultData/uncorrelatedListInfo/_item", HFILL }},
    { &hf_dap_unsignedListResult,
      { "unsignedListResult", "dap.unsignedListResult",
        FT_UINT32, BASE_DEC, VALS(dap_ListResultData_vals), 0,
        "ListResult/unsignedListResult", HFILL }},
    { &hf_dap_signedListResult,
      { "signedListResult", "dap.signedListResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListResult/signedListResult", HFILL }},
    { &hf_dap_listResult,
      { "listResult", "dap.listResult",
        FT_UINT32, BASE_DEC, VALS(dap_ListResultData_vals), 0,
        "ListResult/signedListResult/listResult", HFILL }},
    { &hf_dap_limitProblem,
      { "limitProblem", "dap.limitProblem",
        FT_INT32, BASE_DEC, VALS(dap_LimitProblem_vals), 0,
        "PartialOutcomeQualifier/limitProblem", HFILL }},
    { &hf_dap_unexplored,
      { "unexplored", "dap.unexplored",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PartialOutcomeQualifier/unexplored", HFILL }},
    { &hf_dap_unexplored_item,
      { "Item", "dap.unexplored_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartialOutcomeQualifier/unexplored/_item", HFILL }},
    { &hf_dap_unavailableCriticalExtensions,
      { "unavailableCriticalExtensions", "dap.unavailableCriticalExtensions",
        FT_BOOLEAN, 8, NULL, 0,
        "PartialOutcomeQualifier/unavailableCriticalExtensions", HFILL }},
    { &hf_dap_unknownErrors,
      { "unknownErrors", "dap.unknownErrors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PartialOutcomeQualifier/unknownErrors", HFILL }},
    { &hf_dap_unknownErrors_item,
      { "Item", "dap.unknownErrors_item",
        FT_OID, BASE_NONE, NULL, 0,
        "PartialOutcomeQualifier/unknownErrors/_item", HFILL }},
    { &hf_dap_overspecFilter,
      { "overspecFilter", "dap.overspecFilter",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "PartialOutcomeQualifier/overspecFilter", HFILL }},
    { &hf_dap_entryCount,
      { "entryCount", "dap.entryCount",
        FT_UINT32, BASE_DEC, VALS(dap_T_entryCount_vals), 0,
        "PartialOutcomeQualifier/entryCount", HFILL }},
    { &hf_dap_bestEstimate,
      { "bestEstimate", "dap.bestEstimate",
        FT_INT32, BASE_DEC, NULL, 0,
        "PartialOutcomeQualifier/entryCount/bestEstimate", HFILL }},
    { &hf_dap_lowEstimate,
      { "lowEstimate", "dap.lowEstimate",
        FT_INT32, BASE_DEC, NULL, 0,
        "PartialOutcomeQualifier/entryCount/lowEstimate", HFILL }},
    { &hf_dap_baseObject,
      { "baseObject", "dap.baseObject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "SearchArgumentData/baseObject", HFILL }},
    { &hf_dap_subset,
      { "subset", "dap.subset",
        FT_INT32, BASE_DEC, VALS(dap_T_subset_vals), 0,
        "SearchArgumentData/subset", HFILL }},
    { &hf_dap_filter,
      { "filter", "dap.filter",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "SearchArgumentData/filter", HFILL }},
    { &hf_dap_searchAliases,
      { "searchAliases", "dap.searchAliases",
        FT_BOOLEAN, 8, NULL, 0,
        "SearchArgumentData/searchAliases", HFILL }},
    { &hf_dap_matchedValuesOnly,
      { "matchedValuesOnly", "dap.matchedValuesOnly",
        FT_BOOLEAN, 8, NULL, 0,
        "SearchArgumentData/matchedValuesOnly", HFILL }},
    { &hf_dap_extendedFilter,
      { "extendedFilter", "dap.extendedFilter",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "SearchArgumentData/extendedFilter", HFILL }},
    { &hf_dap_checkOverspecified,
      { "checkOverspecified", "dap.checkOverspecified",
        FT_BOOLEAN, 8, NULL, 0,
        "SearchArgumentData/checkOverspecified", HFILL }},
    { &hf_dap_relaxation,
      { "relaxation", "dap.relaxation",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchArgumentData/relaxation", HFILL }},
    { &hf_dap_extendedArea,
      { "extendedArea", "dap.extendedArea",
        FT_INT32, BASE_DEC, NULL, 0,
        "SearchArgumentData/extendedArea", HFILL }},
    { &hf_dap_hierarchySelections,
      { "hierarchySelections", "dap.hierarchySelections",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SearchArgumentData/hierarchySelections", HFILL }},
    { &hf_dap_searchControlOptions,
      { "searchControlOptions", "dap.searchControlOptions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SearchArgumentData/searchControlOptions", HFILL }},
    { &hf_dap_joinArguments,
      { "joinArguments", "dap.joinArguments",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchArgumentData/joinArguments", HFILL }},
    { &hf_dap_joinArguments_item,
      { "Item", "dap.joinArguments_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchArgumentData/joinArguments/_item", HFILL }},
    { &hf_dap_joinType,
      { "joinType", "dap.joinType",
        FT_UINT32, BASE_DEC, VALS(dap_T_joinType_vals), 0,
        "SearchArgumentData/joinType", HFILL }},
    { &hf_dap_unsignedSearchArgument,
      { "unsignedSearchArgument", "dap.unsignedSearchArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchArgument/unsignedSearchArgument", HFILL }},
    { &hf_dap_signedSearchArgument,
      { "signedSearchArgument", "dap.signedSearchArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchArgument/signedSearchArgument", HFILL }},
    { &hf_dap_searchArgument,
      { "searchArgument", "dap.searchArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchArgument/signedSearchArgument/searchArgument", HFILL }},
    { &hf_dap_joinBaseObject,
      { "joinBaseObject", "dap.joinBaseObject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "JoinArgument/joinBaseObject", HFILL }},
    { &hf_dap_domainLocalID,
      { "domainLocalID", "dap.domainLocalID",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "JoinArgument/domainLocalID", HFILL }},
    { &hf_dap_joinSubset,
      { "joinSubset", "dap.joinSubset",
        FT_UINT32, BASE_DEC, VALS(dap_T_joinSubset_vals), 0,
        "JoinArgument/joinSubset", HFILL }},
    { &hf_dap_joinFilter,
      { "joinFilter", "dap.joinFilter",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "JoinArgument/joinFilter", HFILL }},
    { &hf_dap_joinAttributes,
      { "joinAttributes", "dap.joinAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "JoinArgument/joinAttributes", HFILL }},
    { &hf_dap_joinAttributes_item,
      { "Item", "dap.joinAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "JoinArgument/joinAttributes/_item", HFILL }},
    { &hf_dap_joinSelection,
      { "joinSelection", "dap.joinSelection",
        FT_NONE, BASE_NONE, NULL, 0,
        "JoinArgument/joinSelection", HFILL }},
    { &hf_dap_baseAtt,
      { "baseAtt", "dap.baseAtt",
        FT_OID, BASE_NONE, NULL, 0,
        "JoinAttPair/baseAtt", HFILL }},
    { &hf_dap_joinAtt,
      { "joinAtt", "dap.joinAtt",
        FT_OID, BASE_NONE, NULL, 0,
        "JoinAttPair/joinAtt", HFILL }},
    { &hf_dap_joinContext,
      { "joinContext", "dap.joinContext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "JoinAttPair/joinContext", HFILL }},
    { &hf_dap_joinContext_item,
      { "Item", "dap.joinContext_item",
        FT_OID, BASE_NONE, NULL, 0,
        "JoinAttPair/joinContext/_item", HFILL }},
    { &hf_dap_searchInfo,
      { "searchInfo", "dap.searchInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchResultData/searchInfo", HFILL }},
    { &hf_dap_entries,
      { "entries", "dap.entries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchResultData/searchInfo/entries", HFILL }},
    { &hf_dap_entries_item,
      { "Item", "dap.entries_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchResultData/searchInfo/entries/_item", HFILL }},
    { &hf_dap_altMatching,
      { "altMatching", "dap.altMatching",
        FT_BOOLEAN, 8, NULL, 0,
        "SearchResultData/searchInfo/altMatching", HFILL }},
    { &hf_dap_uncorrelatedSearchInfo,
      { "uncorrelatedSearchInfo", "dap.uncorrelatedSearchInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchResultData/uncorrelatedSearchInfo", HFILL }},
    { &hf_dap_uncorrelatedSearchInfo_item,
      { "Item", "dap.uncorrelatedSearchInfo_item",
        FT_UINT32, BASE_DEC, VALS(dap_SearchResult_vals), 0,
        "SearchResultData/uncorrelatedSearchInfo/_item", HFILL }},
    { &hf_dap_unsignedSearchResult,
      { "unsignedSearchResult", "dap.unsignedSearchResult",
        FT_UINT32, BASE_DEC, VALS(dap_SearchResultData_vals), 0,
        "SearchResult/unsignedSearchResult", HFILL }},
    { &hf_dap_signedSearchResult,
      { "signedSearchResult", "dap.signedSearchResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchResult/signedSearchResult", HFILL }},
    { &hf_dap_searchResult,
      { "searchResult", "dap.searchResult",
        FT_UINT32, BASE_DEC, VALS(dap_SearchResultData_vals), 0,
        "SearchResult/signedSearchResult/searchResult", HFILL }},
    { &hf_dap_add_entry,
      { "entry", "dap.entry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddEntryArgumentData/entry", HFILL }},
    { &hf_dap_entry_item,
      { "Item", "dap.entry_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryArgumentData/entry/_item", HFILL }},
    { &hf_dap_targetSystem,
      { "targetSystem", "dap.targetSystem",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryArgumentData/targetSystem", HFILL }},
    { &hf_dap_unsignedAddEntryArgument,
      { "unsignedAddEntryArgument", "dap.unsignedAddEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryArgument/unsignedAddEntryArgument", HFILL }},
    { &hf_dap_signedAddEntryArgument,
      { "signedAddEntryArgument", "dap.signedAddEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryArgument/signedAddEntryArgument", HFILL }},
    { &hf_dap_addEntryArgument,
      { "addEntryArgument", "dap.addEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryArgument/signedAddEntryArgument/addEntryArgument", HFILL }},
    { &hf_dap_add_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_AddEntryInformation_vals), 0,
        "AddEntryResult/information", HFILL }},
    { &hf_dap_unsignedAddEntryResult,
      { "unsignedAddEntryResult", "dap.unsignedAddEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryResult/information/unsignedAddEntryResult", HFILL }},
    { &hf_dap_signedAddEntryResult,
      { "signedAddEntryResult", "dap.signedAddEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryResult/information/signedAddEntryResult", HFILL }},
    { &hf_dap_addEntryResult,
      { "addEntryResult", "dap.addEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryResult/information/signedAddEntryResult/addEntryResult", HFILL }},
    { &hf_dap_unsignedRemoveEntryArgument,
      { "unsignedRemoveEntryArgument", "dap.unsignedRemoveEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryArgument/unsignedRemoveEntryArgument", HFILL }},
    { &hf_dap_signedRemoveEntryArgument,
      { "signedRemoveEntryArgument", "dap.signedRemoveEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryArgument/signedRemoveEntryArgument", HFILL }},
    { &hf_dap_removeEntryArgument,
      { "removeEntryArgument", "dap.removeEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryArgument/signedRemoveEntryArgument/removeEntryArgument", HFILL }},
    { &hf_dap_remove_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_RemoveEntryInformation_vals), 0,
        "RemoveEntryResult/information", HFILL }},
    { &hf_dap_unsignedRemoveEntryResult,
      { "unsignedRemoveEntryResult", "dap.unsignedRemoveEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryResult/information/unsignedRemoveEntryResult", HFILL }},
    { &hf_dap_signedRemoveEntryResult,
      { "signedRemoveEntryResult", "dap.signedRemoveEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryResult/information/signedRemoveEntryResult", HFILL }},
    { &hf_dap_removeEntryResult,
      { "removeEntryResult", "dap.removeEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryResult/information/signedRemoveEntryResult/removeEntryResult", HFILL }},
    { &hf_dap_changes,
      { "changes", "dap.changes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ModifyEntryArgumentData/changes", HFILL }},
    { &hf_dap_changes_item,
      { "Item", "dap.changes_item",
        FT_UINT32, BASE_DEC, VALS(dap_EntryModification_vals), 0,
        "ModifyEntryArgumentData/changes/_item", HFILL }},
    { &hf_dap_unsignedModifyEntryArgument,
      { "unsignedModifyEntryArgument", "dap.unsignedModifyEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryArgument/unsignedModifyEntryArgument", HFILL }},
    { &hf_dap_signedModifyEntryArgument,
      { "signedModifyEntryArgument", "dap.signedModifyEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryArgument/signedModifyEntryArgument", HFILL }},
    { &hf_dap_modifyEntryArgument,
      { "modifyEntryArgument", "dap.modifyEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryArgument/signedModifyEntryArgument/modifyEntryArgument", HFILL }},
    { &hf_dap_modify_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyEntryInformation_vals), 0,
        "ModifyEntryResult/information", HFILL }},
    { &hf_dap_unsignedModifyEntryResult,
      { "unsignedModifyEntryResult", "dap.unsignedModifyEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryResult/information/unsignedModifyEntryResult", HFILL }},
    { &hf_dap_signedModifyEntryResult,
      { "signedModifyEntryResult", "dap.signedModifyEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryResult/information/signedModifyEntryResult", HFILL }},
    { &hf_dap_modifyEntryResult,
      { "modifyEntryResult", "dap.modifyEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryResult/information/signedModifyEntryResult/modifyEntryResult", HFILL }},
    { &hf_dap_addAttribute,
      { "addAttribute", "dap.addAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryModification/addAttribute", HFILL }},
    { &hf_dap_removeAttribute,
      { "removeAttribute", "dap.removeAttribute",
        FT_OID, BASE_NONE, NULL, 0,
        "EntryModification/removeAttribute", HFILL }},
    { &hf_dap_addValues,
      { "addValues", "dap.addValues",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryModification/addValues", HFILL }},
    { &hf_dap_removeValues,
      { "removeValues", "dap.removeValues",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryModification/removeValues", HFILL }},
    { &hf_dap_alterValues,
      { "alterValues", "dap.alterValues",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryModification/alterValues", HFILL }},
    { &hf_dap_resetValue,
      { "resetValue", "dap.resetValue",
        FT_OID, BASE_NONE, NULL, 0,
        "EntryModification/resetValue", HFILL }},
    { &hf_dap_newRDN,
      { "newRDN", "dap.newRDN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dap_deleteOldRDN,
      { "deleteOldRDN", "dap.deleteOldRDN",
        FT_BOOLEAN, 8, NULL, 0,
        "ModifyDNArgument/deleteOldRDN", HFILL }},
    { &hf_dap_newSuperior,
      { "newSuperior", "dap.newSuperior",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ModifyDNArgument/newSuperior", HFILL }},
    { &hf_dap_modify_dn_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyDNInformation_vals), 0,
        "ModifyDNResult/information", HFILL }},
    { &hf_dap_unsignedModifyDNResult,
      { "unsignedModifyDNResult", "dap.unsignedModifyDNResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNResult/information/unsignedModifyDNResult", HFILL }},
    { &hf_dap_signedModifyDNResult,
      { "signedModifyDNResult", "dap.signedModifyDNResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNResult/information/signedModifyDNResult", HFILL }},
    { &hf_dap_modifyDNResult,
      { "modifyDNResult", "dap.modifyDNResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNResult/information/signedModifyDNResult/modifyDNResult", HFILL }},
    { &hf_dap_unsignedAbandoned,
      { "unsignedAbandoned", "dap.unsignedAbandoned",
        FT_NONE, BASE_NONE, NULL, 0,
        "Abandoned/unsignedAbandoned", HFILL }},
    { &hf_dap_signedAbandoned,
      { "signedAbandoned", "dap.signedAbandoned",
        FT_NONE, BASE_NONE, NULL, 0,
        "Abandoned/signedAbandoned", HFILL }},
    { &hf_dap_abandoned,
      { "abandoned", "dap.abandoned",
        FT_NONE, BASE_NONE, NULL, 0,
        "Abandoned/signedAbandoned/abandoned", HFILL }},
    { &hf_dap_abandon_failed_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_AbandonProblem_vals), 0,
        "AbandonFailedErrorData/problem", HFILL }},
    { &hf_dap_operation,
      { "operation", "dap.operation",
        FT_UINT32, BASE_DEC, VALS(ros_InvokeId_vals), 0,
        "AbandonFailedErrorData/operation", HFILL }},
    { &hf_dap_unsignedAbandonFailedError,
      { "unsignedAbandonFailedError", "dap.unsignedAbandonFailedError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonFailedError/unsignedAbandonFailedError", HFILL }},
    { &hf_dap_signedAbandonFailedError,
      { "signedAbandonFailedError", "dap.signedAbandonFailedError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonFailedError/signedAbandonFailedError", HFILL }},
    { &hf_dap_abandonFailedError,
      { "abandonFailedError", "dap.abandonFailedError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonFailedError/signedAbandonFailedError/abandonFailedError", HFILL }},
    { &hf_dap_problems,
      { "problems", "dap.problems",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeErrorData/problems", HFILL }},
    { &hf_dap_problems_item,
      { "Item", "dap.problems_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeErrorData/problems/_item", HFILL }},
    { &hf_dap_attribute_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_AttributeProblem_vals), 0,
        "AttributeErrorData/problems/_item/problem", HFILL }},
    { &hf_dap_value,
      { "value", "dap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeErrorData/problems/_item/value", HFILL }},
    { &hf_dap_unsignedAttributeError,
      { "unsignedAttributeError", "dap.unsignedAttributeError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeError/unsignedAttributeError", HFILL }},
    { &hf_dap_signedAttributeError,
      { "signedAttributeError", "dap.signedAttributeError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeError/signedAttributeError", HFILL }},
    { &hf_dap_attributeError,
      { "attributeError", "dap.attributeError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeError/signedAttributeError/attributeError", HFILL }},
    { &hf_dap_name_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_NameProblem_vals), 0,
        "NameErrorData/problem", HFILL }},
    { &hf_dap_matched_name,
      { "matched", "dap.matched",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "NameErrorData/matched", HFILL }},
    { &hf_dap_unsignedNameError,
      { "unsignedNameError", "dap.unsignedNameError",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameError/unsignedNameError", HFILL }},
    { &hf_dap_signedNameError,
      { "signedNameError", "dap.signedNameError",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameError/signedNameError", HFILL }},
    { &hf_dap_nameError,
      { "nameError", "dap.nameError",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameError/signedNameError/nameError", HFILL }},
    { &hf_dap_candidate,
      { "candidate", "dap.candidate",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferralData/candidate", HFILL }},
    { &hf_dap_unsignedReferral,
      { "unsignedReferral", "dap.unsignedReferral",
        FT_NONE, BASE_NONE, NULL, 0,
        "Referral/unsignedReferral", HFILL }},
    { &hf_dap_signedReferral,
      { "signedReferral", "dap.signedReferral",
        FT_NONE, BASE_NONE, NULL, 0,
        "Referral/signedReferral", HFILL }},
    { &hf_dap_referral,
      { "referral", "dap.referral",
        FT_NONE, BASE_NONE, NULL, 0,
        "Referral/signedReferral/referral", HFILL }},
    { &hf_dap_security_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_SecurityProblem_vals), 0,
        "SecurityErrorData/problem", HFILL }},
    { &hf_dap_spkmInfo,
      { "spkmInfo", "dap.spkmInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrorData/spkmInfo", HFILL }},
    { &hf_dap_unsignedSecurityError,
      { "unsignedSecurityError", "dap.unsignedSecurityError",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityError/unsignedSecurityError", HFILL }},
    { &hf_dap_signedSecurityError,
      { "signedSecurityError", "dap.signedSecurityError",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityError/signedSecurityError", HFILL }},
    { &hf_dap_securityErrorData,
      { "securityError", "dap.securityError",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityError/signedSecurityError/securityError", HFILL }},
    { &hf_dap_service_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_ServiceProblem_vals), 0,
        "ServiceErrorData/problem", HFILL }},
    { &hf_dap_unsignedServiceError,
      { "unsignedServiceError", "dap.unsignedServiceError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceError/unsignedServiceError", HFILL }},
    { &hf_dap_signedServiceError,
      { "signedServiceError", "dap.signedServiceError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceError/signedServiceError", HFILL }},
    { &hf_dap_serviceError,
      { "serviceError", "dap.serviceError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceError/signedServiceError/serviceError", HFILL }},
    { &hf_dap_update_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_UpdateProblem_vals), 0,
        "UpdateErrorData/problem", HFILL }},
    { &hf_dap_attributeInfo,
      { "attributeInfo", "dap.attributeInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UpdateErrorData/attributeInfo", HFILL }},
    { &hf_dap_attributeInfo_item,
      { "Item", "dap.attributeInfo_item",
        FT_UINT32, BASE_DEC, VALS(dap_T_attributeInfo_item_vals), 0,
        "UpdateErrorData/attributeInfo/_item", HFILL }},
    { &hf_dap_unsignedUpdateError,
      { "unsignedUpdateError", "dap.unsignedUpdateError",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateError/unsignedUpdateError", HFILL }},
    { &hf_dap_signedUpdateError,
      { "signedUpdateError", "dap.signedUpdateError",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateError/signedUpdateError", HFILL }},
    { &hf_dap_updateError,
      { "updateError", "dap.updateError",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateError/signedUpdateError/updateError", HFILL }},
    { &hf_dap_ServiceControlOptions_preferChaining,
      { "preferChaining", "dap.preferChaining",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_chainingProhibited,
      { "chainingProhibited", "dap.chainingProhibited",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_localScope,
      { "localScope", "dap.localScope",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_dontUseCopy,
      { "dontUseCopy", "dap.dontUseCopy",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_dontDereferenceAliases,
      { "dontDereferenceAliases", "dap.dontDereferenceAliases",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_subentries,
      { "subentries", "dap.subentries",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_copyShallDo,
      { "copyShallDo", "dap.copyShallDo",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_partialNameResolution,
      { "partialNameResolution", "dap.partialNameResolution",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_manageDSAIT,
      { "manageDSAIT", "dap.manageDSAIT",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_noSubtypeMatch,
      { "noSubtypeMatch", "dap.noSubtypeMatch",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_noSubtypeSelection,
      { "noSubtypeSelection", "dap.noSubtypeSelection",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dap_ServiceControlOptions_countFamily,
      { "countFamily", "dap.countFamily",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dap_Versions_v1,
      { "v1", "dap.v1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dap_Versions_v2,
      { "v2", "dap.v2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dap_T_permission_add,
      { "add", "dap.add",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dap_T_permission_remove,
      { "remove", "dap.remove",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dap_T_permission_rename,
      { "rename", "dap.rename",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dap_T_permission_move,
      { "move", "dap.move",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dap_HierarchySelections_self,
      { "self", "dap.self",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dap_HierarchySelections_children,
      { "children", "dap.children",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dap_HierarchySelections_parent,
      { "parent", "dap.parent",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dap_HierarchySelections_hierarchy,
      { "hierarchy", "dap.hierarchy",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dap_HierarchySelections_top,
      { "top", "dap.top",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_dap_HierarchySelections_subtree,
      { "subtree", "dap.subtree",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_dap_HierarchySelections_siblings,
      { "siblings", "dap.siblings",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_dap_HierarchySelections_siblingChildren,
      { "siblingChildren", "dap.siblingChildren",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_dap_HierarchySelections_siblingSubtree,
      { "siblingSubtree", "dap.siblingSubtree",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dap_HierarchySelections_all,
      { "all", "dap.all",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_searchAliases,
      { "searchAliases", "dap.searchAliases",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_matchedValuesOnly,
      { "matchedValuesOnly", "dap.matchedValuesOnly",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_checkOverspecified,
      { "checkOverspecified", "dap.checkOverspecified",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_performExactly,
      { "performExactly", "dap.performExactly",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_includeAllAreas,
      { "includeAllAreas", "dap.includeAllAreas",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_noSystemRelaxation,
      { "noSystemRelaxation", "dap.noSystemRelaxation",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_dnAttribute,
      { "dnAttribute", "dap.dnAttribute",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_matchOnResidualName,
      { "matchOnResidualName", "dap.matchOnResidualName",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_entryCount,
      { "entryCount", "dap.entryCount",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_useSubset,
      { "useSubset", "dap.useSubset",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_separateFamilyMembers,
      { "separateFamilyMembers", "dap.separateFamilyMembers",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dap_SearchControlOptions_searchFamily,
      { "searchFamily", "dap.searchFamily",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},

/*--- End of included file: packet-dap-hfarr.c ---*/
#line 278 "packet-dap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_dap,

/*--- Included file: packet-dap-ettarr.c ---*/
#line 1 "packet-dap-ettarr.c"
    &ett_dap_CommonResults,
    &ett_dap_SEQUENCE_OF_Attribute,
    &ett_dap_ServiceControls,
    &ett_dap_T_manageDSAITPlaneRef,
    &ett_dap_ServiceControlOptions,
    &ett_dap_EntryInformationSelection,
    &ett_dap_T_attributes,
    &ett_dap_SET_OF_AttributeType,
    &ett_dap_T_extraAttributes,
    &ett_dap_ContextSelection,
    &ett_dap_SET_OF_TypeAndContextAssertion,
    &ett_dap_TypeAndContextAssertion,
    &ett_dap_T_contextAssertions,
    &ett_dap_SEQUENCE_OF_ContextAssertion,
    &ett_dap_SET_OF_ContextAssertion,
    &ett_dap_FamilyReturn,
    &ett_dap_T_familySelect,
    &ett_dap_EntryInformation,
    &ett_dap_T_information,
    &ett_dap_EntryInformationItem,
    &ett_dap_FamilyEntries,
    &ett_dap_SEQUENCE_OF_FamilyEntry,
    &ett_dap_FamilyEntry,
    &ett_dap_FamilyInformation,
    &ett_dap_T_information_item,
    &ett_dap_SEQUENCE_OF_FamilyEntries,
    &ett_dap_Filter,
    &ett_dap_SetOfFilter,
    &ett_dap_FilterItem,
    &ett_dap_T_substrings,
    &ett_dap_T_strings,
    &ett_dap_T_strings_item,
    &ett_dap_MatchingRuleAssertion,
    &ett_dap_T_matchingRule,
    &ett_dap_PagedResultsRequest,
    &ett_dap_T_newRequest,
    &ett_dap_SEQUENCE_OF_SortKey,
    &ett_dap_SortKey,
    &ett_dap_SecurityParameters,
    &ett_dap_Time,
    &ett_dap_DirectoryBindArgument,
    &ett_dap_Credentials,
    &ett_dap_SimpleCredentials,
    &ett_dap_T_validity,
    &ett_dap_T_time1,
    &ett_dap_T_time2,
    &ett_dap_T_password,
    &ett_dap_T_protected,
    &ett_dap_StrongCredentials,
    &ett_dap_SpkmCredentials,
    &ett_dap_Versions,
    &ett_dap_DirectoryBindErrorData,
    &ett_dap_T_error,
    &ett_dap_DirectoryBindError,
    &ett_dap_T_signedDirectoryBindError,
    &ett_dap_ReadArgumentData,
    &ett_dap_Name,
    &ett_dap_ReadArgument,
    &ett_dap_T_signedReadArgument,
    &ett_dap_ReadResultData,
    &ett_dap_ReadResult,
    &ett_dap_T_signedReadResult,
    &ett_dap_ModifyRights,
    &ett_dap_ModifyRights_item,
    &ett_dap_T_item,
    &ett_dap_T_permission,
    &ett_dap_CompareArgumentData,
    &ett_dap_CompareArgument,
    &ett_dap_T_signedCompareArgument,
    &ett_dap_CompareResultData,
    &ett_dap_CompareResult,
    &ett_dap_T_signedCompareResult,
    &ett_dap_AbandonArgumentData,
    &ett_dap_AbandonArgument,
    &ett_dap_T_signedAbandonArgument,
    &ett_dap_AbandonResultData,
    &ett_dap_AbandonResult,
    &ett_dap_AbandonInformation,
    &ett_dap_T_signedAbandonResult,
    &ett_dap_ListArgumentData,
    &ett_dap_ListArgument,
    &ett_dap_T_signedListArgument,
    &ett_dap_ListResultData,
    &ett_dap_T_listInfo,
    &ett_dap_T_subordinates,
    &ett_dap_T_subordinates_item,
    &ett_dap_SET_OF_ListResult,
    &ett_dap_ListResult,
    &ett_dap_T_signedListResult,
    &ett_dap_PartialOutcomeQualifier,
    &ett_dap_SET_OF_ContinuationReference,
    &ett_dap_T_unknownErrors,
    &ett_dap_T_entryCount,
    &ett_dap_SearchArgumentData,
    &ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument,
    &ett_dap_SearchArgument,
    &ett_dap_T_signedSearchArgument,
    &ett_dap_HierarchySelections,
    &ett_dap_SearchControlOptions,
    &ett_dap_JoinArgument,
    &ett_dap_SEQUENCE_OF_JoinAttPair,
    &ett_dap_JoinAttPair,
    &ett_dap_SEQUENCE_OF_JoinContextType,
    &ett_dap_SearchResultData,
    &ett_dap_T_searchInfo,
    &ett_dap_SET_OF_EntryInformation,
    &ett_dap_SET_OF_SearchResult,
    &ett_dap_SearchResult,
    &ett_dap_T_signedSearchResult,
    &ett_dap_AddEntryArgumentData,
    &ett_dap_SET_OF_Attribute,
    &ett_dap_AddEntryArgument,
    &ett_dap_T_signedAddEntryArgument,
    &ett_dap_AddEntryResultData,
    &ett_dap_AddEntryResult,
    &ett_dap_AddEntryInformation,
    &ett_dap_T_signedAddEntryResult,
    &ett_dap_RemoveEntryArgumentData,
    &ett_dap_RemoveEntryArgument,
    &ett_dap_T_signedRemoveEntryArgument,
    &ett_dap_RemoveEntryResultData,
    &ett_dap_RemoveEntryResult,
    &ett_dap_RemoveEntryInformation,
    &ett_dap_T_signedRemoveEntryResult,
    &ett_dap_ModifyEntryArgumentData,
    &ett_dap_SEQUENCE_OF_EntryModification,
    &ett_dap_ModifyEntryArgument,
    &ett_dap_T_signedModifyEntryArgument,
    &ett_dap_ModifyEntryResultData,
    &ett_dap_ModifyEntryResult,
    &ett_dap_ModifyEntryInformation,
    &ett_dap_T_signedModifyEntryResult,
    &ett_dap_EntryModification,
    &ett_dap_ModifyDNArgument,
    &ett_dap_ModifyDNResultData,
    &ett_dap_ModifyDNResult,
    &ett_dap_ModifyDNInformation,
    &ett_dap_T_signedModifyDNResult,
    &ett_dap_AbandonedData,
    &ett_dap_Abandoned,
    &ett_dap_T_signedAbandoned,
    &ett_dap_AbandonFailedErrorData,
    &ett_dap_AbandonFailedError,
    &ett_dap_T_signedAbandonFailedError,
    &ett_dap_AttributeErrorData,
    &ett_dap_T_problems,
    &ett_dap_T_problems_item,
    &ett_dap_AttributeError,
    &ett_dap_T_signedAttributeError,
    &ett_dap_NameErrorData,
    &ett_dap_NameError,
    &ett_dap_T_signedNameError,
    &ett_dap_ReferralData,
    &ett_dap_Referral,
    &ett_dap_T_signedReferral,
    &ett_dap_SecurityErrorData,
    &ett_dap_SecurityError,
    &ett_dap_T_signedSecurityError,
    &ett_dap_ServiceErrorData,
    &ett_dap_ServiceError,
    &ett_dap_T_signedServiceError,
    &ett_dap_UpdateErrorData,
    &ett_dap_T_attributeInfo,
    &ett_dap_T_attributeInfo_item,
    &ett_dap_UpdateError,
    &ett_dap_T_signedUpdateError,

/*--- End of included file: packet-dap-ettarr.c ---*/
#line 284 "packet-dap-template.c"
  };
  module_t *dap_module;

  /* Register protocol */
  proto_dap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("dap", dissect_dap, proto_dap);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DAP, particularly our port */

#ifdef PREFERENCE_GROUPING
  dap_module = prefs_register_protocol_subtree("OSI/X.500", proto_dap, prefs_register_dap);
#else
  dap_module = prefs_register_protocol(proto_dap, prefs_register_dap);
#endif

  prefs_register_uint_preference(dap_module, "tcp.port", "DAP TCP Port",
				 "Set the port for DAP operations (if other"
				 " than the default of 102)",
				 10, &global_dap_tcp_port);

}


/*--- proto_reg_handoff_dap --- */
void proto_reg_handoff_dap(void) {
  dissector_handle_t handle = NULL;

  /* #include "packet-dap-dis-tab.c" */

  /* APPLICATION CONTEXT */

  register_ber_oid_name("2.5.3.1", "id-ac-directory-access");

  /* ABSTRACT SYNTAXES */
    
  /* Register DAP with ROS (with no use of RTSE) */
  if((handle = find_dissector("dap"))) {
    register_ros_oid_dissector_handle("2.5.9.1", handle, 0, "id-as-directory-access", FALSE); 
  }

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");

  /* AttributeValueAssertions */
  x509if_register_fmt(hf_dap_equality, "=");
  x509if_register_fmt(hf_dap_greaterOrEqual, ">=");
  x509if_register_fmt(hf_dap_lessOrEqual, "<=");
  x509if_register_fmt(hf_dap_approximateMatch, "=~");
  /* AttributeTypes */
  x509if_register_fmt(hf_dap_present, "= *");


}


void prefs_register_dap(void) {

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port != 102) && tpkt_handle)
    dissector_delete("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_dap_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add("tcp.port", global_dap_tcp_port, tpkt_handle);

}
