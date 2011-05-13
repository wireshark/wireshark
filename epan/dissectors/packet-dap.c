/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-dap.c                                                               */
/* ../../tools/asn2wrs.py -b -e -L -p dap -c ./dap.cnf -s ./packet-dap-template -D . dap.asn DirectoryAccessProtocol.asn */

/* Input file: packet-dap-template.c */

#line 1 "../../asn1/dap/packet-dap-template.c"
/* packet-dap.c
 * Routines for X.511 (X.500 Directory Asbtract Service) and X.519 DAP  packet dissection
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
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-idmp.h"

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
static dissector_handle_t tpkt_handle;
static void prefs_register_dap(void); /* forward declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
static int proto_dap = -1;



/*--- Included file: packet-dap-hf.c ---*/
#line 1 "../../asn1/dap/packet-dap-hf.c"
static int hf_dap_DirectoryBindArgument_PDU = -1;  /* DirectoryBindArgument */
static int hf_dap_DirectoryBindResult_PDU = -1;   /* DirectoryBindResult */
static int hf_dap_DirectoryBindError_PDU = -1;    /* DirectoryBindError */
static int hf_dap_ReadArgument_PDU = -1;          /* ReadArgument */
static int hf_dap_ReadResult_PDU = -1;            /* ReadResult */
static int hf_dap_CompareArgument_PDU = -1;       /* CompareArgument */
static int hf_dap_CompareResult_PDU = -1;         /* CompareResult */
static int hf_dap_AbandonArgument_PDU = -1;       /* AbandonArgument */
static int hf_dap_AbandonResult_PDU = -1;         /* AbandonResult */
static int hf_dap_ListArgument_PDU = -1;          /* ListArgument */
static int hf_dap_ListResult_PDU = -1;            /* ListResult */
static int hf_dap_SearchArgument_PDU = -1;        /* SearchArgument */
static int hf_dap_SearchResult_PDU = -1;          /* SearchResult */
static int hf_dap_AddEntryArgument_PDU = -1;      /* AddEntryArgument */
static int hf_dap_AddEntryResult_PDU = -1;        /* AddEntryResult */
static int hf_dap_RemoveEntryArgument_PDU = -1;   /* RemoveEntryArgument */
static int hf_dap_RemoveEntryResult_PDU = -1;     /* RemoveEntryResult */
static int hf_dap_ModifyEntryArgument_PDU = -1;   /* ModifyEntryArgument */
static int hf_dap_ModifyEntryResult_PDU = -1;     /* ModifyEntryResult */
static int hf_dap_ModifyDNArgument_PDU = -1;      /* ModifyDNArgument */
static int hf_dap_ModifyDNResult_PDU = -1;        /* ModifyDNResult */
static int hf_dap_Abandoned_PDU = -1;             /* Abandoned */
static int hf_dap_AbandonFailedError_PDU = -1;    /* AbandonFailedError */
static int hf_dap_AttributeError_PDU = -1;        /* AttributeError */
static int hf_dap_NameError_PDU = -1;             /* NameError */
static int hf_dap_Referral_PDU = -1;              /* Referral */
static int hf_dap_SecurityError_PDU = -1;         /* SecurityError */
static int hf_dap_ServiceError_PDU = -1;          /* ServiceError */
static int hf_dap_UpdateError_PDU = -1;           /* UpdateError */
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
static int hf_dap_extraSelect = -1;               /* SET_SIZE_1_MAX_OF_AttributeType */
static int hf_dap_extraSelect_item = -1;          /* AttributeType */
static int hf_dap_contextSelection = -1;          /* ContextSelection */
static int hf_dap_returnContexts = -1;            /* BOOLEAN */
static int hf_dap_familyReturn = -1;              /* FamilyReturn */
static int hf_dap_allContexts = -1;               /* NULL */
static int hf_dap_selectedContexts = -1;          /* SET_SIZE_1_MAX_OF_TypeAndContextAssertion */
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
static int hf_dap_entry_information = -1;         /* T_entry_information */
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
static int hf_dap_family_information_item = -1;   /* T_family_information_item */
static int hf_dap_family_info = -1;               /* SEQUENCE_SIZE_1_MAX_OF_FamilyEntries */
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
static int hf_dap_sortKeys = -1;                  /* SEQUENCE_SIZE_1_MAX_OF_SortKey */
static int hf_dap_sortKeys_item = -1;             /* SortKey */
static int hf_dap_reverse = -1;                   /* BOOLEAN */
static int hf_dap_unmerged = -1;                  /* BOOLEAN */
static int hf_dap_pagedResultsQueryReference = -1;  /* T_pagedResultsQueryReference */
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
static int hf_dap_sasl = -1;                      /* SaslCredentials */
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
static int hf_dap_bind_token = -1;                /* Token */
static int hf_dap_req = -1;                       /* T_req */
static int hf_dap_rep = -1;                       /* T_rep */
static int hf_dap_mechanism = -1;                 /* DirectoryString */
static int hf_dap_saslCredentials = -1;           /* OCTET_STRING */
static int hf_dap_saslAbort = -1;                 /* BOOLEAN */
static int hf_dap_algorithm = -1;                 /* AlgorithmIdentifier */
static int hf_dap_utctime = -1;                   /* UTCTime */
static int hf_dap_bindIntAlgorithm = -1;          /* SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier */
static int hf_dap_bindIntAlgorithm_item = -1;     /* AlgorithmIdentifier */
static int hf_dap_bindIntKeyInfo = -1;            /* BindKeyInfo */
static int hf_dap_bindConfAlgorithm = -1;         /* SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier */
static int hf_dap_bindConfAlgorithm_item = -1;    /* AlgorithmIdentifier */
static int hf_dap_bindConfKeyInfo = -1;           /* BindKeyInfo */
static int hf_dap_token_data = -1;                /* TokenData */
static int hf_dap_algorithm_identifier = -1;      /* AlgorithmIdentifier */
static int hf_dap_unsignedDirectoryBindError = -1;  /* DirectoryBindErrorData */
static int hf_dap_signedDirectoryBindError = -1;  /* T_signedDirectoryBindError */
static int hf_dap_directoryBindError = -1;        /* DirectoryBindErrorData */
static int hf_dap_error = -1;                     /* T_error */
static int hf_dap_serviceProblem = -1;            /* ServiceProblem */
static int hf_dap_securityProblem = -1;           /* SecurityProblem */
static int hf_dap_securityParameters = -1;        /* SecurityParameters */
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
static int hf_dap_exclusions = -1;                /* Exclusions */
static int hf_dap_nameResolveOnMaster = -1;       /* BOOLEAN */
static int hf_dap_operationContexts = -1;         /* ContextSelection */
static int hf_dap_familyGrouping = -1;            /* FamilyGrouping */
static int hf_dap_rdnSequence = -1;               /* RDNSequence */
static int hf_dap_unsignedReadArgument = -1;      /* ReadArgumentData */
static int hf_dap_signedReadArgument = -1;        /* T_signedReadArgument */
static int hf_dap_readArgument = -1;              /* ReadArgumentData */
static int hf_dap_entry = -1;                     /* EntryInformation */
static int hf_dap_modifyRights = -1;              /* ModifyRights */
static int hf_dap_performer = -1;                 /* DistinguishedName */
static int hf_dap_aliasDereferenced = -1;         /* BOOLEAN */
static int hf_dap_notification = -1;              /* SEQUENCE_SIZE_1_MAX_OF_Attribute */
static int hf_dap_notification_item = -1;         /* Attribute */
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
static int hf_dap_unexplored = -1;                /* SET_SIZE_1_MAX_OF_ContinuationReference */
static int hf_dap_unexplored_item = -1;           /* ContinuationReference */
static int hf_dap_unavailableCriticalExtensions = -1;  /* BOOLEAN */
static int hf_dap_unknownErrors = -1;             /* T_unknownErrors */
static int hf_dap_unknownErrors_item = -1;        /* OBJECT_IDENTIFIER */
static int hf_dap_queryReference = -1;            /* OCTET_STRING */
static int hf_dap_overspecFilter = -1;            /* Filter */
static int hf_dap_entryCount = -1;                /* T_entryCount */
static int hf_dap_bestEstimate = -1;              /* INTEGER */
static int hf_dap_lowEstimate = -1;               /* INTEGER */
static int hf_dap_exact = -1;                     /* INTEGER */
static int hf_dap_streamedResult = -1;            /* BOOLEAN */
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
static int hf_dap_joinAttributes = -1;            /* SEQUENCE_SIZE_1_MAX_OF_JoinAttPair */
static int hf_dap_joinAttributes_item = -1;       /* JoinAttPair */
static int hf_dap_joinSelection = -1;             /* EntryInformationSelection */
static int hf_dap_baseAtt = -1;                   /* AttributeType */
static int hf_dap_joinAtt = -1;                   /* AttributeType */
static int hf_dap_joinContext = -1;               /* SEQUENCE_SIZE_1_MAX_OF_JoinContextType */
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
static int hf_dap_add_entry_item = -1;            /* Attribute */
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
static int hf_dap_ServiceControlOptions_dontSelectFriends = -1;
static int hf_dap_ServiceControlOptions_dontMatchFriends = -1;
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
#line 67 "../../asn1/dap/packet-dap-template.c"

/* Initialize the subtree pointers */
static gint ett_dap = -1;

/*--- Included file: packet-dap-ett.c ---*/
#line 1 "../../asn1/dap/packet-dap-ett.c"
static gint ett_dap_ServiceControls = -1;
static gint ett_dap_T_manageDSAITPlaneRef = -1;
static gint ett_dap_ServiceControlOptions = -1;
static gint ett_dap_EntryInformationSelection = -1;
static gint ett_dap_T_attributes = -1;
static gint ett_dap_SET_OF_AttributeType = -1;
static gint ett_dap_T_extraAttributes = -1;
static gint ett_dap_SET_SIZE_1_MAX_OF_AttributeType = -1;
static gint ett_dap_ContextSelection = -1;
static gint ett_dap_SET_SIZE_1_MAX_OF_TypeAndContextAssertion = -1;
static gint ett_dap_TypeAndContextAssertion = -1;
static gint ett_dap_T_contextAssertions = -1;
static gint ett_dap_SEQUENCE_OF_ContextAssertion = -1;
static gint ett_dap_SET_OF_ContextAssertion = -1;
static gint ett_dap_FamilyReturn = -1;
static gint ett_dap_T_familySelect = -1;
static gint ett_dap_EntryInformation = -1;
static gint ett_dap_T_entry_information = -1;
static gint ett_dap_EntryInformationItem = -1;
static gint ett_dap_FamilyEntries = -1;
static gint ett_dap_SEQUENCE_OF_FamilyEntry = -1;
static gint ett_dap_FamilyEntry = -1;
static gint ett_dap_FamilyInformation = -1;
static gint ett_dap_T_family_information_item = -1;
static gint ett_dap_SEQUENCE_SIZE_1_MAX_OF_FamilyEntries = -1;
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
static gint ett_dap_SEQUENCE_SIZE_1_MAX_OF_SortKey = -1;
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
static gint ett_dap_SaslCredentials = -1;
static gint ett_dap_TokenData = -1;
static gint ett_dap_SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier = -1;
static gint ett_dap_Token = -1;
static gint ett_dap_Versions = -1;
static gint ett_dap_DirectoryBindError = -1;
static gint ett_dap_T_signedDirectoryBindError = -1;
static gint ett_dap_DirectoryBindErrorData = -1;
static gint ett_dap_T_error = -1;
static gint ett_dap_ReadArgumentData = -1;
static gint ett_dap_Name = -1;
static gint ett_dap_ReadArgument = -1;
static gint ett_dap_T_signedReadArgument = -1;
static gint ett_dap_ReadResultData = -1;
static gint ett_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute = -1;
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
static gint ett_dap_SET_SIZE_1_MAX_OF_ContinuationReference = -1;
static gint ett_dap_T_unknownErrors = -1;
static gint ett_dap_T_entryCount = -1;
static gint ett_dap_SearchArgumentData = -1;
static gint ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument = -1;
static gint ett_dap_SearchArgument = -1;
static gint ett_dap_T_signedSearchArgument = -1;
static gint ett_dap_HierarchySelections = -1;
static gint ett_dap_SearchControlOptions = -1;
static gint ett_dap_JoinArgument = -1;
static gint ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinAttPair = -1;
static gint ett_dap_JoinAttPair = -1;
static gint ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinContextType = -1;
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
#line 71 "../../asn1/dap/packet-dap-template.c"


/*--- Included file: packet-dap-val.h ---*/
#line 1 "../../asn1/dap/packet-dap-val.h"
#define id_opcode_read                 1
#define id_opcode_compare              2
#define id_opcode_abandon              3
#define id_opcode_list                 4
#define id_opcode_search               5
#define id_opcode_addEntry             6
#define id_opcode_removeEntry          7
#define id_opcode_modifyEntry          8
#define id_opcode_modifyDN             9
#define id_errcode_attributeError      1
#define id_errcode_nameError           2
#define id_errcode_serviceError        3
#define id_errcode_referral            4
#define id_errcode_abandoned           5
#define id_errcode_securityError       6
#define id_errcode_abandonFailed       7
#define id_errcode_updateError         8
#define id_errcode_dsaReferral         9

/*--- End of included file: packet-dap-val.h ---*/
#line 73 "../../asn1/dap/packet-dap-template.c"


/*--- Included file: packet-dap-table.c ---*/
#line 1 "../../asn1/dap/packet-dap-table.c"

/* DAP OPERATIONS */
const value_string dap_opr_code_string_vals[] = {
	{ op_ros_bind, "directoryBind" },
	{ id_opcode_read, "read" },
	{ id_opcode_compare, "compare" },
	{ id_opcode_abandon, "abandon" },
	{ id_opcode_list, "list" },
	{ id_opcode_search, "search" },
	{ id_opcode_addEntry, "addEntry" },
	{ id_opcode_removeEntry, "removeEntry" },
	{ id_opcode_modifyEntry, "modifyEntry" },
	{ id_opcode_modifyDN, "modifyDN" },
	{ 0, NULL }
};


/* DAP ERRORS */
static const value_string dap_err_code_string_vals[] = {
	{ err_ros_bind, "directoryBindError" },  
	{ id_errcode_abandoned, "abandoned" },  
	{ id_errcode_abandonFailed, "abandonFailed" },  
	{ id_errcode_attributeError, "attributeError" },  
	{ id_errcode_nameError, "nameError" },  
	{ id_errcode_referral, "referral" },  
	{ id_errcode_securityError, "securityError" },  
	{ id_errcode_serviceError, "serviceError" },  
	{ id_errcode_updateError, "updateError" },  
	  { 0, NULL }
};


/*--- End of included file: packet-dap-table.c ---*/
#line 75 "../../asn1/dap/packet-dap-template.c"


/*--- Included file: packet-dap-fn.c ---*/
#line 1 "../../asn1/dap/packet-dap-fn.c"
/*--- Cyclic dependencies ---*/

/* FamilyEntries -> FamilyEntries/familyEntries -> FamilyEntry -> FamilyEntry/family-info -> FamilyEntries */
static int dissect_dap_FamilyEntries(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* Filter -> SetOfFilter -> Filter */
/* Filter -> Filter */
int dissect_dap_Filter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* ListResultData -> ListResultData/uncorrelatedListInfo -> ListResult -> ListResultData */
/* ListResultData -> ListResultData/uncorrelatedListInfo -> ListResult -> ListResult/signedListResult -> ListResultData */
static int dissect_dap_ListResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* SearchResultData -> SearchResultData/uncorrelatedSearchInfo -> SearchResult -> SearchResultData */
/* SearchResultData -> SearchResultData/uncorrelatedSearchInfo -> SearchResult -> SearchResult/signedSearchResult -> SearchResultData */
static int dissect_dap_SearchResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);



const value_string dap_FamilyGrouping_vals[] = {
  {   1, "entryOnly" },
  {   2, "compoundEntry" },
  {   3, "strands" },
  {   4, "multiStrand" },
  { 0, NULL }
};


int
dissect_dap_FamilyGrouping(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

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
  { 12, &hf_dap_ServiceControlOptions_dontSelectFriends, -1, -1, "dontSelectFriends", NULL },
  { 13, &hf_dap_ServiceControlOptions_dontMatchFriends, -1, -1, "dontMatchFriends", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_dap_ServiceControlOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ServiceControlOptions_bits, hf_index, ett_dap_ServiceControlOptions,
                                    NULL);

  return offset;
}


static const value_string dap_T_priority_vals[] = {
  {   0, "low" },
  {   1, "medium" },
  {   2, "high" },
  { 0, NULL }
};


static int
dissect_dap_T_priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_dap_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string dap_T_scopeOfReferral_vals[] = {
  {   0, "dmd" },
  {   1, "country" },
  { 0, NULL }
};


static int
dissect_dap_T_scopeOfReferral(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string dap_Name_vals[] = {
  {   0, "rdnSequence" },
  { 0, NULL }
};

static const ber_choice_t Name_choice[] = {
  {   0, &hf_dap_rdnSequence     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RDNSequence },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_Name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	const char *dn;

	  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Name_choice, hf_index, ett_dap_Name,
                                 NULL);


	dn = x509if_get_last_dn();
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", (dn && *dn) ? dn : "(root)");


  return offset;
}


static const ber_sequence_t T_manageDSAITPlaneRef_sequence[] = {
  { &hf_dap_dsaName         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_agreementID     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_AgreementID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_manageDSAITPlaneRef(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_manageDSAITPlaneRef_sequence, hf_index, ett_dap_T_manageDSAITPlaneRef);

  return offset;
}



static int
dissect_dap_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ServiceControls_set[] = {
  { &hf_dap_options         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControlOptions },
  { &hf_dap_priority        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_T_priority },
  { &hf_dap_timeLimit       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_sizeLimit       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_scopeOfReferral , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dap_T_scopeOfReferral },
  { &hf_dap_attributeSizeLimit, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_manageDSAITPlaneRef, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_dap_T_manageDSAITPlaneRef },
  { &hf_dap_serviceType     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_dap_OBJECT_IDENTIFIER },
  { &hf_dap_userClass       , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ServiceControls(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ServiceControls_set, hf_index, ett_dap_ServiceControls);

  return offset;
}



static int
dissect_dap_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeType_set_of[1] = {
  { &hf_dap_select_item     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_dap_SET_OF_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AttributeType_set_of, hf_index, ett_dap_SET_OF_AttributeType);

  return offset;
}


static const value_string dap_T_attributes_vals[] = {
  {   0, "allUserAttributes" },
  {   1, "select" },
  { 0, NULL }
};

static const ber_choice_t T_attributes_choice[] = {
  {   0, &hf_dap_allUserAttributes, BER_CLASS_CON, 0, 0, dissect_dap_NULL },
  {   1, &hf_dap_select          , BER_CLASS_CON, 1, 0, dissect_dap_SET_OF_AttributeType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_attributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_attributes_choice, hf_index, ett_dap_T_attributes,
                                 NULL);

  return offset;
}


static const value_string dap_T_infoTypes_vals[] = {
  {   0, "attributeTypesOnly" },
  {   1, "attributeTypesAndValues" },
  { 0, NULL }
};


static int
dissect_dap_T_infoTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_AttributeType_set_of[1] = {
  { &hf_dap_extraSelect_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_dap_SET_SIZE_1_MAX_OF_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_AttributeType_set_of, hf_index, ett_dap_SET_SIZE_1_MAX_OF_AttributeType);

  return offset;
}


static const value_string dap_T_extraAttributes_vals[] = {
  {   3, "allOperationalAttributes" },
  {   4, "select" },
  { 0, NULL }
};

static const ber_choice_t T_extraAttributes_choice[] = {
  {   3, &hf_dap_allOperationalAttributes, BER_CLASS_CON, 3, 0, dissect_dap_NULL },
  {   4, &hf_dap_extraSelect     , BER_CLASS_CON, 4, 0, dissect_dap_SET_SIZE_1_MAX_OF_AttributeType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_extraAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_extraAttributes_choice, hf_index, ett_dap_T_extraAttributes,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ContextAssertion_sequence_of[1] = {
  { &hf_dap_preference_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_dap_SEQUENCE_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ContextAssertion_sequence_of, hf_index, ett_dap_SEQUENCE_OF_ContextAssertion);

  return offset;
}


static const ber_sequence_t SET_OF_ContextAssertion_set_of[1] = {
  { &hf_dap_all_item        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_dap_SET_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ContextAssertion_set_of, hf_index, ett_dap_SET_OF_ContextAssertion);

  return offset;
}


static const value_string dap_T_contextAssertions_vals[] = {
  {   0, "preference" },
  {   1, "all" },
  { 0, NULL }
};

static const ber_choice_t T_contextAssertions_choice[] = {
  {   0, &hf_dap_preference      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_SEQUENCE_OF_ContextAssertion },
  {   1, &hf_dap_all             , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_SET_OF_ContextAssertion },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_contextAssertions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_contextAssertions_choice, hf_index, ett_dap_T_contextAssertions,
                                 NULL);

  return offset;
}


static const ber_sequence_t TypeAndContextAssertion_sequence[] = {
  { &hf_dap_type            , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  { &hf_dap_contextAssertions, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_contextAssertions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_TypeAndContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TypeAndContextAssertion_sequence, hf_index, ett_dap_TypeAndContextAssertion);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_TypeAndContextAssertion_set_of[1] = {
  { &hf_dap_selectedContexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_TypeAndContextAssertion },
};

static int
dissect_dap_SET_SIZE_1_MAX_OF_TypeAndContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_TypeAndContextAssertion_set_of, hf_index, ett_dap_SET_SIZE_1_MAX_OF_TypeAndContextAssertion);

  return offset;
}


const value_string dap_ContextSelection_vals[] = {
  {   0, "allContexts" },
  {   1, "selectedContexts" },
  { 0, NULL }
};

static const ber_choice_t ContextSelection_choice[] = {
  {   0, &hf_dap_allContexts     , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_dap_NULL },
  {   1, &hf_dap_selectedContexts, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_SET_SIZE_1_MAX_OF_TypeAndContextAssertion },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ContextSelection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ContextSelection_choice, hf_index, ett_dap_ContextSelection,
                                 NULL);

  return offset;
}



static int
dissect_dap_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string dap_T_memberSelect_vals[] = {
  {   1, "contributingEntriesOnly" },
  {   2, "participatingEntriesOnly" },
  {   3, "compoundEntry" },
  { 0, NULL }
};


static int
dissect_dap_T_memberSelect(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_familySelect_sequence_of[1] = {
  { &hf_dap_familySelect_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
};

static int
dissect_dap_T_familySelect(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_familySelect_sequence_of, hf_index, ett_dap_T_familySelect);

  return offset;
}


static const ber_sequence_t FamilyReturn_sequence[] = {
  { &hf_dap_memberSelect    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_dap_T_memberSelect },
  { &hf_dap_familySelect    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_T_familySelect },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dap_FamilyReturn(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FamilyReturn_sequence, hf_index, ett_dap_FamilyReturn);

  return offset;
}


static const ber_sequence_t EntryInformationSelection_set[] = {
  { &hf_dap_attributes      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_attributes },
  { &hf_dap_infoTypes       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_T_infoTypes },
  { &hf_dap_extraAttributes , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_extraAttributes },
  { &hf_dap_contextSelection, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_ContextSelection },
  { &hf_dap_returnContexts  , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_BOOLEAN },
  { &hf_dap_familyReturn    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_FamilyReturn },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_EntryInformationSelection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              EntryInformationSelection_set, hf_index, ett_dap_EntryInformationSelection);

  return offset;
}


static const value_string dap_EntryInformationItem_vals[] = {
  {   0, "attributeType" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t EntryInformationItem_choice[] = {
  {   0, &hf_dap_attributeType   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  {   1, &hf_dap_attribute       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_EntryInformationItem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EntryInformationItem_choice, hf_index, ett_dap_EntryInformationItem,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_entry_information_set_of[1] = {
  { &hf_dap_entry_information_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_EntryInformationItem },
};

static int
dissect_dap_T_entry_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_entry_information_set_of, hf_index, ett_dap_T_entry_information);

  return offset;
}


static const ber_sequence_t EntryInformation_sequence[] = {
  { &hf_dap_name            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_fromEntry       , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_BOOLEAN },
  { &hf_dap_entry_information, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_T_entry_information },
  { &hf_dap_incompleteEntry , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_partialName     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_derivedEntry    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_EntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EntryInformation_sequence, hf_index, ett_dap_EntryInformation);

  return offset;
}


static const value_string dap_T_family_information_item_vals[] = {
  {   0, "attributeType" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t T_family_information_item_choice[] = {
  {   0, &hf_dap_attributeType   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  {   1, &hf_dap_attribute       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_family_information_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_family_information_item_choice, hf_index, ett_dap_T_family_information_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t FamilyInformation_sequence_of[1] = {
  { &hf_dap_family_information_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_family_information_item },
};

static int
dissect_dap_FamilyInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      FamilyInformation_sequence_of, hf_index, ett_dap_FamilyInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_FamilyEntries_sequence_of[1] = {
  { &hf_dap_family_info_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_FamilyEntries },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_FamilyEntries(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_FamilyEntries_sequence_of, hf_index, ett_dap_SEQUENCE_SIZE_1_MAX_OF_FamilyEntries);

  return offset;
}


static const ber_sequence_t FamilyEntry_sequence[] = {
  { &hf_dap_rdn             , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_RelativeDistinguishedName },
  { &hf_dap_family_information, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_FamilyInformation },
  { &hf_dap_family_info     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_FamilyEntries },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_FamilyEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FamilyEntry_sequence, hf_index, ett_dap_FamilyEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_FamilyEntry_sequence_of[1] = {
  { &hf_dap_familyEntries_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_FamilyEntry },
};

static int
dissect_dap_SEQUENCE_OF_FamilyEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_FamilyEntry_sequence_of, hf_index, ett_dap_SEQUENCE_OF_FamilyEntry);

  return offset;
}


static const ber_sequence_t FamilyEntries_sequence[] = {
  { &hf_dap_family_class    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
  { &hf_dap_familyEntries   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_SEQUENCE_OF_FamilyEntry },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_FamilyEntries(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FamilyEntries_sequence, hf_index, ett_dap_FamilyEntries);

  return offset;
}



static int
dissect_dap_T_initial(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	proto_item *it;
	it = proto_tree_add_item(tree, hf_index, tvb, offset, -1, FALSE);
	proto_item_append_text(it," XXX: Not yet implemented!");


  return offset;
}



static int
dissect_dap_T_any(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	/* XXX: not yet implemented */


  return offset;
}



static int
dissect_dap_T_final(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	/* XXX: not yet implemented */


  return offset;
}


static const value_string dap_T_strings_item_vals[] = {
  {   0, "initial" },
  {   1, "any" },
  {   2, "final" },
  {   3, "control" },
  { 0, NULL }
};

static const ber_choice_t T_strings_item_choice[] = {
  {   0, &hf_dap_initial         , BER_CLASS_CON, 0, 0, dissect_dap_T_initial },
  {   1, &hf_dap_any             , BER_CLASS_CON, 1, 0, dissect_dap_T_any },
  {   2, &hf_dap_final           , BER_CLASS_CON, 2, 0, dissect_dap_T_final },
  {   3, &hf_dap_control         , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_strings_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_strings_item_choice, hf_index, ett_dap_T_strings_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_strings_sequence_of[1] = {
  { &hf_dap_strings_item    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_strings_item },
};

static int
dissect_dap_T_strings(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_strings_sequence_of, hf_index, ett_dap_T_strings);

  return offset;
}


static const ber_sequence_t T_substrings_sequence[] = {
  { &hf_dap_sunstringType   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
  { &hf_dap_strings         , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_strings },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_substrings(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_substrings_sequence, hf_index, ett_dap_T_substrings);

  return offset;
}


static const ber_sequence_t T_matchingRule_set_of[1] = {
  { &hf_dap_matchingRule_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
};

static int
dissect_dap_T_matchingRule(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_matchingRule_set_of, hf_index, ett_dap_T_matchingRule);

  return offset;
}



static int
dissect_dap_T_matchValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	/* XXX: not yet implemented */


  return offset;
}


static const ber_sequence_t MatchingRuleAssertion_sequence[] = {
  { &hf_dap_matchingRule    , BER_CLASS_CON, 1, 0, dissect_dap_T_matchingRule },
  { &hf_dap_type            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_AttributeType },
  { &hf_dap_matchValue      , BER_CLASS_CON, 3, 0, dissect_dap_T_matchValue },
  { &hf_dap_dnAttributes    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_MatchingRuleAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MatchingRuleAssertion_sequence, hf_index, ett_dap_MatchingRuleAssertion);

  return offset;
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
  {   0, &hf_dap_equality        , BER_CLASS_CON, 0, 0, dissect_x509if_AttributeValueAssertion },
  {   1, &hf_dap_substrings      , BER_CLASS_CON, 1, 0, dissect_dap_T_substrings },
  {   2, &hf_dap_greaterOrEqual  , BER_CLASS_CON, 2, 0, dissect_x509if_AttributeValueAssertion },
  {   3, &hf_dap_lessOrEqual     , BER_CLASS_CON, 3, 0, dissect_x509if_AttributeValueAssertion },
  {   4, &hf_dap_present         , BER_CLASS_CON, 4, 0, dissect_x509if_AttributeType },
  {   5, &hf_dap_approximateMatch, BER_CLASS_CON, 5, 0, dissect_x509if_AttributeValueAssertion },
  {   6, &hf_dap_extensibleMatch , BER_CLASS_CON, 6, 0, dissect_dap_MatchingRuleAssertion },
  {   7, &hf_dap_contextPresent  , BER_CLASS_CON, 7, 0, dissect_x509if_AttributeTypeAssertion },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_FilterItem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FilterItem_choice, hf_index, ett_dap_FilterItem,
                                 NULL);

  return offset;
}


static const ber_sequence_t SetOfFilter_set_of[1] = {
  { &hf_dap_SetOfFilter_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_Filter },
};

static int
dissect_dap_SetOfFilter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SetOfFilter_set_of, hf_index, ett_dap_SetOfFilter);

  return offset;
}


const value_string dap_Filter_vals[] = {
  {   0, "item" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t Filter_choice[] = {
  {   0, &hf_dap_filter_item     , BER_CLASS_CON, 0, 0, dissect_dap_FilterItem },
  {   1, &hf_dap_and             , BER_CLASS_CON, 1, 0, dissect_dap_SetOfFilter },
  {   2, &hf_dap_or              , BER_CLASS_CON, 2, 0, dissect_dap_SetOfFilter },
  {   3, &hf_dap_not             , BER_CLASS_CON, 3, 0, dissect_dap_Filter },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_Filter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Filter_choice, hf_index, ett_dap_Filter,
                                 NULL);

  return offset;
}


static const ber_sequence_t SortKey_sequence[] = {
  { &hf_dap_type            , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  { &hf_dap_orderingRule    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_SortKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortKey_sequence, hf_index, ett_dap_SortKey);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_SortKey_sequence_of[1] = {
  { &hf_dap_sortKeys_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_SortKey },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_SortKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_SortKey_sequence_of, hf_index, ett_dap_SEQUENCE_SIZE_1_MAX_OF_SortKey);

  return offset;
}


static const ber_sequence_t T_newRequest_sequence[] = {
  { &hf_dap_pageSize        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_dap_INTEGER },
  { &hf_dap_sortKeys        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_SortKey },
  { &hf_dap_reverse         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_unmerged        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_newRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_newRequest_sequence, hf_index, ett_dap_T_newRequest);

  return offset;
}



static int
dissect_dap_T_pagedResultsQueryReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	tvbuff_t *out_tvb;
	int 	i;
	int	len;

    	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &out_tvb);


	if(out_tvb) {
		len = tvb_length(out_tvb);
		/* now see if we can add a string representation */
		for(i=0; i<len; i++)
			if(!g_ascii_isprint(tvb_get_guint8(out_tvb, i)))
				break;
	
		if(i == len) {
			if(actx->created_item) {

				proto_item_append_text(actx->created_item," (");
				for(i=0; i<len; i++)
					proto_item_append_text(actx->created_item,"%c",tvb_get_guint8(out_tvb,i));
				proto_item_append_text(actx->created_item,")");
			}
		}
	}
	

  return offset;
}


static const value_string dap_PagedResultsRequest_vals[] = {
  {   0, "newRequest" },
  {   1, "queryReference" },
  { 0, NULL }
};

static const ber_choice_t PagedResultsRequest_choice[] = {
  {   0, &hf_dap_newRequest      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_newRequest },
  {   1, &hf_dap_pagedResultsQueryReference, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_T_pagedResultsQueryReference },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_PagedResultsRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PagedResultsRequest_choice, hf_index, ett_dap_PagedResultsRequest,
                                 NULL);

  return offset;
}



static int
dissect_dap_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_dap_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string dap_Time_vals[] = {
  {   0, "utcTime" },
  {   1, "generalizedTime" },
  { 0, NULL }
};

static const ber_choice_t Time_choice[] = {
  {   0, &hf_dap_utcTime         , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_dap_UTCTime },
  {   1, &hf_dap_generalizedTime , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_dap_GeneralizedTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_Time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Time_choice, hf_index, ett_dap_Time,
                                 NULL);

  return offset;
}



static int
dissect_dap_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const value_string dap_ProtectionRequest_vals[] = {
  {   0, "none" },
  {   1, "signed" },
  {   2, "encrypted" },
  {   3, "signed-encrypted" },
  { 0, NULL }
};


static int
dissect_dap_ProtectionRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string dap_ErrorProtectionRequest_vals[] = {
  {   0, "none" },
  {   1, "signed" },
  {   2, "encrypted" },
  {   3, "signed-encrypted" },
  { 0, NULL }
};


static int
dissect_dap_ErrorProtectionRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SecurityParameters_set[] = {
  { &hf_dap_certification_path, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509af_CertificationPath },
  { &hf_dap_distinguished_name, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_time            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_Time },
  { &hf_dap_random          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_target          , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dap_ProtectionRequest },
  { &hf_dap_response        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_operationCode   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_ros_Code },
  { &hf_dap_attributeCertificationPath, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_x509af_AttributeCertificationPath },
  { &hf_dap_errorProtection , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_dap_ErrorProtectionRequest },
  { &hf_dap_errorCode       , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_ros_Code },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dap_SecurityParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SecurityParameters_set, hf_index, ett_dap_SecurityParameters);

  return offset;
}


static const value_string dap_T_time1_vals[] = {
  {   0, "utc" },
  {   1, "gt" },
  { 0, NULL }
};

static const ber_choice_t T_time1_choice[] = {
  {   0, &hf_dap_utc             , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_dap_UTCTime },
  {   1, &hf_dap_gt              , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_dap_GeneralizedTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_time1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_time1_choice, hf_index, ett_dap_T_time1,
                                 NULL);

  return offset;
}


static const value_string dap_T_time2_vals[] = {
  {   0, "utc" },
  {   1, "gt" },
  { 0, NULL }
};

static const ber_choice_t T_time2_choice[] = {
  {   0, &hf_dap_utc             , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_dap_UTCTime },
  {   1, &hf_dap_gt              , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_dap_GeneralizedTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_time2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_time2_choice, hf_index, ett_dap_T_time2,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_validity_set[] = {
  { &hf_dap_time1           , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dap_T_time1 },
  { &hf_dap_time2           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_T_time2 },
  { &hf_dap_random1         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_random2         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_validity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              T_validity_set, hf_index, ett_dap_T_validity);

  return offset;
}



static int
dissect_dap_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_protected_sequence[] = {
  { &hf_dap_protectedPassword, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_OCTET_STRING },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_protected(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_protected_sequence, hf_index, ett_dap_T_protected);

  return offset;
}


static const value_string dap_T_password_vals[] = {
  {   0, "unprotected" },
  {   1, "protected" },
  { 0, NULL }
};

static const ber_choice_t T_password_choice[] = {
  {   0, &hf_dap_unprotected     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_OCTET_STRING },
  {   1, &hf_dap_protected       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_protected },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_password(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_password_choice, hf_index, ett_dap_T_password,
                                 NULL);

  return offset;
}


static const ber_sequence_t SimpleCredentials_sequence[] = {
  { &hf_dap_distinguished_name, BER_CLASS_CON, 0, 0, dissect_x509if_DistinguishedName },
  { &hf_dap_validity        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_T_validity },
  { &hf_dap_password        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_T_password },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_SimpleCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SimpleCredentials_sequence, hf_index, ett_dap_SimpleCredentials);


	col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", x509if_get_last_dn());


	
	

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier_sequence_of[1] = {
  { &hf_dap_bindIntAlgorithm_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier_sequence_of, hf_index, ett_dap_SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier);

  return offset;
}



static int
dissect_dap_BindKeyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t TokenData_sequence[] = {
  { &hf_dap_algorithm       , BER_CLASS_CON, 0, 0, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_distinguished_name, BER_CLASS_CON, 1, 0, dissect_x509if_DistinguishedName },
  { &hf_dap_utctime         , BER_CLASS_CON, 2, 0, dissect_dap_UTCTime },
  { &hf_dap_random          , BER_CLASS_CON, 3, 0, dissect_dap_BIT_STRING },
  { &hf_dap_response        , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_bindIntAlgorithm, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier },
  { &hf_dap_bindIntKeyInfo  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_dap_BindKeyInfo },
  { &hf_dap_bindConfAlgorithm, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier },
  { &hf_dap_bindConfKeyInfo , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_dap_BindKeyInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_TokenData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TokenData_sequence, hf_index, ett_dap_TokenData);

  return offset;
}


static const ber_sequence_t Token_sequence[] = {
  { &hf_dap_token_data      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_TokenData },
  { &hf_dap_algorithm_identifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_Token(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Token_sequence, hf_index, ett_dap_Token);

  return offset;
}


static const ber_sequence_t StrongCredentials_set[] = {
  { &hf_dap_certification_path, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509af_CertificationPath },
  { &hf_dap_bind_token      , BER_CLASS_CON, 1, 0, dissect_dap_Token },
  { &hf_dap_distinguished_name, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_attributeCertificationPath, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509af_AttributeCertificationPath },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_StrongCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              StrongCredentials_set, hf_index, ett_dap_StrongCredentials);

  return offset;
}



static int
dissect_dap_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}



static int
dissect_dap_T_req(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	/* XXX: not yet implemented */


  return offset;
}



static int
dissect_dap_T_rep(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	/* XXX: not yet implemented */


  return offset;
}


static const value_string dap_SpkmCredentials_vals[] = {
  {   0, "req" },
  {   1, "rep" },
  { 0, NULL }
};

static const ber_choice_t SpkmCredentials_choice[] = {
  {   0, &hf_dap_req             , BER_CLASS_CON, 0, 0, dissect_dap_T_req },
  {   1, &hf_dap_rep             , BER_CLASS_CON, 1, 0, dissect_dap_T_rep },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_SpkmCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SpkmCredentials_choice, hf_index, ett_dap_SpkmCredentials,
                                 NULL);

  return offset;
}


static const ber_sequence_t SaslCredentials_sequence[] = {
  { &hf_dap_mechanism       , BER_CLASS_CON, 0, 0, dissect_x509sat_DirectoryString },
  { &hf_dap_saslCredentials , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_OCTET_STRING },
  { &hf_dap_saslAbort       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_SaslCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SaslCredentials_sequence, hf_index, ett_dap_SaslCredentials);

  return offset;
}


static const value_string dap_Credentials_vals[] = {
  {   0, "simple" },
  {   1, "strong" },
  {   2, "externalProcedure" },
  {   3, "spkm" },
  {   4, "sasl" },
  { 0, NULL }
};

static const ber_choice_t Credentials_choice[] = {
  {   0, &hf_dap_simple          , BER_CLASS_CON, 0, 0, dissect_dap_SimpleCredentials },
  {   1, &hf_dap_strong          , BER_CLASS_CON, 1, 0, dissect_dap_StrongCredentials },
  {   2, &hf_dap_externalProcedure, BER_CLASS_CON, 2, 0, dissect_dap_EXTERNAL },
  {   3, &hf_dap_spkm            , BER_CLASS_CON, 3, 0, dissect_dap_SpkmCredentials },
  {   4, &hf_dap_sasl            , BER_CLASS_CON, 4, 0, dissect_dap_SaslCredentials },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_Credentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Credentials_choice, hf_index, ett_dap_Credentials,
                                 NULL);

  return offset;
}


static const asn_namedbit Versions_bits[] = {
  {  0, &hf_dap_Versions_v1, -1, -1, "v1", NULL },
  {  1, &hf_dap_Versions_v2, -1, -1, "v2", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_dap_Versions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Versions_bits, hf_index, ett_dap_Versions,
                                    NULL);

  return offset;
}


static const ber_sequence_t DirectoryBindArgument_set[] = {
  { &hf_dap_credentials     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_Credentials },
  { &hf_dap_versions        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_Versions },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dap_DirectoryBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	guint32 len;

	/* check and see if this is an empty set */
	dissect_ber_length(actx->pinfo, tree, tvb, offset+1, &len, NULL);

	if(len == 0) {
		/* its an empty set - i.e anonymous  (assuming version is DEFAULTed) */
		proto_tree_add_text(tree, tvb, offset, -1,"Anonymous");

		col_append_str(actx->pinfo->cinfo, COL_INFO, " anonymous");

	}
	/* do the default thing */

	  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DirectoryBindArgument_set, hf_index, ett_dap_DirectoryBindArgument);
	


  return offset;
}



static int
dissect_dap_DirectoryBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

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
  {  15, "unsupportedMatchingUse" },
  {  16, "ambiguousKeyAttributes" },
  {  17, "saslBindInProgress" },
  { 0, NULL }
};


static int
dissect_dap_ServiceProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  guint32 problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, dap_ServiceProblem_vals, "ServiceProblem(%d)"));


  return offset;
}


const value_string dap_SecurityProblem_vals[] = {
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


int
dissect_dap_SecurityProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  guint32 problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, dap_SecurityProblem_vals, "SecurityProblem(%d)"));


  return offset;
}


static const value_string dap_T_error_vals[] = {
  {   1, "serviceError" },
  {   2, "securityError" },
  { 0, NULL }
};

static const ber_choice_t T_error_choice[] = {
  {   1, &hf_dap_serviceProblem  , BER_CLASS_CON, 1, 0, dissect_dap_ServiceProblem },
  {   2, &hf_dap_securityProblem , BER_CLASS_CON, 2, 0, dissect_dap_SecurityProblem },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_error_choice, hf_index, ett_dap_T_error,
                                 NULL);

  return offset;
}


static const ber_sequence_t DirectoryBindErrorData_set[] = {
  { &hf_dap_versions        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dap_Versions },
  { &hf_dap_error           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_error },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_DirectoryBindErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DirectoryBindErrorData_set, hf_index, ett_dap_DirectoryBindErrorData);

  return offset;
}


static const ber_sequence_t T_signedDirectoryBindError_sequence[] = {
  { &hf_dap_directoryBindError, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_DirectoryBindErrorData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedDirectoryBindError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedDirectoryBindError_sequence, hf_index, ett_dap_T_signedDirectoryBindError);

  return offset;
}


const value_string dap_DirectoryBindError_vals[] = {
  {   0, "unsignedDirectoryBindError" },
  {   1, "signedDirectoryBindError" },
  { 0, NULL }
};

static const ber_choice_t DirectoryBindError_choice[] = {
  {   0, &hf_dap_unsignedDirectoryBindError, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_DirectoryBindErrorData },
  {   1, &hf_dap_signedDirectoryBindError, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedDirectoryBindError },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_DirectoryBindError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DirectoryBindError_choice, hf_index, ett_dap_DirectoryBindError,
                                 NULL);

  return offset;
}


static const ber_sequence_t ReadArgumentData_set[] = {
  { &hf_dap_object          , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_selection       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_EntryInformationSelection },
  { &hf_dap_modifyRightsRequest, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_serviceControls , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControls },
  { &hf_dap_securityParameters, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_requestor       , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_operationProgress, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dsp_OperationProgress },
  { &hf_dap_aliasedRDNs     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_criticalExtensions, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_referenceType   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_dsp_ReferenceType },
  { &hf_dap_entryOnly       , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_exclusions      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dap_nameResolveOnMaster, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_operationContexts, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_ContextSelection },
  { &hf_dap_familyGrouping  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ReadArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReadArgumentData_set, hf_index, ett_dap_ReadArgumentData);

  return offset;
}


static const ber_sequence_t T_signedReadArgument_sequence[] = {
  { &hf_dap_readArgument    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ReadArgumentData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedReadArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedReadArgument_sequence, hf_index, ett_dap_T_signedReadArgument);

  return offset;
}


const value_string dap_ReadArgument_vals[] = {
  {   0, "unsignedReadArgument" },
  {   1, "signedReadArgument" },
  { 0, NULL }
};

static const ber_choice_t ReadArgument_choice[] = {
  {   0, &hf_dap_unsignedReadArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ReadArgumentData },
  {   1, &hf_dap_signedReadArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedReadArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ReadArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
  {   0, &hf_dap_item_entry      , BER_CLASS_CON, 0, 0, dissect_dap_NULL },
  {   1, &hf_dap_attribute_type  , BER_CLASS_CON, 1, 0, dissect_x509if_AttributeType },
  {   2, &hf_dap_value_assertion , BER_CLASS_CON, 2, 0, dissect_x509if_AttributeValueAssertion },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_item_choice, hf_index, ett_dap_T_item,
                                 NULL);

  return offset;
}


static const asn_namedbit T_permission_bits[] = {
  {  0, &hf_dap_T_permission_add, -1, -1, "add", NULL },
  {  1, &hf_dap_T_permission_remove, -1, -1, "remove", NULL },
  {  2, &hf_dap_T_permission_rename, -1, -1, "rename", NULL },
  {  3, &hf_dap_T_permission_move, -1, -1, "move", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_dap_T_permission(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_permission_bits, hf_index, ett_dap_T_permission,
                                    NULL);

  return offset;
}


static const ber_sequence_t ModifyRights_item_sequence[] = {
  { &hf_dap_item            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_item },
  { &hf_dap_permission      , BER_CLASS_CON, 3, 0, dissect_dap_T_permission },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyRights_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyRights_item_sequence, hf_index, ett_dap_ModifyRights_item);

  return offset;
}


static const ber_sequence_t ModifyRights_set_of[1] = {
  { &hf_dap_ModifyRights_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyRights_item },
};

static int
dissect_dap_ModifyRights(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ModifyRights_set_of, hf_index, ett_dap_ModifyRights);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_Attribute_sequence_of[1] = {
  { &hf_dap_notification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_Attribute_sequence_of, hf_index, ett_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute);

  return offset;
}


static const ber_sequence_t ReadResultData_set[] = {
  { &hf_dap_entry           , BER_CLASS_CON, 0, 0, dissect_dap_EntryInformation },
  { &hf_dap_modifyRights    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_ModifyRights },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ReadResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReadResultData_set, hf_index, ett_dap_ReadResultData);

  return offset;
}


static const ber_sequence_t T_signedReadResult_sequence[] = {
  { &hf_dap_readResult      , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ReadResultData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedReadResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedReadResult_sequence, hf_index, ett_dap_T_signedReadResult);

  return offset;
}


const value_string dap_ReadResult_vals[] = {
  {   0, "unsignedReadResult" },
  {   1, "signedReadResult" },
  { 0, NULL }
};

static const ber_choice_t ReadResult_choice[] = {
  {   0, &hf_dap_unsignedReadResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ReadResultData },
  {   1, &hf_dap_signedReadResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedReadResult },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ReadResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReadResult_choice, hf_index, ett_dap_ReadResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t CompareArgumentData_set[] = {
  { &hf_dap_object          , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_purported       , BER_CLASS_CON, 1, 0, dissect_x509if_AttributeValueAssertion },
  { &hf_dap_serviceControls , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControls },
  { &hf_dap_securityParameters, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_requestor       , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_operationProgress, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dsp_OperationProgress },
  { &hf_dap_aliasedRDNs     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_criticalExtensions, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_referenceType   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_dsp_ReferenceType },
  { &hf_dap_entryOnly       , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_exclusions      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dap_nameResolveOnMaster, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_operationContexts, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_ContextSelection },
  { &hf_dap_familyGrouping  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_CompareArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CompareArgumentData_set, hf_index, ett_dap_CompareArgumentData);

  return offset;
}


static const ber_sequence_t T_signedCompareArgument_sequence[] = {
  { &hf_dap_compareArgument , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_CompareArgumentData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedCompareArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedCompareArgument_sequence, hf_index, ett_dap_T_signedCompareArgument);

  return offset;
}


const value_string dap_CompareArgument_vals[] = {
  {   0, "unsignedCompareArgument" },
  {   1, "signedCompareArgument" },
  { 0, NULL }
};

static const ber_choice_t CompareArgument_choice[] = {
  {   0, &hf_dap_unsignedCompareArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_CompareArgumentData },
  {   1, &hf_dap_signedCompareArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedCompareArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_CompareArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CompareArgument_choice, hf_index, ett_dap_CompareArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t CompareResultData_set[] = {
  { &hf_dap_name            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_matched         , BER_CLASS_CON, 0, 0, dissect_dap_BOOLEAN },
  { &hf_dap_fromEntry       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_matchedSubtype  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_AttributeType },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_CompareResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CompareResultData_set, hf_index, ett_dap_CompareResultData);

  return offset;
}


static const ber_sequence_t T_signedCompareResult_sequence[] = {
  { &hf_dap_compareResult   , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_CompareResultData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedCompareResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedCompareResult_sequence, hf_index, ett_dap_T_signedCompareResult);

  return offset;
}


const value_string dap_CompareResult_vals[] = {
  {   0, "unsignedCompareResult" },
  {   1, "signedCompareResult" },
  { 0, NULL }
};

static const ber_choice_t CompareResult_choice[] = {
  {   0, &hf_dap_unsignedCompareResult, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_CompareResultData },
  {   1, &hf_dap_signedCompareResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedCompareResult },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_CompareResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CompareResult_choice, hf_index, ett_dap_CompareResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t AbandonArgumentData_sequence[] = {
  { &hf_dap_invokeID        , BER_CLASS_CON, 0, 0, dissect_ros_InvokeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AbandonArgumentData_sequence, hf_index, ett_dap_AbandonArgumentData);

  return offset;
}


static const ber_sequence_t T_signedAbandonArgument_sequence[] = {
  { &hf_dap_abandonArgument , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_AbandonArgumentData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAbandonArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedAbandonArgument_sequence, hf_index, ett_dap_T_signedAbandonArgument);

  return offset;
}


const value_string dap_AbandonArgument_vals[] = {
  {   0, "unsignedAbandonArgument" },
  {   1, "signedAbandonArgument" },
  { 0, NULL }
};

static const ber_choice_t AbandonArgument_choice[] = {
  {   0, &hf_dap_unsignedAbandonArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_AbandonArgumentData },
  {   1, &hf_dap_signedAbandonArgument, BER_CLASS_CON, 0, 0, dissect_dap_T_signedAbandonArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_AbandonArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AbandonArgument_choice, hf_index, ett_dap_AbandonArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t AbandonResultData_sequence[] = {
  { &hf_dap_invokeID        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ros_InvokeId },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AbandonResultData_sequence, hf_index, ett_dap_AbandonResultData);

  return offset;
}


static const ber_sequence_t T_signedAbandonResult_sequence[] = {
  { &hf_dap_abandonResult   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_AbandonResultData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAbandonResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedAbandonResult_sequence, hf_index, ett_dap_T_signedAbandonResult);

  return offset;
}


static const value_string dap_AbandonInformation_vals[] = {
  {   0, "unsignedAbandonResult" },
  {   1, "signedAbandonResult" },
  { 0, NULL }
};

static const ber_choice_t AbandonInformation_choice[] = {
  {   0, &hf_dap_unsignedAbandonResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_AbandonResultData },
  {   1, &hf_dap_signedAbandonResult, BER_CLASS_CON, 0, 0, dissect_dap_T_signedAbandonResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AbandonInformation_choice, hf_index, ett_dap_AbandonInformation,
                                 NULL);

  return offset;
}


const value_string dap_AbandonResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t AbandonResult_choice[] = {
  {   0, &hf_dap_null            , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_dap_NULL },
  {   1, &hf_dap_abandon_information, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dap_AbandonInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_AbandonResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AbandonResult_choice, hf_index, ett_dap_AbandonResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ListArgumentData_set[] = {
  { &hf_dap_object          , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_pagedResults    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_PagedResultsRequest },
  { &hf_dap_listFamily      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_serviceControls , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControls },
  { &hf_dap_securityParameters, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_requestor       , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_operationProgress, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dsp_OperationProgress },
  { &hf_dap_aliasedRDNs     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_criticalExtensions, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_referenceType   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_dsp_ReferenceType },
  { &hf_dap_entryOnly       , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_exclusions      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dap_nameResolveOnMaster, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_operationContexts, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_ContextSelection },
  { &hf_dap_familyGrouping  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ListArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ListArgumentData_set, hf_index, ett_dap_ListArgumentData);

  return offset;
}


static const ber_sequence_t T_signedListArgument_sequence[] = {
  { &hf_dap_listArgument    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ListArgumentData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedListArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedListArgument_sequence, hf_index, ett_dap_T_signedListArgument);

  return offset;
}


const value_string dap_ListArgument_vals[] = {
  {   0, "unsignedListArgument" },
  {   1, "signedListArgument" },
  { 0, NULL }
};

static const ber_choice_t ListArgument_choice[] = {
  {   0, &hf_dap_unsignedListArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ListArgumentData },
  {   1, &hf_dap_signedListArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedListArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ListArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ListArgument_choice, hf_index, ett_dap_ListArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_subordinates_item_sequence[] = {
  { &hf_dap_rdn             , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_RelativeDistinguishedName },
  { &hf_dap_aliasEntry      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_fromEntry       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_subordinates_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_subordinates_item_sequence, hf_index, ett_dap_T_subordinates_item);

  return offset;
}


static const ber_sequence_t T_subordinates_set_of[1] = {
  { &hf_dap_subordinates_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_subordinates_item },
};

static int
dissect_dap_T_subordinates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_subordinates_set_of, hf_index, ett_dap_T_subordinates);

  return offset;
}


static const value_string dap_LimitProblem_vals[] = {
  {   0, "timeLimitExceeded" },
  {   1, "sizeLimitExceeded" },
  {   2, "administrativeLimitExceeded" },
  { 0, NULL }
};


static int
dissect_dap_LimitProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  guint32 problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, dap_LimitProblem_vals, "LimitProblem(%d)"));


  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_ContinuationReference_set_of[1] = {
  { &hf_dap_unexplored_item , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ContinuationReference },
};

static int
dissect_dap_SET_SIZE_1_MAX_OF_ContinuationReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_ContinuationReference_set_of, hf_index, ett_dap_SET_SIZE_1_MAX_OF_ContinuationReference);

  return offset;
}


static const ber_sequence_t T_unknownErrors_set_of[1] = {
  { &hf_dap_unknownErrors_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
};

static int
dissect_dap_T_unknownErrors(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_unknownErrors_set_of, hf_index, ett_dap_T_unknownErrors);

  return offset;
}


static const value_string dap_T_entryCount_vals[] = {
  {   7, "bestEstimate" },
  {   8, "lowEstimate" },
  {   9, "exact" },
  { 0, NULL }
};

static const ber_choice_t T_entryCount_choice[] = {
  {   7, &hf_dap_bestEstimate    , BER_CLASS_CON, 7, 0, dissect_dap_INTEGER },
  {   8, &hf_dap_lowEstimate     , BER_CLASS_CON, 8, 0, dissect_dap_INTEGER },
  {   9, &hf_dap_exact           , BER_CLASS_CON, 9, 0, dissect_dap_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_entryCount(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_entryCount_choice, hf_index, ett_dap_T_entryCount,
                                 NULL);

  return offset;
}


static const ber_sequence_t PartialOutcomeQualifier_set[] = {
  { &hf_dap_limitProblem    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dap_LimitProblem },
  { &hf_dap_unexplored      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_SET_SIZE_1_MAX_OF_ContinuationReference },
  { &hf_dap_unavailableCriticalExtensions, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_unknownErrors   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dap_T_unknownErrors },
  { &hf_dap_queryReference  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dap_OCTET_STRING },
  { &hf_dap_overspecFilter  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_Filter },
  { &hf_dap_notification    , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { &hf_dap_entryCount      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_entryCount },
  { &hf_dap_streamedResult  , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_PartialOutcomeQualifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PartialOutcomeQualifier_set, hf_index, ett_dap_PartialOutcomeQualifier);

  return offset;
}


static const ber_sequence_t T_listInfo_set[] = {
  { &hf_dap_name            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_subordinates    , BER_CLASS_CON, 1, 0, dissect_dap_T_subordinates },
  { &hf_dap_partialOutcomeQualifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_PartialOutcomeQualifier },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_listInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              T_listInfo_set, hf_index, ett_dap_T_listInfo);

  return offset;
}


static const ber_sequence_t T_signedListResult_sequence[] = {
  { &hf_dap_listResult      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_ListResultData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedListResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedListResult_sequence, hf_index, ett_dap_T_signedListResult);

  return offset;
}


const value_string dap_ListResult_vals[] = {
  {   0, "unsignedListResult" },
  {   1, "signedListResult" },
  { 0, NULL }
};

static const ber_choice_t ListResult_choice[] = {
  {   0, &hf_dap_unsignedListResult, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dap_ListResultData },
  {   1, &hf_dap_signedListResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedListResult },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ListResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ListResult_choice, hf_index, ett_dap_ListResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ListResult_set_of[1] = {
  { &hf_dap_uncorrelatedListInfo_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_ListResult },
};

static int
dissect_dap_SET_OF_ListResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ListResult_set_of, hf_index, ett_dap_SET_OF_ListResult);

  return offset;
}


static const value_string dap_ListResultData_vals[] = {
  {   0, "listInfo" },
  {   1, "uncorrelatedListInfo" },
  { 0, NULL }
};

static const ber_choice_t ListResultData_choice[] = {
  {   0, &hf_dap_listInfo        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_T_listInfo },
  {   1, &hf_dap_uncorrelatedListInfo, BER_CLASS_CON, 0, 0, dissect_dap_SET_OF_ListResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ListResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
dissect_dap_T_subset(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  guint32 subset;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &subset);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(subset, dap_T_subset_vals, "Subset(%d)"));



  return offset;
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

int
dissect_dap_HierarchySelections(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    HierarchySelections_bits, hf_index, ett_dap_HierarchySelections,
                                    NULL);

  return offset;
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

int
dissect_dap_SearchControlOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    SearchControlOptions_bits, hf_index, ett_dap_SearchControlOptions,
                                    NULL);

  return offset;
}



static int
dissect_dap_DomainLocalID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509sat_DirectoryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string dap_T_joinSubset_vals[] = {
  {   0, "baseObject" },
  {   1, "oneLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_dap_T_joinSubset(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dap_JoinContextType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_JoinContextType_sequence_of[1] = {
  { &hf_dap_joinContext_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_JoinContextType },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinContextType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_JoinContextType_sequence_of, hf_index, ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinContextType);

  return offset;
}


static const ber_sequence_t JoinAttPair_sequence[] = {
  { &hf_dap_baseAtt         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  { &hf_dap_joinAtt         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  { &hf_dap_joinContext     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinContextType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_JoinAttPair(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   JoinAttPair_sequence, hf_index, ett_dap_JoinAttPair);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_JoinAttPair_sequence_of[1] = {
  { &hf_dap_joinAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_JoinAttPair },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinAttPair(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_JoinAttPair_sequence_of, hf_index, ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinAttPair);

  return offset;
}


static const ber_sequence_t JoinArgument_sequence[] = {
  { &hf_dap_joinBaseObject  , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_domainLocalID   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_DomainLocalID },
  { &hf_dap_joinSubset      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_T_joinSubset },
  { &hf_dap_joinFilter      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_Filter },
  { &hf_dap_joinAttributes  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinAttPair },
  { &hf_dap_joinSelection   , BER_CLASS_CON, 5, 0, dissect_dap_EntryInformationSelection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_JoinArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   JoinArgument_sequence, hf_index, ett_dap_JoinArgument);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_JoinArgument_sequence_of[1] = {
  { &hf_dap_joinArguments_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_JoinArgument },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_JoinArgument_sequence_of, hf_index, ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument);

  return offset;
}


static const value_string dap_T_joinType_vals[] = {
  {   0, "innerJoin" },
  {   1, "leftOuterJoin" },
  {   2, "fullOuterJoin" },
  { 0, NULL }
};


static int
dissect_dap_T_joinType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SearchArgumentData_set[] = {
  { &hf_dap_baseObject      , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_subset          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_T_subset },
  { &hf_dap_filter          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_Filter },
  { &hf_dap_searchAliases   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_selection       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dap_EntryInformationSelection },
  { &hf_dap_pagedResults    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_PagedResultsRequest },
  { &hf_dap_matchedValuesOnly, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_extendedFilter  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_Filter },
  { &hf_dap_checkOverspecified, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_relaxation      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_x509if_RelaxationPolicy },
  { &hf_dap_extendedArea    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_hierarchySelections, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_dap_HierarchySelections },
  { &hf_dap_searchControlOptions, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_dap_SearchControlOptions },
  { &hf_dap_joinArguments   , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument },
  { &hf_dap_joinType        , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_dap_T_joinType },
  { &hf_dap_serviceControls , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControls },
  { &hf_dap_securityParameters, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_requestor       , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_operationProgress, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dsp_OperationProgress },
  { &hf_dap_aliasedRDNs     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_criticalExtensions, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_referenceType   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_dsp_ReferenceType },
  { &hf_dap_entryOnly       , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_exclusions      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dap_nameResolveOnMaster, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_operationContexts, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_ContextSelection },
  { &hf_dap_familyGrouping  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_SearchArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SearchArgumentData_set, hf_index, ett_dap_SearchArgumentData);

  return offset;
}


static const ber_sequence_t T_signedSearchArgument_sequence[] = {
  { &hf_dap_searchArgument  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_SearchArgumentData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedSearchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedSearchArgument_sequence, hf_index, ett_dap_T_signedSearchArgument);

  return offset;
}


const value_string dap_SearchArgument_vals[] = {
  {   0, "unsignedSearchArgument" },
  {   1, "signedSearchArgument" },
  { 0, NULL }
};

static const ber_choice_t SearchArgument_choice[] = {
  {   0, &hf_dap_unsignedSearchArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_SearchArgumentData },
  {   1, &hf_dap_signedSearchArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedSearchArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_SearchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SearchArgument_choice, hf_index, ett_dap_SearchArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_EntryInformation_set_of[1] = {
  { &hf_dap_entries_item    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_EntryInformation },
};

static int
dissect_dap_SET_OF_EntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_EntryInformation_set_of, hf_index, ett_dap_SET_OF_EntryInformation);

  return offset;
}


static const ber_sequence_t T_searchInfo_set[] = {
  { &hf_dap_name            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_entries         , BER_CLASS_CON, 0, 0, dissect_dap_SET_OF_EntryInformation },
  { &hf_dap_partialOutcomeQualifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_PartialOutcomeQualifier },
  { &hf_dap_altMatching     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_searchInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              T_searchInfo_set, hf_index, ett_dap_T_searchInfo);

  return offset;
}


static const ber_sequence_t T_signedSearchResult_sequence[] = {
  { &hf_dap_searchResult    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_SearchResultData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedSearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedSearchResult_sequence, hf_index, ett_dap_T_signedSearchResult);

  return offset;
}


const value_string dap_SearchResult_vals[] = {
  {   0, "unsignedSearchResult" },
  {   1, "signedSearchResult" },
  { 0, NULL }
};

static const ber_choice_t SearchResult_choice[] = {
  {   0, &hf_dap_unsignedSearchResult, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dap_SearchResultData },
  {   1, &hf_dap_signedSearchResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedSearchResult },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_SearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SearchResult_choice, hf_index, ett_dap_SearchResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_SearchResult_set_of[1] = {
  { &hf_dap_uncorrelatedSearchInfo_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_SearchResult },
};

static int
dissect_dap_SET_OF_SearchResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_SearchResult_set_of, hf_index, ett_dap_SET_OF_SearchResult);

  return offset;
}


static const value_string dap_SearchResultData_vals[] = {
  {   0, "searchInfo" },
  {   1, "uncorrelatedSearchInfo" },
  { 0, NULL }
};

static const ber_choice_t SearchResultData_choice[] = {
  {   0, &hf_dap_searchInfo      , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_T_searchInfo },
  {   1, &hf_dap_uncorrelatedSearchInfo, BER_CLASS_CON, 0, 0, dissect_dap_SET_OF_SearchResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_SearchResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SearchResultData_choice, hf_index, ett_dap_SearchResultData,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { &hf_dap_add_entry_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dap_SET_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Attribute_set_of, hf_index, ett_dap_SET_OF_Attribute);

  return offset;
}


static const ber_sequence_t AddEntryArgumentData_set[] = {
  { &hf_dap_object          , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_add_entry       , BER_CLASS_CON, 1, 0, dissect_dap_SET_OF_Attribute },
  { &hf_dap_targetSystem    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dsp_AccessPoint },
  { &hf_dap_serviceControls , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControls },
  { &hf_dap_securityParameters, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_requestor       , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_operationProgress, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dsp_OperationProgress },
  { &hf_dap_aliasedRDNs     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_criticalExtensions, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_referenceType   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_dsp_ReferenceType },
  { &hf_dap_entryOnly       , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_exclusions      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dap_nameResolveOnMaster, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_operationContexts, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_ContextSelection },
  { &hf_dap_familyGrouping  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_AddEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AddEntryArgumentData_set, hf_index, ett_dap_AddEntryArgumentData);

  return offset;
}


static const ber_sequence_t T_signedAddEntryArgument_sequence[] = {
  { &hf_dap_addEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_AddEntryArgumentData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAddEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedAddEntryArgument_sequence, hf_index, ett_dap_T_signedAddEntryArgument);

  return offset;
}


const value_string dap_AddEntryArgument_vals[] = {
  {   0, "unsignedAddEntryArgument" },
  {   1, "signedAddEntryArgument" },
  { 0, NULL }
};

static const ber_choice_t AddEntryArgument_choice[] = {
  {   0, &hf_dap_unsignedAddEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_AddEntryArgumentData },
  {   1, &hf_dap_signedAddEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedAddEntryArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_AddEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AddEntryArgument_choice, hf_index, ett_dap_AddEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t AddEntryResultData_sequence[] = {
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_AddEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddEntryResultData_sequence, hf_index, ett_dap_AddEntryResultData);

  return offset;
}


static const ber_sequence_t T_signedAddEntryResult_sequence[] = {
  { &hf_dap_addEntryResult  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_AddEntryResultData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAddEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedAddEntryResult_sequence, hf_index, ett_dap_T_signedAddEntryResult);

  return offset;
}


static const value_string dap_AddEntryInformation_vals[] = {
  {   0, "unsignedAddEntryResult" },
  {   1, "signedAddEntryResult" },
  { 0, NULL }
};

static const ber_choice_t AddEntryInformation_choice[] = {
  {   0, &hf_dap_unsignedAddEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_AddEntryResultData },
  {   1, &hf_dap_signedAddEntryResult, BER_CLASS_CON, 0, 0, dissect_dap_T_signedAddEntryResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_AddEntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AddEntryInformation_choice, hf_index, ett_dap_AddEntryInformation,
                                 NULL);

  return offset;
}


const value_string dap_AddEntryResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t AddEntryResult_choice[] = {
  {   0, &hf_dap_null            , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_dap_NULL },
  {   1, &hf_dap_add_entry_information, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dap_AddEntryInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_AddEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AddEntryResult_choice, hf_index, ett_dap_AddEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t RemoveEntryArgumentData_set[] = {
  { &hf_dap_object          , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_serviceControls , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControls },
  { &hf_dap_securityParameters, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_requestor       , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_operationProgress, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dsp_OperationProgress },
  { &hf_dap_aliasedRDNs     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_criticalExtensions, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_referenceType   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_dsp_ReferenceType },
  { &hf_dap_entryOnly       , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_exclusions      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dap_nameResolveOnMaster, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_operationContexts, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_ContextSelection },
  { &hf_dap_familyGrouping  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_RemoveEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RemoveEntryArgumentData_set, hf_index, ett_dap_RemoveEntryArgumentData);

  return offset;
}


static const ber_sequence_t T_signedRemoveEntryArgument_sequence[] = {
  { &hf_dap_removeEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_RemoveEntryArgumentData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedRemoveEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedRemoveEntryArgument_sequence, hf_index, ett_dap_T_signedRemoveEntryArgument);

  return offset;
}


const value_string dap_RemoveEntryArgument_vals[] = {
  {   0, "unsignedRemoveEntryArgument" },
  {   1, "signedRemoveEntryArgument" },
  { 0, NULL }
};

static const ber_choice_t RemoveEntryArgument_choice[] = {
  {   0, &hf_dap_unsignedRemoveEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_RemoveEntryArgumentData },
  {   1, &hf_dap_signedRemoveEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedRemoveEntryArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_RemoveEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RemoveEntryArgument_choice, hf_index, ett_dap_RemoveEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t RemoveEntryResultData_sequence[] = {
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_RemoveEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RemoveEntryResultData_sequence, hf_index, ett_dap_RemoveEntryResultData);

  return offset;
}


static const ber_sequence_t T_signedRemoveEntryResult_sequence[] = {
  { &hf_dap_removeEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_RemoveEntryResultData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedRemoveEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedRemoveEntryResult_sequence, hf_index, ett_dap_T_signedRemoveEntryResult);

  return offset;
}


static const value_string dap_RemoveEntryInformation_vals[] = {
  {   0, "unsignedRemoveEntryResult" },
  {   1, "signedRemoveEntryResult" },
  { 0, NULL }
};

static const ber_choice_t RemoveEntryInformation_choice[] = {
  {   0, &hf_dap_unsignedRemoveEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_RemoveEntryResultData },
  {   1, &hf_dap_signedRemoveEntryResult, BER_CLASS_CON, 0, 0, dissect_dap_T_signedRemoveEntryResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_RemoveEntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RemoveEntryInformation_choice, hf_index, ett_dap_RemoveEntryInformation,
                                 NULL);

  return offset;
}


const value_string dap_RemoveEntryResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t RemoveEntryResult_choice[] = {
  {   0, &hf_dap_null            , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_dap_NULL },
  {   1, &hf_dap_remove_entry_information, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dap_RemoveEntryInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_RemoveEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
  {   0, &hf_dap_addAttribute    , BER_CLASS_CON, 0, 0, dissect_x509if_Attribute },
  {   1, &hf_dap_removeAttribute , BER_CLASS_CON, 1, 0, dissect_x509if_AttributeType },
  {   2, &hf_dap_addValues       , BER_CLASS_CON, 2, 0, dissect_x509if_Attribute },
  {   3, &hf_dap_removeValues    , BER_CLASS_CON, 3, 0, dissect_x509if_Attribute },
  {   4, &hf_dap_alterValues     , BER_CLASS_CON, 4, 0, dissect_crmf_AttributeTypeAndValue },
  {   5, &hf_dap_resetValue      , BER_CLASS_CON, 5, 0, dissect_x509if_AttributeType },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_EntryModification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EntryModification_choice, hf_index, ett_dap_EntryModification,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EntryModification_sequence_of[1] = {
  { &hf_dap_changes_item    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_EntryModification },
};

static int
dissect_dap_SEQUENCE_OF_EntryModification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_EntryModification_sequence_of, hf_index, ett_dap_SEQUENCE_OF_EntryModification);

  return offset;
}


static const ber_sequence_t ModifyEntryArgumentData_set[] = {
  { &hf_dap_object          , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_changes         , BER_CLASS_CON, 1, 0, dissect_dap_SEQUENCE_OF_EntryModification },
  { &hf_dap_selection       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_EntryInformationSelection },
  { &hf_dap_serviceControls , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControls },
  { &hf_dap_securityParameters, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_requestor       , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_operationProgress, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dsp_OperationProgress },
  { &hf_dap_aliasedRDNs     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_criticalExtensions, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_referenceType   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_dsp_ReferenceType },
  { &hf_dap_entryOnly       , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_exclusions      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dap_nameResolveOnMaster, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_operationContexts, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_ContextSelection },
  { &hf_dap_familyGrouping  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyEntryArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ModifyEntryArgumentData_set, hf_index, ett_dap_ModifyEntryArgumentData);

  return offset;
}


static const ber_sequence_t T_signedModifyEntryArgument_sequence[] = {
  { &hf_dap_modifyEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyEntryArgumentData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedModifyEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedModifyEntryArgument_sequence, hf_index, ett_dap_T_signedModifyEntryArgument);

  return offset;
}


const value_string dap_ModifyEntryArgument_vals[] = {
  {   0, "unsignedModifyEntryArgument" },
  {   1, "signedModifyEntryArgument" },
  { 0, NULL }
};

static const ber_choice_t ModifyEntryArgument_choice[] = {
  {   0, &hf_dap_unsignedModifyEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyEntryArgumentData },
  {   1, &hf_dap_signedModifyEntryArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedModifyEntryArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ModifyEntryArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyEntryArgument_choice, hf_index, ett_dap_ModifyEntryArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t ModifyEntryResultData_sequence[] = {
  { &hf_dap_entry           , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dap_EntryInformation },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyEntryResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyEntryResultData_sequence, hf_index, ett_dap_ModifyEntryResultData);

  return offset;
}


static const ber_sequence_t T_signedModifyEntryResult_sequence[] = {
  { &hf_dap_modifyEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyEntryResultData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedModifyEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedModifyEntryResult_sequence, hf_index, ett_dap_T_signedModifyEntryResult);

  return offset;
}


static const value_string dap_ModifyEntryInformation_vals[] = {
  {   0, "unsignedModifyEntryResult" },
  {   1, "signedModifyEntryResult" },
  { 0, NULL }
};

static const ber_choice_t ModifyEntryInformation_choice[] = {
  {   0, &hf_dap_unsignedModifyEntryResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyEntryResultData },
  {   1, &hf_dap_signedModifyEntryResult, BER_CLASS_CON, 0, 0, dissect_dap_T_signedModifyEntryResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyEntryInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyEntryInformation_choice, hf_index, ett_dap_ModifyEntryInformation,
                                 NULL);

  return offset;
}


const value_string dap_ModifyEntryResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t ModifyEntryResult_choice[] = {
  {   0, &hf_dap_null            , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_dap_NULL },
  {   1, &hf_dap_modify_entry_information, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyEntryInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ModifyEntryResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyEntryResult_choice, hf_index, ett_dap_ModifyEntryResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ModifyDNArgument_set[] = {
  { &hf_dap_distinguished_name, BER_CLASS_CON, 0, 0, dissect_x509if_DistinguishedName },
  { &hf_dap_newRDN          , BER_CLASS_CON, 1, 0, dissect_x509if_RelativeDistinguishedName },
  { &hf_dap_deleteOldRDN    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_newSuperior     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_serviceControls , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControls },
  { &hf_dap_securityParameters, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_requestor       , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_operationProgress, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dsp_OperationProgress },
  { &hf_dap_aliasedRDNs     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL, dissect_dap_INTEGER },
  { &hf_dap_criticalExtensions, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL, dissect_dap_BIT_STRING },
  { &hf_dap_referenceType   , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_dsp_ReferenceType },
  { &hf_dap_entryOnly       , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_exclusions      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_dsp_Exclusions },
  { &hf_dap_nameResolveOnMaster, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_operationContexts, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_ContextSelection },
  { &hf_dap_familyGrouping  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ModifyDNArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ModifyDNArgument_set, hf_index, ett_dap_ModifyDNArgument);

  return offset;
}


static const ber_sequence_t ModifyDNResultData_sequence[] = {
  { &hf_dap_newRDN          , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_RelativeDistinguishedName },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyDNResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyDNResultData_sequence, hf_index, ett_dap_ModifyDNResultData);

  return offset;
}


static const ber_sequence_t T_signedModifyDNResult_sequence[] = {
  { &hf_dap_modifyDNResult  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyDNResultData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedModifyDNResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedModifyDNResult_sequence, hf_index, ett_dap_T_signedModifyDNResult);

  return offset;
}


static const value_string dap_ModifyDNInformation_vals[] = {
  {   0, "unsignedModifyDNResult" },
  {   1, "signedModifyDNResult" },
  { 0, NULL }
};

static const ber_choice_t ModifyDNInformation_choice[] = {
  {   0, &hf_dap_unsignedModifyDNResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyDNResultData },
  {   1, &hf_dap_signedModifyDNResult, BER_CLASS_CON, 0, 0, dissect_dap_T_signedModifyDNResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyDNInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyDNInformation_choice, hf_index, ett_dap_ModifyDNInformation,
                                 NULL);

  return offset;
}


const value_string dap_ModifyDNResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t ModifyDNResult_choice[] = {
  {   0, &hf_dap_null            , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_dap_NULL },
  {   1, &hf_dap_modify_dn_information, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyDNInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ModifyDNResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyDNResult_choice, hf_index, ett_dap_ModifyDNResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t AbandonedData_set[] = {
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AbandonedData_set, hf_index, ett_dap_AbandonedData);

  return offset;
}


static const ber_sequence_t T_signedAbandoned_sequence[] = {
  { &hf_dap_abandoned       , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_AbandonedData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAbandoned(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedAbandoned_sequence, hf_index, ett_dap_T_signedAbandoned);

  return offset;
}


const value_string dap_Abandoned_vals[] = {
  {   0, "unsignedAbandoned" },
  {   1, "signedAbandoned" },
  { 0, NULL }
};

static const ber_choice_t Abandoned_choice[] = {
  {   0, &hf_dap_unsignedAbandoned, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_AbandonedData },
  {   1, &hf_dap_signedAbandoned , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedAbandoned },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_Abandoned(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
dissect_dap_AbandonProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AbandonFailedErrorData_set[] = {
  { &hf_dap_abandon_failed_problem, BER_CLASS_CON, 0, 0, dissect_dap_AbandonProblem },
  { &hf_dap_operation       , BER_CLASS_CON, 1, 0, dissect_ros_InvokeId },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_AbandonFailedErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AbandonFailedErrorData_set, hf_index, ett_dap_AbandonFailedErrorData);

  return offset;
}


static const ber_sequence_t T_signedAbandonFailedError_sequence[] = {
  { &hf_dap_abandonFailedError, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_AbandonFailedErrorData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAbandonFailedError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedAbandonFailedError_sequence, hf_index, ett_dap_T_signedAbandonFailedError);

  return offset;
}


const value_string dap_AbandonFailedError_vals[] = {
  {   0, "unsignedAbandonFailedError" },
  {   1, "signedAbandonFailedError" },
  { 0, NULL }
};

static const ber_choice_t AbandonFailedError_choice[] = {
  {   0, &hf_dap_unsignedAbandonFailedError, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_AbandonFailedErrorData },
  {   1, &hf_dap_signedAbandonFailedError, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedAbandonFailedError },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_AbandonFailedError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
dissect_dap_AttributeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_problems_item_sequence[] = {
  { &hf_dap_attribute_error_problem, BER_CLASS_CON, 0, 0, dissect_dap_AttributeProblem },
  { &hf_dap_type            , BER_CLASS_CON, 1, 0, dissect_x509if_AttributeType },
  { &hf_dap_value           , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_AttributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_problems_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_problems_item_sequence, hf_index, ett_dap_T_problems_item);

  return offset;
}


static const ber_sequence_t T_problems_set_of[1] = {
  { &hf_dap_problems_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_problems_item },
};

static int
dissect_dap_T_problems(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_problems_set_of, hf_index, ett_dap_T_problems);

  return offset;
}


static const ber_sequence_t AttributeErrorData_set[] = {
  { &hf_dap_object          , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_problems        , BER_CLASS_CON, 1, 0, dissect_dap_T_problems },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_AttributeErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              AttributeErrorData_set, hf_index, ett_dap_AttributeErrorData);

  return offset;
}


static const ber_sequence_t T_signedAttributeError_sequence[] = {
  { &hf_dap_attributeError  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_AttributeErrorData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedAttributeError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedAttributeError_sequence, hf_index, ett_dap_T_signedAttributeError);

  return offset;
}


const value_string dap_AttributeError_vals[] = {
  {   0, "unsignedAttributeError" },
  {   1, "signedAttributeError" },
  { 0, NULL }
};

static const ber_choice_t AttributeError_choice[] = {
  {   0, &hf_dap_unsignedAttributeError, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_AttributeErrorData },
  {   1, &hf_dap_signedAttributeError, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedAttributeError },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_AttributeError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
dissect_dap_NameProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t NameErrorData_set[] = {
  { &hf_dap_name_error_problem, BER_CLASS_CON, 0, 0, dissect_dap_NameProblem },
  { &hf_dap_matched_name    , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_dap_Name },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_NameErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              NameErrorData_set, hf_index, ett_dap_NameErrorData);

  return offset;
}


static const ber_sequence_t T_signedNameError_sequence[] = {
  { &hf_dap_nameError       , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_NameErrorData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedNameError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedNameError_sequence, hf_index, ett_dap_T_signedNameError);

  return offset;
}


const value_string dap_NameError_vals[] = {
  {   0, "unsignedNameError" },
  {   1, "signedNameError" },
  { 0, NULL }
};

static const ber_choice_t NameError_choice[] = {
  {   0, &hf_dap_unsignedNameError, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_NameErrorData },
  {   1, &hf_dap_signedNameError , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedNameError },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_NameError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NameError_choice, hf_index, ett_dap_NameError,
                                 NULL);

  return offset;
}


static const ber_sequence_t ReferralData_set[] = {
  { &hf_dap_candidate       , BER_CLASS_CON, 0, 0, dissect_dsp_ContinuationReference },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ReferralData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ReferralData_set, hf_index, ett_dap_ReferralData);

  return offset;
}


static const ber_sequence_t T_signedReferral_sequence[] = {
  { &hf_dap_referral        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ReferralData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedReferral(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedReferral_sequence, hf_index, ett_dap_T_signedReferral);

  return offset;
}


const value_string dap_Referral_vals[] = {
  {   0, "unsignedReferral" },
  {   1, "signedReferral" },
  { 0, NULL }
};

static const ber_choice_t Referral_choice[] = {
  {   0, &hf_dap_unsignedReferral, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ReferralData },
  {   1, &hf_dap_signedReferral  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedReferral },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_Referral(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Referral_choice, hf_index, ett_dap_Referral,
                                 NULL);

  return offset;
}



static int
dissect_dap_T_spkmInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	/* XXX: not yet implemented */


  return offset;
}


static const ber_sequence_t SecurityErrorData_set[] = {
  { &hf_dap_security_error_problem, BER_CLASS_CON, 0, 0, dissect_dap_SecurityProblem },
  { &hf_dap_spkmInfo        , BER_CLASS_CON, 1, 0, dissect_dap_T_spkmInfo },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_SecurityErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SecurityErrorData_set, hf_index, ett_dap_SecurityErrorData);

  return offset;
}


static const ber_sequence_t T_signedSecurityError_sequence[] = {
  { &hf_dap_securityErrorData, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_SecurityErrorData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedSecurityError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedSecurityError_sequence, hf_index, ett_dap_T_signedSecurityError);

  return offset;
}


const value_string dap_SecurityError_vals[] = {
  {   0, "unsignedSecurityError" },
  {   1, "signedSecurityError" },
  { 0, NULL }
};

static const ber_choice_t SecurityError_choice[] = {
  {   0, &hf_dap_unsignedSecurityError, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_SecurityErrorData },
  {   1, &hf_dap_signedSecurityError, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedSecurityError },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_SecurityError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SecurityError_choice, hf_index, ett_dap_SecurityError,
                                 NULL);

  return offset;
}


static const ber_sequence_t ServiceErrorData_set[] = {
  { &hf_dap_service_error_problem, BER_CLASS_CON, 0, 0, dissect_dap_ServiceProblem },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ServiceErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ServiceErrorData_set, hf_index, ett_dap_ServiceErrorData);

  return offset;
}


static const ber_sequence_t T_signedServiceError_sequence[] = {
  { &hf_dap_serviceError    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ServiceErrorData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedServiceError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedServiceError_sequence, hf_index, ett_dap_T_signedServiceError);

  return offset;
}


const value_string dap_ServiceError_vals[] = {
  {   0, "unsignedServiceError" },
  {   1, "signedServiceError" },
  { 0, NULL }
};

static const ber_choice_t ServiceError_choice[] = {
  {   0, &hf_dap_unsignedServiceError, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_ServiceErrorData },
  {   1, &hf_dap_signedServiceError, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedServiceError },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_ServiceError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
dissect_dap_UpdateProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  guint32 problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, dap_UpdateProblem_vals, "UpdateProblem(%d)"));


  return offset;
}


static const value_string dap_T_attributeInfo_item_vals[] = {
  {   0, "attributeType" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t T_attributeInfo_item_choice[] = {
  {   0, &hf_dap_attributeType   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  {   1, &hf_dap_attribute       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_attributeInfo_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_attributeInfo_item_choice, hf_index, ett_dap_T_attributeInfo_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_attributeInfo_set_of[1] = {
  { &hf_dap_attributeInfo_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_attributeInfo_item },
};

static int
dissect_dap_T_attributeInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_attributeInfo_set_of, hf_index, ett_dap_T_attributeInfo);

  return offset;
}


static const ber_sequence_t UpdateErrorData_set[] = {
  { &hf_dap_update_error_problem, BER_CLASS_CON, 0, 0, dissect_dap_UpdateProblem },
  { &hf_dap_attributeInfo   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_T_attributeInfo },
  { &hf_dap_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dap_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dap_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dap_BOOLEAN },
  { &hf_dap_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_UpdateErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              UpdateErrorData_set, hf_index, ett_dap_UpdateErrorData);

  return offset;
}


static const ber_sequence_t T_signedUpdateError_sequence[] = {
  { &hf_dap_updateError     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_UpdateErrorData },
  { &hf_dap_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dap_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dap_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_T_signedUpdateError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedUpdateError_sequence, hf_index, ett_dap_T_signedUpdateError);

  return offset;
}


const value_string dap_UpdateError_vals[] = {
  {   0, "unsignedUpdateError" },
  {   1, "signedUpdateError" },
  { 0, NULL }
};

static const ber_choice_t UpdateError_choice[] = {
  {   0, &hf_dap_unsignedUpdateError, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dap_UpdateErrorData },
  {   1, &hf_dap_signedUpdateError, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_signedUpdateError },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_dap_UpdateError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UpdateError_choice, hf_index, ett_dap_UpdateError,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_DirectoryBindArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_DirectoryBindArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_DirectoryBindArgument_PDU);
  return offset;
}
static int dissect_DirectoryBindResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_DirectoryBindResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_DirectoryBindResult_PDU);
  return offset;
}
static int dissect_DirectoryBindError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_DirectoryBindError(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_DirectoryBindError_PDU);
  return offset;
}
static int dissect_ReadArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_ReadArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_ReadArgument_PDU);
  return offset;
}
static int dissect_ReadResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_ReadResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_ReadResult_PDU);
  return offset;
}
static int dissect_CompareArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_CompareArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_CompareArgument_PDU);
  return offset;
}
static int dissect_CompareResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_CompareResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_CompareResult_PDU);
  return offset;
}
static int dissect_AbandonArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_AbandonArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_AbandonArgument_PDU);
  return offset;
}
static int dissect_AbandonResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_AbandonResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_AbandonResult_PDU);
  return offset;
}
static int dissect_ListArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_ListArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_ListArgument_PDU);
  return offset;
}
static int dissect_ListResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_ListResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_ListResult_PDU);
  return offset;
}
static int dissect_SearchArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_SearchArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_SearchArgument_PDU);
  return offset;
}
static int dissect_SearchResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_SearchResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_SearchResult_PDU);
  return offset;
}
static int dissect_AddEntryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_AddEntryArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_AddEntryArgument_PDU);
  return offset;
}
static int dissect_AddEntryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_AddEntryResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_AddEntryResult_PDU);
  return offset;
}
static int dissect_RemoveEntryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_RemoveEntryArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_RemoveEntryArgument_PDU);
  return offset;
}
static int dissect_RemoveEntryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_RemoveEntryResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_RemoveEntryResult_PDU);
  return offset;
}
static int dissect_ModifyEntryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_ModifyEntryArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_ModifyEntryArgument_PDU);
  return offset;
}
static int dissect_ModifyEntryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_ModifyEntryResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_ModifyEntryResult_PDU);
  return offset;
}
static int dissect_ModifyDNArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_ModifyDNArgument(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_ModifyDNArgument_PDU);
  return offset;
}
static int dissect_ModifyDNResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_ModifyDNResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_ModifyDNResult_PDU);
  return offset;
}
static int dissect_Abandoned_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_Abandoned(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_Abandoned_PDU);
  return offset;
}
static int dissect_AbandonFailedError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_AbandonFailedError(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_AbandonFailedError_PDU);
  return offset;
}
static int dissect_AttributeError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_AttributeError(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_AttributeError_PDU);
  return offset;
}
static int dissect_NameError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_NameError(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_NameError_PDU);
  return offset;
}
static int dissect_Referral_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_Referral(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_Referral_PDU);
  return offset;
}
static int dissect_SecurityError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_SecurityError(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_SecurityError_PDU);
  return offset;
}
static int dissect_ServiceError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_ServiceError(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_ServiceError_PDU);
  return offset;
}
static int dissect_UpdateError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_dap_UpdateError(FALSE, tvb, offset, &asn1_ctx, tree, hf_dap_UpdateError_PDU);
  return offset;
}


/*--- End of included file: packet-dap-fn.c ---*/
#line 77 "../../asn1/dap/packet-dap-template.c"


/*--- Included file: packet-dap-table11.c ---*/
#line 1 "../../asn1/dap/packet-dap-table11.c"

static const ros_opr_t dap_opr_tab[] = {
  /* directoryBind */ 
  { op_ros_bind              ,	dissect_DirectoryBindArgument_PDU,	dissect_DirectoryBindResult_PDU }, 
  /* read */ 
  { id_opcode_read           ,	dissect_ReadArgument_PDU,	dissect_ReadResult_PDU }, 
  /* compare */ 
  { id_opcode_compare        ,	dissect_CompareArgument_PDU,	dissect_CompareResult_PDU }, 
  /* abandon */ 
  { id_opcode_abandon        ,	dissect_AbandonArgument_PDU,	dissect_AbandonResult_PDU }, 
  /* list */ 
  { id_opcode_list           ,	dissect_ListArgument_PDU,	dissect_ListResult_PDU }, 
  /* search */ 
  { id_opcode_search         ,	dissect_SearchArgument_PDU,	dissect_SearchResult_PDU }, 
  /* addEntry */ 
  { id_opcode_addEntry       ,	dissect_AddEntryArgument_PDU,	dissect_AddEntryResult_PDU }, 
  /* removeEntry */ 
  { id_opcode_removeEntry    ,	dissect_RemoveEntryArgument_PDU,	dissect_RemoveEntryResult_PDU }, 
  /* modifyEntry */ 
  { id_opcode_modifyEntry    ,	dissect_ModifyEntryArgument_PDU,	dissect_ModifyEntryResult_PDU }, 
  /* modifyDN */ 
  { id_opcode_modifyDN       ,	dissect_ModifyDNArgument_PDU,	dissect_ModifyDNResult_PDU }, 
  { 0,				(new_dissector_t)(-1),	(new_dissector_t)(-1) },
};


/*--- End of included file: packet-dap-table11.c ---*/
#line 79 "../../asn1/dap/packet-dap-template.c"

/*--- Included file: packet-dap-table21.c ---*/
#line 1 "../../asn1/dap/packet-dap-table21.c"

static const ros_err_t dap_err_tab[] = {
  /* directoryBindError*/ 
  { err_ros_bind,	dissect_DirectoryBindError_PDU },
  /* abandoned*/ 
  { id_errcode_abandoned,	dissect_Abandoned_PDU },
  /* abandonFailed*/ 
  { id_errcode_abandonFailed,	dissect_AbandonFailedError_PDU },
  /* attributeError*/ 
  { id_errcode_attributeError,	dissect_AttributeError_PDU },
  /* nameError*/ 
  { id_errcode_nameError,	dissect_NameError_PDU },
  /* referral*/ 
  { id_errcode_referral,	dissect_Referral_PDU },
  /* securityError*/ 
  { id_errcode_securityError,	dissect_SecurityError_PDU },
  /* serviceError*/ 
  { id_errcode_serviceError,	dissect_ServiceError_PDU },
  /* updateError*/ 
  { id_errcode_updateError,	dissect_UpdateError_PDU },
  { 0,	(new_dissector_t)(-1) },
};


/*--- End of included file: packet-dap-table21.c ---*/
#line 80 "../../asn1/dap/packet-dap-template.c"

static const ros_info_t dap_ros_info = {
  "DAP",
  &proto_dap,
  &ett_dap,
  dap_opr_code_string_vals,
  dap_opr_tab,
  dap_err_code_string_vals,
  dap_err_tab
};


/*--- proto_register_dap -------------------------------------------*/
void proto_register_dap(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-dap-hfarr.c ---*/
#line 1 "../../asn1/dap/packet-dap-hfarr.c"
    { &hf_dap_DirectoryBindArgument_PDU,
      { "DirectoryBindArgument", "dap.DirectoryBindArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_DirectoryBindResult_PDU,
      { "DirectoryBindResult", "dap.DirectoryBindResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_DirectoryBindError_PDU,
      { "DirectoryBindError", "dap.DirectoryBindError",
        FT_UINT32, BASE_DEC, VALS(dap_DirectoryBindError_vals), 0,
        NULL, HFILL }},
    { &hf_dap_ReadArgument_PDU,
      { "ReadArgument", "dap.ReadArgument",
        FT_UINT32, BASE_DEC, VALS(dap_ReadArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dap_ReadResult_PDU,
      { "ReadResult", "dap.ReadResult",
        FT_UINT32, BASE_DEC, VALS(dap_ReadResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_CompareArgument_PDU,
      { "CompareArgument", "dap.CompareArgument",
        FT_UINT32, BASE_DEC, VALS(dap_CompareArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dap_CompareResult_PDU,
      { "CompareResult", "dap.CompareResult",
        FT_UINT32, BASE_DEC, VALS(dap_CompareResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_AbandonArgument_PDU,
      { "AbandonArgument", "dap.AbandonArgument",
        FT_UINT32, BASE_DEC, VALS(dap_AbandonArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dap_AbandonResult_PDU,
      { "AbandonResult", "dap.AbandonResult",
        FT_UINT32, BASE_DEC, VALS(dap_AbandonResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_ListArgument_PDU,
      { "ListArgument", "dap.ListArgument",
        FT_UINT32, BASE_DEC, VALS(dap_ListArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dap_ListResult_PDU,
      { "ListResult", "dap.ListResult",
        FT_UINT32, BASE_DEC, VALS(dap_ListResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_SearchArgument_PDU,
      { "SearchArgument", "dap.SearchArgument",
        FT_UINT32, BASE_DEC, VALS(dap_SearchArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dap_SearchResult_PDU,
      { "SearchResult", "dap.SearchResult",
        FT_UINT32, BASE_DEC, VALS(dap_SearchResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_AddEntryArgument_PDU,
      { "AddEntryArgument", "dap.AddEntryArgument",
        FT_UINT32, BASE_DEC, VALS(dap_AddEntryArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dap_AddEntryResult_PDU,
      { "AddEntryResult", "dap.AddEntryResult",
        FT_UINT32, BASE_DEC, VALS(dap_AddEntryResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_RemoveEntryArgument_PDU,
      { "RemoveEntryArgument", "dap.RemoveEntryArgument",
        FT_UINT32, BASE_DEC, VALS(dap_RemoveEntryArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dap_RemoveEntryResult_PDU,
      { "RemoveEntryResult", "dap.RemoveEntryResult",
        FT_UINT32, BASE_DEC, VALS(dap_RemoveEntryResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_ModifyEntryArgument_PDU,
      { "ModifyEntryArgument", "dap.ModifyEntryArgument",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyEntryArgument_vals), 0,
        NULL, HFILL }},
    { &hf_dap_ModifyEntryResult_PDU,
      { "ModifyEntryResult", "dap.ModifyEntryResult",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyEntryResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_ModifyDNArgument_PDU,
      { "ModifyDNArgument", "dap.ModifyDNArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_ModifyDNResult_PDU,
      { "ModifyDNResult", "dap.ModifyDNResult",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyDNResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_Abandoned_PDU,
      { "Abandoned", "dap.Abandoned",
        FT_UINT32, BASE_DEC, VALS(dap_Abandoned_vals), 0,
        NULL, HFILL }},
    { &hf_dap_AbandonFailedError_PDU,
      { "AbandonFailedError", "dap.AbandonFailedError",
        FT_UINT32, BASE_DEC, VALS(dap_AbandonFailedError_vals), 0,
        NULL, HFILL }},
    { &hf_dap_AttributeError_PDU,
      { "AttributeError", "dap.AttributeError",
        FT_UINT32, BASE_DEC, VALS(dap_AttributeError_vals), 0,
        NULL, HFILL }},
    { &hf_dap_NameError_PDU,
      { "NameError", "dap.NameError",
        FT_UINT32, BASE_DEC, VALS(dap_NameError_vals), 0,
        NULL, HFILL }},
    { &hf_dap_Referral_PDU,
      { "Referral", "dap.Referral",
        FT_UINT32, BASE_DEC, VALS(dap_Referral_vals), 0,
        NULL, HFILL }},
    { &hf_dap_SecurityError_PDU,
      { "SecurityError", "dap.SecurityError",
        FT_UINT32, BASE_DEC, VALS(dap_SecurityError_vals), 0,
        NULL, HFILL }},
    { &hf_dap_ServiceError_PDU,
      { "ServiceError", "dap.ServiceError",
        FT_UINT32, BASE_DEC, VALS(dap_ServiceError_vals), 0,
        NULL, HFILL }},
    { &hf_dap_UpdateError_PDU,
      { "UpdateError", "dap.UpdateError",
        FT_UINT32, BASE_DEC, VALS(dap_UpdateError_vals), 0,
        NULL, HFILL }},
    { &hf_dap_options,
      { "options", "dap.options",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ServiceControlOptions", HFILL }},
    { &hf_dap_priority,
      { "priority", "dap.priority",
        FT_INT32, BASE_DEC, VALS(dap_T_priority_vals), 0,
        NULL, HFILL }},
    { &hf_dap_timeLimit,
      { "timeLimit", "dap.timeLimit",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_sizeLimit,
      { "sizeLimit", "dap.sizeLimit",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_scopeOfReferral,
      { "scopeOfReferral", "dap.scopeOfReferral",
        FT_INT32, BASE_DEC, VALS(dap_T_scopeOfReferral_vals), 0,
        NULL, HFILL }},
    { &hf_dap_attributeSizeLimit,
      { "attributeSizeLimit", "dap.attributeSizeLimit",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_manageDSAITPlaneRef,
      { "manageDSAITPlaneRef", "dap.manageDSAITPlaneRef",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_dsaName,
      { "dsaName", "dap.dsaName",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dap_agreementID,
      { "agreementID", "dap.agreementID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_serviceType,
      { "serviceType", "dap.serviceType",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_dap_userClass,
      { "userClass", "dap.userClass",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_attributes,
      { "attributes", "dap.attributes",
        FT_UINT32, BASE_DEC, VALS(dap_T_attributes_vals), 0,
        NULL, HFILL }},
    { &hf_dap_allUserAttributes,
      { "allUserAttributes", "dap.allUserAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_select,
      { "select", "dap.select",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeType", HFILL }},
    { &hf_dap_select_item,
      { "AttributeType", "dap.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_infoTypes,
      { "infoTypes", "dap.infoTypes",
        FT_INT32, BASE_DEC, VALS(dap_T_infoTypes_vals), 0,
        NULL, HFILL }},
    { &hf_dap_extraAttributes,
      { "extraAttributes", "dap.extraAttributes",
        FT_UINT32, BASE_DEC, VALS(dap_T_extraAttributes_vals), 0,
        NULL, HFILL }},
    { &hf_dap_allOperationalAttributes,
      { "allOperationalAttributes", "dap.allOperationalAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_extraSelect,
      { "select", "dap.select",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_AttributeType", HFILL }},
    { &hf_dap_extraSelect_item,
      { "AttributeType", "dap.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_contextSelection,
      { "contextSelection", "dap.contextSelection",
        FT_UINT32, BASE_DEC, VALS(dap_ContextSelection_vals), 0,
        NULL, HFILL }},
    { &hf_dap_returnContexts,
      { "returnContexts", "dap.returnContexts",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_familyReturn,
      { "familyReturn", "dap.familyReturn",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_allContexts,
      { "allContexts", "dap.allContexts",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_selectedContexts,
      { "selectedContexts", "dap.selectedContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_TypeAndContextAssertion", HFILL }},
    { &hf_dap_selectedContexts_item,
      { "TypeAndContextAssertion", "dap.TypeAndContextAssertion",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_type,
      { "type", "dap.type",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_contextAssertions,
      { "contextAssertions", "dap.contextAssertions",
        FT_UINT32, BASE_DEC, VALS(dap_T_contextAssertions_vals), 0,
        NULL, HFILL }},
    { &hf_dap_preference,
      { "preference", "dap.preference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ContextAssertion", HFILL }},
    { &hf_dap_preference_item,
      { "ContextAssertion", "dap.ContextAssertion",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_all,
      { "all", "dap.all",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ContextAssertion", HFILL }},
    { &hf_dap_all_item,
      { "ContextAssertion", "dap.ContextAssertion",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_memberSelect,
      { "memberSelect", "dap.memberSelect",
        FT_UINT32, BASE_DEC, VALS(dap_T_memberSelect_vals), 0,
        NULL, HFILL }},
    { &hf_dap_familySelect,
      { "familySelect", "dap.familySelect",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_familySelect_item,
      { "familySelect item", "dap.familySelect_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_dap_name,
      { "name", "dap.name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        NULL, HFILL }},
    { &hf_dap_fromEntry,
      { "fromEntry", "dap.fromEntry",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_entry_information", HFILL }},
    { &hf_dap_entry_information_item,
      { "information item", "dap.information_item",
        FT_UINT32, BASE_DEC, VALS(dap_EntryInformationItem_vals), 0,
        "EntryInformationItem", HFILL }},
    { &hf_dap_attributeType,
      { "attributeType", "dap.attributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_attribute,
      { "attribute", "dap.attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_incompleteEntry,
      { "incompleteEntry", "dap.incompleteEntry",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_partialName,
      { "partialName", "dap.partialName",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_derivedEntry,
      { "derivedEntry", "dap.derivedEntry",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_family_class,
      { "family-class", "dap.family_class",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_dap_familyEntries,
      { "familyEntries", "dap.familyEntries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_FamilyEntry", HFILL }},
    { &hf_dap_familyEntries_item,
      { "FamilyEntry", "dap.FamilyEntry",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_rdn,
      { "rdn", "dap.rdn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelativeDistinguishedName", HFILL }},
    { &hf_dap_family_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FamilyInformation", HFILL }},
    { &hf_dap_family_information_item,
      { "information item", "dap.information_item",
        FT_UINT32, BASE_DEC, VALS(dap_T_family_information_item_vals), 0,
        "T_family_information_item", HFILL }},
    { &hf_dap_family_info,
      { "family-info", "dap.family_info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_FamilyEntries", HFILL }},
    { &hf_dap_family_info_item,
      { "FamilyEntries", "dap.FamilyEntries",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_filter_item,
      { "item", "dap.item",
        FT_UINT32, BASE_DEC, VALS(dap_FilterItem_vals), 0,
        "FilterItem", HFILL }},
    { &hf_dap_and,
      { "and", "dap.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SetOfFilter", HFILL }},
    { &hf_dap_or,
      { "or", "dap.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SetOfFilter", HFILL }},
    { &hf_dap_not,
      { "not", "dap.not",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "Filter", HFILL }},
    { &hf_dap_SetOfFilter_item,
      { "Filter", "dap.Filter",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        NULL, HFILL }},
    { &hf_dap_equality,
      { "equality", "dap.equality",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_substrings,
      { "substrings", "dap.substrings",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_sunstringType,
      { "type", "dap.type",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_dap_strings,
      { "strings", "dap.strings",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_strings_item,
      { "strings item", "dap.strings_item",
        FT_UINT32, BASE_DEC, VALS(dap_T_strings_item_vals), 0,
        NULL, HFILL }},
    { &hf_dap_initial,
      { "initial", "dap.initial",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_any,
      { "any", "dap.any",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_final,
      { "final", "dap.final",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_control,
      { "control", "dap.control",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_dap_greaterOrEqual,
      { "greaterOrEqual", "dap.greaterOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_lessOrEqual,
      { "lessOrEqual", "dap.lessOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_present,
      { "present", "dap.present",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_approximateMatch,
      { "approximateMatch", "dap.approximateMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_extensibleMatch,
      { "extensibleMatch", "dap.extensibleMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        "MatchingRuleAssertion", HFILL }},
    { &hf_dap_contextPresent,
      { "contextPresent", "dap.contextPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeTypeAssertion", HFILL }},
    { &hf_dap_matchingRule,
      { "matchingRule", "dap.matchingRule",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_matchingRule_item,
      { "matchingRule item", "dap.matchingRule_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_dap_matchValue,
      { "matchValue", "dap.matchValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_dnAttributes,
      { "dnAttributes", "dap.dnAttributes",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_newRequest,
      { "newRequest", "dap.newRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_pageSize,
      { "pageSize", "dap.pageSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_sortKeys,
      { "sortKeys", "dap.sortKeys",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_SortKey", HFILL }},
    { &hf_dap_sortKeys_item,
      { "SortKey", "dap.SortKey",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_reverse,
      { "reverse", "dap.reverse",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_unmerged,
      { "unmerged", "dap.unmerged",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_pagedResultsQueryReference,
      { "queryReference", "dap.queryReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_pagedResultsQueryReference", HFILL }},
    { &hf_dap_orderingRule,
      { "orderingRule", "dap.orderingRule",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_dap_certification_path,
      { "certification-path", "dap.certification_path",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificationPath", HFILL }},
    { &hf_dap_distinguished_name,
      { "name", "dap.name",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dap_time,
      { "time", "dap.time",
        FT_UINT32, BASE_DEC, VALS(dap_Time_vals), 0,
        NULL, HFILL }},
    { &hf_dap_random,
      { "random", "dap.random",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_dap_target,
      { "target", "dap.target",
        FT_INT32, BASE_DEC, VALS(dap_ProtectionRequest_vals), 0,
        "ProtectionRequest", HFILL }},
    { &hf_dap_response,
      { "response", "dap.response",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_dap_operationCode,
      { "operationCode", "dap.operationCode",
        FT_UINT32, BASE_DEC, VALS(ros_Code_vals), 0,
        "Code", HFILL }},
    { &hf_dap_attributeCertificationPath,
      { "attributeCertificationPath", "dap.attributeCertificationPath",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_errorProtection,
      { "errorProtection", "dap.errorProtection",
        FT_INT32, BASE_DEC, VALS(dap_ErrorProtectionRequest_vals), 0,
        "ErrorProtectionRequest", HFILL }},
    { &hf_dap_errorCode,
      { "errorCode", "dap.errorCode",
        FT_UINT32, BASE_DEC, VALS(ros_Code_vals), 0,
        "Code", HFILL }},
    { &hf_dap_utcTime,
      { "utcTime", "dap.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_generalizedTime,
      { "generalizedTime", "dap.generalizedTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_credentials,
      { "credentials", "dap.credentials",
        FT_UINT32, BASE_DEC, VALS(dap_Credentials_vals), 0,
        NULL, HFILL }},
    { &hf_dap_versions,
      { "versions", "dap.versions",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_simple,
      { "simple", "dap.simple",
        FT_NONE, BASE_NONE, NULL, 0,
        "SimpleCredentials", HFILL }},
    { &hf_dap_strong,
      { "strong", "dap.strong",
        FT_NONE, BASE_NONE, NULL, 0,
        "StrongCredentials", HFILL }},
    { &hf_dap_externalProcedure,
      { "externalProcedure", "dap.externalProcedure",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_dap_spkm,
      { "spkm", "dap.spkm",
        FT_UINT32, BASE_DEC, VALS(dap_SpkmCredentials_vals), 0,
        "SpkmCredentials", HFILL }},
    { &hf_dap_sasl,
      { "sasl", "dap.sasl",
        FT_NONE, BASE_NONE, NULL, 0,
        "SaslCredentials", HFILL }},
    { &hf_dap_validity,
      { "validity", "dap.validity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_time1,
      { "time1", "dap.time1",
        FT_UINT32, BASE_DEC, VALS(dap_T_time1_vals), 0,
        NULL, HFILL }},
    { &hf_dap_utc,
      { "utc", "dap.utc",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_dap_gt,
      { "gt", "dap.gt",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_dap_time2,
      { "time2", "dap.time2",
        FT_UINT32, BASE_DEC, VALS(dap_T_time2_vals), 0,
        NULL, HFILL }},
    { &hf_dap_random1,
      { "random1", "dap.random1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_dap_random2,
      { "random2", "dap.random2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_dap_password,
      { "password", "dap.password",
        FT_UINT32, BASE_DEC, VALS(dap_T_password_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unprotected,
      { "unprotected", "dap.unprotected",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_dap_protected,
      { "protected", "dap.protected",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_protectedPassword,
      { "protectedPassword", "dap.protectedPassword",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_dap_algorithmIdentifier,
      { "algorithmIdentifier", "dap.algorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_encrypted,
      { "encrypted", "dap.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_dap_bind_token,
      { "bind-token", "dap.bind_token",
        FT_NONE, BASE_NONE, NULL, 0,
        "Token", HFILL }},
    { &hf_dap_req,
      { "req", "dap.req",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_rep,
      { "rep", "dap.rep",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_mechanism,
      { "mechanism", "dap.mechanism",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_dap_saslCredentials,
      { "credentials", "dap.credentials",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_dap_saslAbort,
      { "saslAbort", "dap.saslAbort",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_algorithm,
      { "algorithm", "dap.algorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_dap_utctime,
      { "time", "dap.time",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_dap_bindIntAlgorithm,
      { "bindIntAlgorithm", "dap.bindIntAlgorithm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier", HFILL }},
    { &hf_dap_bindIntAlgorithm_item,
      { "AlgorithmIdentifier", "dap.AlgorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_bindIntKeyInfo,
      { "bindIntKeyInfo", "dap.bindIntKeyInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BindKeyInfo", HFILL }},
    { &hf_dap_bindConfAlgorithm,
      { "bindConfAlgorithm", "dap.bindConfAlgorithm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier", HFILL }},
    { &hf_dap_bindConfAlgorithm_item,
      { "AlgorithmIdentifier", "dap.AlgorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_bindConfKeyInfo,
      { "bindConfKeyInfo", "dap.bindConfKeyInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BindKeyInfo", HFILL }},
    { &hf_dap_token_data,
      { "token-data", "dap.token_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "TokenData", HFILL }},
    { &hf_dap_algorithm_identifier,
      { "algorithm-identifier", "dap.algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_dap_unsignedDirectoryBindError,
      { "unsignedDirectoryBindError", "dap.unsignedDirectoryBindError",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectoryBindErrorData", HFILL }},
    { &hf_dap_signedDirectoryBindError,
      { "signedDirectoryBindError", "dap.signedDirectoryBindError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_directoryBindError,
      { "directoryBindError", "dap.directoryBindError",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectoryBindErrorData", HFILL }},
    { &hf_dap_error,
      { "error", "dap.error",
        FT_UINT32, BASE_DEC, VALS(dap_T_error_vals), 0,
        NULL, HFILL }},
    { &hf_dap_serviceProblem,
      { "serviceError", "dap.serviceError",
        FT_INT32, BASE_DEC, VALS(dap_ServiceProblem_vals), 0,
        "ServiceProblem", HFILL }},
    { &hf_dap_securityProblem,
      { "securityError", "dap.securityError",
        FT_INT32, BASE_DEC, VALS(dap_SecurityProblem_vals), 0,
        "SecurityProblem", HFILL }},
    { &hf_dap_securityParameters,
      { "securityParameters", "dap.securityParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_object,
      { "object", "dap.object",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dap_selection,
      { "selection", "dap.selection",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryInformationSelection", HFILL }},
    { &hf_dap_modifyRightsRequest,
      { "modifyRightsRequest", "dap.modifyRightsRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_serviceControls,
      { "serviceControls", "dap.serviceControls",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_requestor,
      { "requestor", "dap.requestor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dap_operationProgress,
      { "operationProgress", "dap.operationProgress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_aliasedRDNs,
      { "aliasedRDNs", "dap.aliasedRDNs",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_criticalExtensions,
      { "criticalExtensions", "dap.criticalExtensions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_dap_referenceType,
      { "referenceType", "dap.referenceType",
        FT_UINT32, BASE_DEC, VALS(dsp_ReferenceType_vals), 0,
        NULL, HFILL }},
    { &hf_dap_entryOnly,
      { "entryOnly", "dap.entryOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_exclusions,
      { "exclusions", "dap.exclusions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_nameResolveOnMaster,
      { "nameResolveOnMaster", "dap.nameResolveOnMaster",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_operationContexts,
      { "operationContexts", "dap.operationContexts",
        FT_UINT32, BASE_DEC, VALS(dap_ContextSelection_vals), 0,
        "ContextSelection", HFILL }},
    { &hf_dap_familyGrouping,
      { "familyGrouping", "dap.familyGrouping",
        FT_UINT32, BASE_DEC, VALS(dap_FamilyGrouping_vals), 0,
        NULL, HFILL }},
    { &hf_dap_rdnSequence,
      { "rdnSequence", "dap.rdnSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_unsignedReadArgument,
      { "unsignedReadArgument", "dap.unsignedReadArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadArgumentData", HFILL }},
    { &hf_dap_signedReadArgument,
      { "signedReadArgument", "dap.signedReadArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_readArgument,
      { "readArgument", "dap.readArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadArgumentData", HFILL }},
    { &hf_dap_entry,
      { "entry", "dap.entry",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryInformation", HFILL }},
    { &hf_dap_modifyRights,
      { "modifyRights", "dap.modifyRights",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_performer,
      { "performer", "dap.performer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dap_aliasDereferenced,
      { "aliasDereferenced", "dap.aliasDereferenced",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_notification,
      { "notification", "dap.notification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_Attribute", HFILL }},
    { &hf_dap_notification_item,
      { "Attribute", "dap.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_unsignedReadResult,
      { "unsignedReadResult", "dap.unsignedReadResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadResultData", HFILL }},
    { &hf_dap_signedReadResult,
      { "signedReadResult", "dap.signedReadResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_readResult,
      { "readResult", "dap.readResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadResultData", HFILL }},
    { &hf_dap_ModifyRights_item,
      { "ModifyRights item", "dap.ModifyRights_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_item,
      { "item", "dap.item",
        FT_UINT32, BASE_DEC, VALS(dap_T_item_vals), 0,
        NULL, HFILL }},
    { &hf_dap_item_entry,
      { "entry", "dap.entry",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_attribute_type,
      { "attribute", "dap.attribute",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_value_assertion,
      { "value", "dap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_permission,
      { "permission", "dap.permission",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_purported,
      { "purported", "dap.purported",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_unsignedCompareArgument,
      { "unsignedCompareArgument", "dap.unsignedCompareArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareArgumentData", HFILL }},
    { &hf_dap_signedCompareArgument,
      { "signedCompareArgument", "dap.signedCompareArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_compareArgument,
      { "compareArgument", "dap.compareArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareArgumentData", HFILL }},
    { &hf_dap_matched,
      { "matched", "dap.matched",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_matchedSubtype,
      { "matchedSubtype", "dap.matchedSubtype",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_unsignedCompareResult,
      { "unsignedCompareResult", "dap.unsignedCompareResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareResultData", HFILL }},
    { &hf_dap_signedCompareResult,
      { "signedCompareResult", "dap.signedCompareResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_compareResult,
      { "compareResult", "dap.compareResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareResultData", HFILL }},
    { &hf_dap_invokeID,
      { "invokeID", "dap.invokeID",
        FT_UINT32, BASE_DEC, VALS(ros_InvokeId_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unsignedAbandonArgument,
      { "unsignedAbandonArgument", "dap.unsignedAbandonArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonArgumentData", HFILL }},
    { &hf_dap_signedAbandonArgument,
      { "signedAbandonArgument", "dap.signedAbandonArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandonArgument,
      { "abandonArgument", "dap.abandonArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonArgumentData", HFILL }},
    { &hf_dap_null,
      { "null", "dap.null",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandon_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_AbandonInformation_vals), 0,
        "AbandonInformation", HFILL }},
    { &hf_dap_unsignedAbandonResult,
      { "unsignedAbandonResult", "dap.unsignedAbandonResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonResultData", HFILL }},
    { &hf_dap_signedAbandonResult,
      { "signedAbandonResult", "dap.signedAbandonResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandonResult,
      { "abandonResult", "dap.abandonResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonResultData", HFILL }},
    { &hf_dap_pagedResults,
      { "pagedResults", "dap.pagedResults",
        FT_UINT32, BASE_DEC, VALS(dap_PagedResultsRequest_vals), 0,
        "PagedResultsRequest", HFILL }},
    { &hf_dap_listFamily,
      { "listFamily", "dap.listFamily",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_unsignedListArgument,
      { "unsignedListArgument", "dap.unsignedListArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListArgumentData", HFILL }},
    { &hf_dap_signedListArgument,
      { "signedListArgument", "dap.signedListArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_listArgument,
      { "listArgument", "dap.listArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListArgumentData", HFILL }},
    { &hf_dap_listInfo,
      { "listInfo", "dap.listInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_subordinates,
      { "subordinates", "dap.subordinates",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_subordinates_item,
      { "subordinates item", "dap.subordinates_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_aliasEntry,
      { "aliasEntry", "dap.aliasEntry",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_partialOutcomeQualifier,
      { "partialOutcomeQualifier", "dap.partialOutcomeQualifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_uncorrelatedListInfo,
      { "uncorrelatedListInfo", "dap.uncorrelatedListInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ListResult", HFILL }},
    { &hf_dap_uncorrelatedListInfo_item,
      { "ListResult", "dap.ListResult",
        FT_UINT32, BASE_DEC, VALS(dap_ListResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unsignedListResult,
      { "unsignedListResult", "dap.unsignedListResult",
        FT_UINT32, BASE_DEC, VALS(dap_ListResultData_vals), 0,
        "ListResultData", HFILL }},
    { &hf_dap_signedListResult,
      { "signedListResult", "dap.signedListResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_listResult,
      { "listResult", "dap.listResult",
        FT_UINT32, BASE_DEC, VALS(dap_ListResultData_vals), 0,
        "ListResultData", HFILL }},
    { &hf_dap_limitProblem,
      { "limitProblem", "dap.limitProblem",
        FT_INT32, BASE_DEC, VALS(dap_LimitProblem_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unexplored,
      { "unexplored", "dap.unexplored",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_ContinuationReference", HFILL }},
    { &hf_dap_unexplored_item,
      { "ContinuationReference", "dap.ContinuationReference",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_unavailableCriticalExtensions,
      { "unavailableCriticalExtensions", "dap.unavailableCriticalExtensions",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_unknownErrors,
      { "unknownErrors", "dap.unknownErrors",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_unknownErrors_item,
      { "unknownErrors item", "dap.unknownErrors_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_dap_queryReference,
      { "queryReference", "dap.queryReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_dap_overspecFilter,
      { "overspecFilter", "dap.overspecFilter",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "Filter", HFILL }},
    { &hf_dap_entryCount,
      { "entryCount", "dap.entryCount",
        FT_UINT32, BASE_DEC, VALS(dap_T_entryCount_vals), 0,
        NULL, HFILL }},
    { &hf_dap_bestEstimate,
      { "bestEstimate", "dap.bestEstimate",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_lowEstimate,
      { "lowEstimate", "dap.lowEstimate",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_exact,
      { "exact", "dap.exact",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_streamedResult,
      { "streamedResult", "dap.streamedResult",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_baseObject,
      { "baseObject", "dap.baseObject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dap_subset,
      { "subset", "dap.subset",
        FT_INT32, BASE_DEC, VALS(dap_T_subset_vals), 0,
        NULL, HFILL }},
    { &hf_dap_filter,
      { "filter", "dap.filter",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        NULL, HFILL }},
    { &hf_dap_searchAliases,
      { "searchAliases", "dap.searchAliases",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_matchedValuesOnly,
      { "matchedValuesOnly", "dap.matchedValuesOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_extendedFilter,
      { "extendedFilter", "dap.extendedFilter",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "Filter", HFILL }},
    { &hf_dap_checkOverspecified,
      { "checkOverspecified", "dap.checkOverspecified",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_relaxation,
      { "relaxation", "dap.relaxation",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelaxationPolicy", HFILL }},
    { &hf_dap_extendedArea,
      { "extendedArea", "dap.extendedArea",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dap_hierarchySelections,
      { "hierarchySelections", "dap.hierarchySelections",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_searchControlOptions,
      { "searchControlOptions", "dap.searchControlOptions",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_joinArguments,
      { "joinArguments", "dap.joinArguments",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_JoinArgument", HFILL }},
    { &hf_dap_joinArguments_item,
      { "JoinArgument", "dap.JoinArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_joinType,
      { "joinType", "dap.joinType",
        FT_UINT32, BASE_DEC, VALS(dap_T_joinType_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unsignedSearchArgument,
      { "unsignedSearchArgument", "dap.unsignedSearchArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchArgumentData", HFILL }},
    { &hf_dap_signedSearchArgument,
      { "signedSearchArgument", "dap.signedSearchArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_searchArgument,
      { "searchArgument", "dap.searchArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchArgumentData", HFILL }},
    { &hf_dap_joinBaseObject,
      { "joinBaseObject", "dap.joinBaseObject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dap_domainLocalID,
      { "domainLocalID", "dap.domainLocalID",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        NULL, HFILL }},
    { &hf_dap_joinSubset,
      { "joinSubset", "dap.joinSubset",
        FT_UINT32, BASE_DEC, VALS(dap_T_joinSubset_vals), 0,
        NULL, HFILL }},
    { &hf_dap_joinFilter,
      { "joinFilter", "dap.joinFilter",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "Filter", HFILL }},
    { &hf_dap_joinAttributes,
      { "joinAttributes", "dap.joinAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_JoinAttPair", HFILL }},
    { &hf_dap_joinAttributes_item,
      { "JoinAttPair", "dap.JoinAttPair",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_joinSelection,
      { "joinSelection", "dap.joinSelection",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryInformationSelection", HFILL }},
    { &hf_dap_baseAtt,
      { "baseAtt", "dap.baseAtt",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_joinAtt,
      { "joinAtt", "dap.joinAtt",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_joinContext,
      { "joinContext", "dap.joinContext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_JoinContextType", HFILL }},
    { &hf_dap_joinContext_item,
      { "JoinContextType", "dap.JoinContextType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_searchInfo,
      { "searchInfo", "dap.searchInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_entries,
      { "entries", "dap.entries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_EntryInformation", HFILL }},
    { &hf_dap_entries_item,
      { "EntryInformation", "dap.EntryInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_altMatching,
      { "altMatching", "dap.altMatching",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_uncorrelatedSearchInfo,
      { "uncorrelatedSearchInfo", "dap.uncorrelatedSearchInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SearchResult", HFILL }},
    { &hf_dap_uncorrelatedSearchInfo_item,
      { "SearchResult", "dap.SearchResult",
        FT_UINT32, BASE_DEC, VALS(dap_SearchResult_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unsignedSearchResult,
      { "unsignedSearchResult", "dap.unsignedSearchResult",
        FT_UINT32, BASE_DEC, VALS(dap_SearchResultData_vals), 0,
        "SearchResultData", HFILL }},
    { &hf_dap_signedSearchResult,
      { "signedSearchResult", "dap.signedSearchResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_searchResult,
      { "searchResult", "dap.searchResult",
        FT_UINT32, BASE_DEC, VALS(dap_SearchResultData_vals), 0,
        "SearchResultData", HFILL }},
    { &hf_dap_add_entry,
      { "entry", "dap.entry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_dap_add_entry_item,
      { "Attribute", "dap.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_targetSystem,
      { "targetSystem", "dap.targetSystem",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessPoint", HFILL }},
    { &hf_dap_unsignedAddEntryArgument,
      { "unsignedAddEntryArgument", "dap.unsignedAddEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryArgumentData", HFILL }},
    { &hf_dap_signedAddEntryArgument,
      { "signedAddEntryArgument", "dap.signedAddEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_addEntryArgument,
      { "addEntryArgument", "dap.addEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryArgumentData", HFILL }},
    { &hf_dap_add_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_AddEntryInformation_vals), 0,
        "AddEntryInformation", HFILL }},
    { &hf_dap_unsignedAddEntryResult,
      { "unsignedAddEntryResult", "dap.unsignedAddEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryResultData", HFILL }},
    { &hf_dap_signedAddEntryResult,
      { "signedAddEntryResult", "dap.signedAddEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_addEntryResult,
      { "addEntryResult", "dap.addEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryResultData", HFILL }},
    { &hf_dap_unsignedRemoveEntryArgument,
      { "unsignedRemoveEntryArgument", "dap.unsignedRemoveEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryArgumentData", HFILL }},
    { &hf_dap_signedRemoveEntryArgument,
      { "signedRemoveEntryArgument", "dap.signedRemoveEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_removeEntryArgument,
      { "removeEntryArgument", "dap.removeEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryArgumentData", HFILL }},
    { &hf_dap_remove_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_RemoveEntryInformation_vals), 0,
        "RemoveEntryInformation", HFILL }},
    { &hf_dap_unsignedRemoveEntryResult,
      { "unsignedRemoveEntryResult", "dap.unsignedRemoveEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryResultData", HFILL }},
    { &hf_dap_signedRemoveEntryResult,
      { "signedRemoveEntryResult", "dap.signedRemoveEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_removeEntryResult,
      { "removeEntryResult", "dap.removeEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryResultData", HFILL }},
    { &hf_dap_changes,
      { "changes", "dap.changes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EntryModification", HFILL }},
    { &hf_dap_changes_item,
      { "EntryModification", "dap.EntryModification",
        FT_UINT32, BASE_DEC, VALS(dap_EntryModification_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unsignedModifyEntryArgument,
      { "unsignedModifyEntryArgument", "dap.unsignedModifyEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryArgumentData", HFILL }},
    { &hf_dap_signedModifyEntryArgument,
      { "signedModifyEntryArgument", "dap.signedModifyEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_modifyEntryArgument,
      { "modifyEntryArgument", "dap.modifyEntryArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryArgumentData", HFILL }},
    { &hf_dap_modify_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyEntryInformation_vals), 0,
        "ModifyEntryInformation", HFILL }},
    { &hf_dap_unsignedModifyEntryResult,
      { "unsignedModifyEntryResult", "dap.unsignedModifyEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryResultData", HFILL }},
    { &hf_dap_signedModifyEntryResult,
      { "signedModifyEntryResult", "dap.signedModifyEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_modifyEntryResult,
      { "modifyEntryResult", "dap.modifyEntryResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryResultData", HFILL }},
    { &hf_dap_addAttribute,
      { "addAttribute", "dap.addAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_dap_removeAttribute,
      { "removeAttribute", "dap.removeAttribute",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_addValues,
      { "addValues", "dap.addValues",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_dap_removeValues,
      { "removeValues", "dap.removeValues",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_dap_alterValues,
      { "alterValues", "dap.alterValues",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeTypeAndValue", HFILL }},
    { &hf_dap_resetValue,
      { "resetValue", "dap.resetValue",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_newRDN,
      { "newRDN", "dap.newRDN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelativeDistinguishedName", HFILL }},
    { &hf_dap_deleteOldRDN,
      { "deleteOldRDN", "dap.deleteOldRDN",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_newSuperior,
      { "newSuperior", "dap.newSuperior",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dap_modify_dn_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyDNInformation_vals), 0,
        "ModifyDNInformation", HFILL }},
    { &hf_dap_unsignedModifyDNResult,
      { "unsignedModifyDNResult", "dap.unsignedModifyDNResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNResultData", HFILL }},
    { &hf_dap_signedModifyDNResult,
      { "signedModifyDNResult", "dap.signedModifyDNResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_modifyDNResult,
      { "modifyDNResult", "dap.modifyDNResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNResultData", HFILL }},
    { &hf_dap_unsignedAbandoned,
      { "unsignedAbandoned", "dap.unsignedAbandoned",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonedData", HFILL }},
    { &hf_dap_signedAbandoned,
      { "signedAbandoned", "dap.signedAbandoned",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandoned,
      { "abandoned", "dap.abandoned",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonedData", HFILL }},
    { &hf_dap_abandon_failed_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_AbandonProblem_vals), 0,
        "AbandonProblem", HFILL }},
    { &hf_dap_operation,
      { "operation", "dap.operation",
        FT_UINT32, BASE_DEC, VALS(ros_InvokeId_vals), 0,
        "InvokeId", HFILL }},
    { &hf_dap_unsignedAbandonFailedError,
      { "unsignedAbandonFailedError", "dap.unsignedAbandonFailedError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonFailedErrorData", HFILL }},
    { &hf_dap_signedAbandonFailedError,
      { "signedAbandonFailedError", "dap.signedAbandonFailedError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandonFailedError,
      { "abandonFailedError", "dap.abandonFailedError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonFailedErrorData", HFILL }},
    { &hf_dap_problems,
      { "problems", "dap.problems",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_problems_item,
      { "problems item", "dap.problems_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_attribute_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_AttributeProblem_vals), 0,
        "AttributeProblem", HFILL }},
    { &hf_dap_value,
      { "value", "dap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValue", HFILL }},
    { &hf_dap_unsignedAttributeError,
      { "unsignedAttributeError", "dap.unsignedAttributeError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeErrorData", HFILL }},
    { &hf_dap_signedAttributeError,
      { "signedAttributeError", "dap.signedAttributeError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_attributeError,
      { "attributeError", "dap.attributeError",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeErrorData", HFILL }},
    { &hf_dap_name_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_NameProblem_vals), 0,
        "NameProblem", HFILL }},
    { &hf_dap_matched_name,
      { "matched", "dap.matched",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dap_unsignedNameError,
      { "unsignedNameError", "dap.unsignedNameError",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameErrorData", HFILL }},
    { &hf_dap_signedNameError,
      { "signedNameError", "dap.signedNameError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_nameError,
      { "nameError", "dap.nameError",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameErrorData", HFILL }},
    { &hf_dap_candidate,
      { "candidate", "dap.candidate",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContinuationReference", HFILL }},
    { &hf_dap_unsignedReferral,
      { "unsignedReferral", "dap.unsignedReferral",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferralData", HFILL }},
    { &hf_dap_signedReferral,
      { "signedReferral", "dap.signedReferral",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_referral,
      { "referral", "dap.referral",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferralData", HFILL }},
    { &hf_dap_security_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_SecurityProblem_vals), 0,
        "SecurityProblem", HFILL }},
    { &hf_dap_spkmInfo,
      { "spkmInfo", "dap.spkmInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_unsignedSecurityError,
      { "unsignedSecurityError", "dap.unsignedSecurityError",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrorData", HFILL }},
    { &hf_dap_signedSecurityError,
      { "signedSecurityError", "dap.signedSecurityError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_securityErrorData,
      { "securityError", "dap.securityError",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrorData", HFILL }},
    { &hf_dap_service_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_ServiceProblem_vals), 0,
        "ServiceProblem", HFILL }},
    { &hf_dap_unsignedServiceError,
      { "unsignedServiceError", "dap.unsignedServiceError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceErrorData", HFILL }},
    { &hf_dap_signedServiceError,
      { "signedServiceError", "dap.signedServiceError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_serviceError,
      { "serviceError", "dap.serviceError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceErrorData", HFILL }},
    { &hf_dap_update_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_UpdateProblem_vals), 0,
        "UpdateProblem", HFILL }},
    { &hf_dap_attributeInfo,
      { "attributeInfo", "dap.attributeInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_attributeInfo_item,
      { "attributeInfo item", "dap.attributeInfo_item",
        FT_UINT32, BASE_DEC, VALS(dap_T_attributeInfo_item_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unsignedUpdateError,
      { "unsignedUpdateError", "dap.unsignedUpdateError",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateErrorData", HFILL }},
    { &hf_dap_signedUpdateError,
      { "signedUpdateError", "dap.signedUpdateError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_updateError,
      { "updateError", "dap.updateError",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateErrorData", HFILL }},
    { &hf_dap_ServiceControlOptions_preferChaining,
      { "preferChaining", "dap.preferChaining",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_chainingProhibited,
      { "chainingProhibited", "dap.chainingProhibited",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_localScope,
      { "localScope", "dap.localScope",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_dontUseCopy,
      { "dontUseCopy", "dap.dontUseCopy",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_dontDereferenceAliases,
      { "dontDereferenceAliases", "dap.dontDereferenceAliases",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_subentries,
      { "subentries", "dap.subentries",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_copyShallDo,
      { "copyShallDo", "dap.copyShallDo",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_partialNameResolution,
      { "partialNameResolution", "dap.partialNameResolution",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_manageDSAIT,
      { "manageDSAIT", "dap.manageDSAIT",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_noSubtypeMatch,
      { "noSubtypeMatch", "dap.noSubtypeMatch",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_noSubtypeSelection,
      { "noSubtypeSelection", "dap.noSubtypeSelection",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_countFamily,
      { "countFamily", "dap.countFamily",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_dontSelectFriends,
      { "dontSelectFriends", "dap.dontSelectFriends",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_dontMatchFriends,
      { "dontMatchFriends", "dap.dontMatchFriends",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dap_Versions_v1,
      { "v1", "dap.v1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_Versions_v2,
      { "v2", "dap.v2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_T_permission_add,
      { "add", "dap.add",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_T_permission_remove,
      { "remove", "dap.remove",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_T_permission_rename,
      { "rename", "dap.rename",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_T_permission_move,
      { "move", "dap.move",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_self,
      { "self", "dap.self",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_children,
      { "children", "dap.children",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_parent,
      { "parent", "dap.parent",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_hierarchy,
      { "hierarchy", "dap.hierarchy",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_top,
      { "top", "dap.top",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_subtree,
      { "subtree", "dap.subtree",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_siblings,
      { "siblings", "dap.siblings",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_siblingChildren,
      { "siblingChildren", "dap.siblingChildren",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_siblingSubtree,
      { "siblingSubtree", "dap.siblingSubtree",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_all,
      { "all", "dap.all",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_searchAliases,
      { "searchAliases", "dap.searchAliases",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_matchedValuesOnly,
      { "matchedValuesOnly", "dap.matchedValuesOnly",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_checkOverspecified,
      { "checkOverspecified", "dap.checkOverspecified",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_performExactly,
      { "performExactly", "dap.performExactly",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_includeAllAreas,
      { "includeAllAreas", "dap.includeAllAreas",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_noSystemRelaxation,
      { "noSystemRelaxation", "dap.noSystemRelaxation",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_dnAttribute,
      { "dnAttribute", "dap.dnAttribute",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_matchOnResidualName,
      { "matchOnResidualName", "dap.matchOnResidualName",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_entryCount,
      { "entryCount", "dap.entryCount",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_useSubset,
      { "useSubset", "dap.useSubset",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_separateFamilyMembers,
      { "separateFamilyMembers", "dap.separateFamilyMembers",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_searchFamily,
      { "searchFamily", "dap.searchFamily",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

/*--- End of included file: packet-dap-hfarr.c ---*/
#line 99 "../../asn1/dap/packet-dap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_dap,

/*--- Included file: packet-dap-ettarr.c ---*/
#line 1 "../../asn1/dap/packet-dap-ettarr.c"
    &ett_dap_ServiceControls,
    &ett_dap_T_manageDSAITPlaneRef,
    &ett_dap_ServiceControlOptions,
    &ett_dap_EntryInformationSelection,
    &ett_dap_T_attributes,
    &ett_dap_SET_OF_AttributeType,
    &ett_dap_T_extraAttributes,
    &ett_dap_SET_SIZE_1_MAX_OF_AttributeType,
    &ett_dap_ContextSelection,
    &ett_dap_SET_SIZE_1_MAX_OF_TypeAndContextAssertion,
    &ett_dap_TypeAndContextAssertion,
    &ett_dap_T_contextAssertions,
    &ett_dap_SEQUENCE_OF_ContextAssertion,
    &ett_dap_SET_OF_ContextAssertion,
    &ett_dap_FamilyReturn,
    &ett_dap_T_familySelect,
    &ett_dap_EntryInformation,
    &ett_dap_T_entry_information,
    &ett_dap_EntryInformationItem,
    &ett_dap_FamilyEntries,
    &ett_dap_SEQUENCE_OF_FamilyEntry,
    &ett_dap_FamilyEntry,
    &ett_dap_FamilyInformation,
    &ett_dap_T_family_information_item,
    &ett_dap_SEQUENCE_SIZE_1_MAX_OF_FamilyEntries,
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
    &ett_dap_SEQUENCE_SIZE_1_MAX_OF_SortKey,
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
    &ett_dap_SaslCredentials,
    &ett_dap_TokenData,
    &ett_dap_SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier,
    &ett_dap_Token,
    &ett_dap_Versions,
    &ett_dap_DirectoryBindError,
    &ett_dap_T_signedDirectoryBindError,
    &ett_dap_DirectoryBindErrorData,
    &ett_dap_T_error,
    &ett_dap_ReadArgumentData,
    &ett_dap_Name,
    &ett_dap_ReadArgument,
    &ett_dap_T_signedReadArgument,
    &ett_dap_ReadResultData,
    &ett_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute,
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
    &ett_dap_SET_SIZE_1_MAX_OF_ContinuationReference,
    &ett_dap_T_unknownErrors,
    &ett_dap_T_entryCount,
    &ett_dap_SearchArgumentData,
    &ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument,
    &ett_dap_SearchArgument,
    &ett_dap_T_signedSearchArgument,
    &ett_dap_HierarchySelections,
    &ett_dap_SearchControlOptions,
    &ett_dap_JoinArgument,
    &ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinAttPair,
    &ett_dap_JoinAttPair,
    &ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinContextType,
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
#line 105 "../../asn1/dap/packet-dap-template.c"
  };
  module_t *dap_module;

  /* Register protocol */
  proto_dap = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DAP, particularly our port */

  dap_module = prefs_register_protocol_subtree("OSI/X.500", proto_dap, prefs_register_dap);

  prefs_register_uint_preference(dap_module, "tcp.port", "DAP TCP Port",
				 "Set the port for DAP operations (if other"
				 " than the default of 102)",
				 10, &global_dap_tcp_port);

}


/*--- proto_reg_handoff_dap --- */
void proto_reg_handoff_dap(void) {

  /* #include "packet-dap-dis-tab.c" */

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-directory-access","2.5.3.1");

  /* ABSTRACT SYNTAXES */

  /* Register DAP with ROS (with no use of RTSE) */
  register_ros_protocol_info("2.5.9.1", &dap_ros_info, 0, "id-as-directory-access", FALSE);

  register_idmp_protocol_info("2.5.33.0", &dap_ros_info, 0, "dap-ip");

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


static void
prefs_register_dap(void)
{
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete_uint("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_dap_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add_uint("tcp.port", global_dap_tcp_port, tpkt_handle);

}
