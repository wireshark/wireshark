/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-dap.c                                                               */
/* asn2wrs.py -b -q -L -p dap -c ./dap.cnf -s ./packet-dap-template -D . -O ../.. dap.asn DirectoryAccessProtocol.asn */

/* packet-dap.c
 * Routines for X.511 (X.500 Directory Asbtract Service) and X.519 DAP  packet dissection
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
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>

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

void proto_register_dap(void);
void proto_reg_handoff_dap(void);

/* Initialize the protocol and registered fields */
static int proto_dap;


static int hf_dap_DirectoryBindArgument_PDU;      /* DirectoryBindArgument */
static int hf_dap_DirectoryBindResult_PDU;        /* DirectoryBindResult */
static int hf_dap_DirectoryBindError_PDU;         /* DirectoryBindError */
static int hf_dap_ReadArgument_PDU;               /* ReadArgument */
static int hf_dap_ReadResult_PDU;                 /* ReadResult */
static int hf_dap_CompareArgument_PDU;            /* CompareArgument */
static int hf_dap_CompareResult_PDU;              /* CompareResult */
static int hf_dap_AbandonArgument_PDU;            /* AbandonArgument */
static int hf_dap_AbandonResult_PDU;              /* AbandonResult */
static int hf_dap_ListArgument_PDU;               /* ListArgument */
static int hf_dap_ListResult_PDU;                 /* ListResult */
static int hf_dap_SearchArgument_PDU;             /* SearchArgument */
static int hf_dap_SearchResult_PDU;               /* SearchResult */
static int hf_dap_AddEntryArgument_PDU;           /* AddEntryArgument */
static int hf_dap_AddEntryResult_PDU;             /* AddEntryResult */
static int hf_dap_RemoveEntryArgument_PDU;        /* RemoveEntryArgument */
static int hf_dap_RemoveEntryResult_PDU;          /* RemoveEntryResult */
static int hf_dap_ModifyEntryArgument_PDU;        /* ModifyEntryArgument */
static int hf_dap_ModifyEntryResult_PDU;          /* ModifyEntryResult */
static int hf_dap_ModifyDNArgument_PDU;           /* ModifyDNArgument */
static int hf_dap_ModifyDNResult_PDU;             /* ModifyDNResult */
static int hf_dap_Abandoned_PDU;                  /* Abandoned */
static int hf_dap_AbandonFailedError_PDU;         /* AbandonFailedError */
static int hf_dap_AttributeError_PDU;             /* AttributeError */
static int hf_dap_NameError_PDU;                  /* NameError */
static int hf_dap_Referral_PDU;                   /* Referral */
static int hf_dap_SecurityError_PDU;              /* SecurityError */
static int hf_dap_ServiceError_PDU;               /* ServiceError */
static int hf_dap_UpdateError_PDU;                /* UpdateError */
static int hf_dap_options;                        /* ServiceControlOptions */
static int hf_dap_priority;                       /* T_priority */
static int hf_dap_timeLimit;                      /* INTEGER */
static int hf_dap_sizeLimit;                      /* INTEGER */
static int hf_dap_scopeOfReferral;                /* T_scopeOfReferral */
static int hf_dap_attributeSizeLimit;             /* INTEGER */
static int hf_dap_manageDSAITPlaneRef;            /* T_manageDSAITPlaneRef */
static int hf_dap_dsaName;                        /* Name */
static int hf_dap_agreementID;                    /* AgreementID */
static int hf_dap_serviceType;                    /* OBJECT_IDENTIFIER */
static int hf_dap_userClass;                      /* INTEGER */
static int hf_dap_attributes;                     /* T_attributes */
static int hf_dap_allUserAttributes;              /* NULL */
static int hf_dap_select;                         /* SET_OF_AttributeType */
static int hf_dap_select_item;                    /* AttributeType */
static int hf_dap_infoTypes;                      /* T_infoTypes */
static int hf_dap_extraAttributes;                /* T_extraAttributes */
static int hf_dap_allOperationalAttributes;       /* NULL */
static int hf_dap_extraSelect;                    /* SET_SIZE_1_MAX_OF_AttributeType */
static int hf_dap_extraSelect_item;               /* AttributeType */
static int hf_dap_contextSelection;               /* ContextSelection */
static int hf_dap_returnContexts;                 /* BOOLEAN */
static int hf_dap_familyReturn;                   /* FamilyReturn */
static int hf_dap_allContexts;                    /* NULL */
static int hf_dap_selectedContexts;               /* SET_SIZE_1_MAX_OF_TypeAndContextAssertion */
static int hf_dap_selectedContexts_item;          /* TypeAndContextAssertion */
static int hf_dap_type;                           /* AttributeType */
static int hf_dap_contextAssertions;              /* T_contextAssertions */
static int hf_dap_preference;                     /* SEQUENCE_OF_ContextAssertion */
static int hf_dap_preference_item;                /* ContextAssertion */
static int hf_dap_all;                            /* SET_OF_ContextAssertion */
static int hf_dap_all_item;                       /* ContextAssertion */
static int hf_dap_memberSelect;                   /* T_memberSelect */
static int hf_dap_familySelect;                   /* T_familySelect */
static int hf_dap_familySelect_item;              /* OBJECT_IDENTIFIER */
static int hf_dap_name;                           /* Name */
static int hf_dap_fromEntry;                      /* BOOLEAN */
static int hf_dap_entry_information;              /* T_entry_information */
static int hf_dap_entry_information_item;         /* EntryInformationItem */
static int hf_dap_attributeType;                  /* AttributeType */
static int hf_dap_attribute;                      /* Attribute */
static int hf_dap_incompleteEntry;                /* BOOLEAN */
static int hf_dap_partialName;                    /* BOOLEAN */
static int hf_dap_derivedEntry;                   /* BOOLEAN */
static int hf_dap_family_class;                   /* OBJECT_IDENTIFIER */
static int hf_dap_familyEntries;                  /* SEQUENCE_OF_FamilyEntry */
static int hf_dap_familyEntries_item;             /* FamilyEntry */
static int hf_dap_rdn;                            /* RelativeDistinguishedName */
static int hf_dap_family_information;             /* FamilyInformation */
static int hf_dap_family_information_item;        /* T_family_information_item */
static int hf_dap_family_info;                    /* SEQUENCE_SIZE_1_MAX_OF_FamilyEntries */
static int hf_dap_family_info_item;               /* FamilyEntries */
static int hf_dap_filter_item;                    /* FilterItem */
static int hf_dap_and;                            /* SetOfFilter */
static int hf_dap_or;                             /* SetOfFilter */
static int hf_dap_not;                            /* Filter */
static int hf_dap_SetOfFilter_item;               /* Filter */
static int hf_dap_equality;                       /* AttributeValueAssertion */
static int hf_dap_substrings;                     /* T_substrings */
static int hf_dap_sunstringType;                  /* OBJECT_IDENTIFIER */
static int hf_dap_strings;                        /* T_strings */
static int hf_dap_strings_item;                   /* T_strings_item */
static int hf_dap_initial;                        /* T_initial */
static int hf_dap_any;                            /* T_any */
static int hf_dap_final;                          /* T_final */
static int hf_dap_control;                        /* Attribute */
static int hf_dap_greaterOrEqual;                 /* AttributeValueAssertion */
static int hf_dap_lessOrEqual;                    /* AttributeValueAssertion */
static int hf_dap_present;                        /* AttributeType */
static int hf_dap_approximateMatch;               /* AttributeValueAssertion */
static int hf_dap_extensibleMatch;                /* MatchingRuleAssertion */
static int hf_dap_contextPresent;                 /* AttributeTypeAssertion */
static int hf_dap_matchingRule;                   /* T_matchingRule */
static int hf_dap_matchingRule_item;              /* OBJECT_IDENTIFIER */
static int hf_dap_matchValue;                     /* T_matchValue */
static int hf_dap_dnAttributes;                   /* BOOLEAN */
static int hf_dap_newRequest;                     /* T_newRequest */
static int hf_dap_pageSize;                       /* INTEGER */
static int hf_dap_sortKeys;                       /* SEQUENCE_SIZE_1_MAX_OF_SortKey */
static int hf_dap_sortKeys_item;                  /* SortKey */
static int hf_dap_reverse;                        /* BOOLEAN */
static int hf_dap_unmerged;                       /* BOOLEAN */
static int hf_dap_pagedResultsQueryReference;     /* T_pagedResultsQueryReference */
static int hf_dap_orderingRule;                   /* OBJECT_IDENTIFIER */
static int hf_dap_certification_path;             /* CertificationPath */
static int hf_dap_distinguished_name;             /* DistinguishedName */
static int hf_dap_time;                           /* Time */
static int hf_dap_random;                         /* BIT_STRING */
static int hf_dap_target;                         /* ProtectionRequest */
static int hf_dap_response;                       /* BIT_STRING */
static int hf_dap_operationCode;                  /* Code */
static int hf_dap_attributeCertificationPath;     /* AttributeCertificationPath */
static int hf_dap_errorProtection;                /* ErrorProtectionRequest */
static int hf_dap_errorCode;                      /* Code */
static int hf_dap_utcTime;                        /* UTCTime */
static int hf_dap_generalizedTime;                /* GeneralizedTime */
static int hf_dap_credentials;                    /* Credentials */
static int hf_dap_versions;                       /* Versions */
static int hf_dap_simple;                         /* SimpleCredentials */
static int hf_dap_strong;                         /* StrongCredentials */
static int hf_dap_externalProcedure;              /* EXTERNAL */
static int hf_dap_spkm;                           /* SpkmCredentials */
static int hf_dap_sasl;                           /* SaslCredentials */
static int hf_dap_validity;                       /* T_validity */
static int hf_dap_time1;                          /* T_time1 */
static int hf_dap_utc;                            /* UTCTime */
static int hf_dap_gt;                             /* GeneralizedTime */
static int hf_dap_time2;                          /* T_time2 */
static int hf_dap_random1;                        /* BIT_STRING */
static int hf_dap_random2;                        /* BIT_STRING */
static int hf_dap_password;                       /* T_password */
static int hf_dap_unprotected;                    /* OCTET_STRING */
static int hf_dap_protected;                      /* T_protected */
static int hf_dap_protectedPassword;              /* OCTET_STRING */
static int hf_dap_algorithmIdentifier;            /* AlgorithmIdentifier */
static int hf_dap_encrypted;                      /* BIT_STRING */
static int hf_dap_bind_token;                     /* Token */
static int hf_dap_req;                            /* T_req */
static int hf_dap_rep;                            /* T_rep */
static int hf_dap_mechanism;                      /* DirectoryString */
static int hf_dap_saslCredentials;                /* OCTET_STRING */
static int hf_dap_saslAbort;                      /* BOOLEAN */
static int hf_dap_algorithm;                      /* AlgorithmIdentifier */
static int hf_dap_utctime;                        /* UTCTime */
static int hf_dap_bindIntAlgorithm;               /* SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier */
static int hf_dap_bindIntAlgorithm_item;          /* AlgorithmIdentifier */
static int hf_dap_bindIntKeyInfo;                 /* BindKeyInfo */
static int hf_dap_bindConfAlgorithm;              /* SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier */
static int hf_dap_bindConfAlgorithm_item;         /* AlgorithmIdentifier */
static int hf_dap_bindConfKeyInfo;                /* BindKeyInfo */
static int hf_dap_token_data;                     /* TokenData */
static int hf_dap_algorithm_identifier;           /* AlgorithmIdentifier */
static int hf_dap_unsignedDirectoryBindError;     /* DirectoryBindErrorData */
static int hf_dap_signedDirectoryBindError;       /* T_signedDirectoryBindError */
static int hf_dap_directoryBindError;             /* DirectoryBindErrorData */
static int hf_dap_error;                          /* T_error */
static int hf_dap_serviceProblem;                 /* ServiceProblem */
static int hf_dap_securityProblem;                /* SecurityProblem */
static int hf_dap_securityParameters;             /* SecurityParameters */
static int hf_dap_object;                         /* Name */
static int hf_dap_selection;                      /* EntryInformationSelection */
static int hf_dap_modifyRightsRequest;            /* BOOLEAN */
static int hf_dap_serviceControls;                /* ServiceControls */
static int hf_dap_requestor;                      /* DistinguishedName */
static int hf_dap_operationProgress;              /* OperationProgress */
static int hf_dap_aliasedRDNs;                    /* INTEGER */
static int hf_dap_criticalExtensions;             /* BIT_STRING */
static int hf_dap_referenceType;                  /* ReferenceType */
static int hf_dap_entryOnly;                      /* BOOLEAN */
static int hf_dap_exclusions;                     /* Exclusions */
static int hf_dap_nameResolveOnMaster;            /* BOOLEAN */
static int hf_dap_operationContexts;              /* ContextSelection */
static int hf_dap_familyGrouping;                 /* FamilyGrouping */
static int hf_dap_rdnSequence;                    /* RDNSequence */
static int hf_dap_unsignedReadArgument;           /* ReadArgumentData */
static int hf_dap_signedReadArgument;             /* T_signedReadArgument */
static int hf_dap_readArgument;                   /* ReadArgumentData */
static int hf_dap_entry;                          /* EntryInformation */
static int hf_dap_modifyRights;                   /* ModifyRights */
static int hf_dap_performer;                      /* DistinguishedName */
static int hf_dap_aliasDereferenced;              /* BOOLEAN */
static int hf_dap_notification;                   /* SEQUENCE_SIZE_1_MAX_OF_Attribute */
static int hf_dap_notification_item;              /* Attribute */
static int hf_dap_unsignedReadResult;             /* ReadResultData */
static int hf_dap_signedReadResult;               /* T_signedReadResult */
static int hf_dap_readResult;                     /* ReadResultData */
static int hf_dap_ModifyRights_item;              /* ModifyRights_item */
static int hf_dap_item;                           /* T_item */
static int hf_dap_item_entry;                     /* NULL */
static int hf_dap_attribute_type;                 /* AttributeType */
static int hf_dap_value_assertion;                /* AttributeValueAssertion */
static int hf_dap_permission;                     /* T_permission */
static int hf_dap_purported;                      /* AttributeValueAssertion */
static int hf_dap_unsignedCompareArgument;        /* CompareArgumentData */
static int hf_dap_signedCompareArgument;          /* T_signedCompareArgument */
static int hf_dap_compareArgument;                /* CompareArgumentData */
static int hf_dap_matched;                        /* BOOLEAN */
static int hf_dap_matchedSubtype;                 /* AttributeType */
static int hf_dap_unsignedCompareResult;          /* CompareResultData */
static int hf_dap_signedCompareResult;            /* T_signedCompareResult */
static int hf_dap_compareResult;                  /* CompareResultData */
static int hf_dap_invokeID;                       /* InvokeId */
static int hf_dap_unsignedAbandonArgument;        /* AbandonArgumentData */
static int hf_dap_signedAbandonArgument;          /* T_signedAbandonArgument */
static int hf_dap_abandonArgument;                /* AbandonArgumentData */
static int hf_dap_null;                           /* NULL */
static int hf_dap_abandon_information;            /* AbandonInformation */
static int hf_dap_unsignedAbandonResult;          /* AbandonResultData */
static int hf_dap_signedAbandonResult;            /* T_signedAbandonResult */
static int hf_dap_abandonResult;                  /* AbandonResultData */
static int hf_dap_pagedResults;                   /* PagedResultsRequest */
static int hf_dap_listFamily;                     /* BOOLEAN */
static int hf_dap_unsignedListArgument;           /* ListArgumentData */
static int hf_dap_signedListArgument;             /* T_signedListArgument */
static int hf_dap_listArgument;                   /* ListArgumentData */
static int hf_dap_listInfo;                       /* T_listInfo */
static int hf_dap_subordinates;                   /* T_subordinates */
static int hf_dap_subordinates_item;              /* T_subordinates_item */
static int hf_dap_aliasEntry;                     /* BOOLEAN */
static int hf_dap_partialOutcomeQualifier;        /* PartialOutcomeQualifier */
static int hf_dap_uncorrelatedListInfo;           /* SET_OF_ListResult */
static int hf_dap_uncorrelatedListInfo_item;      /* ListResult */
static int hf_dap_unsignedListResult;             /* ListResultData */
static int hf_dap_signedListResult;               /* T_signedListResult */
static int hf_dap_listResult;                     /* ListResultData */
static int hf_dap_limitProblem;                   /* LimitProblem */
static int hf_dap_unexplored;                     /* SET_SIZE_1_MAX_OF_ContinuationReference */
static int hf_dap_unexplored_item;                /* ContinuationReference */
static int hf_dap_unavailableCriticalExtensions;  /* BOOLEAN */
static int hf_dap_unknownErrors;                  /* T_unknownErrors */
static int hf_dap_unknownErrors_item;             /* OBJECT_IDENTIFIER */
static int hf_dap_queryReference;                 /* OCTET_STRING */
static int hf_dap_overspecFilter;                 /* Filter */
static int hf_dap_entryCount;                     /* T_entryCount */
static int hf_dap_bestEstimate;                   /* INTEGER */
static int hf_dap_lowEstimate;                    /* INTEGER */
static int hf_dap_exact;                          /* INTEGER */
static int hf_dap_streamedResult;                 /* BOOLEAN */
static int hf_dap_baseObject;                     /* Name */
static int hf_dap_subset;                         /* T_subset */
static int hf_dap_filter;                         /* Filter */
static int hf_dap_searchAliases;                  /* BOOLEAN */
static int hf_dap_matchedValuesOnly;              /* BOOLEAN */
static int hf_dap_extendedFilter;                 /* Filter */
static int hf_dap_checkOverspecified;             /* BOOLEAN */
static int hf_dap_relaxation;                     /* RelaxationPolicy */
static int hf_dap_extendedArea;                   /* INTEGER */
static int hf_dap_hierarchySelections;            /* HierarchySelections */
static int hf_dap_searchControlOptions;           /* SearchControlOptions */
static int hf_dap_joinArguments;                  /* SEQUENCE_SIZE_1_MAX_OF_JoinArgument */
static int hf_dap_joinArguments_item;             /* JoinArgument */
static int hf_dap_joinType;                       /* T_joinType */
static int hf_dap_unsignedSearchArgument;         /* SearchArgumentData */
static int hf_dap_signedSearchArgument;           /* T_signedSearchArgument */
static int hf_dap_searchArgument;                 /* SearchArgumentData */
static int hf_dap_joinBaseObject;                 /* Name */
static int hf_dap_domainLocalID;                  /* DomainLocalID */
static int hf_dap_joinSubset;                     /* T_joinSubset */
static int hf_dap_joinFilter;                     /* Filter */
static int hf_dap_joinAttributes;                 /* SEQUENCE_SIZE_1_MAX_OF_JoinAttPair */
static int hf_dap_joinAttributes_item;            /* JoinAttPair */
static int hf_dap_joinSelection;                  /* EntryInformationSelection */
static int hf_dap_baseAtt;                        /* AttributeType */
static int hf_dap_joinAtt;                        /* AttributeType */
static int hf_dap_joinContext;                    /* SEQUENCE_SIZE_1_MAX_OF_JoinContextType */
static int hf_dap_joinContext_item;               /* JoinContextType */
static int hf_dap_searchInfo;                     /* T_searchInfo */
static int hf_dap_entries;                        /* SET_OF_EntryInformation */
static int hf_dap_entries_item;                   /* EntryInformation */
static int hf_dap_altMatching;                    /* BOOLEAN */
static int hf_dap_uncorrelatedSearchInfo;         /* SET_OF_SearchResult */
static int hf_dap_uncorrelatedSearchInfo_item;    /* SearchResult */
static int hf_dap_unsignedSearchResult;           /* SearchResultData */
static int hf_dap_signedSearchResult;             /* T_signedSearchResult */
static int hf_dap_searchResult;                   /* SearchResultData */
static int hf_dap_add_entry;                      /* SET_OF_Attribute */
static int hf_dap_add_entry_item;                 /* Attribute */
static int hf_dap_targetSystem;                   /* AccessPoint */
static int hf_dap_unsignedAddEntryArgument;       /* AddEntryArgumentData */
static int hf_dap_signedAddEntryArgument;         /* T_signedAddEntryArgument */
static int hf_dap_addEntryArgument;               /* AddEntryArgumentData */
static int hf_dap_add_entry_information;          /* AddEntryInformation */
static int hf_dap_unsignedAddEntryResult;         /* AddEntryResultData */
static int hf_dap_signedAddEntryResult;           /* T_signedAddEntryResult */
static int hf_dap_addEntryResult;                 /* AddEntryResultData */
static int hf_dap_unsignedRemoveEntryArgument;    /* RemoveEntryArgumentData */
static int hf_dap_signedRemoveEntryArgument;      /* T_signedRemoveEntryArgument */
static int hf_dap_removeEntryArgument;            /* RemoveEntryArgumentData */
static int hf_dap_remove_entry_information;       /* RemoveEntryInformation */
static int hf_dap_unsignedRemoveEntryResult;      /* RemoveEntryResultData */
static int hf_dap_signedRemoveEntryResult;        /* T_signedRemoveEntryResult */
static int hf_dap_removeEntryResult;              /* RemoveEntryResultData */
static int hf_dap_changes;                        /* SEQUENCE_OF_EntryModification */
static int hf_dap_changes_item;                   /* EntryModification */
static int hf_dap_unsignedModifyEntryArgument;    /* ModifyEntryArgumentData */
static int hf_dap_signedModifyEntryArgument;      /* T_signedModifyEntryArgument */
static int hf_dap_modifyEntryArgument;            /* ModifyEntryArgumentData */
static int hf_dap_modify_entry_information;       /* ModifyEntryInformation */
static int hf_dap_unsignedModifyEntryResult;      /* ModifyEntryResultData */
static int hf_dap_signedModifyEntryResult;        /* T_signedModifyEntryResult */
static int hf_dap_modifyEntryResult;              /* ModifyEntryResultData */
static int hf_dap_addAttribute;                   /* Attribute */
static int hf_dap_removeAttribute;                /* AttributeType */
static int hf_dap_addValues;                      /* Attribute */
static int hf_dap_removeValues;                   /* Attribute */
static int hf_dap_alterValues;                    /* AttributeTypeAndValue */
static int hf_dap_resetValue;                     /* AttributeType */
static int hf_dap_newRDN;                         /* RelativeDistinguishedName */
static int hf_dap_deleteOldRDN;                   /* BOOLEAN */
static int hf_dap_newSuperior;                    /* DistinguishedName */
static int hf_dap_modify_dn_information;          /* ModifyDNInformation */
static int hf_dap_unsignedModifyDNResult;         /* ModifyDNResultData */
static int hf_dap_signedModifyDNResult;           /* T_signedModifyDNResult */
static int hf_dap_modifyDNResult;                 /* ModifyDNResultData */
static int hf_dap_unsignedAbandoned;              /* AbandonedData */
static int hf_dap_signedAbandoned;                /* T_signedAbandoned */
static int hf_dap_abandoned;                      /* AbandonedData */
static int hf_dap_abandon_failed_problem;         /* AbandonProblem */
static int hf_dap_operation;                      /* InvokeId */
static int hf_dap_unsignedAbandonFailedError;     /* AbandonFailedErrorData */
static int hf_dap_signedAbandonFailedError;       /* T_signedAbandonFailedError */
static int hf_dap_abandonFailedError;             /* AbandonFailedErrorData */
static int hf_dap_problems;                       /* T_problems */
static int hf_dap_problems_item;                  /* T_problems_item */
static int hf_dap_attribute_error_problem;        /* AttributeProblem */
static int hf_dap_value;                          /* AttributeValue */
static int hf_dap_unsignedAttributeError;         /* AttributeErrorData */
static int hf_dap_signedAttributeError;           /* T_signedAttributeError */
static int hf_dap_attributeError;                 /* AttributeErrorData */
static int hf_dap_name_error_problem;             /* NameProblem */
static int hf_dap_matched_name;                   /* Name */
static int hf_dap_unsignedNameError;              /* NameErrorData */
static int hf_dap_signedNameError;                /* T_signedNameError */
static int hf_dap_nameError;                      /* NameErrorData */
static int hf_dap_candidate;                      /* ContinuationReference */
static int hf_dap_unsignedReferral;               /* ReferralData */
static int hf_dap_signedReferral;                 /* T_signedReferral */
static int hf_dap_referral;                       /* ReferralData */
static int hf_dap_security_error_problem;         /* SecurityProblem */
static int hf_dap_spkmInfo;                       /* T_spkmInfo */
static int hf_dap_unsignedSecurityError;          /* SecurityErrorData */
static int hf_dap_signedSecurityError;            /* T_signedSecurityError */
static int hf_dap_securityErrorData;              /* SecurityErrorData */
static int hf_dap_service_error_problem;          /* ServiceProblem */
static int hf_dap_unsignedServiceError;           /* ServiceErrorData */
static int hf_dap_signedServiceError;             /* T_signedServiceError */
static int hf_dap_serviceError;                   /* ServiceErrorData */
static int hf_dap_update_error_problem;           /* UpdateProblem */
static int hf_dap_attributeInfo;                  /* T_attributeInfo */
static int hf_dap_attributeInfo_item;             /* T_attributeInfo_item */
static int hf_dap_unsignedUpdateError;            /* UpdateErrorData */
static int hf_dap_signedUpdateError;              /* T_signedUpdateError */
static int hf_dap_updateError;                    /* UpdateErrorData */
/* named bits */
static int hf_dap_ServiceControlOptions_preferChaining;
static int hf_dap_ServiceControlOptions_chainingProhibited;
static int hf_dap_ServiceControlOptions_localScope;
static int hf_dap_ServiceControlOptions_dontUseCopy;
static int hf_dap_ServiceControlOptions_dontDereferenceAliases;
static int hf_dap_ServiceControlOptions_subentries;
static int hf_dap_ServiceControlOptions_copyShallDo;
static int hf_dap_ServiceControlOptions_partialNameResolution;
static int hf_dap_ServiceControlOptions_manageDSAIT;
static int hf_dap_ServiceControlOptions_noSubtypeMatch;
static int hf_dap_ServiceControlOptions_noSubtypeSelection;
static int hf_dap_ServiceControlOptions_countFamily;
static int hf_dap_ServiceControlOptions_dontSelectFriends;
static int hf_dap_ServiceControlOptions_dontMatchFriends;
static int hf_dap_Versions_v1;
static int hf_dap_Versions_v2;
static int hf_dap_T_permission_add;
static int hf_dap_T_permission_remove;
static int hf_dap_T_permission_rename;
static int hf_dap_T_permission_move;
static int hf_dap_HierarchySelections_self;
static int hf_dap_HierarchySelections_children;
static int hf_dap_HierarchySelections_parent;
static int hf_dap_HierarchySelections_hierarchy;
static int hf_dap_HierarchySelections_top;
static int hf_dap_HierarchySelections_subtree;
static int hf_dap_HierarchySelections_siblings;
static int hf_dap_HierarchySelections_siblingChildren;
static int hf_dap_HierarchySelections_siblingSubtree;
static int hf_dap_HierarchySelections_all;
static int hf_dap_SearchControlOptions_searchAliases;
static int hf_dap_SearchControlOptions_matchedValuesOnly;
static int hf_dap_SearchControlOptions_checkOverspecified;
static int hf_dap_SearchControlOptions_performExactly;
static int hf_dap_SearchControlOptions_includeAllAreas;
static int hf_dap_SearchControlOptions_noSystemRelaxation;
static int hf_dap_SearchControlOptions_dnAttribute;
static int hf_dap_SearchControlOptions_matchOnResidualName;
static int hf_dap_SearchControlOptions_entryCount;
static int hf_dap_SearchControlOptions_useSubset;
static int hf_dap_SearchControlOptions_separateFamilyMembers;
static int hf_dap_SearchControlOptions_searchFamily;

/* Initialize the subtree pointers */
static int ett_dap;
static int ett_dap_ServiceControls;
static int ett_dap_T_manageDSAITPlaneRef;
static int ett_dap_ServiceControlOptions;
static int ett_dap_EntryInformationSelection;
static int ett_dap_T_attributes;
static int ett_dap_SET_OF_AttributeType;
static int ett_dap_T_extraAttributes;
static int ett_dap_SET_SIZE_1_MAX_OF_AttributeType;
static int ett_dap_ContextSelection;
static int ett_dap_SET_SIZE_1_MAX_OF_TypeAndContextAssertion;
static int ett_dap_TypeAndContextAssertion;
static int ett_dap_T_contextAssertions;
static int ett_dap_SEQUENCE_OF_ContextAssertion;
static int ett_dap_SET_OF_ContextAssertion;
static int ett_dap_FamilyReturn;
static int ett_dap_T_familySelect;
static int ett_dap_EntryInformation;
static int ett_dap_T_entry_information;
static int ett_dap_EntryInformationItem;
static int ett_dap_FamilyEntries;
static int ett_dap_SEQUENCE_OF_FamilyEntry;
static int ett_dap_FamilyEntry;
static int ett_dap_FamilyInformation;
static int ett_dap_T_family_information_item;
static int ett_dap_SEQUENCE_SIZE_1_MAX_OF_FamilyEntries;
static int ett_dap_Filter;
static int ett_dap_SetOfFilter;
static int ett_dap_FilterItem;
static int ett_dap_T_substrings;
static int ett_dap_T_strings;
static int ett_dap_T_strings_item;
static int ett_dap_MatchingRuleAssertion;
static int ett_dap_T_matchingRule;
static int ett_dap_PagedResultsRequest;
static int ett_dap_T_newRequest;
static int ett_dap_SEQUENCE_SIZE_1_MAX_OF_SortKey;
static int ett_dap_SortKey;
static int ett_dap_SecurityParameters;
static int ett_dap_Time;
static int ett_dap_DirectoryBindArgument;
static int ett_dap_Credentials;
static int ett_dap_SimpleCredentials;
static int ett_dap_T_validity;
static int ett_dap_T_time1;
static int ett_dap_T_time2;
static int ett_dap_T_password;
static int ett_dap_T_protected;
static int ett_dap_StrongCredentials;
static int ett_dap_SpkmCredentials;
static int ett_dap_SaslCredentials;
static int ett_dap_TokenData;
static int ett_dap_SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier;
static int ett_dap_Token;
static int ett_dap_Versions;
static int ett_dap_DirectoryBindError;
static int ett_dap_T_signedDirectoryBindError;
static int ett_dap_DirectoryBindErrorData;
static int ett_dap_T_error;
static int ett_dap_ReadArgumentData;
static int ett_dap_Name;
static int ett_dap_ReadArgument;
static int ett_dap_T_signedReadArgument;
static int ett_dap_ReadResultData;
static int ett_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute;
static int ett_dap_ReadResult;
static int ett_dap_T_signedReadResult;
static int ett_dap_ModifyRights;
static int ett_dap_ModifyRights_item;
static int ett_dap_T_item;
static int ett_dap_T_permission;
static int ett_dap_CompareArgumentData;
static int ett_dap_CompareArgument;
static int ett_dap_T_signedCompareArgument;
static int ett_dap_CompareResultData;
static int ett_dap_CompareResult;
static int ett_dap_T_signedCompareResult;
static int ett_dap_AbandonArgumentData;
static int ett_dap_AbandonArgument;
static int ett_dap_T_signedAbandonArgument;
static int ett_dap_AbandonResultData;
static int ett_dap_AbandonResult;
static int ett_dap_AbandonInformation;
static int ett_dap_T_signedAbandonResult;
static int ett_dap_ListArgumentData;
static int ett_dap_ListArgument;
static int ett_dap_T_signedListArgument;
static int ett_dap_ListResultData;
static int ett_dap_T_listInfo;
static int ett_dap_T_subordinates;
static int ett_dap_T_subordinates_item;
static int ett_dap_SET_OF_ListResult;
static int ett_dap_ListResult;
static int ett_dap_T_signedListResult;
static int ett_dap_PartialOutcomeQualifier;
static int ett_dap_SET_SIZE_1_MAX_OF_ContinuationReference;
static int ett_dap_T_unknownErrors;
static int ett_dap_T_entryCount;
static int ett_dap_SearchArgumentData;
static int ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument;
static int ett_dap_SearchArgument;
static int ett_dap_T_signedSearchArgument;
static int ett_dap_HierarchySelections;
static int ett_dap_SearchControlOptions;
static int ett_dap_JoinArgument;
static int ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinAttPair;
static int ett_dap_JoinAttPair;
static int ett_dap_SEQUENCE_SIZE_1_MAX_OF_JoinContextType;
static int ett_dap_SearchResultData;
static int ett_dap_T_searchInfo;
static int ett_dap_SET_OF_EntryInformation;
static int ett_dap_SET_OF_SearchResult;
static int ett_dap_SearchResult;
static int ett_dap_T_signedSearchResult;
static int ett_dap_AddEntryArgumentData;
static int ett_dap_SET_OF_Attribute;
static int ett_dap_AddEntryArgument;
static int ett_dap_T_signedAddEntryArgument;
static int ett_dap_AddEntryResultData;
static int ett_dap_AddEntryResult;
static int ett_dap_AddEntryInformation;
static int ett_dap_T_signedAddEntryResult;
static int ett_dap_RemoveEntryArgumentData;
static int ett_dap_RemoveEntryArgument;
static int ett_dap_T_signedRemoveEntryArgument;
static int ett_dap_RemoveEntryResultData;
static int ett_dap_RemoveEntryResult;
static int ett_dap_RemoveEntryInformation;
static int ett_dap_T_signedRemoveEntryResult;
static int ett_dap_ModifyEntryArgumentData;
static int ett_dap_SEQUENCE_OF_EntryModification;
static int ett_dap_ModifyEntryArgument;
static int ett_dap_T_signedModifyEntryArgument;
static int ett_dap_ModifyEntryResultData;
static int ett_dap_ModifyEntryResult;
static int ett_dap_ModifyEntryInformation;
static int ett_dap_T_signedModifyEntryResult;
static int ett_dap_EntryModification;
static int ett_dap_ModifyDNArgument;
static int ett_dap_ModifyDNResultData;
static int ett_dap_ModifyDNResult;
static int ett_dap_ModifyDNInformation;
static int ett_dap_T_signedModifyDNResult;
static int ett_dap_AbandonedData;
static int ett_dap_Abandoned;
static int ett_dap_T_signedAbandoned;
static int ett_dap_AbandonFailedErrorData;
static int ett_dap_AbandonFailedError;
static int ett_dap_T_signedAbandonFailedError;
static int ett_dap_AttributeErrorData;
static int ett_dap_T_problems;
static int ett_dap_T_problems_item;
static int ett_dap_AttributeError;
static int ett_dap_T_signedAttributeError;
static int ett_dap_NameErrorData;
static int ett_dap_NameError;
static int ett_dap_T_signedNameError;
static int ett_dap_ReferralData;
static int ett_dap_Referral;
static int ett_dap_T_signedReferral;
static int ett_dap_SecurityErrorData;
static int ett_dap_SecurityError;
static int ett_dap_T_signedSecurityError;
static int ett_dap_ServiceErrorData;
static int ett_dap_ServiceError;
static int ett_dap_T_signedServiceError;
static int ett_dap_UpdateErrorData;
static int ett_dap_T_attributeInfo;
static int ett_dap_T_attributeInfo_item;
static int ett_dap_UpdateError;
static int ett_dap_T_signedUpdateError;

static expert_field ei_dap_anonymous;

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


/*--- Cyclic dependencies ---*/

/* FamilyEntries -> FamilyEntries/familyEntries -> FamilyEntry -> FamilyEntry/family-info -> FamilyEntries */
static int dissect_dap_FamilyEntries(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* Filter -> SetOfFilter -> Filter */
/* Filter -> Filter */
/*int dissect_dap_Filter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);*/

/* ListResultData -> ListResultData/uncorrelatedListInfo -> ListResult -> ListResultData */
/* ListResultData -> ListResultData/uncorrelatedListInfo -> ListResult -> ListResult/signedListResult -> ListResultData */
static int dissect_dap_ListResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* SearchResultData -> SearchResultData/uncorrelatedSearchInfo -> SearchResult -> SearchResultData */
/* SearchResultData -> SearchResultData/uncorrelatedSearchInfo -> SearchResult -> SearchResult/signedSearchResult -> SearchResultData */
static int dissect_dap_SearchResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);



const value_string dap_FamilyGrouping_vals[] = {
  {   1, "entryOnly" },
  {   2, "compoundEntry" },
  {   3, "strands" },
  {   4, "multiStrand" },
  { 0, NULL }
};


int
dissect_dap_FamilyGrouping(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const ServiceControlOptions_bits[] = {
  &hf_dap_ServiceControlOptions_preferChaining,
  &hf_dap_ServiceControlOptions_chainingProhibited,
  &hf_dap_ServiceControlOptions_localScope,
  &hf_dap_ServiceControlOptions_dontUseCopy,
  &hf_dap_ServiceControlOptions_dontDereferenceAliases,
  &hf_dap_ServiceControlOptions_subentries,
  &hf_dap_ServiceControlOptions_copyShallDo,
  &hf_dap_ServiceControlOptions_partialNameResolution,
  &hf_dap_ServiceControlOptions_manageDSAIT,
  &hf_dap_ServiceControlOptions_noSubtypeMatch,
  &hf_dap_ServiceControlOptions_noSubtypeSelection,
  &hf_dap_ServiceControlOptions_countFamily,
  &hf_dap_ServiceControlOptions_dontSelectFriends,
  &hf_dap_ServiceControlOptions_dontMatchFriends,
  NULL
};

int
dissect_dap_ServiceControlOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ServiceControlOptions_bits, 14, hf_index, ett_dap_ServiceControlOptions,
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
dissect_dap_T_priority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_dap_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_scopeOfReferral(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_choice_t Name_choice[] = {
  {   0, &hf_dap_rdnSequence     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RDNSequence },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_manageDSAITPlaneRef(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_manageDSAITPlaneRef_sequence, hf_index, ett_dap_T_manageDSAITPlaneRef);

  return offset;
}



static int
dissect_dap_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ServiceControls(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ServiceControls_set, hf_index, ett_dap_ServiceControls);

  return offset;
}



static int
dissect_dap_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeType_set_of[1] = {
  { &hf_dap_select_item     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_dap_SET_OF_AttributeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_attributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_infoTypes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_AttributeType_set_of[1] = {
  { &hf_dap_extraSelect_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_dap_SET_SIZE_1_MAX_OF_AttributeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_extraAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_extraAttributes_choice, hf_index, ett_dap_T_extraAttributes,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ContextAssertion_sequence_of[1] = {
  { &hf_dap_preference_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_dap_SEQUENCE_OF_ContextAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ContextAssertion_sequence_of, hf_index, ett_dap_SEQUENCE_OF_ContextAssertion);

  return offset;
}


static const ber_sequence_t SET_OF_ContextAssertion_set_of[1] = {
  { &hf_dap_all_item        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_dap_SET_OF_ContextAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_contextAssertions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_TypeAndContextAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TypeAndContextAssertion_sequence, hf_index, ett_dap_TypeAndContextAssertion);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_TypeAndContextAssertion_set_of[1] = {
  { &hf_dap_selectedContexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_TypeAndContextAssertion },
};

static int
dissect_dap_SET_SIZE_1_MAX_OF_TypeAndContextAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ContextSelection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ContextSelection_choice, hf_index, ett_dap_ContextSelection,
                                 NULL);

  return offset;
}



static int
dissect_dap_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_memberSelect(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_familySelect_sequence_of[1] = {
  { &hf_dap_familySelect_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
};

static int
dissect_dap_T_familySelect(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_FamilyReturn(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_EntryInformationSelection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_EntryInformationItem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EntryInformationItem_choice, hf_index, ett_dap_EntryInformationItem,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_entry_information_set_of[1] = {
  { &hf_dap_entry_information_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_EntryInformationItem },
};

static int
dissect_dap_T_entry_information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_EntryInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_family_information_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_family_information_item_choice, hf_index, ett_dap_T_family_information_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t FamilyInformation_sequence_of[1] = {
  { &hf_dap_family_information_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_family_information_item },
};

static int
dissect_dap_FamilyInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      FamilyInformation_sequence_of, hf_index, ett_dap_FamilyInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_FamilyEntries_sequence_of[1] = {
  { &hf_dap_family_info_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_FamilyEntries },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_FamilyEntries(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_FamilyEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FamilyEntry_sequence, hf_index, ett_dap_FamilyEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_FamilyEntry_sequence_of[1] = {
  { &hf_dap_familyEntries_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_FamilyEntry },
};

static int
dissect_dap_SEQUENCE_OF_FamilyEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_FamilyEntries(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // FamilyEntries -> FamilyEntries/familyEntries -> FamilyEntry -> FamilyEntry/family-info -> FamilyEntries
  actx->pinfo->dissection_depth += 4;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FamilyEntries_sequence, hf_index, ett_dap_FamilyEntries);

  actx->pinfo->dissection_depth -= 4;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}



static int
dissect_dap_T_initial(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	proto_item *it;
	it = proto_tree_add_item(tree, hf_index, tvb, offset, -1, ENC_BIG_ENDIAN);
	proto_item_append_text(it," XXX: Not yet implemented!");


  return offset;
}



static int
dissect_dap_T_any(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	/* XXX: not yet implemented */


  return offset;
}



static int
dissect_dap_T_final(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_strings_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_strings_item_choice, hf_index, ett_dap_T_strings_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_strings_sequence_of[1] = {
  { &hf_dap_strings_item    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_strings_item },
};

static int
dissect_dap_T_strings(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_substrings(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_substrings_sequence, hf_index, ett_dap_T_substrings);

  return offset;
}


static const ber_sequence_t T_matchingRule_set_of[1] = {
  { &hf_dap_matchingRule_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
};

static int
dissect_dap_T_matchingRule(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_matchingRule_set_of, hf_index, ett_dap_T_matchingRule);

  return offset;
}



static int
dissect_dap_T_matchValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_MatchingRuleAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_FilterItem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FilterItem_choice, hf_index, ett_dap_FilterItem,
                                 NULL);

  return offset;
}


static const ber_sequence_t SetOfFilter_set_of[1] = {
  { &hf_dap_SetOfFilter_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_Filter },
};

static int
dissect_dap_SetOfFilter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_Filter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // Filter -> SetOfFilter -> Filter
  actx->pinfo->dissection_depth += 2;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Filter_choice, hf_index, ett_dap_Filter,
                                 NULL);

  actx->pinfo->dissection_depth -= 2;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t SortKey_sequence[] = {
  { &hf_dap_type            , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  { &hf_dap_orderingRule    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_SortKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SortKey_sequence, hf_index, ett_dap_SortKey);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_SortKey_sequence_of[1] = {
  { &hf_dap_sortKeys_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_SortKey },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_SortKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_newRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_newRequest_sequence, hf_index, ett_dap_T_newRequest);

  return offset;
}



static int
dissect_dap_T_pagedResultsQueryReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	tvbuff_t *out_tvb;
	int	i;
	int	len;

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &out_tvb);


	if(out_tvb) {
		/* now see if we can add a string representation */
		len = tvb_reported_length(out_tvb);
		if(tvb_ascii_isprint(out_tvb, 0, len)) {
			if(actx->created_item) {

				proto_item_append_text(actx->created_item," (");
				for(i=0; i<len; i++)
					proto_item_append_text(actx->created_item,"%c",tvb_get_uint8(out_tvb,i));
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
dissect_dap_PagedResultsRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PagedResultsRequest_choice, hf_index, ett_dap_PagedResultsRequest,
                                 NULL);

  return offset;
}



static int
dissect_dap_UTCTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index, NULL, NULL);

  return offset;
}



static int
dissect_dap_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_Time(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Time_choice, hf_index, ett_dap_Time,
                                 NULL);

  return offset;
}



static int
dissect_dap_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
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
dissect_dap_ProtectionRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ErrorProtectionRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SecurityParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_time1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_time2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_validity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              T_validity_set, hf_index, ett_dap_T_validity);

  return offset;
}



static int
dissect_dap_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_protected(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_password(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SimpleCredentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SimpleCredentials_sequence, hf_index, ett_dap_SimpleCredentials);


	col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", x509if_get_last_dn());





  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier_sequence_of[1] = {
  { &hf_dap_bindIntAlgorithm_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier_sequence_of, hf_index, ett_dap_SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier);

  return offset;
}



static int
dissect_dap_BindKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
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
dissect_dap_TokenData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_Token(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_StrongCredentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              StrongCredentials_set, hf_index, ett_dap_StrongCredentials);

  return offset;
}



static int
dissect_dap_EXTERNAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}



static int
dissect_dap_T_req(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	/* XXX: not yet implemented */


  return offset;
}



static int
dissect_dap_T_rep(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SpkmCredentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SaslCredentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_Credentials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Credentials_choice, hf_index, ett_dap_Credentials,
                                 NULL);

  return offset;
}


static int * const Versions_bits[] = {
  &hf_dap_Versions_v1,
  &hf_dap_Versions_v2,
  NULL
};

static int
dissect_dap_Versions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Versions_bits, 2, hf_index, ett_dap_Versions,
                                    NULL);

  return offset;
}


static const ber_sequence_t DirectoryBindArgument_set[] = {
  { &hf_dap_credentials     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dap_Credentials },
  { &hf_dap_versions        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_Versions },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dap_DirectoryBindArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	uint32_t len;

	/* check and see if this is an empty set */
	dissect_ber_length(actx->pinfo, tree, tvb, offset+1, &len, NULL);

	if(len == 0) {
		/* it's an empty set - i.e anonymous  (assuming version is DEFAULTed) */
		proto_tree_add_expert(tree, actx->pinfo, &ei_dap_anonymous, tvb, offset, -1);

		col_append_str(actx->pinfo->cinfo, COL_INFO, " anonymous");

	}
	/* do the default thing */

	  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DirectoryBindArgument_set, hf_index, ett_dap_DirectoryBindArgument);



  return offset;
}



static int
dissect_dap_DirectoryBindResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ServiceProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t problem;

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
dissect_dap_SecurityProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t problem;

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
dissect_dap_T_error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_DirectoryBindErrorData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedDirectoryBindError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_DirectoryBindError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ReadArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedReadArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ReadArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_item_choice, hf_index, ett_dap_T_item,
                                 NULL);

  return offset;
}


static int * const T_permission_bits[] = {
  &hf_dap_T_permission_add,
  &hf_dap_T_permission_remove,
  &hf_dap_T_permission_rename,
  &hf_dap_T_permission_move,
  NULL
};

static int
dissect_dap_T_permission(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_permission_bits, 4, hf_index, ett_dap_T_permission,
                                    NULL);

  return offset;
}


static const ber_sequence_t ModifyRights_item_sequence[] = {
  { &hf_dap_item            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_item },
  { &hf_dap_permission      , BER_CLASS_CON, 3, 0, dissect_dap_T_permission },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dap_ModifyRights_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyRights_item_sequence, hf_index, ett_dap_ModifyRights_item);

  return offset;
}


static const ber_sequence_t ModifyRights_set_of[1] = {
  { &hf_dap_ModifyRights_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_ModifyRights_item },
};

static int
dissect_dap_ModifyRights(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ModifyRights_set_of, hf_index, ett_dap_ModifyRights);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_Attribute_sequence_of[1] = {
  { &hf_dap_notification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ReadResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedReadResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ReadResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_CompareArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedCompareArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_CompareArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_CompareResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedCompareResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_CompareResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AbandonArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedAbandonArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AbandonArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AbandonResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedAbandonResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AbandonInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AbandonResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ListArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedListArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ListArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_subordinates_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_subordinates_item_sequence, hf_index, ett_dap_T_subordinates_item);

  return offset;
}


static const ber_sequence_t T_subordinates_set_of[1] = {
  { &hf_dap_subordinates_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_subordinates_item },
};

static int
dissect_dap_T_subordinates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_LimitProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, dap_LimitProblem_vals, "LimitProblem(%d)"));


  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_ContinuationReference_set_of[1] = {
  { &hf_dap_unexplored_item , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_ContinuationReference },
};

static int
dissect_dap_SET_SIZE_1_MAX_OF_ContinuationReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_ContinuationReference_set_of, hf_index, ett_dap_SET_SIZE_1_MAX_OF_ContinuationReference);

  return offset;
}


static const ber_sequence_t T_unknownErrors_set_of[1] = {
  { &hf_dap_unknownErrors_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_OBJECT_IDENTIFIER },
};

static int
dissect_dap_T_unknownErrors(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_entryCount(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_PartialOutcomeQualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_listInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedListResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ListResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ListResult_choice, hf_index, ett_dap_ListResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ListResult_set_of[1] = {
  { &hf_dap_uncorrelatedListInfo_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_ListResult },
};

static int
dissect_dap_SET_OF_ListResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ListResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // ListResultData -> ListResultData/uncorrelatedListInfo -> ListResult -> ListResultData
  actx->pinfo->dissection_depth += 3;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ListResultData_choice, hf_index, ett_dap_ListResultData,
                                 NULL);

  actx->pinfo->dissection_depth -= 3;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const value_string dap_T_subset_vals[] = {
  {   0, "baseObject" },
  {   1, "oneLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_dap_T_subset(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t subset;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &subset);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(subset, dap_T_subset_vals, "Subset(%d)"));



  return offset;
}


static int * const HierarchySelections_bits[] = {
  &hf_dap_HierarchySelections_self,
  &hf_dap_HierarchySelections_children,
  &hf_dap_HierarchySelections_parent,
  &hf_dap_HierarchySelections_hierarchy,
  &hf_dap_HierarchySelections_top,
  &hf_dap_HierarchySelections_subtree,
  &hf_dap_HierarchySelections_siblings,
  &hf_dap_HierarchySelections_siblingChildren,
  &hf_dap_HierarchySelections_siblingSubtree,
  &hf_dap_HierarchySelections_all,
  NULL
};

int
dissect_dap_HierarchySelections(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    HierarchySelections_bits, 10, hf_index, ett_dap_HierarchySelections,
                                    NULL);

  return offset;
}


static int * const SearchControlOptions_bits[] = {
  &hf_dap_SearchControlOptions_searchAliases,
  &hf_dap_SearchControlOptions_matchedValuesOnly,
  &hf_dap_SearchControlOptions_checkOverspecified,
  &hf_dap_SearchControlOptions_performExactly,
  &hf_dap_SearchControlOptions_includeAllAreas,
  &hf_dap_SearchControlOptions_noSystemRelaxation,
  &hf_dap_SearchControlOptions_dnAttribute,
  &hf_dap_SearchControlOptions_matchOnResidualName,
  &hf_dap_SearchControlOptions_entryCount,
  &hf_dap_SearchControlOptions_useSubset,
  &hf_dap_SearchControlOptions_separateFamilyMembers,
  &hf_dap_SearchControlOptions_searchFamily,
  NULL
};

int
dissect_dap_SearchControlOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    SearchControlOptions_bits, 12, hf_index, ett_dap_SearchControlOptions,
                                    NULL);

  return offset;
}



static int
dissect_dap_DomainLocalID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_joinSubset(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dap_JoinContextType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_JoinContextType_sequence_of[1] = {
  { &hf_dap_joinContext_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dap_JoinContextType },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinContextType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_JoinAttPair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   JoinAttPair_sequence, hf_index, ett_dap_JoinAttPair);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_JoinAttPair_sequence_of[1] = {
  { &hf_dap_joinAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_JoinAttPair },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinAttPair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_JoinArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   JoinArgument_sequence, hf_index, ett_dap_JoinArgument);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_JoinArgument_sequence_of[1] = {
  { &hf_dap_joinArguments_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_JoinArgument },
};

static int
dissect_dap_SEQUENCE_SIZE_1_MAX_OF_JoinArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_joinType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SearchArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedSearchArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SearchArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SearchArgument_choice, hf_index, ett_dap_SearchArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_EntryInformation_set_of[1] = {
  { &hf_dap_entries_item    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_EntryInformation },
};

static int
dissect_dap_SET_OF_EntryInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_searchInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedSearchResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SearchResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SearchResult_choice, hf_index, ett_dap_SearchResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_SearchResult_set_of[1] = {
  { &hf_dap_uncorrelatedSearchInfo_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_SearchResult },
};

static int
dissect_dap_SET_OF_SearchResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SearchResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // SearchResultData -> SearchResultData/uncorrelatedSearchInfo -> SearchResult -> SearchResultData
  actx->pinfo->dissection_depth += 3;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SearchResultData_choice, hf_index, ett_dap_SearchResultData,
                                 NULL);

  actx->pinfo->dissection_depth -= 3;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { &hf_dap_add_entry_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dap_SET_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AddEntryArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedAddEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AddEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AddEntryResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedAddEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AddEntryInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AddEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_RemoveEntryArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedRemoveEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_RemoveEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_RemoveEntryResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedRemoveEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_RemoveEntryInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_RemoveEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_EntryModification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EntryModification_choice, hf_index, ett_dap_EntryModification,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EntryModification_sequence_of[1] = {
  { &hf_dap_changes_item    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_EntryModification },
};

static int
dissect_dap_SEQUENCE_OF_EntryModification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ModifyEntryArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedModifyEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ModifyEntryArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ModifyEntryResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedModifyEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ModifyEntryInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ModifyEntryResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ModifyDNArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ModifyDNResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedModifyDNResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ModifyDNInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ModifyDNResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AbandonedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedAbandoned(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_Abandoned(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AbandonProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AbandonFailedErrorData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedAbandonFailedError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AbandonFailedError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AttributeProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_problems_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_problems_item_sequence, hf_index, ett_dap_T_problems_item);

  return offset;
}


static const ber_sequence_t T_problems_set_of[1] = {
  { &hf_dap_problems_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dap_T_problems_item },
};

static int
dissect_dap_T_problems(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AttributeErrorData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedAttributeError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_AttributeError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_NameProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_NameErrorData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedNameError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_NameError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ReferralData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedReferral(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_Referral(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Referral_choice, hf_index, ett_dap_Referral,
                                 NULL);

  return offset;
}



static int
dissect_dap_T_spkmInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SecurityErrorData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedSecurityError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_SecurityError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ServiceErrorData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedServiceError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_ServiceError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_UpdateProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t problem;

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
dissect_dap_T_attributeInfo_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_attributeInfo_item_choice, hf_index, ett_dap_T_attributeInfo_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_attributeInfo_set_of[1] = {
  { &hf_dap_attributeInfo_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dap_T_attributeInfo_item },
};

static int
dissect_dap_T_attributeInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_UpdateErrorData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_T_signedUpdateError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dap_UpdateError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UpdateError_choice, hf_index, ett_dap_UpdateError,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_DirectoryBindArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_DirectoryBindArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_DirectoryBindArgument_PDU);
  return offset;
}
static int dissect_DirectoryBindResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_DirectoryBindResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_DirectoryBindResult_PDU);
  return offset;
}
static int dissect_DirectoryBindError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_DirectoryBindError(false, tvb, offset, &asn1_ctx, tree, hf_dap_DirectoryBindError_PDU);
  return offset;
}
static int dissect_ReadArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_ReadArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_ReadArgument_PDU);
  return offset;
}
static int dissect_ReadResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_ReadResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_ReadResult_PDU);
  return offset;
}
static int dissect_CompareArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_CompareArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_CompareArgument_PDU);
  return offset;
}
static int dissect_CompareResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_CompareResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_CompareResult_PDU);
  return offset;
}
static int dissect_AbandonArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_AbandonArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_AbandonArgument_PDU);
  return offset;
}
static int dissect_AbandonResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_AbandonResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_AbandonResult_PDU);
  return offset;
}
static int dissect_ListArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_ListArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_ListArgument_PDU);
  return offset;
}
static int dissect_ListResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_ListResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_ListResult_PDU);
  return offset;
}
static int dissect_SearchArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_SearchArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_SearchArgument_PDU);
  return offset;
}
static int dissect_SearchResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_SearchResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_SearchResult_PDU);
  return offset;
}
static int dissect_AddEntryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_AddEntryArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_AddEntryArgument_PDU);
  return offset;
}
static int dissect_AddEntryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_AddEntryResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_AddEntryResult_PDU);
  return offset;
}
static int dissect_RemoveEntryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_RemoveEntryArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_RemoveEntryArgument_PDU);
  return offset;
}
static int dissect_RemoveEntryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_RemoveEntryResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_RemoveEntryResult_PDU);
  return offset;
}
static int dissect_ModifyEntryArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_ModifyEntryArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_ModifyEntryArgument_PDU);
  return offset;
}
static int dissect_ModifyEntryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_ModifyEntryResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_ModifyEntryResult_PDU);
  return offset;
}
static int dissect_ModifyDNArgument_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_ModifyDNArgument(false, tvb, offset, &asn1_ctx, tree, hf_dap_ModifyDNArgument_PDU);
  return offset;
}
static int dissect_ModifyDNResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_ModifyDNResult(false, tvb, offset, &asn1_ctx, tree, hf_dap_ModifyDNResult_PDU);
  return offset;
}
static int dissect_Abandoned_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_Abandoned(false, tvb, offset, &asn1_ctx, tree, hf_dap_Abandoned_PDU);
  return offset;
}
static int dissect_AbandonFailedError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_AbandonFailedError(false, tvb, offset, &asn1_ctx, tree, hf_dap_AbandonFailedError_PDU);
  return offset;
}
static int dissect_AttributeError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_AttributeError(false, tvb, offset, &asn1_ctx, tree, hf_dap_AttributeError_PDU);
  return offset;
}
static int dissect_NameError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_NameError(false, tvb, offset, &asn1_ctx, tree, hf_dap_NameError_PDU);
  return offset;
}
static int dissect_Referral_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_Referral(false, tvb, offset, &asn1_ctx, tree, hf_dap_Referral_PDU);
  return offset;
}
static int dissect_SecurityError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_SecurityError(false, tvb, offset, &asn1_ctx, tree, hf_dap_SecurityError_PDU);
  return offset;
}
static int dissect_ServiceError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_ServiceError(false, tvb, offset, &asn1_ctx, tree, hf_dap_ServiceError_PDU);
  return offset;
}
static int dissect_UpdateError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dap_UpdateError(false, tvb, offset, &asn1_ctx, tree, hf_dap_UpdateError_PDU);
  return offset;
}



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
  { 0,				(dissector_t)(-1),	(dissector_t)(-1) },
};


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
  { 0,	(dissector_t)(-1) },
};


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
    { &hf_dap_DirectoryBindArgument_PDU,
      { "DirectoryBindArgument", "dap.DirectoryBindArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_DirectoryBindResult_PDU,
      { "DirectoryBindResult", "dap.DirectoryBindResult_element",
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
      { "ModifyDNArgument", "dap.ModifyDNArgument_element",
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
      { "manageDSAITPlaneRef", "dap.manageDSAITPlaneRef_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_dsaName,
      { "dsaName", "dap.dsaName",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dap_agreementID,
      { "agreementID", "dap.agreementID_element",
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
      { "allUserAttributes", "dap.allUserAttributes_element",
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
      { "allOperationalAttributes", "dap.allOperationalAttributes_element",
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
      { "familyReturn", "dap.familyReturn_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_allContexts,
      { "allContexts", "dap.allContexts_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_selectedContexts,
      { "selectedContexts", "dap.selectedContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_TypeAndContextAssertion", HFILL }},
    { &hf_dap_selectedContexts_item,
      { "TypeAndContextAssertion", "dap.TypeAndContextAssertion_element",
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
      { "ContextAssertion", "dap.ContextAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_all,
      { "all", "dap.all",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ContextAssertion", HFILL }},
    { &hf_dap_all_item,
      { "ContextAssertion", "dap.ContextAssertion_element",
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
      { "attribute", "dap.attribute_element",
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
      { "FamilyEntry", "dap.FamilyEntry_element",
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
      { "FamilyEntries", "dap.FamilyEntries_element",
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
      { "equality", "dap.equality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_substrings,
      { "substrings", "dap.substrings_element",
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
      { "initial", "dap.initial_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_any,
      { "any", "dap.any_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_final,
      { "final", "dap.final_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_control,
      { "control", "dap.control_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_dap_greaterOrEqual,
      { "greaterOrEqual", "dap.greaterOrEqual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_lessOrEqual,
      { "lessOrEqual", "dap.lessOrEqual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_present,
      { "present", "dap.present",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_approximateMatch,
      { "approximateMatch", "dap.approximateMatch_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_extensibleMatch,
      { "extensibleMatch", "dap.extensibleMatch_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MatchingRuleAssertion", HFILL }},
    { &hf_dap_contextPresent,
      { "contextPresent", "dap.contextPresent_element",
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
      { "matchValue", "dap.matchValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_dnAttributes,
      { "dnAttributes", "dap.dnAttributes",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_newRequest,
      { "newRequest", "dap.newRequest_element",
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
      { "SortKey", "dap.SortKey_element",
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
      { "certification-path", "dap.certification_path_element",
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
      { "attributeCertificationPath", "dap.attributeCertificationPath_element",
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
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
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
      { "simple", "dap.simple_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SimpleCredentials", HFILL }},
    { &hf_dap_strong,
      { "strong", "dap.strong_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StrongCredentials", HFILL }},
    { &hf_dap_externalProcedure,
      { "externalProcedure", "dap.externalProcedure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_dap_spkm,
      { "spkm", "dap.spkm",
        FT_UINT32, BASE_DEC, VALS(dap_SpkmCredentials_vals), 0,
        "SpkmCredentials", HFILL }},
    { &hf_dap_sasl,
      { "sasl", "dap.sasl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SaslCredentials", HFILL }},
    { &hf_dap_validity,
      { "validity", "dap.validity_element",
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
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
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
      { "protected", "dap.protected_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_protectedPassword,
      { "protectedPassword", "dap.protectedPassword",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_dap_algorithmIdentifier,
      { "algorithmIdentifier", "dap.algorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_encrypted,
      { "encrypted", "dap.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_dap_bind_token,
      { "bind-token", "dap.bind_token_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Token", HFILL }},
    { &hf_dap_req,
      { "req", "dap.req_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_rep,
      { "rep", "dap.rep_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_mechanism,
      { "mechanism", "dap.mechanism",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_dap_saslCredentials,
      { "credentials", "dap.saslCredentials",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_dap_saslAbort,
      { "saslAbort", "dap.saslAbort",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_algorithm,
      { "algorithm", "dap.algorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_dap_utctime,
      { "time", "dap.utctime",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_dap_bindIntAlgorithm,
      { "bindIntAlgorithm", "dap.bindIntAlgorithm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_AlgorithmIdentifier", HFILL }},
    { &hf_dap_bindIntAlgorithm_item,
      { "AlgorithmIdentifier", "dap.AlgorithmIdentifier_element",
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
      { "AlgorithmIdentifier", "dap.AlgorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_bindConfKeyInfo,
      { "bindConfKeyInfo", "dap.bindConfKeyInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BindKeyInfo", HFILL }},
    { &hf_dap_token_data,
      { "token-data", "dap.token_data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TokenData", HFILL }},
    { &hf_dap_algorithm_identifier,
      { "algorithm-identifier", "dap.algorithm_identifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_dap_unsignedDirectoryBindError,
      { "unsignedDirectoryBindError", "dap.unsignedDirectoryBindError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DirectoryBindErrorData", HFILL }},
    { &hf_dap_signedDirectoryBindError,
      { "signedDirectoryBindError", "dap.signedDirectoryBindError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_directoryBindError,
      { "directoryBindError", "dap.directoryBindError_element",
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
      { "securityParameters", "dap.securityParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_object,
      { "object", "dap.object",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dap_selection,
      { "selection", "dap.selection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntryInformationSelection", HFILL }},
    { &hf_dap_modifyRightsRequest,
      { "modifyRightsRequest", "dap.modifyRightsRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_serviceControls,
      { "serviceControls", "dap.serviceControls_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_requestor,
      { "requestor", "dap.requestor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dap_operationProgress,
      { "operationProgress", "dap.operationProgress_element",
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
      { "unsignedReadArgument", "dap.unsignedReadArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadArgumentData", HFILL }},
    { &hf_dap_signedReadArgument,
      { "signedReadArgument", "dap.signedReadArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_readArgument,
      { "readArgument", "dap.readArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadArgumentData", HFILL }},
    { &hf_dap_entry,
      { "entry", "dap.entry_element",
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
      { "Attribute", "dap.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_unsignedReadResult,
      { "unsignedReadResult", "dap.unsignedReadResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadResultData", HFILL }},
    { &hf_dap_signedReadResult,
      { "signedReadResult", "dap.signedReadResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_readResult,
      { "readResult", "dap.readResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadResultData", HFILL }},
    { &hf_dap_ModifyRights_item,
      { "ModifyRights item", "dap.ModifyRights_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_item,
      { "item", "dap.item",
        FT_UINT32, BASE_DEC, VALS(dap_T_item_vals), 0,
        NULL, HFILL }},
    { &hf_dap_item_entry,
      { "entry", "dap.entry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_attribute_type,
      { "attribute", "dap.attribute",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_value_assertion,
      { "value", "dap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_permission,
      { "permission", "dap.permission",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_purported,
      { "purported", "dap.purported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion", HFILL }},
    { &hf_dap_unsignedCompareArgument,
      { "unsignedCompareArgument", "dap.unsignedCompareArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareArgumentData", HFILL }},
    { &hf_dap_signedCompareArgument,
      { "signedCompareArgument", "dap.signedCompareArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_compareArgument,
      { "compareArgument", "dap.compareArgument_element",
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
      { "unsignedCompareResult", "dap.unsignedCompareResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareResultData", HFILL }},
    { &hf_dap_signedCompareResult,
      { "signedCompareResult", "dap.signedCompareResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_compareResult,
      { "compareResult", "dap.compareResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompareResultData", HFILL }},
    { &hf_dap_invokeID,
      { "invokeID", "dap.invokeID",
        FT_UINT32, BASE_DEC, VALS(ros_InvokeId_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unsignedAbandonArgument,
      { "unsignedAbandonArgument", "dap.unsignedAbandonArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonArgumentData", HFILL }},
    { &hf_dap_signedAbandonArgument,
      { "signedAbandonArgument", "dap.signedAbandonArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandonArgument,
      { "abandonArgument", "dap.abandonArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonArgumentData", HFILL }},
    { &hf_dap_null,
      { "null", "dap.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandon_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_AbandonInformation_vals), 0,
        "AbandonInformation", HFILL }},
    { &hf_dap_unsignedAbandonResult,
      { "unsignedAbandonResult", "dap.unsignedAbandonResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonResultData", HFILL }},
    { &hf_dap_signedAbandonResult,
      { "signedAbandonResult", "dap.signedAbandonResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandonResult,
      { "abandonResult", "dap.abandonResult_element",
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
      { "unsignedListArgument", "dap.unsignedListArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListArgumentData", HFILL }},
    { &hf_dap_signedListArgument,
      { "signedListArgument", "dap.signedListArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_listArgument,
      { "listArgument", "dap.listArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ListArgumentData", HFILL }},
    { &hf_dap_listInfo,
      { "listInfo", "dap.listInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_subordinates,
      { "subordinates", "dap.subordinates",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_subordinates_item,
      { "subordinates item", "dap.subordinates_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_aliasEntry,
      { "aliasEntry", "dap.aliasEntry",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dap_partialOutcomeQualifier,
      { "partialOutcomeQualifier", "dap.partialOutcomeQualifier_element",
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
      { "signedListResult", "dap.signedListResult_element",
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
      { "ContinuationReference", "dap.ContinuationReference_element",
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
      { "relaxation", "dap.relaxation_element",
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
      { "JoinArgument", "dap.JoinArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_joinType,
      { "joinType", "dap.joinType",
        FT_UINT32, BASE_DEC, VALS(dap_T_joinType_vals), 0,
        NULL, HFILL }},
    { &hf_dap_unsignedSearchArgument,
      { "unsignedSearchArgument", "dap.unsignedSearchArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchArgumentData", HFILL }},
    { &hf_dap_signedSearchArgument,
      { "signedSearchArgument", "dap.signedSearchArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_searchArgument,
      { "searchArgument", "dap.searchArgument_element",
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
      { "JoinAttPair", "dap.JoinAttPair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_joinSelection,
      { "joinSelection", "dap.joinSelection_element",
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
      { "searchInfo", "dap.searchInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_entries,
      { "entries", "dap.entries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_EntryInformation", HFILL }},
    { &hf_dap_entries_item,
      { "EntryInformation", "dap.EntryInformation_element",
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
      { "signedSearchResult", "dap.signedSearchResult_element",
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
      { "Attribute", "dap.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_targetSystem,
      { "targetSystem", "dap.targetSystem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessPoint", HFILL }},
    { &hf_dap_unsignedAddEntryArgument,
      { "unsignedAddEntryArgument", "dap.unsignedAddEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryArgumentData", HFILL }},
    { &hf_dap_signedAddEntryArgument,
      { "signedAddEntryArgument", "dap.signedAddEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_addEntryArgument,
      { "addEntryArgument", "dap.addEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryArgumentData", HFILL }},
    { &hf_dap_add_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_AddEntryInformation_vals), 0,
        "AddEntryInformation", HFILL }},
    { &hf_dap_unsignedAddEntryResult,
      { "unsignedAddEntryResult", "dap.unsignedAddEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryResultData", HFILL }},
    { &hf_dap_signedAddEntryResult,
      { "signedAddEntryResult", "dap.signedAddEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_addEntryResult,
      { "addEntryResult", "dap.addEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddEntryResultData", HFILL }},
    { &hf_dap_unsignedRemoveEntryArgument,
      { "unsignedRemoveEntryArgument", "dap.unsignedRemoveEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryArgumentData", HFILL }},
    { &hf_dap_signedRemoveEntryArgument,
      { "signedRemoveEntryArgument", "dap.signedRemoveEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_removeEntryArgument,
      { "removeEntryArgument", "dap.removeEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryArgumentData", HFILL }},
    { &hf_dap_remove_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_RemoveEntryInformation_vals), 0,
        "RemoveEntryInformation", HFILL }},
    { &hf_dap_unsignedRemoveEntryResult,
      { "unsignedRemoveEntryResult", "dap.unsignedRemoveEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoveEntryResultData", HFILL }},
    { &hf_dap_signedRemoveEntryResult,
      { "signedRemoveEntryResult", "dap.signedRemoveEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_removeEntryResult,
      { "removeEntryResult", "dap.removeEntryResult_element",
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
      { "unsignedModifyEntryArgument", "dap.unsignedModifyEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryArgumentData", HFILL }},
    { &hf_dap_signedModifyEntryArgument,
      { "signedModifyEntryArgument", "dap.signedModifyEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_modifyEntryArgument,
      { "modifyEntryArgument", "dap.modifyEntryArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryArgumentData", HFILL }},
    { &hf_dap_modify_entry_information,
      { "information", "dap.information",
        FT_UINT32, BASE_DEC, VALS(dap_ModifyEntryInformation_vals), 0,
        "ModifyEntryInformation", HFILL }},
    { &hf_dap_unsignedModifyEntryResult,
      { "unsignedModifyEntryResult", "dap.unsignedModifyEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryResultData", HFILL }},
    { &hf_dap_signedModifyEntryResult,
      { "signedModifyEntryResult", "dap.signedModifyEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_modifyEntryResult,
      { "modifyEntryResult", "dap.modifyEntryResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyEntryResultData", HFILL }},
    { &hf_dap_addAttribute,
      { "addAttribute", "dap.addAttribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_dap_removeAttribute,
      { "removeAttribute", "dap.removeAttribute",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dap_addValues,
      { "addValues", "dap.addValues_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_dap_removeValues,
      { "removeValues", "dap.removeValues_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_dap_alterValues,
      { "alterValues", "dap.alterValues_element",
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
      { "unsignedModifyDNResult", "dap.unsignedModifyDNResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNResultData", HFILL }},
    { &hf_dap_signedModifyDNResult,
      { "signedModifyDNResult", "dap.signedModifyDNResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_modifyDNResult,
      { "modifyDNResult", "dap.modifyDNResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyDNResultData", HFILL }},
    { &hf_dap_unsignedAbandoned,
      { "unsignedAbandoned", "dap.unsignedAbandoned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonedData", HFILL }},
    { &hf_dap_signedAbandoned,
      { "signedAbandoned", "dap.signedAbandoned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandoned,
      { "abandoned", "dap.abandoned_element",
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
      { "unsignedAbandonFailedError", "dap.unsignedAbandonFailedError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonFailedErrorData", HFILL }},
    { &hf_dap_signedAbandonFailedError,
      { "signedAbandonFailedError", "dap.signedAbandonFailedError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_abandonFailedError,
      { "abandonFailedError", "dap.abandonFailedError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AbandonFailedErrorData", HFILL }},
    { &hf_dap_problems,
      { "problems", "dap.problems",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_problems_item,
      { "problems item", "dap.problems_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_attribute_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_AttributeProblem_vals), 0,
        "AttributeProblem", HFILL }},
    { &hf_dap_value,
      { "value", "dap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValue", HFILL }},
    { &hf_dap_unsignedAttributeError,
      { "unsignedAttributeError", "dap.unsignedAttributeError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeErrorData", HFILL }},
    { &hf_dap_signedAttributeError,
      { "signedAttributeError", "dap.signedAttributeError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_attributeError,
      { "attributeError", "dap.attributeError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeErrorData", HFILL }},
    { &hf_dap_name_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_NameProblem_vals), 0,
        "NameProblem", HFILL }},
    { &hf_dap_matched_name,
      { "matched", "dap.matched_name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dap_unsignedNameError,
      { "unsignedNameError", "dap.unsignedNameError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameErrorData", HFILL }},
    { &hf_dap_signedNameError,
      { "signedNameError", "dap.signedNameError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_nameError,
      { "nameError", "dap.nameError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameErrorData", HFILL }},
    { &hf_dap_candidate,
      { "candidate", "dap.candidate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContinuationReference", HFILL }},
    { &hf_dap_unsignedReferral,
      { "unsignedReferral", "dap.unsignedReferral_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferralData", HFILL }},
    { &hf_dap_signedReferral,
      { "signedReferral", "dap.signedReferral_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_referral,
      { "referral", "dap.referral_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferralData", HFILL }},
    { &hf_dap_security_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_SecurityProblem_vals), 0,
        "SecurityProblem", HFILL }},
    { &hf_dap_spkmInfo,
      { "spkmInfo", "dap.spkmInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_unsignedSecurityError,
      { "unsignedSecurityError", "dap.unsignedSecurityError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrorData", HFILL }},
    { &hf_dap_signedSecurityError,
      { "signedSecurityError", "dap.signedSecurityError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_securityErrorData,
      { "securityError", "dap.securityError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrorData", HFILL }},
    { &hf_dap_service_error_problem,
      { "problem", "dap.problem",
        FT_INT32, BASE_DEC, VALS(dap_ServiceProblem_vals), 0,
        "ServiceProblem", HFILL }},
    { &hf_dap_unsignedServiceError,
      { "unsignedServiceError", "dap.unsignedServiceError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceErrorData", HFILL }},
    { &hf_dap_signedServiceError,
      { "signedServiceError", "dap.signedServiceError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_serviceError,
      { "serviceError", "dap.serviceError_element",
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
      { "unsignedUpdateError", "dap.unsignedUpdateError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateErrorData", HFILL }},
    { &hf_dap_signedUpdateError,
      { "signedUpdateError", "dap.signedUpdateError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dap_updateError,
      { "updateError", "dap.updateError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateErrorData", HFILL }},
    { &hf_dap_ServiceControlOptions_preferChaining,
      { "preferChaining", "dap.ServiceControlOptions.preferChaining",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_chainingProhibited,
      { "chainingProhibited", "dap.ServiceControlOptions.chainingProhibited",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_localScope,
      { "localScope", "dap.ServiceControlOptions.localScope",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_dontUseCopy,
      { "dontUseCopy", "dap.ServiceControlOptions.dontUseCopy",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_dontDereferenceAliases,
      { "dontDereferenceAliases", "dap.ServiceControlOptions.dontDereferenceAliases",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_subentries,
      { "subentries", "dap.ServiceControlOptions.subentries",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_copyShallDo,
      { "copyShallDo", "dap.ServiceControlOptions.copyShallDo",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_partialNameResolution,
      { "partialNameResolution", "dap.ServiceControlOptions.partialNameResolution",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_manageDSAIT,
      { "manageDSAIT", "dap.ServiceControlOptions.manageDSAIT",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_noSubtypeMatch,
      { "noSubtypeMatch", "dap.ServiceControlOptions.noSubtypeMatch",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_noSubtypeSelection,
      { "noSubtypeSelection", "dap.ServiceControlOptions.noSubtypeSelection",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_countFamily,
      { "countFamily", "dap.ServiceControlOptions.countFamily",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_dontSelectFriends,
      { "dontSelectFriends", "dap.ServiceControlOptions.dontSelectFriends",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dap_ServiceControlOptions_dontMatchFriends,
      { "dontMatchFriends", "dap.ServiceControlOptions.dontMatchFriends",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dap_Versions_v1,
      { "v1", "dap.Versions.v1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_Versions_v2,
      { "v2", "dap.Versions.v2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_T_permission_add,
      { "add", "dap.T.permission.add",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_T_permission_remove,
      { "remove", "dap.T.permission.remove",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_T_permission_rename,
      { "rename", "dap.T.permission.rename",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_T_permission_move,
      { "move", "dap.T.permission.move",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_self,
      { "self", "dap.HierarchySelections.self",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_children,
      { "children", "dap.HierarchySelections.children",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_parent,
      { "parent", "dap.HierarchySelections.parent",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_hierarchy,
      { "hierarchy", "dap.HierarchySelections.hierarchy",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_top,
      { "top", "dap.HierarchySelections.top",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_subtree,
      { "subtree", "dap.HierarchySelections.subtree",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_siblings,
      { "siblings", "dap.HierarchySelections.siblings",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_siblingChildren,
      { "siblingChildren", "dap.HierarchySelections.siblingChildren",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_siblingSubtree,
      { "siblingSubtree", "dap.HierarchySelections.siblingSubtree",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_HierarchySelections_all,
      { "all", "dap.HierarchySelections.all",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_searchAliases,
      { "searchAliases", "dap.SearchControlOptions.searchAliases",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_matchedValuesOnly,
      { "matchedValuesOnly", "dap.SearchControlOptions.matchedValuesOnly",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_checkOverspecified,
      { "checkOverspecified", "dap.SearchControlOptions.checkOverspecified",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_performExactly,
      { "performExactly", "dap.SearchControlOptions.performExactly",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_includeAllAreas,
      { "includeAllAreas", "dap.SearchControlOptions.includeAllAreas",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_noSystemRelaxation,
      { "noSystemRelaxation", "dap.SearchControlOptions.noSystemRelaxation",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_dnAttribute,
      { "dnAttribute", "dap.SearchControlOptions.dnAttribute",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_matchOnResidualName,
      { "matchOnResidualName", "dap.SearchControlOptions.matchOnResidualName",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_entryCount,
      { "entryCount", "dap.SearchControlOptions.entryCount",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_useSubset,
      { "useSubset", "dap.SearchControlOptions.useSubset",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_separateFamilyMembers,
      { "separateFamilyMembers", "dap.SearchControlOptions.separateFamilyMembers",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dap_SearchControlOptions_searchFamily,
      { "searchFamily", "dap.SearchControlOptions.searchFamily",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_dap,
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
  };

  static ei_register_info ei[] = {
    { &ei_dap_anonymous, { "dap.anonymous", PI_PROTOCOL, PI_NOTE, "Anonymous", EXPFILL }},
  };

  module_t *dap_module;
  expert_module_t* expert_dap;

  /* Register protocol */
  proto_dap = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dap = expert_register_protocol(proto_dap);
  expert_register_field_array(expert_dap, ei, array_length(ei));

  /* Register our configuration options for DAP, particularly our port */

  dap_module = prefs_register_protocol_subtree("OSI/X.500", proto_dap, NULL);

  prefs_register_obsolete_preference(dap_module, "tcp.port");

  prefs_register_static_text_preference(dap_module, "tcp_port_info",
            "The TCP ports used by the DAP protocol should be added to the TPKT preference \"TPKT TCP ports\", or the IDMP preference \"IDMP TCP Port\", or by selecting \"TPKT\" as the \"Transport\" protocol in the \"Decode As\" dialog.",
            "DAP TCP Port preference moved information");
}


/*--- proto_reg_handoff_dap --- */
void proto_reg_handoff_dap(void) {

  /* #include "packet-dap-dis-tab.c" */

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-directory-access","2.5.3.1");

  /* ABSTRACT SYNTAXES */

  /* Register DAP with ROS (with no use of RTSE) */
  register_ros_protocol_info("2.5.9.1", &dap_ros_info, 0, "id-as-directory-access", false);

  register_idmp_protocol_info("2.5.33.0", &dap_ros_info, 0, "dap-ip");

  /* AttributeValueAssertions */
  x509if_register_fmt(hf_dap_equality, "=");
  x509if_register_fmt(hf_dap_greaterOrEqual, ">=");
  x509if_register_fmt(hf_dap_lessOrEqual, "<=");
  x509if_register_fmt(hf_dap_approximateMatch, "=~");
  /* AttributeTypes */
  x509if_register_fmt(hf_dap_present, "= *");

}
