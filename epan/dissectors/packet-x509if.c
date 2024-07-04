/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-x509if.c                                                            */
/* asn2wrs.py -b -q -L -p x509if -c ./x509if.cnf -s ./packet-x509if-template -D . -O ../.. InformationFramework.asn ServiceAdministration.asn */

/* packet-x509if.c
 * Routines for X.509 Information Framework packet dissection
 *  Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <epan/strutil.h>

#include "packet-ber.h"
#include "packet-dap.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-frame.h"

#define PNAME  "X.509 Information Framework"
#define PSNAME "X509IF"
#define PFNAME "x509if"

void proto_register_x509if(void);
void proto_reg_handoff_x509if(void);

/* Initialize the protocol and registered fields */
static int proto_x509if;
static int hf_x509if_object_identifier_id;
static int hf_x509if_any_string;
static int hf_x509if_DistinguishedName_PDU;       /* DistinguishedName */
static int hf_x509if_SubtreeSpecification_PDU;    /* SubtreeSpecification */
static int hf_x509if_HierarchyLevel_PDU;          /* HierarchyLevel */
static int hf_x509if_HierarchyBelow_PDU;          /* HierarchyBelow */
static int hf_x509if_type;                        /* T_type */
static int hf_x509if_values;                      /* T_values */
static int hf_x509if_values_item;                 /* T_values_item */
static int hf_x509if_valuesWithContext;           /* T_valuesWithContext */
static int hf_x509if_valuesWithContext_item;      /* T_valuesWithContext_item */
static int hf_x509if_value;                       /* T_value */
static int hf_x509if_contextList;                 /* SET_SIZE_1_MAX_OF_Context */
static int hf_x509if_contextList_item;            /* Context */
static int hf_x509if_contextType;                 /* T_contextType */
static int hf_x509if_contextValues;               /* T_contextValues */
static int hf_x509if_contextValues_item;          /* T_contextValues_item */
static int hf_x509if_fallback;                    /* BOOLEAN */
static int hf_x509if_type_01;                     /* T_type_01 */
static int hf_x509if_assertion;                   /* T_assertion */
static int hf_x509if_assertedContexts;            /* T_assertedContexts */
static int hf_x509if_allContexts;                 /* NULL */
static int hf_x509if_selectedContexts;            /* SET_SIZE_1_MAX_OF_ContextAssertion */
static int hf_x509if_selectedContexts_item;       /* ContextAssertion */
static int hf_x509if_ca_contextType;              /* T_ca_contextType */
static int hf_x509if_ca_contextValues;            /* T_ca_contextValues */
static int hf_x509if_ca_contextValues_item;       /* T_ca_contextValues_item */
static int hf_x509if_type_02;                     /* OBJECT_IDENTIFIER */
static int hf_x509if_ata_assertedContexts;        /* SEQUENCE_SIZE_1_MAX_OF_ContextAssertion */
static int hf_x509if_ata_assertedContexts_item;   /* ContextAssertion */
static int hf_x509if_rdnSequence;                 /* RDNSequence */
static int hf_x509if_RDNSequence_item;            /* RDNSequence_item */
static int hf_x509if_RelativeDistinguishedName_item;  /* RelativeDistinguishedName_item */
static int hf_x509if_type_03;                     /* T_type_02 */
static int hf_x509if_atadv_value;                 /* T_atadv_value */
static int hf_x509if_primaryDistinguished;        /* BOOLEAN */
static int hf_x509if_valueswithContext;           /* T_valWithContext */
static int hf_x509if_valueswithContext_item;      /* T_valWithContext_item */
static int hf_x509if_distingAttrValue;            /* T_distingAttrValue */
static int hf_x509if_chopSpecificExclusions;      /* T_chopSpecificExclusions */
static int hf_x509if_chopSpecificExclusions_item;  /* T_chopSpecificExclusions_item */
static int hf_x509if_chopBefore;                  /* LocalName */
static int hf_x509if_chopAfter;                   /* LocalName */
static int hf_x509if_minimum;                     /* BaseDistance */
static int hf_x509if_maximum;                     /* BaseDistance */
static int hf_x509if_item;                        /* OBJECT_IDENTIFIER */
static int hf_x509if_refinement_and;              /* SET_OF_Refinement */
static int hf_x509if_refinement_and_item;         /* Refinement */
static int hf_x509if_refinement_or;               /* SET_OF_Refinement */
static int hf_x509if_refinement_or_item;          /* Refinement */
static int hf_x509if_refinement_not;              /* Refinement */
static int hf_x509if_ruleIdentifier;              /* RuleIdentifier */
static int hf_x509if_nameForm;                    /* OBJECT_IDENTIFIER */
static int hf_x509if_superiorStructureRules;      /* SET_SIZE_1_MAX_OF_RuleIdentifier */
static int hf_x509if_superiorStructureRules_item;  /* RuleIdentifier */
static int hf_x509if_structuralObjectClass;       /* OBJECT_IDENTIFIER */
static int hf_x509if_auxiliaries;                 /* T_auxiliaries */
static int hf_x509if_auxiliaries_item;            /* OBJECT_IDENTIFIER */
static int hf_x509if_mandatory;                   /* T_mandatory */
static int hf_x509if_mandatory_item;              /* OBJECT_IDENTIFIER */
static int hf_x509if_optional;                    /* T_optional */
static int hf_x509if_optional_item;               /* OBJECT_IDENTIFIER */
static int hf_x509if_precluded;                   /* T_precluded */
static int hf_x509if_precluded_item;              /* OBJECT_IDENTIFIER */
static int hf_x509if_attributeType;               /* OBJECT_IDENTIFIER */
static int hf_x509if_mandatoryContexts;           /* T_mandatoryContexts */
static int hf_x509if_mandatoryContexts_item;      /* OBJECT_IDENTIFIER */
static int hf_x509if_optionalContexts;            /* T_optionalContexts */
static int hf_x509if_optionalContexts_item;       /* OBJECT_IDENTIFIER */
static int hf_x509if_id;                          /* INTEGER */
static int hf_x509if_dmdId;                       /* OBJECT_IDENTIFIER */
static int hf_x509if_attributeType_01;            /* T_attributeType */
static int hf_x509if_includeSubtypes;             /* BOOLEAN */
static int hf_x509if_ra_selectedValues;           /* T_ra_selectedValues */
static int hf_x509if_ra_selectedValues_item;      /* T_ra_selectedValues_item */
static int hf_x509if_defaultValues;               /* T_defaultValues */
static int hf_x509if_defaultValues_item;          /* T_defaultValues_item */
static int hf_x509if_entryType;                   /* T_entryType */
static int hf_x509if_ra_values;                   /* T_ra_values */
static int hf_x509if_ra_values_item;              /* T_ra_values_item */
static int hf_x509if_contexts;                    /* SEQUENCE_SIZE_0_MAX_OF_ContextProfile */
static int hf_x509if_contexts_item;               /* ContextProfile */
static int hf_x509if_contextCombination;          /* ContextCombination */
static int hf_x509if_matchingUse;                 /* SEQUENCE_SIZE_1_MAX_OF_MatchingUse */
static int hf_x509if_matchingUse_item;            /* MatchingUse */
static int hf_x509if_contextType_01;              /* T_contextType_01 */
static int hf_x509if_contextValue;                /* T_contextValue */
static int hf_x509if_contextValue_item;           /* T_contextValue_item */
static int hf_x509if_context;                     /* OBJECT_IDENTIFIER */
static int hf_x509if_contextcombination_and;      /* SEQUENCE_OF_ContextCombination */
static int hf_x509if_contextcombination_and_item;  /* ContextCombination */
static int hf_x509if_contextcombination_or;       /* SEQUENCE_OF_ContextCombination */
static int hf_x509if_contextcombination_or_item;  /* ContextCombination */
static int hf_x509if_contextcombination_not;      /* ContextCombination */
static int hf_x509if_restrictionType;             /* T_restrictionType */
static int hf_x509if_restrictionValue;            /* T_restrictionValue */
static int hf_x509if_attribute;                   /* AttributeType */
static int hf_x509if_and;                         /* SEQUENCE_OF_AttributeCombination */
static int hf_x509if_and_item;                    /* AttributeCombination */
static int hf_x509if_or;                          /* SEQUENCE_OF_AttributeCombination */
static int hf_x509if_or_item;                     /* AttributeCombination */
static int hf_x509if_not;                         /* AttributeCombination */
static int hf_x509if_attributeType_02;            /* T_attributeType_01 */
static int hf_x509if_outputValues;                /* T_outputValues */
static int hf_x509if_selectedValues;              /* T_selectedValues */
static int hf_x509if_selectedValues_item;         /* T_selectedValues_item */
static int hf_x509if_matchedValuesOnly;           /* NULL */
static int hf_x509if_contexts_01;                 /* SEQUENCE_SIZE_1_MAX_OF_ContextProfile */
static int hf_x509if_serviceControls;             /* ServiceControlOptions */
static int hf_x509if_searchOptions;               /* SearchControlOptions */
static int hf_x509if_hierarchyOptions;            /* HierarchySelections */
static int hf_x509if_default;                     /* INTEGER */
static int hf_x509if_max;                         /* INTEGER */
static int hf_x509if_basic;                       /* MRMapping */
static int hf_x509if_tightenings;                 /* SEQUENCE_SIZE_1_MAX_OF_MRMapping */
static int hf_x509if_tightenings_item;            /* MRMapping */
static int hf_x509if_relaxations;                 /* SEQUENCE_SIZE_1_MAX_OF_MRMapping */
static int hf_x509if_relaxations_item;            /* MRMapping */
static int hf_x509if_maximum_relaxation;          /* INTEGER */
static int hf_x509if_minimum_relaxation;          /* INTEGER */
static int hf_x509if_mapping;                     /* SEQUENCE_SIZE_1_MAX_OF_Mapping */
static int hf_x509if_mapping_item;                /* Mapping */
static int hf_x509if_substitution;                /* SEQUENCE_SIZE_1_MAX_OF_MRSubstitution */
static int hf_x509if_substitution_item;           /* MRSubstitution */
static int hf_x509if_mappingFunction;             /* OBJECT_IDENTIFIER */
static int hf_x509if_level;                       /* INTEGER */
static int hf_x509if_oldMatchingRule;             /* OBJECT_IDENTIFIER */
static int hf_x509if_newMatchingRule;             /* OBJECT_IDENTIFIER */
static int hf_x509if_base;                        /* LocalName */
static int hf_x509if_specificExclusions;          /* T_specificExclusions */
static int hf_x509if_specificExclusions_item;     /* T_specificExclusions_item */
static int hf_x509if_specificationFilter;         /* Refinement */
static int hf_x509if_serviceType;                 /* OBJECT_IDENTIFIER */
static int hf_x509if_userClass;                   /* INTEGER */
static int hf_x509if_inputAttributeTypes;         /* SEQUENCE_SIZE_0_MAX_OF_RequestAttribute */
static int hf_x509if_inputAttributeTypes_item;    /* RequestAttribute */
static int hf_x509if_attributeCombination;        /* AttributeCombination */
static int hf_x509if_outputAttributeTypes;        /* SEQUENCE_SIZE_1_MAX_OF_ResultAttribute */
static int hf_x509if_outputAttributeTypes_item;   /* ResultAttribute */
static int hf_x509if_defaultControls;             /* ControlOptions */
static int hf_x509if_mandatoryControls;           /* ControlOptions */
static int hf_x509if_searchRuleControls;          /* ControlOptions */
static int hf_x509if_familyGrouping;              /* FamilyGrouping */
static int hf_x509if_familyReturn;                /* FamilyReturn */
static int hf_x509if_relaxation;                  /* RelaxationPolicy */
static int hf_x509if_additionalControl;           /* SEQUENCE_SIZE_1_MAX_OF_AttributeType */
static int hf_x509if_additionalControl_item;      /* AttributeType */
static int hf_x509if_allowedSubset;               /* AllowedSubset */
static int hf_x509if_imposedSubset;               /* ImposedSubset */
static int hf_x509if_entryLimit;                  /* EntryLimit */
static int hf_x509if_name;                        /* SET_SIZE_1_MAX_OF_DirectoryString */
static int hf_x509if_name_item;                   /* DirectoryString */
static int hf_x509if_description;                 /* DirectoryString */
/* named bits */
static int hf_x509if_AllowedSubset_baseObject;
static int hf_x509if_AllowedSubset_oneLevel;
static int hf_x509if_AllowedSubset_wholeSubtree;

/* Initialize the subtree pointers */
static int ett_x509if_Attribute;
static int ett_x509if_T_values;
static int ett_x509if_T_valuesWithContext;
static int ett_x509if_T_valuesWithContext_item;
static int ett_x509if_SET_SIZE_1_MAX_OF_Context;
static int ett_x509if_Context;
static int ett_x509if_T_contextValues;
static int ett_x509if_AttributeValueAssertion;
static int ett_x509if_T_assertedContexts;
static int ett_x509if_SET_SIZE_1_MAX_OF_ContextAssertion;
static int ett_x509if_ContextAssertion;
static int ett_x509if_T_ca_contextValues;
static int ett_x509if_AttributeTypeAssertion;
static int ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextAssertion;
static int ett_x509if_Name;
static int ett_x509if_RDNSequence;
static int ett_x509if_RelativeDistinguishedName;
static int ett_x509if_AttributeTypeAndDistinguishedValue;
static int ett_x509if_T_valWithContext;
static int ett_x509if_T_valWithContext_item;
static int ett_x509if_SubtreeSpecification;
static int ett_x509if_ChopSpecification;
static int ett_x509if_T_chopSpecificExclusions;
static int ett_x509if_T_chopSpecificExclusions_item;
static int ett_x509if_Refinement;
static int ett_x509if_SET_OF_Refinement;
static int ett_x509if_DITStructureRule;
static int ett_x509if_SET_SIZE_1_MAX_OF_RuleIdentifier;
static int ett_x509if_DITContentRule;
static int ett_x509if_T_auxiliaries;
static int ett_x509if_T_mandatory;
static int ett_x509if_T_optional;
static int ett_x509if_T_precluded;
static int ett_x509if_DITContextUse;
static int ett_x509if_T_mandatoryContexts;
static int ett_x509if_T_optionalContexts;
static int ett_x509if_SearchRuleDescription;
static int ett_x509if_SearchRule;
static int ett_x509if_SearchRuleId;
static int ett_x509if_AllowedSubset;
static int ett_x509if_RequestAttribute;
static int ett_x509if_T_ra_selectedValues;
static int ett_x509if_T_defaultValues;
static int ett_x509if_T_defaultValues_item;
static int ett_x509if_T_ra_values;
static int ett_x509if_SEQUENCE_SIZE_0_MAX_OF_ContextProfile;
static int ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MatchingUse;
static int ett_x509if_ContextProfile;
static int ett_x509if_T_contextValue;
static int ett_x509if_ContextCombination;
static int ett_x509if_SEQUENCE_OF_ContextCombination;
static int ett_x509if_MatchingUse;
static int ett_x509if_AttributeCombination;
static int ett_x509if_SEQUENCE_OF_AttributeCombination;
static int ett_x509if_ResultAttribute;
static int ett_x509if_T_outputValues;
static int ett_x509if_T_selectedValues;
static int ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextProfile;
static int ett_x509if_ControlOptions;
static int ett_x509if_EntryLimit;
static int ett_x509if_RelaxationPolicy;
static int ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MRMapping;
static int ett_x509if_MRMapping;
static int ett_x509if_SEQUENCE_SIZE_1_MAX_OF_Mapping;
static int ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MRSubstitution;
static int ett_x509if_Mapping;
static int ett_x509if_MRSubstitution;
static int ett_x509if_T_specificExclusions;
static int ett_x509if_T_specificExclusions_item;
static int ett_x509if_SEQUENCE_SIZE_0_MAX_OF_RequestAttribute;
static int ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ResultAttribute;
static int ett_x509if_SEQUENCE_SIZE_1_MAX_OF_AttributeType;
static int ett_x509if_SET_SIZE_1_MAX_OF_DirectoryString;

static proto_tree *top_of_dn;
static proto_tree *top_of_rdn;

static bool rdn_one_value; /* have we seen one value in an RDN yet */
static bool dn_one_rdn; /* have we seen one RDN in a DN yet */
static bool doing_attr;

static wmem_strbuf_t *last_dn_buf;
static wmem_strbuf_t *last_rdn_buf;

static int ava_hf_index;
#define MAX_FMT_VALS   32
static value_string fmt_vals[MAX_FMT_VALS];
#define MAX_AVA_STR_LEN   64
static char *last_ava;

static void
x509if_frame_end(void)
{
  top_of_dn = NULL;
  top_of_rdn = NULL;

  rdn_one_value = false;
  dn_one_rdn = false;
  doing_attr = false;

  last_dn_buf = NULL;
  last_rdn_buf = NULL;
  last_ava = NULL;
}

/*--- Cyclic dependencies ---*/

/* Refinement -> Refinement/and -> Refinement */
/* Refinement -> Refinement */
/*int dissect_x509if_Refinement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);*/

/* ContextCombination -> ContextCombination/and -> ContextCombination */
/* ContextCombination -> ContextCombination */
/*int dissect_x509if_ContextCombination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);*/

/* AttributeCombination -> AttributeCombination/and -> AttributeCombination */
/* AttributeCombination -> AttributeCombination */
/*int dissect_x509if_AttributeCombination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);*/




static int
dissect_x509if_T_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509if_T_values_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t T_values_set_of[1] = {
  { &hf_x509if_values_item  , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_values_item },
};

static int
dissect_x509if_T_values(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_values_set_of, hf_index, ett_x509if_T_values);

  return offset;
}



static int
dissect_x509if_T_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback("unknown", tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}



static int
dissect_x509if_T_contextType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509if_T_contextValues_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t T_contextValues_set_of[1] = {
  { &hf_x509if_contextValues_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_contextValues_item },
};

static int
dissect_x509if_T_contextValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_contextValues_set_of, hf_index, ett_x509if_T_contextValues);

  return offset;
}



static int
dissect_x509if_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t Context_sequence[] = {
  { &hf_x509if_contextType  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_contextType },
  { &hf_x509if_contextValues, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_T_contextValues },
  { &hf_x509if_fallback     , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_Context(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Context_sequence, hf_index, ett_x509if_Context);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_Context_set_of[1] = {
  { &hf_x509if_contextList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Context },
};

static int
dissect_x509if_SET_SIZE_1_MAX_OF_Context(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_Context_set_of, hf_index, ett_x509if_SET_SIZE_1_MAX_OF_Context);

  return offset;
}


static const ber_sequence_t T_valuesWithContext_item_sequence[] = {
  { &hf_x509if_value        , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_value },
  { &hf_x509if_contextList  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_SET_SIZE_1_MAX_OF_Context },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_valuesWithContext_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_valuesWithContext_item_sequence, hf_index, ett_x509if_T_valuesWithContext_item);

  return offset;
}


static const ber_sequence_t T_valuesWithContext_set_of[1] = {
  { &hf_x509if_valuesWithContext_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_T_valuesWithContext_item },
};

static int
dissect_x509if_T_valuesWithContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_valuesWithContext_set_of, hf_index, ett_x509if_T_valuesWithContext);

  return offset;
}


static const ber_sequence_t Attribute_sequence[] = {
  { &hf_x509if_type         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_type },
  { &hf_x509if_values       , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_T_values },
  { &hf_x509if_valuesWithContext, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_T_valuesWithContext },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	doing_attr = true;
	register_frame_end_routine (actx->pinfo, x509if_frame_end);

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Attribute_sequence, hf_index, ett_x509if_Attribute);


  return offset;
}



int
dissect_x509if_AttributeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



int
dissect_x509if_AttributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}



static int
dissect_x509if_T_type_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509if_T_assertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}



static int
dissect_x509if_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x509if_T_ca_contextType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509if_T_ca_contextValues_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t T_ca_contextValues_set_of[1] = {
  { &hf_x509if_ca_contextValues_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_ca_contextValues_item },
};

static int
dissect_x509if_T_ca_contextValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_ca_contextValues_set_of, hf_index, ett_x509if_T_ca_contextValues);

  return offset;
}


static const ber_sequence_t ContextAssertion_sequence[] = {
  { &hf_x509if_ca_contextType, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_ca_contextType },
  { &hf_x509if_ca_contextValues, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_T_ca_contextValues },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_ContextAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContextAssertion_sequence, hf_index, ett_x509if_ContextAssertion);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_ContextAssertion_set_of[1] = {
  { &hf_x509if_selectedContexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_x509if_SET_SIZE_1_MAX_OF_ContextAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_ContextAssertion_set_of, hf_index, ett_x509if_SET_SIZE_1_MAX_OF_ContextAssertion);

  return offset;
}


static const value_string x509if_T_assertedContexts_vals[] = {
  {   0, "allContexts" },
  {   1, "selectedContexts" },
  { 0, NULL }
};

static const ber_choice_t T_assertedContexts_choice[] = {
  {   0, &hf_x509if_allContexts  , BER_CLASS_CON, 0, 0, dissect_x509if_NULL },
  {   1, &hf_x509if_selectedContexts, BER_CLASS_CON, 1, 0, dissect_x509if_SET_SIZE_1_MAX_OF_ContextAssertion },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_assertedContexts(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_assertedContexts_choice, hf_index, ett_x509if_T_assertedContexts,
                                 NULL);

  return offset;
}


static const ber_sequence_t AttributeValueAssertion_sequence[] = {
  { &hf_x509if_type_01      , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_type_01 },
  { &hf_x509if_assertion    , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_assertion },
  { &hf_x509if_assertedContexts, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_T_assertedContexts },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_AttributeValueAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	ava_hf_index = hf_index;
	last_ava = (char *)wmem_alloc(actx->pinfo->pool, MAX_AVA_STR_LEN); *last_ava = '\0';
	register_frame_end_routine (actx->pinfo, x509if_frame_end);

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeValueAssertion_sequence, hf_index, ett_x509if_AttributeValueAssertion);


	ava_hf_index=-1;


  return offset;
}



static int
dissect_x509if_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_ContextAssertion_sequence_of[1] = {
  { &hf_x509if_ata_assertedContexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_ContextAssertion_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextAssertion);

  return offset;
}


static const ber_sequence_t AttributeTypeAssertion_sequence[] = {
  { &hf_x509if_type_02      , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_ata_assertedContexts, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextAssertion },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_AttributeTypeAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeTypeAssertion_sequence, hf_index, ett_x509if_AttributeTypeAssertion);

  return offset;
}



static int
dissect_x509if_T_type_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const char *fmt;
  const char *name;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);


  if(actx->external.direct_reference) {
    /* see if we can find a nice name */
    name = oid_resolved_from_string(actx->pinfo->pool, actx->external.direct_reference);
    if(!name) name = actx->external.direct_reference;

    if(last_rdn_buf) { /* append it to the RDN */
      wmem_strbuf_append(last_rdn_buf, name);
      wmem_strbuf_append_c(last_rdn_buf, '=');

     /* append it to the tree */
     proto_item_append_text(tree, " (%s=", name);
    } else if(doing_attr) {
      /* append it to the parent item */
      proto_item_append_text(tree, " (%s)", name);
    }

    if((fmt = val_to_str_const(hf_index, fmt_vals, "")) && *fmt) {
      /* we have a format */
      last_ava = (char *)wmem_alloc(actx->pinfo->pool, MAX_AVA_STR_LEN); *last_ava = '\0';
      register_frame_end_routine (actx->pinfo, x509if_frame_end);

      snprintf(last_ava, MAX_AVA_STR_LEN, "%s %s", name, fmt);

      proto_item_append_text(tree, " %s", last_ava);

    }
  }


  return offset;
}



static int
dissect_x509if_T_atadv_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int old_offset = offset;
  tvbuff_t	*out_tvb;
  char  	*value = NULL;
  const char 	*fmt;
  const char	*name = NULL;
  const char    *orig_oid = actx->external.direct_reference;

  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);

  /* in dissecting the value we may have overridden the OID of the value - which is
     a problem if there are multiple values */
  actx->external.direct_reference = orig_oid;

  /* try and dissect as a string */
  dissect_ber_octet_string(false, actx, NULL, tvb, old_offset, hf_x509if_any_string, &out_tvb);

  /* should also try and dissect as an OID and integer */
  /* of course, if I can look up the syntax .... */

  if(out_tvb) {
    /* it was a string - format it */
    value = tvb_format_text(actx->pinfo->pool, out_tvb, 0, tvb_reported_length(out_tvb));

    if(last_rdn_buf) {
      wmem_strbuf_append(last_rdn_buf, value);

      /* append it to the tree*/
      proto_item_append_text(tree, "%s)", value);
    }

    if((fmt = val_to_str_const(ava_hf_index, fmt_vals, "")) && *fmt) {
      /* we have a format */

      if (!last_ava) {
        last_ava = (char *)wmem_alloc(actx->pinfo->pool, MAX_AVA_STR_LEN);
      }

      if(!(name = oid_resolved_from_string(actx->pinfo->pool, actx->external.direct_reference)))
        name = actx->external.direct_reference;
      snprintf(last_ava, MAX_AVA_STR_LEN, "%s %s %s", name, fmt, value);

      proto_item_append_text(tree, " %s", last_ava);

    }
  }


  return offset;
}



static int
dissect_x509if_T_distingAttrValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t T_valWithContext_item_sequence[] = {
  { &hf_x509if_distingAttrValue, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509if_T_distingAttrValue },
  { &hf_x509if_contextList  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_SET_SIZE_1_MAX_OF_Context },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_valWithContext_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_valWithContext_item_sequence, hf_index, ett_x509if_T_valWithContext_item);

  return offset;
}


static const ber_sequence_t T_valWithContext_set_of[1] = {
  { &hf_x509if_valueswithContext_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_T_valWithContext_item },
};

static int
dissect_x509if_T_valWithContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_valWithContext_set_of, hf_index, ett_x509if_T_valWithContext);

  return offset;
}


static const ber_sequence_t AttributeTypeAndDistinguishedValue_sequence[] = {
  { &hf_x509if_type_03      , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_type_02 },
  { &hf_x509if_atadv_value  , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_atadv_value },
  { &hf_x509if_primaryDistinguished, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_BOOLEAN },
  { &hf_x509if_valueswithContext, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_T_valWithContext },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_AttributeTypeAndDistinguishedValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeTypeAndDistinguishedValue_sequence, hf_index, ett_x509if_AttributeTypeAndDistinguishedValue);

  return offset;
}



static int
dissect_x509if_RelativeDistinguishedName_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  if(!rdn_one_value) {
    top_of_rdn = tree;
  } else {

   if(last_rdn_buf)
     /* this is an additional value - delimit */
     wmem_strbuf_append_c(last_rdn_buf, '+');
  }

    offset = dissect_x509if_AttributeTypeAndDistinguishedValue(implicit_tag, tvb, offset, actx, tree, hf_index);


  rdn_one_value = true;


  return offset;
}


static const ber_sequence_t RelativeDistinguishedName_set_of[1] = {
  { &hf_x509if_RelativeDistinguishedName_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RelativeDistinguishedName_item },
};

int
dissect_x509if_RelativeDistinguishedName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  rdn_one_value = false;
  top_of_rdn = tree;
  last_rdn_buf = wmem_strbuf_new(actx->pinfo->pool, "");
  register_frame_end_routine (actx->pinfo, x509if_frame_end);

    offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 RelativeDistinguishedName_set_of, hf_index, ett_x509if_RelativeDistinguishedName);


  /* we've finished - close the bracket */
  proto_item_append_text(top_of_rdn, " (%s)", wmem_strbuf_get_str(last_rdn_buf));

  /* now append this to the DN */
  if (last_dn_buf) {
    if(wmem_strbuf_get_len(last_dn_buf) > 0) {
      wmem_strbuf_t *temp_dn_buf = wmem_strbuf_new_sized(actx->pinfo->pool, wmem_strbuf_get_len(last_rdn_buf) + wmem_strbuf_get_len(last_dn_buf) + 1);
      wmem_strbuf_append(temp_dn_buf, wmem_strbuf_get_str(last_rdn_buf));
      wmem_strbuf_append_c(temp_dn_buf, ',');
      wmem_strbuf_append(temp_dn_buf, wmem_strbuf_get_str(last_dn_buf));
      wmem_strbuf_destroy(last_dn_buf);
      last_dn_buf = temp_dn_buf;
    } else {
      wmem_strbuf_append(last_dn_buf, wmem_strbuf_get_str(last_rdn_buf));
    }
  }

  last_rdn_buf = NULL; /* it will get freed when the next packet is dissected */


  return offset;
}



static int
dissect_x509if_RDNSequence_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  if(!dn_one_rdn)  {
    /* this is the first element - record the top */
    top_of_dn = tree;
  }

    offset = dissect_x509if_RelativeDistinguishedName(implicit_tag, tvb, offset, actx, tree, hf_index);


  dn_one_rdn = true;


  return offset;
}


static const ber_sequence_t RDNSequence_sequence_of[1] = {
  { &hf_x509if_RDNSequence_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_RDNSequence_item },
};

int
dissect_x509if_RDNSequence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const char *fmt;

  dn_one_rdn = false; /* reset */
  last_dn_buf = wmem_strbuf_new(actx->pinfo->pool, "");
  top_of_dn = NULL;
  register_frame_end_routine (actx->pinfo, x509if_frame_end);


    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RDNSequence_sequence_of, hf_index, ett_x509if_RDNSequence);


  /* we've finished - append the dn */
  proto_item_append_text(top_of_dn, " (%s)", wmem_strbuf_get_str(last_dn_buf));

 /* see if we should append this to the col info */
  if((fmt = val_to_str_const(hf_index, fmt_vals, "")) && *fmt) {
    /* we have a format */
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s%s", fmt, wmem_strbuf_get_str(last_dn_buf));
  }



  return offset;
}


const value_string x509if_Name_vals[] = {
  {   0, "rdnSequence" },
  { 0, NULL }
};

static const ber_choice_t Name_choice[] = {
  {   0, &hf_x509if_rdnSequence  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RDNSequence },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Name_choice, hf_index, ett_x509if_Name,
                                 NULL);

  return offset;
}



int
dissect_x509if_DistinguishedName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509if_RDNSequence(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x509if_LocalName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509if_RDNSequence(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string x509if_T_specificExclusions_item_vals[] = {
  {   0, "chopBefore" },
  {   1, "chopAfter" },
  { 0, NULL }
};

static const ber_choice_t T_specificExclusions_item_choice[] = {
  {   0, &hf_x509if_chopBefore   , BER_CLASS_CON, 0, 0, dissect_x509if_LocalName },
  {   1, &hf_x509if_chopAfter    , BER_CLASS_CON, 1, 0, dissect_x509if_LocalName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_specificExclusions_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_specificExclusions_item_choice, hf_index, ett_x509if_T_specificExclusions_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_specificExclusions_set_of[1] = {
  { &hf_x509if_specificExclusions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_T_specificExclusions_item },
};

static int
dissect_x509if_T_specificExclusions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_specificExclusions_set_of, hf_index, ett_x509if_T_specificExclusions);

  return offset;
}



static int
dissect_x509if_BaseDistance(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Refinement_set_of[1] = {
  { &hf_x509if_refinement_and_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_Refinement },
};

static int
dissect_x509if_SET_OF_Refinement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Refinement_set_of, hf_index, ett_x509if_SET_OF_Refinement);

  return offset;
}


const value_string x509if_Refinement_vals[] = {
  {   0, "item" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t Refinement_choice[] = {
  {   0, &hf_x509if_item         , BER_CLASS_CON, 0, 0, dissect_x509if_OBJECT_IDENTIFIER },
  {   1, &hf_x509if_refinement_and, BER_CLASS_CON, 1, 0, dissect_x509if_SET_OF_Refinement },
  {   2, &hf_x509if_refinement_or, BER_CLASS_CON, 2, 0, dissect_x509if_SET_OF_Refinement },
  {   3, &hf_x509if_refinement_not, BER_CLASS_CON, 3, 0, dissect_x509if_Refinement },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_Refinement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // Refinement -> Refinement/and -> Refinement
  actx->pinfo->dissection_depth += 2;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Refinement_choice, hf_index, ett_x509if_Refinement,
                                 NULL);

  actx->pinfo->dissection_depth -= 2;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t SubtreeSpecification_sequence[] = {
  { &hf_x509if_base         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509if_LocalName },
  { &hf_x509if_specificExclusions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_T_specificExclusions },
  { &hf_x509if_minimum      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_BaseDistance },
  { &hf_x509if_maximum      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509if_BaseDistance },
  { &hf_x509if_specificationFilter, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_x509if_Refinement },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_SubtreeSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubtreeSpecification_sequence, hf_index, ett_x509if_SubtreeSpecification);

  return offset;
}


static const value_string x509if_T_chopSpecificExclusions_item_vals[] = {
  {   0, "chopBefore" },
  {   1, "chopAfter" },
  { 0, NULL }
};

static const ber_choice_t T_chopSpecificExclusions_item_choice[] = {
  {   0, &hf_x509if_chopBefore   , BER_CLASS_CON, 0, 0, dissect_x509if_LocalName },
  {   1, &hf_x509if_chopAfter    , BER_CLASS_CON, 1, 0, dissect_x509if_LocalName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_chopSpecificExclusions_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_chopSpecificExclusions_item_choice, hf_index, ett_x509if_T_chopSpecificExclusions_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_chopSpecificExclusions_set_of[1] = {
  { &hf_x509if_chopSpecificExclusions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_T_chopSpecificExclusions_item },
};

static int
dissect_x509if_T_chopSpecificExclusions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_chopSpecificExclusions_set_of, hf_index, ett_x509if_T_chopSpecificExclusions);

  return offset;
}


static const ber_sequence_t ChopSpecification_sequence[] = {
  { &hf_x509if_chopSpecificExclusions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_T_chopSpecificExclusions },
  { &hf_x509if_minimum      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_BaseDistance },
  { &hf_x509if_maximum      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509if_BaseDistance },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_ChopSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChopSpecification_sequence, hf_index, ett_x509if_ChopSpecification);

  return offset;
}


const value_string x509if_AttributeUsage_vals[] = {
  {   0, "userApplications" },
  {   1, "directoryOperation" },
  {   2, "distributedOperation" },
  {   3, "dSAOperation" },
  { 0, NULL }
};


int
dissect_x509if_AttributeUsage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



int
dissect_x509if_RuleIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_RuleIdentifier_set_of[1] = {
  { &hf_x509if_superiorStructureRules_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509if_RuleIdentifier },
};

static int
dissect_x509if_SET_SIZE_1_MAX_OF_RuleIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_RuleIdentifier_set_of, hf_index, ett_x509if_SET_SIZE_1_MAX_OF_RuleIdentifier);

  return offset;
}


static const ber_sequence_t DITStructureRule_sequence[] = {
  { &hf_x509if_ruleIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509if_RuleIdentifier },
  { &hf_x509if_nameForm     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_superiorStructureRules, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_SET_SIZE_1_MAX_OF_RuleIdentifier },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_DITStructureRule(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DITStructureRule_sequence, hf_index, ett_x509if_DITStructureRule);

  return offset;
}


static const ber_sequence_t T_auxiliaries_set_of[1] = {
  { &hf_x509if_auxiliaries_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_auxiliaries(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_auxiliaries_set_of, hf_index, ett_x509if_T_auxiliaries);

  return offset;
}


static const ber_sequence_t T_mandatory_set_of[1] = {
  { &hf_x509if_mandatory_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_mandatory(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_mandatory_set_of, hf_index, ett_x509if_T_mandatory);

  return offset;
}


static const ber_sequence_t T_optional_set_of[1] = {
  { &hf_x509if_optional_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_optional(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_optional_set_of, hf_index, ett_x509if_T_optional);

  return offset;
}


static const ber_sequence_t T_precluded_set_of[1] = {
  { &hf_x509if_precluded_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_precluded(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_precluded_set_of, hf_index, ett_x509if_T_precluded);

  return offset;
}


static const ber_sequence_t DITContentRule_sequence[] = {
  { &hf_x509if_structuralObjectClass, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_auxiliaries  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_T_auxiliaries },
  { &hf_x509if_mandatory    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_T_mandatory },
  { &hf_x509if_optional     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_T_optional },
  { &hf_x509if_precluded    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509if_T_precluded },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_DITContentRule(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DITContentRule_sequence, hf_index, ett_x509if_DITContentRule);

  return offset;
}


static const ber_sequence_t T_mandatoryContexts_set_of[1] = {
  { &hf_x509if_mandatoryContexts_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_mandatoryContexts(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_mandatoryContexts_set_of, hf_index, ett_x509if_T_mandatoryContexts);

  return offset;
}


static const ber_sequence_t T_optionalContexts_set_of[1] = {
  { &hf_x509if_optionalContexts_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_optionalContexts(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_optionalContexts_set_of, hf_index, ett_x509if_T_optionalContexts);

  return offset;
}


static const ber_sequence_t DITContextUse_sequence[] = {
  { &hf_x509if_attributeType, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_mandatoryContexts, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_T_mandatoryContexts },
  { &hf_x509if_optionalContexts, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_T_optionalContexts },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_DITContextUse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DITContextUse_sequence, hf_index, ett_x509if_DITContextUse);

  return offset;
}



static int
dissect_x509if_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x509if_T_attributeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509if_T_ra_selectedValues_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t T_ra_selectedValues_sequence_of[1] = {
  { &hf_x509if_ra_selectedValues_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_ra_selectedValues_item },
};

static int
dissect_x509if_T_ra_selectedValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_ra_selectedValues_sequence_of, hf_index, ett_x509if_T_ra_selectedValues);

  return offset;
}



static int
dissect_x509if_T_entryType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509if_T_ra_values_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t T_ra_values_sequence_of[1] = {
  { &hf_x509if_ra_values_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_ra_values_item },
};

static int
dissect_x509if_T_ra_values(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_ra_values_sequence_of, hf_index, ett_x509if_T_ra_values);

  return offset;
}


static const ber_sequence_t T_defaultValues_item_sequence[] = {
  { &hf_x509if_entryType    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_T_entryType },
  { &hf_x509if_ra_values    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_T_ra_values },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_defaultValues_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_defaultValues_item_sequence, hf_index, ett_x509if_T_defaultValues_item);

  return offset;
}


static const ber_sequence_t T_defaultValues_sequence_of[1] = {
  { &hf_x509if_defaultValues_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_T_defaultValues_item },
};

static int
dissect_x509if_T_defaultValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_defaultValues_sequence_of, hf_index, ett_x509if_T_defaultValues);

  return offset;
}



static int
dissect_x509if_T_contextType_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509if_T_contextValue_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t T_contextValue_sequence_of[1] = {
  { &hf_x509if_contextValue_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_contextValue_item },
};

static int
dissect_x509if_T_contextValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_contextValue_sequence_of, hf_index, ett_x509if_T_contextValue);

  return offset;
}


static const ber_sequence_t ContextProfile_sequence[] = {
  { &hf_x509if_contextType_01, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_contextType_01 },
  { &hf_x509if_contextValue , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_T_contextValue },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_ContextProfile(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContextProfile_sequence, hf_index, ett_x509if_ContextProfile);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_0_MAX_OF_ContextProfile_sequence_of[1] = {
  { &hf_x509if_contexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextProfile },
};

static int
dissect_x509if_SEQUENCE_SIZE_0_MAX_OF_ContextProfile(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_0_MAX_OF_ContextProfile_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_0_MAX_OF_ContextProfile);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ContextCombination_sequence_of[1] = {
  { &hf_x509if_contextcombination_and_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_ContextCombination },
};

static int
dissect_x509if_SEQUENCE_OF_ContextCombination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ContextCombination_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_ContextCombination);

  return offset;
}


const value_string x509if_ContextCombination_vals[] = {
  {   0, "context" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t ContextCombination_choice[] = {
  {   0, &hf_x509if_context      , BER_CLASS_CON, 0, 0, dissect_x509if_OBJECT_IDENTIFIER },
  {   1, &hf_x509if_contextcombination_and, BER_CLASS_CON, 1, 0, dissect_x509if_SEQUENCE_OF_ContextCombination },
  {   2, &hf_x509if_contextcombination_or, BER_CLASS_CON, 2, 0, dissect_x509if_SEQUENCE_OF_ContextCombination },
  {   3, &hf_x509if_contextcombination_not, BER_CLASS_CON, 3, 0, dissect_x509if_ContextCombination },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_ContextCombination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // ContextCombination -> ContextCombination/and -> ContextCombination
  actx->pinfo->dissection_depth += 2;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ContextCombination_choice, hf_index, ett_x509if_ContextCombination,
                                 NULL);

  actx->pinfo->dissection_depth -= 2;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}



static int
dissect_x509if_T_restrictionType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509if_T_restrictionValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t MatchingUse_sequence[] = {
  { &hf_x509if_restrictionType, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_restrictionType },
  { &hf_x509if_restrictionValue, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_restrictionValue },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_MatchingUse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MatchingUse_sequence, hf_index, ett_x509if_MatchingUse);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_MatchingUse_sequence_of[1] = {
  { &hf_x509if_matchingUse_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_MatchingUse },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MatchingUse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_MatchingUse_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MatchingUse);

  return offset;
}


static const ber_sequence_t RequestAttribute_sequence[] = {
  { &hf_x509if_attributeType_01, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_attributeType },
  { &hf_x509if_includeSubtypes, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509if_BOOLEAN },
  { &hf_x509if_ra_selectedValues, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_T_ra_selectedValues },
  { &hf_x509if_defaultValues, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_T_defaultValues },
  { &hf_x509if_contexts     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_0_MAX_OF_ContextProfile },
  { &hf_x509if_contextCombination, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_x509if_ContextCombination },
  { &hf_x509if_matchingUse  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MatchingUse },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_RequestAttribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestAttribute_sequence, hf_index, ett_x509if_RequestAttribute);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_0_MAX_OF_RequestAttribute_sequence_of[1] = {
  { &hf_x509if_inputAttributeTypes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RequestAttribute },
};

static int
dissect_x509if_SEQUENCE_SIZE_0_MAX_OF_RequestAttribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_0_MAX_OF_RequestAttribute_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_0_MAX_OF_RequestAttribute);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeCombination_sequence_of[1] = {
  { &hf_x509if_and_item     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_AttributeCombination },
};

static int
dissect_x509if_SEQUENCE_OF_AttributeCombination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeCombination_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_AttributeCombination);

  return offset;
}


const value_string x509if_AttributeCombination_vals[] = {
  {   0, "attribute" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t AttributeCombination_choice[] = {
  {   0, &hf_x509if_attribute    , BER_CLASS_CON, 0, 0, dissect_x509if_AttributeType },
  {   1, &hf_x509if_and          , BER_CLASS_CON, 1, 0, dissect_x509if_SEQUENCE_OF_AttributeCombination },
  {   2, &hf_x509if_or           , BER_CLASS_CON, 2, 0, dissect_x509if_SEQUENCE_OF_AttributeCombination },
  {   3, &hf_x509if_not          , BER_CLASS_CON, 3, 0, dissect_x509if_AttributeCombination },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_AttributeCombination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // AttributeCombination -> AttributeCombination/and -> AttributeCombination
  actx->pinfo->dissection_depth += 2;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AttributeCombination_choice, hf_index, ett_x509if_AttributeCombination,
                                 NULL);

  actx->pinfo->dissection_depth -= 2;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}



static int
dissect_x509if_T_attributeType_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509if_T_selectedValues_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t T_selectedValues_sequence_of[1] = {
  { &hf_x509if_selectedValues_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_selectedValues_item },
};

static int
dissect_x509if_T_selectedValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_selectedValues_sequence_of, hf_index, ett_x509if_T_selectedValues);

  return offset;
}


static const value_string x509if_T_outputValues_vals[] = {
  {   0, "selectedValues" },
  {   1, "matchedValuesOnly" },
  { 0, NULL }
};

static const ber_choice_t T_outputValues_choice[] = {
  {   0, &hf_x509if_selectedValues, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_T_selectedValues },
  {   1, &hf_x509if_matchedValuesOnly, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_x509if_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_outputValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_outputValues_choice, hf_index, ett_x509if_T_outputValues,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_ContextProfile_sequence_of[1] = {
  { &hf_x509if_contexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextProfile },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextProfile(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_ContextProfile_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextProfile);

  return offset;
}


static const ber_sequence_t ResultAttribute_sequence[] = {
  { &hf_x509if_attributeType_02, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_attributeType_01 },
  { &hf_x509if_outputValues , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_T_outputValues },
  { &hf_x509if_contexts_01  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextProfile },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_ResultAttribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResultAttribute_sequence, hf_index, ett_x509if_ResultAttribute);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_ResultAttribute_sequence_of[1] = {
  { &hf_x509if_outputAttributeTypes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ResultAttribute },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ResultAttribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_ResultAttribute_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ResultAttribute);

  return offset;
}


static const ber_sequence_t ControlOptions_sequence[] = {
  { &hf_x509if_serviceControls, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dap_ServiceControlOptions },
  { &hf_x509if_searchOptions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dap_SearchControlOptions },
  { &hf_x509if_hierarchyOptions, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dap_HierarchySelections },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_ControlOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ControlOptions_sequence, hf_index, ett_x509if_ControlOptions);

  return offset;
}


static const ber_sequence_t Mapping_sequence[] = {
  { &hf_x509if_mappingFunction, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_level        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_Mapping(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Mapping_sequence, hf_index, ett_x509if_Mapping);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_Mapping_sequence_of[1] = {
  { &hf_x509if_mapping_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Mapping },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_Mapping(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_Mapping_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_1_MAX_OF_Mapping);

  return offset;
}


static const ber_sequence_t MRSubstitution_sequence[] = {
  { &hf_x509if_attribute    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  { &hf_x509if_oldMatchingRule, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_newMatchingRule, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_OBJECT_IDENTIFIER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_MRSubstitution(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MRSubstitution_sequence, hf_index, ett_x509if_MRSubstitution);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_MRSubstitution_sequence_of[1] = {
  { &hf_x509if_substitution_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_MRSubstitution },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MRSubstitution(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_MRSubstitution_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MRSubstitution);

  return offset;
}


static const ber_sequence_t MRMapping_sequence[] = {
  { &hf_x509if_mapping      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_Mapping },
  { &hf_x509if_substitution , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MRSubstitution },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_MRMapping(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MRMapping_sequence, hf_index, ett_x509if_MRMapping);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_MRMapping_sequence_of[1] = {
  { &hf_x509if_tightenings_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_MRMapping },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MRMapping(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_MRMapping_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MRMapping);

  return offset;
}


static const ber_sequence_t RelaxationPolicy_sequence[] = {
  { &hf_x509if_basic        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509if_MRMapping },
  { &hf_x509if_tightenings  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MRMapping },
  { &hf_x509if_relaxations  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MRMapping },
  { &hf_x509if_maximum_relaxation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509if_INTEGER },
  { &hf_x509if_minimum_relaxation, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_x509if_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_RelaxationPolicy(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RelaxationPolicy_sequence, hf_index, ett_x509if_RelaxationPolicy);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_AttributeType_sequence_of[1] = {
  { &hf_x509if_additionalControl_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_AttributeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_AttributeType_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_1_MAX_OF_AttributeType);

  return offset;
}


static int * const AllowedSubset_bits[] = {
  &hf_x509if_AllowedSubset_baseObject,
  &hf_x509if_AllowedSubset_oneLevel,
  &hf_x509if_AllowedSubset_wholeSubtree,
  NULL
};

int
dissect_x509if_AllowedSubset(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    AllowedSubset_bits, 3, hf_index, ett_x509if_AllowedSubset,
                                    NULL);

  return offset;
}


const value_string x509if_ImposedSubset_vals[] = {
  {   0, "baseObject" },
  {   1, "oneLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


int
dissect_x509if_ImposedSubset(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t EntryLimit_sequence[] = {
  { &hf_x509if_default      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509if_INTEGER },
  { &hf_x509if_max          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509if_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_EntryLimit(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EntryLimit_sequence, hf_index, ett_x509if_EntryLimit);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_DirectoryString_set_of[1] = {
  { &hf_x509if_name_item    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509sat_DirectoryString },
};

static int
dissect_x509if_SET_SIZE_1_MAX_OF_DirectoryString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_DirectoryString_set_of, hf_index, ett_x509if_SET_SIZE_1_MAX_OF_DirectoryString);

  return offset;
}


static const ber_sequence_t SearchRuleDescription_sequence[] = {
  { &hf_x509if_id           , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509if_INTEGER },
  { &hf_x509if_dmdId        , BER_CLASS_CON, 0, 0, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_serviceType  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_userClass    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_INTEGER },
  { &hf_x509if_inputAttributeTypes, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_0_MAX_OF_RequestAttribute },
  { &hf_x509if_attributeCombination, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_x509if_AttributeCombination },
  { &hf_x509if_outputAttributeTypes, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ResultAttribute },
  { &hf_x509if_defaultControls, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_x509if_ControlOptions },
  { &hf_x509if_mandatoryControls, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_x509if_ControlOptions },
  { &hf_x509if_searchRuleControls, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_x509if_ControlOptions },
  { &hf_x509if_familyGrouping, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { &hf_x509if_familyReturn , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_dap_FamilyReturn },
  { &hf_x509if_relaxation   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_x509if_RelaxationPolicy },
  { &hf_x509if_additionalControl, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_AttributeType },
  { &hf_x509if_allowedSubset, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_x509if_AllowedSubset },
  { &hf_x509if_imposedSubset, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_x509if_ImposedSubset },
  { &hf_x509if_entryLimit   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL, dissect_x509if_EntryLimit },
  { &hf_x509if_name         , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_x509if_SET_SIZE_1_MAX_OF_DirectoryString },
  { &hf_x509if_description  , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509sat_DirectoryString },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_SearchRuleDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchRuleDescription_sequence, hf_index, ett_x509if_SearchRuleDescription);

  return offset;
}



static int
dissect_x509if_HierarchyLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x509if_HierarchyBelow(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SearchRule_sequence[] = {
  { &hf_x509if_id           , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509if_INTEGER },
  { &hf_x509if_dmdId        , BER_CLASS_CON, 0, 0, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_serviceType  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_OBJECT_IDENTIFIER },
  { &hf_x509if_userClass    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509if_INTEGER },
  { &hf_x509if_inputAttributeTypes, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_0_MAX_OF_RequestAttribute },
  { &hf_x509if_attributeCombination, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_x509if_AttributeCombination },
  { &hf_x509if_outputAttributeTypes, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ResultAttribute },
  { &hf_x509if_defaultControls, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_x509if_ControlOptions },
  { &hf_x509if_mandatoryControls, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_x509if_ControlOptions },
  { &hf_x509if_searchRuleControls, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_x509if_ControlOptions },
  { &hf_x509if_familyGrouping, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_dap_FamilyGrouping },
  { &hf_x509if_familyReturn , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_dap_FamilyReturn },
  { &hf_x509if_relaxation   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_x509if_RelaxationPolicy },
  { &hf_x509if_additionalControl, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_AttributeType },
  { &hf_x509if_allowedSubset, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_x509if_AllowedSubset },
  { &hf_x509if_imposedSubset, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_x509if_ImposedSubset },
  { &hf_x509if_entryLimit   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL, dissect_x509if_EntryLimit },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_SearchRule(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchRule_sequence, hf_index, ett_x509if_SearchRule);

  return offset;
}


static const ber_sequence_t SearchRuleId_sequence[] = {
  { &hf_x509if_id           , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509if_INTEGER },
  { &hf_x509if_dmdId        , BER_CLASS_CON, 0, 0, dissect_x509if_OBJECT_IDENTIFIER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_SearchRuleId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchRuleId_sequence, hf_index, ett_x509if_SearchRuleId);

  return offset;
}

/*--- PDUs ---*/

static int dissect_DistinguishedName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509if_DistinguishedName(false, tvb, offset, &asn1_ctx, tree, hf_x509if_DistinguishedName_PDU);
  return offset;
}
static int dissect_SubtreeSpecification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509if_SubtreeSpecification(false, tvb, offset, &asn1_ctx, tree, hf_x509if_SubtreeSpecification_PDU);
  return offset;
}
static int dissect_HierarchyLevel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509if_HierarchyLevel(false, tvb, offset, &asn1_ctx, tree, hf_x509if_HierarchyLevel_PDU);
  return offset;
}
static int dissect_HierarchyBelow_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509if_HierarchyBelow(false, tvb, offset, &asn1_ctx, tree, hf_x509if_HierarchyBelow_PDU);
  return offset;
}


const char * x509if_get_last_dn(void)
{
  return last_dn_buf ? wmem_strbuf_get_str(last_dn_buf) : NULL;
}

bool x509if_register_fmt(int hf_index, const char *fmt)
{
  static int idx = 0;

  if(idx < (MAX_FMT_VALS - 1)) {

    fmt_vals[idx].value = hf_index;
    fmt_vals[idx].strptr = fmt;

    idx++;

    fmt_vals[idx].value = 0;
    fmt_vals[idx].strptr = NULL;

    return true;

  } else
    return false; /* couldn't register it */

}

const char * x509if_get_last_ava(void)
{
  return last_ava;
}

/*--- proto_register_x509if ----------------------------------------------*/
void proto_register_x509if(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509if_object_identifier_id,
      { "Object Id", "x509if.oid", FT_OID, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},
    { &hf_x509if_any_string,
      { "AnyString", "x509if.any.String", FT_BYTES, BASE_NONE,
	    NULL, 0, "This is any String", HFILL }},

    { &hf_x509if_DistinguishedName_PDU,
      { "DistinguishedName", "x509if.DistinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_SubtreeSpecification_PDU,
      { "SubtreeSpecification", "x509if.SubtreeSpecification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_HierarchyLevel_PDU,
      { "HierarchyLevel", "x509if.HierarchyLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_HierarchyBelow_PDU,
      { "HierarchyBelow", "x509if.HierarchyBelow",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_type,
      { "type", "x509if.type",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_values,
      { "values", "x509if.values",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_values_item,
      { "values item", "x509if.values_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_valuesWithContext,
      { "valuesWithContext", "x509if.valuesWithContext",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_valuesWithContext_item,
      { "valuesWithContext item", "x509if.valuesWithContext_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_valuesWithContext_item", HFILL }},
    { &hf_x509if_value,
      { "value", "x509if.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contextList,
      { "contextList", "x509if.contextList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_Context", HFILL }},
    { &hf_x509if_contextList_item,
      { "Context", "x509if.Context_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contextType,
      { "contextType", "x509if.contextType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contextValues,
      { "contextValues", "x509if.contextValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contextValues_item,
      { "contextValues item", "x509if.contextValues_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_fallback,
      { "fallback", "x509if.fallback",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509if_type_01,
      { "type", "x509if.type",
        FT_OID, BASE_NONE, NULL, 0,
        "T_type_01", HFILL }},
    { &hf_x509if_assertion,
      { "assertion", "x509if.assertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_assertedContexts,
      { "assertedContexts", "x509if.assertedContexts",
        FT_UINT32, BASE_DEC, VALS(x509if_T_assertedContexts_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_allContexts,
      { "allContexts", "x509if.allContexts_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_selectedContexts,
      { "selectedContexts", "x509if.selectedContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_ContextAssertion", HFILL }},
    { &hf_x509if_selectedContexts_item,
      { "ContextAssertion", "x509if.ContextAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_ca_contextType,
      { "contextType", "x509if.contextType",
        FT_OID, BASE_NONE, NULL, 0,
        "T_ca_contextType", HFILL }},
    { &hf_x509if_ca_contextValues,
      { "contextValues", "x509if.contextValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_ca_contextValues", HFILL }},
    { &hf_x509if_ca_contextValues_item,
      { "contextValues item", "x509if.contextValues_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ca_contextValues_item", HFILL }},
    { &hf_x509if_type_02,
      { "type", "x509if.type",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_ata_assertedContexts,
      { "assertedContexts", "x509if.assertedContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_ContextAssertion", HFILL }},
    { &hf_x509if_ata_assertedContexts_item,
      { "ContextAssertion", "x509if.ContextAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_rdnSequence,
      { "rdnSequence", "x509if.rdnSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_RDNSequence_item,
      { "RDNSequence item", "x509if.RDNSequence_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_RelativeDistinguishedName_item,
      { "RelativeDistinguishedName item", "x509if.RelativeDistinguishedName_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_type_03,
      { "type", "x509if.type",
        FT_OID, BASE_NONE, NULL, 0,
        "T_type_02", HFILL }},
    { &hf_x509if_atadv_value,
      { "value", "x509if.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_atadv_value", HFILL }},
    { &hf_x509if_primaryDistinguished,
      { "primaryDistinguished", "x509if.primaryDistinguished",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509if_valueswithContext,
      { "valuesWithContext", "x509if.valuesWithContext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_valWithContext", HFILL }},
    { &hf_x509if_valueswithContext_item,
      { "valuesWithContext item", "x509if.valuesWithContext_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_valWithContext_item", HFILL }},
    { &hf_x509if_distingAttrValue,
      { "distingAttrValue", "x509if.distingAttrValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_chopSpecificExclusions,
      { "specificExclusions", "x509if.specificExclusions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_chopSpecificExclusions", HFILL }},
    { &hf_x509if_chopSpecificExclusions_item,
      { "specificExclusions item", "x509if.specificExclusions_item",
        FT_UINT32, BASE_DEC, VALS(x509if_T_chopSpecificExclusions_item_vals), 0,
        "T_chopSpecificExclusions_item", HFILL }},
    { &hf_x509if_chopBefore,
      { "chopBefore", "x509if.chopBefore",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocalName", HFILL }},
    { &hf_x509if_chopAfter,
      { "chopAfter", "x509if.chopAfter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocalName", HFILL }},
    { &hf_x509if_minimum,
      { "minimum", "x509if.minimum",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BaseDistance", HFILL }},
    { &hf_x509if_maximum,
      { "maximum", "x509if.maximum",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BaseDistance", HFILL }},
    { &hf_x509if_item,
      { "item", "x509if.item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_refinement_and,
      { "and", "x509if.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Refinement", HFILL }},
    { &hf_x509if_refinement_and_item,
      { "Refinement", "x509if.Refinement",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_refinement_or,
      { "or", "x509if.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Refinement", HFILL }},
    { &hf_x509if_refinement_or_item,
      { "Refinement", "x509if.Refinement",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_refinement_not,
      { "not", "x509if.not",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        "Refinement", HFILL }},
    { &hf_x509if_ruleIdentifier,
      { "ruleIdentifier", "x509if.ruleIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_nameForm,
      { "nameForm", "x509if.nameForm",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_superiorStructureRules,
      { "superiorStructureRules", "x509if.superiorStructureRules",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_RuleIdentifier", HFILL }},
    { &hf_x509if_superiorStructureRules_item,
      { "RuleIdentifier", "x509if.RuleIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_structuralObjectClass,
      { "structuralObjectClass", "x509if.structuralObjectClass",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_auxiliaries,
      { "auxiliaries", "x509if.auxiliaries",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_auxiliaries_item,
      { "auxiliaries item", "x509if.auxiliaries_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_mandatory,
      { "mandatory", "x509if.mandatory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_mandatory_item,
      { "mandatory item", "x509if.mandatory_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_optional,
      { "optional", "x509if.optional",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_optional_item,
      { "optional item", "x509if.optional_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_precluded,
      { "precluded", "x509if.precluded",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_precluded_item,
      { "precluded item", "x509if.precluded_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_attributeType,
      { "attributeType", "x509if.attributeType",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_mandatoryContexts,
      { "mandatoryContexts", "x509if.mandatoryContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_mandatoryContexts_item,
      { "mandatoryContexts item", "x509if.mandatoryContexts_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_optionalContexts,
      { "optionalContexts", "x509if.optionalContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_optionalContexts_item,
      { "optionalContexts item", "x509if.optionalContexts_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_id,
      { "id", "x509if.id",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509if_dmdId,
      { "dmdId", "x509if.dmdId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_attributeType_01,
      { "attributeType", "x509if.attributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_includeSubtypes,
      { "includeSubtypes", "x509if.includeSubtypes",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509if_ra_selectedValues,
      { "selectedValues", "x509if.selectedValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_ra_selectedValues", HFILL }},
    { &hf_x509if_ra_selectedValues_item,
      { "selectedValues item", "x509if.selectedValues_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ra_selectedValues_item", HFILL }},
    { &hf_x509if_defaultValues,
      { "defaultValues", "x509if.defaultValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_defaultValues_item,
      { "defaultValues item", "x509if.defaultValues_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_entryType,
      { "entryType", "x509if.entryType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_ra_values,
      { "values", "x509if.values",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_ra_values", HFILL }},
    { &hf_x509if_ra_values_item,
      { "values item", "x509if.values_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ra_values_item", HFILL }},
    { &hf_x509if_contexts,
      { "contexts", "x509if.contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_MAX_OF_ContextProfile", HFILL }},
    { &hf_x509if_contexts_item,
      { "ContextProfile", "x509if.ContextProfile_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contextCombination,
      { "contextCombination", "x509if.contextCombination",
        FT_UINT32, BASE_DEC, VALS(x509if_ContextCombination_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_matchingUse,
      { "matchingUse", "x509if.matchingUse",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_MatchingUse", HFILL }},
    { &hf_x509if_matchingUse_item,
      { "MatchingUse", "x509if.MatchingUse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contextType_01,
      { "contextType", "x509if.contextType",
        FT_OID, BASE_NONE, NULL, 0,
        "T_contextType_01", HFILL }},
    { &hf_x509if_contextValue,
      { "contextValue", "x509if.contextValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contextValue_item,
      { "contextValue item", "x509if.contextValue_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_context,
      { "context", "x509if.context",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_contextcombination_and,
      { "and", "x509if.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ContextCombination", HFILL }},
    { &hf_x509if_contextcombination_and_item,
      { "ContextCombination", "x509if.ContextCombination",
        FT_UINT32, BASE_DEC, VALS(x509if_ContextCombination_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_contextcombination_or,
      { "or", "x509if.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ContextCombination", HFILL }},
    { &hf_x509if_contextcombination_or_item,
      { "ContextCombination", "x509if.ContextCombination",
        FT_UINT32, BASE_DEC, VALS(x509if_ContextCombination_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_contextcombination_not,
      { "not", "x509if.not",
        FT_UINT32, BASE_DEC, VALS(x509if_ContextCombination_vals), 0,
        "ContextCombination", HFILL }},
    { &hf_x509if_restrictionType,
      { "restrictionType", "x509if.restrictionType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_restrictionValue,
      { "restrictionValue", "x509if.restrictionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_attribute,
      { "attribute", "x509if.attribute",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_x509if_and,
      { "and", "x509if.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeCombination", HFILL }},
    { &hf_x509if_and_item,
      { "AttributeCombination", "x509if.AttributeCombination",
        FT_UINT32, BASE_DEC, VALS(x509if_AttributeCombination_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_or,
      { "or", "x509if.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeCombination", HFILL }},
    { &hf_x509if_or_item,
      { "AttributeCombination", "x509if.AttributeCombination",
        FT_UINT32, BASE_DEC, VALS(x509if_AttributeCombination_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_not,
      { "not", "x509if.not",
        FT_UINT32, BASE_DEC, VALS(x509if_AttributeCombination_vals), 0,
        "AttributeCombination", HFILL }},
    { &hf_x509if_attributeType_02,
      { "attributeType", "x509if.attributeType",
        FT_OID, BASE_NONE, NULL, 0,
        "T_attributeType_01", HFILL }},
    { &hf_x509if_outputValues,
      { "outputValues", "x509if.outputValues",
        FT_UINT32, BASE_DEC, VALS(x509if_T_outputValues_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_selectedValues,
      { "selectedValues", "x509if.selectedValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_selectedValues_item,
      { "selectedValues item", "x509if.selectedValues_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_matchedValuesOnly,
      { "matchedValuesOnly", "x509if.matchedValuesOnly_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contexts_01,
      { "contexts", "x509if.contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_ContextProfile", HFILL }},
    { &hf_x509if_serviceControls,
      { "serviceControls", "x509if.serviceControls_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlOptions", HFILL }},
    { &hf_x509if_searchOptions,
      { "searchOptions", "x509if.searchOptions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchControlOptions", HFILL }},
    { &hf_x509if_hierarchyOptions,
      { "hierarchyOptions", "x509if.hierarchyOptions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HierarchySelections", HFILL }},
    { &hf_x509if_default,
      { "default", "x509if.default",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509if_max,
      { "max", "x509if.max",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509if_basic,
      { "basic", "x509if.basic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MRMapping", HFILL }},
    { &hf_x509if_tightenings,
      { "tightenings", "x509if.tightenings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_MRMapping", HFILL }},
    { &hf_x509if_tightenings_item,
      { "MRMapping", "x509if.MRMapping_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_relaxations,
      { "relaxations", "x509if.relaxations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_MRMapping", HFILL }},
    { &hf_x509if_relaxations_item,
      { "MRMapping", "x509if.MRMapping_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_maximum_relaxation,
      { "maximum", "x509if.maximum",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509if_minimum_relaxation,
      { "minimum", "x509if.minimum",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509if_mapping,
      { "mapping", "x509if.mapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_Mapping", HFILL }},
    { &hf_x509if_mapping_item,
      { "Mapping", "x509if.Mapping_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_substitution,
      { "substitution", "x509if.substitution",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_MRSubstitution", HFILL }},
    { &hf_x509if_substitution_item,
      { "MRSubstitution", "x509if.MRSubstitution_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_mappingFunction,
      { "mappingFunction", "x509if.mappingFunction",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_level,
      { "level", "x509if.level",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509if_oldMatchingRule,
      { "oldMatchingRule", "x509if.oldMatchingRule",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_newMatchingRule,
      { "newMatchingRule", "x509if.newMatchingRule",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_base,
      { "base", "x509if.base",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocalName", HFILL }},
    { &hf_x509if_specificExclusions,
      { "specificExclusions", "x509if.specificExclusions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_specificExclusions_item,
      { "specificExclusions item", "x509if.specificExclusions_item",
        FT_UINT32, BASE_DEC, VALS(x509if_T_specificExclusions_item_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_specificationFilter,
      { "specificationFilter", "x509if.specificationFilter",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        "Refinement", HFILL }},
    { &hf_x509if_serviceType,
      { "serviceType", "x509if.serviceType",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509if_userClass,
      { "userClass", "x509if.userClass",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509if_inputAttributeTypes,
      { "inputAttributeTypes", "x509if.inputAttributeTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_MAX_OF_RequestAttribute", HFILL }},
    { &hf_x509if_inputAttributeTypes_item,
      { "RequestAttribute", "x509if.RequestAttribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_attributeCombination,
      { "attributeCombination", "x509if.attributeCombination",
        FT_UINT32, BASE_DEC, VALS(x509if_AttributeCombination_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_outputAttributeTypes,
      { "outputAttributeTypes", "x509if.outputAttributeTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_ResultAttribute", HFILL }},
    { &hf_x509if_outputAttributeTypes_item,
      { "ResultAttribute", "x509if.ResultAttribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_defaultControls,
      { "defaultControls", "x509if.defaultControls_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlOptions", HFILL }},
    { &hf_x509if_mandatoryControls,
      { "mandatoryControls", "x509if.mandatoryControls_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlOptions", HFILL }},
    { &hf_x509if_searchRuleControls,
      { "searchRuleControls", "x509if.searchRuleControls_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlOptions", HFILL }},
    { &hf_x509if_familyGrouping,
      { "familyGrouping", "x509if.familyGrouping_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_familyReturn,
      { "familyReturn", "x509if.familyReturn_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_relaxation,
      { "relaxation", "x509if.relaxation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelaxationPolicy", HFILL }},
    { &hf_x509if_additionalControl,
      { "additionalControl", "x509if.additionalControl",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_AttributeType", HFILL }},
    { &hf_x509if_additionalControl_item,
      { "AttributeType", "x509if.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_allowedSubset,
      { "allowedSubset", "x509if.allowedSubset",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_imposedSubset,
      { "imposedSubset", "x509if.imposedSubset",
        FT_UINT32, BASE_DEC, VALS(x509if_ImposedSubset_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_entryLimit,
      { "entryLimit", "x509if.entryLimit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_name,
      { "name", "x509if.name",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_DirectoryString", HFILL }},
    { &hf_x509if_name_item,
      { "DirectoryString", "x509if.DirectoryString",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_description,
      { "description", "x509if.description",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_x509if_AllowedSubset_baseObject,
      { "baseObject", "x509if.AllowedSubset.baseObject",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509if_AllowedSubset_oneLevel,
      { "oneLevel", "x509if.AllowedSubset.oneLevel",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509if_AllowedSubset_wholeSubtree,
      { "wholeSubtree", "x509if.AllowedSubset.wholeSubtree",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_x509if_Attribute,
    &ett_x509if_T_values,
    &ett_x509if_T_valuesWithContext,
    &ett_x509if_T_valuesWithContext_item,
    &ett_x509if_SET_SIZE_1_MAX_OF_Context,
    &ett_x509if_Context,
    &ett_x509if_T_contextValues,
    &ett_x509if_AttributeValueAssertion,
    &ett_x509if_T_assertedContexts,
    &ett_x509if_SET_SIZE_1_MAX_OF_ContextAssertion,
    &ett_x509if_ContextAssertion,
    &ett_x509if_T_ca_contextValues,
    &ett_x509if_AttributeTypeAssertion,
    &ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextAssertion,
    &ett_x509if_Name,
    &ett_x509if_RDNSequence,
    &ett_x509if_RelativeDistinguishedName,
    &ett_x509if_AttributeTypeAndDistinguishedValue,
    &ett_x509if_T_valWithContext,
    &ett_x509if_T_valWithContext_item,
    &ett_x509if_SubtreeSpecification,
    &ett_x509if_ChopSpecification,
    &ett_x509if_T_chopSpecificExclusions,
    &ett_x509if_T_chopSpecificExclusions_item,
    &ett_x509if_Refinement,
    &ett_x509if_SET_OF_Refinement,
    &ett_x509if_DITStructureRule,
    &ett_x509if_SET_SIZE_1_MAX_OF_RuleIdentifier,
    &ett_x509if_DITContentRule,
    &ett_x509if_T_auxiliaries,
    &ett_x509if_T_mandatory,
    &ett_x509if_T_optional,
    &ett_x509if_T_precluded,
    &ett_x509if_DITContextUse,
    &ett_x509if_T_mandatoryContexts,
    &ett_x509if_T_optionalContexts,
    &ett_x509if_SearchRuleDescription,
    &ett_x509if_SearchRule,
    &ett_x509if_SearchRuleId,
    &ett_x509if_AllowedSubset,
    &ett_x509if_RequestAttribute,
    &ett_x509if_T_ra_selectedValues,
    &ett_x509if_T_defaultValues,
    &ett_x509if_T_defaultValues_item,
    &ett_x509if_T_ra_values,
    &ett_x509if_SEQUENCE_SIZE_0_MAX_OF_ContextProfile,
    &ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MatchingUse,
    &ett_x509if_ContextProfile,
    &ett_x509if_T_contextValue,
    &ett_x509if_ContextCombination,
    &ett_x509if_SEQUENCE_OF_ContextCombination,
    &ett_x509if_MatchingUse,
    &ett_x509if_AttributeCombination,
    &ett_x509if_SEQUENCE_OF_AttributeCombination,
    &ett_x509if_ResultAttribute,
    &ett_x509if_T_outputValues,
    &ett_x509if_T_selectedValues,
    &ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextProfile,
    &ett_x509if_ControlOptions,
    &ett_x509if_EntryLimit,
    &ett_x509if_RelaxationPolicy,
    &ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MRMapping,
    &ett_x509if_MRMapping,
    &ett_x509if_SEQUENCE_SIZE_1_MAX_OF_Mapping,
    &ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MRSubstitution,
    &ett_x509if_Mapping,
    &ett_x509if_MRSubstitution,
    &ett_x509if_T_specificExclusions,
    &ett_x509if_T_specificExclusions_item,
    &ett_x509if_SEQUENCE_SIZE_0_MAX_OF_RequestAttribute,
    &ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ResultAttribute,
    &ett_x509if_SEQUENCE_SIZE_1_MAX_OF_AttributeType,
    &ett_x509if_SET_SIZE_1_MAX_OF_DirectoryString,
  };

  /* Register protocol */
  proto_x509if = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509if, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* initialise array */
  fmt_vals[0].value = 0;
  fmt_vals[0].strptr = NULL;

}


/*--- proto_reg_handoff_x509if -------------------------------------------*/
void proto_reg_handoff_x509if(void) {
  register_ber_oid_dissector("2.5.4.1", dissect_DistinguishedName_PDU, proto_x509if, "id-at-aliasedEntryName");
  register_ber_oid_dissector("2.5.4.31", dissect_DistinguishedName_PDU, proto_x509if, "id-at-member");
  register_ber_oid_dissector("2.5.4.32", dissect_DistinguishedName_PDU, proto_x509if, "id-at-owner");
  register_ber_oid_dissector("2.5.4.33", dissect_DistinguishedName_PDU, proto_x509if, "id-at-roleOccupant");
  register_ber_oid_dissector("2.5.4.34", dissect_DistinguishedName_PDU, proto_x509if, "id-at-seeAlso");
  register_ber_oid_dissector("2.5.4.49", dissect_DistinguishedName_PDU, proto_x509if, "id-at-distinguishedName");
  register_ber_oid_dissector("2.5.18.3", dissect_DistinguishedName_PDU, proto_x509if, "id-oa-creatorsName");
  register_ber_oid_dissector("2.5.18.4", dissect_DistinguishedName_PDU, proto_x509if, "id-oa-modifiersName");
  register_ber_oid_dissector("2.5.18.6", dissect_SubtreeSpecification_PDU, proto_x509if, "id-oa-subtreeSpecification");
  register_ber_oid_dissector("2.5.18.10", dissect_DistinguishedName_PDU, proto_x509if, "id-oa-subschemaSubentry");
  register_ber_oid_dissector("2.5.18.11", dissect_DistinguishedName_PDU, proto_x509if, "id-oa-accessControlSubentry");
  register_ber_oid_dissector("2.5.18.12", dissect_DistinguishedName_PDU, proto_x509if, "id-oa-collectiveAttributeSubentry");
  register_ber_oid_dissector("2.5.18.13", dissect_DistinguishedName_PDU, proto_x509if, "id-oa-contextDefaultSubentry");
  register_ber_oid_dissector("2.5.18.17", dissect_HierarchyLevel_PDU, proto_x509if, "id-oa-hierarchyLevel");
  register_ber_oid_dissector("2.5.18.18", dissect_HierarchyBelow_PDU, proto_x509if, "iid-oa-hierarchyBelow");
  register_ber_oid_dissector("2.6.5.2.5", dissect_DistinguishedName_PDU, proto_x509if, "id-at-mhs-message-store-dn");
  register_ber_oid_dissector("2.6.5.2.14", dissect_DistinguishedName_PDU, proto_x509if, "id-at-mhs-dl-related-lists");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.3", dissect_DistinguishedName_PDU, proto_x509if, "id-at-alternateRecipient");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.4", dissect_DistinguishedName_PDU, proto_x509if, "id-at-associatedOrganization");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.6", dissect_DistinguishedName_PDU, proto_x509if, "id-at-associatedPLA");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.49", dissect_DistinguishedName_PDU, proto_x509if, "id-at-aliasPointer");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.61", dissect_DistinguishedName_PDU, proto_x509if, "id-at-listPointer");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.110", dissect_DistinguishedName_PDU, proto_x509if, "id-at-administrator");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.111", dissect_DistinguishedName_PDU, proto_x509if, "id-at-aigsExpanded");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.113", dissect_DistinguishedName_PDU, proto_x509if, "id-at-associatedAL");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.114", dissect_DistinguishedName_PDU, proto_x509if, "id-at-copyMember");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.117", dissect_DistinguishedName_PDU, proto_x509if, "id-at-guard");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.121", dissect_DistinguishedName_PDU, proto_x509if, "id-at-networkDN");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.138", dissect_DistinguishedName_PDU, proto_x509if, "id-at-plasServed");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.139", dissect_DistinguishedName_PDU, proto_x509if, "id-at-deployed");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.140", dissect_DistinguishedName_PDU, proto_x509if, "id-at-garrison");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.184", dissect_DistinguishedName_PDU, proto_x509if, "id-at-aCPDutyOfficer");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.188", dissect_DistinguishedName_PDU, proto_x509if, "id-at-primaryMember");

}

