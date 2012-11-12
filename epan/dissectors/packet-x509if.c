/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-x509if.c                                                            */
/* ../../tools/asn2wrs.py -b -p x509if -c ./x509if.cnf -s ./packet-x509if-template -D . -O ../../epan/dissectors InformationFramework.asn ServiceAdministration.asn */

/* Input file: packet-x509if-template.c */

#line 1 "../../asn1/x509if/packet-x509if-template.c"
/* packet-x509if.c
 * Routines for X.509 Information Framework packet dissection
 *  Ronnie Sahlberg 2004
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-dap.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include <epan/strutil.h>
#include <epan/dissectors/packet-frame.h>

#define PNAME  "X.509 Information Framework"
#define PSNAME "X509IF"
#define PFNAME "x509if"

/* Initialize the protocol and registered fields */
static int proto_x509if = -1;
static int hf_x509if_object_identifier_id = -1;
static int hf_x509if_any_string = -1;

/*--- Included file: packet-x509if-hf.c ---*/
#line 1 "../../asn1/x509if/packet-x509if-hf.c"
static int hf_x509if_DistinguishedName_PDU = -1;  /* DistinguishedName */
static int hf_x509if_SubtreeSpecification_PDU = -1;  /* SubtreeSpecification */
static int hf_x509if_HierarchyLevel_PDU = -1;     /* HierarchyLevel */
static int hf_x509if_HierarchyBelow_PDU = -1;     /* HierarchyBelow */
static int hf_x509if_type = -1;                   /* T_type */
static int hf_x509if_values = -1;                 /* T_values */
static int hf_x509if_values_item = -1;            /* T_values_item */
static int hf_x509if_valuesWithContext = -1;      /* T_valuesWithContext */
static int hf_x509if_valuesWithContext_item = -1;  /* T_valuesWithContext_item */
static int hf_x509if_value = -1;                  /* T_value */
static int hf_x509if_contextList = -1;            /* SET_SIZE_1_MAX_OF_Context */
static int hf_x509if_contextList_item = -1;       /* Context */
static int hf_x509if_contextType = -1;            /* T_contextType */
static int hf_x509if_contextValues = -1;          /* T_contextValues */
static int hf_x509if_contextValues_item = -1;     /* T_contextValues_item */
static int hf_x509if_fallback = -1;               /* BOOLEAN */
static int hf_x509if_type_01 = -1;                /* T_type_01 */
static int hf_x509if_assertion = -1;              /* T_assertion */
static int hf_x509if_assertedContexts = -1;       /* T_assertedContexts */
static int hf_x509if_allContexts = -1;            /* NULL */
static int hf_x509if_selectedContexts = -1;       /* SET_SIZE_1_MAX_OF_ContextAssertion */
static int hf_x509if_selectedContexts_item = -1;  /* ContextAssertion */
static int hf_x509if_ca_contextType = -1;         /* T_ca_contextType */
static int hf_x509if_ca_contextValues = -1;       /* T_ca_contextValues */
static int hf_x509if_ca_contextValues_item = -1;  /* T_ca_contextValues_item */
static int hf_x509if_type_02 = -1;                /* OBJECT_IDENTIFIER */
static int hf_x509if_ata_assertedContexts = -1;   /* SEQUENCE_SIZE_1_MAX_OF_ContextAssertion */
static int hf_x509if_ata_assertedContexts_item = -1;  /* ContextAssertion */
static int hf_x509if_rdnSequence = -1;            /* RDNSequence */
static int hf_x509if_RDNSequence_item = -1;       /* RDNSequence_item */
static int hf_x509if_RelativeDistinguishedName_item = -1;  /* RelativeDistinguishedName_item */
static int hf_x509if_type_03 = -1;                /* T_type_02 */
static int hf_x509if_atadv_value = -1;            /* T_atadv_value */
static int hf_x509if_primaryDistinguished = -1;   /* BOOLEAN */
static int hf_x509if_valueswithContext = -1;      /* T_valWithContext */
static int hf_x509if_valueswithContext_item = -1;  /* T_valWithContext_item */
static int hf_x509if_distingAttrValue = -1;       /* T_distingAttrValue */
static int hf_x509if_chopSpecificExclusions = -1;  /* T_chopSpecificExclusions */
static int hf_x509if_chopSpecificExclusions_item = -1;  /* T_chopSpecificExclusions_item */
static int hf_x509if_chopBefore = -1;             /* LocalName */
static int hf_x509if_chopAfter = -1;              /* LocalName */
static int hf_x509if_minimum = -1;                /* BaseDistance */
static int hf_x509if_maximum = -1;                /* BaseDistance */
static int hf_x509if_item = -1;                   /* OBJECT_IDENTIFIER */
static int hf_x509if_refinement_and = -1;         /* SET_OF_Refinement */
static int hf_x509if_refinement_and_item = -1;    /* Refinement */
static int hf_x509if_refinement_or = -1;          /* SET_OF_Refinement */
static int hf_x509if_refinement_or_item = -1;     /* Refinement */
static int hf_x509if_refinement_not = -1;         /* Refinement */
static int hf_x509if_ruleIdentifier = -1;         /* RuleIdentifier */
static int hf_x509if_nameForm = -1;               /* OBJECT_IDENTIFIER */
static int hf_x509if_superiorStructureRules = -1;  /* SET_SIZE_1_MAX_OF_RuleIdentifier */
static int hf_x509if_superiorStructureRules_item = -1;  /* RuleIdentifier */
static int hf_x509if_structuralObjectClass = -1;  /* OBJECT_IDENTIFIER */
static int hf_x509if_auxiliaries = -1;            /* T_auxiliaries */
static int hf_x509if_auxiliaries_item = -1;       /* OBJECT_IDENTIFIER */
static int hf_x509if_mandatory = -1;              /* T_mandatory */
static int hf_x509if_mandatory_item = -1;         /* OBJECT_IDENTIFIER */
static int hf_x509if_optional = -1;               /* T_optional */
static int hf_x509if_optional_item = -1;          /* OBJECT_IDENTIFIER */
static int hf_x509if_precluded = -1;              /* T_precluded */
static int hf_x509if_precluded_item = -1;         /* OBJECT_IDENTIFIER */
static int hf_x509if_attributeType = -1;          /* OBJECT_IDENTIFIER */
static int hf_x509if_mandatoryContexts = -1;      /* T_mandatoryContexts */
static int hf_x509if_mandatoryContexts_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_x509if_optionalContexts = -1;       /* T_optionalContexts */
static int hf_x509if_optionalContexts_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_x509if_id = -1;                     /* INTEGER */
static int hf_x509if_dmdId = -1;                  /* OBJECT_IDENTIFIER */
static int hf_x509if_attributeType_01 = -1;       /* T_attributeType */
static int hf_x509if_includeSubtypes = -1;        /* BOOLEAN */
static int hf_x509if_ra_selectedValues = -1;      /* T_ra_selectedValues */
static int hf_x509if_ra_selectedValues_item = -1;  /* T_ra_selectedValues_item */
static int hf_x509if_defaultValues = -1;          /* T_defaultValues */
static int hf_x509if_defaultValues_item = -1;     /* T_defaultValues_item */
static int hf_x509if_entryType = -1;              /* T_entryType */
static int hf_x509if_ra_values = -1;              /* T_ra_values */
static int hf_x509if_ra_values_item = -1;         /* T_ra_values_item */
static int hf_x509if_contexts = -1;               /* SEQUENCE_SIZE_0_MAX_OF_ContextProfile */
static int hf_x509if_contexts_item = -1;          /* ContextProfile */
static int hf_x509if_contextCombination = -1;     /* ContextCombination */
static int hf_x509if_matchingUse = -1;            /* SEQUENCE_SIZE_1_MAX_OF_MatchingUse */
static int hf_x509if_matchingUse_item = -1;       /* MatchingUse */
static int hf_x509if_contextType_01 = -1;         /* T_contextType_01 */
static int hf_x509if_contextValue = -1;           /* T_contextValue */
static int hf_x509if_contextValue_item = -1;      /* T_contextValue_item */
static int hf_x509if_context = -1;                /* OBJECT_IDENTIFIER */
static int hf_x509if_contextcombination_and = -1;  /* SEQUENCE_OF_ContextCombination */
static int hf_x509if_contextcombination_and_item = -1;  /* ContextCombination */
static int hf_x509if_contextcombination_or = -1;  /* SEQUENCE_OF_ContextCombination */
static int hf_x509if_contextcombination_or_item = -1;  /* ContextCombination */
static int hf_x509if_contextcombination_not = -1;  /* ContextCombination */
static int hf_x509if_restrictionType = -1;        /* T_restrictionType */
static int hf_x509if_restrictionValue = -1;       /* T_restrictionValue */
static int hf_x509if_attribute = -1;              /* AttributeType */
static int hf_x509if_and = -1;                    /* SEQUENCE_OF_AttributeCombination */
static int hf_x509if_and_item = -1;               /* AttributeCombination */
static int hf_x509if_or = -1;                     /* SEQUENCE_OF_AttributeCombination */
static int hf_x509if_or_item = -1;                /* AttributeCombination */
static int hf_x509if_not = -1;                    /* AttributeCombination */
static int hf_x509if_attributeType_02 = -1;       /* T_attributeType_01 */
static int hf_x509if_outputValues = -1;           /* T_outputValues */
static int hf_x509if_selectedValues = -1;         /* T_selectedValues */
static int hf_x509if_selectedValues_item = -1;    /* T_selectedValues_item */
static int hf_x509if_matchedValuesOnly = -1;      /* NULL */
static int hf_x509if_contexts_01 = -1;            /* SEQUENCE_SIZE_1_MAX_OF_ContextProfile */
static int hf_x509if_serviceControls = -1;        /* ServiceControlOptions */
static int hf_x509if_searchOptions = -1;          /* SearchControlOptions */
static int hf_x509if_hierarchyOptions = -1;       /* HierarchySelections */
static int hf_x509if_default = -1;                /* INTEGER */
static int hf_x509if_max = -1;                    /* INTEGER */
static int hf_x509if_basic = -1;                  /* MRMapping */
static int hf_x509if_tightenings = -1;            /* SEQUENCE_SIZE_1_MAX_OF_MRMapping */
static int hf_x509if_tightenings_item = -1;       /* MRMapping */
static int hf_x509if_relaxations = -1;            /* SEQUENCE_SIZE_1_MAX_OF_MRMapping */
static int hf_x509if_relaxations_item = -1;       /* MRMapping */
static int hf_x509if_maximum_relaxation = -1;     /* INTEGER */
static int hf_x509if_minimum_relaxation = -1;     /* INTEGER */
static int hf_x509if_mapping = -1;                /* SEQUENCE_SIZE_1_MAX_OF_Mapping */
static int hf_x509if_mapping_item = -1;           /* Mapping */
static int hf_x509if_substitution = -1;           /* SEQUENCE_SIZE_1_MAX_OF_MRSubstitution */
static int hf_x509if_substitution_item = -1;      /* MRSubstitution */
static int hf_x509if_mappingFunction = -1;        /* OBJECT_IDENTIFIER */
static int hf_x509if_level = -1;                  /* INTEGER */
static int hf_x509if_oldMatchingRule = -1;        /* OBJECT_IDENTIFIER */
static int hf_x509if_newMatchingRule = -1;        /* OBJECT_IDENTIFIER */
static int hf_x509if_base = -1;                   /* LocalName */
static int hf_x509if_specificExclusions = -1;     /* T_specificExclusions */
static int hf_x509if_specificExclusions_item = -1;  /* T_specificExclusions_item */
static int hf_x509if_specificationFilter = -1;    /* Refinement */
static int hf_x509if_serviceType = -1;            /* OBJECT_IDENTIFIER */
static int hf_x509if_userClass = -1;              /* INTEGER */
static int hf_x509if_inputAttributeTypes = -1;    /* SEQUENCE_SIZE_0_MAX_OF_RequestAttribute */
static int hf_x509if_inputAttributeTypes_item = -1;  /* RequestAttribute */
static int hf_x509if_attributeCombination = -1;   /* AttributeCombination */
static int hf_x509if_outputAttributeTypes = -1;   /* SEQUENCE_SIZE_1_MAX_OF_ResultAttribute */
static int hf_x509if_outputAttributeTypes_item = -1;  /* ResultAttribute */
static int hf_x509if_defaultControls = -1;        /* ControlOptions */
static int hf_x509if_mandatoryControls = -1;      /* ControlOptions */
static int hf_x509if_searchRuleControls = -1;     /* ControlOptions */
static int hf_x509if_familyGrouping = -1;         /* FamilyGrouping */
static int hf_x509if_familyReturn = -1;           /* FamilyReturn */
static int hf_x509if_relaxation = -1;             /* RelaxationPolicy */
static int hf_x509if_additionalControl = -1;      /* SEQUENCE_SIZE_1_MAX_OF_AttributeType */
static int hf_x509if_additionalControl_item = -1;  /* AttributeType */
static int hf_x509if_allowedSubset = -1;          /* AllowedSubset */
static int hf_x509if_imposedSubset = -1;          /* ImposedSubset */
static int hf_x509if_entryLimit = -1;             /* EntryLimit */
static int hf_x509if_name = -1;                   /* SET_SIZE_1_MAX_OF_DirectoryString */
static int hf_x509if_name_item = -1;              /* DirectoryString */
static int hf_x509if_description = -1;            /* DirectoryString */
/* named bits */
static int hf_x509if_AllowedSubset_baseObject = -1;
static int hf_x509if_AllowedSubset_oneLevel = -1;
static int hf_x509if_AllowedSubset_wholeSubtree = -1;

/*--- End of included file: packet-x509if-hf.c ---*/
#line 49 "../../asn1/x509if/packet-x509if-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-x509if-ett.c ---*/
#line 1 "../../asn1/x509if/packet-x509if-ett.c"
static gint ett_x509if_Attribute = -1;
static gint ett_x509if_T_values = -1;
static gint ett_x509if_T_valuesWithContext = -1;
static gint ett_x509if_T_valuesWithContext_item = -1;
static gint ett_x509if_SET_SIZE_1_MAX_OF_Context = -1;
static gint ett_x509if_Context = -1;
static gint ett_x509if_T_contextValues = -1;
static gint ett_x509if_AttributeValueAssertion = -1;
static gint ett_x509if_T_assertedContexts = -1;
static gint ett_x509if_SET_SIZE_1_MAX_OF_ContextAssertion = -1;
static gint ett_x509if_ContextAssertion = -1;
static gint ett_x509if_T_ca_contextValues = -1;
static gint ett_x509if_AttributeTypeAssertion = -1;
static gint ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextAssertion = -1;
static gint ett_x509if_Name = -1;
static gint ett_x509if_RDNSequence = -1;
static gint ett_x509if_RelativeDistinguishedName = -1;
static gint ett_x509if_AttributeTypeAndDistinguishedValue = -1;
static gint ett_x509if_T_valWithContext = -1;
static gint ett_x509if_T_valWithContext_item = -1;
static gint ett_x509if_SubtreeSpecification = -1;
static gint ett_x509if_ChopSpecification = -1;
static gint ett_x509if_T_chopSpecificExclusions = -1;
static gint ett_x509if_T_chopSpecificExclusions_item = -1;
static gint ett_x509if_Refinement = -1;
static gint ett_x509if_SET_OF_Refinement = -1;
static gint ett_x509if_DITStructureRule = -1;
static gint ett_x509if_SET_SIZE_1_MAX_OF_RuleIdentifier = -1;
static gint ett_x509if_DITContentRule = -1;
static gint ett_x509if_T_auxiliaries = -1;
static gint ett_x509if_T_mandatory = -1;
static gint ett_x509if_T_optional = -1;
static gint ett_x509if_T_precluded = -1;
static gint ett_x509if_DITContextUse = -1;
static gint ett_x509if_T_mandatoryContexts = -1;
static gint ett_x509if_T_optionalContexts = -1;
static gint ett_x509if_SearchRuleDescription = -1;
static gint ett_x509if_SearchRule = -1;
static gint ett_x509if_SearchRuleId = -1;
static gint ett_x509if_AllowedSubset = -1;
static gint ett_x509if_RequestAttribute = -1;
static gint ett_x509if_T_ra_selectedValues = -1;
static gint ett_x509if_T_defaultValues = -1;
static gint ett_x509if_T_defaultValues_item = -1;
static gint ett_x509if_T_ra_values = -1;
static gint ett_x509if_SEQUENCE_SIZE_0_MAX_OF_ContextProfile = -1;
static gint ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MatchingUse = -1;
static gint ett_x509if_ContextProfile = -1;
static gint ett_x509if_T_contextValue = -1;
static gint ett_x509if_ContextCombination = -1;
static gint ett_x509if_SEQUENCE_OF_ContextCombination = -1;
static gint ett_x509if_MatchingUse = -1;
static gint ett_x509if_AttributeCombination = -1;
static gint ett_x509if_SEQUENCE_OF_AttributeCombination = -1;
static gint ett_x509if_ResultAttribute = -1;
static gint ett_x509if_T_outputValues = -1;
static gint ett_x509if_T_selectedValues = -1;
static gint ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextProfile = -1;
static gint ett_x509if_ControlOptions = -1;
static gint ett_x509if_EntryLimit = -1;
static gint ett_x509if_RelaxationPolicy = -1;
static gint ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MRMapping = -1;
static gint ett_x509if_MRMapping = -1;
static gint ett_x509if_SEQUENCE_SIZE_1_MAX_OF_Mapping = -1;
static gint ett_x509if_SEQUENCE_SIZE_1_MAX_OF_MRSubstitution = -1;
static gint ett_x509if_Mapping = -1;
static gint ett_x509if_MRSubstitution = -1;
static gint ett_x509if_T_specificExclusions = -1;
static gint ett_x509if_T_specificExclusions_item = -1;
static gint ett_x509if_SEQUENCE_SIZE_0_MAX_OF_RequestAttribute = -1;
static gint ett_x509if_SEQUENCE_SIZE_1_MAX_OF_ResultAttribute = -1;
static gint ett_x509if_SEQUENCE_SIZE_1_MAX_OF_AttributeType = -1;
static gint ett_x509if_SET_SIZE_1_MAX_OF_DirectoryString = -1;

/*--- End of included file: packet-x509if-ett.c ---*/
#line 52 "../../asn1/x509if/packet-x509if-template.c"

static const char *object_identifier_id = NULL;
static proto_tree *top_of_dn = NULL;
static proto_tree *top_of_rdn = NULL;

static gboolean rdn_one_value = FALSE; /* have we seen one value in an RDN yet */
static gboolean dn_one_rdn = FALSE; /* have we seen one RDN in a DN yet */
static gboolean doing_attr = FALSE;

#define MAX_RDN_STR_LEN   64
#define MAX_DN_STR_LEN    (20 * MAX_RDN_STR_LEN)

static char *last_dn = NULL;
static char *last_rdn = NULL;

static int ava_hf_index;
#define MAX_FMT_VALS   32
static value_string fmt_vals[MAX_FMT_VALS];
#define MAX_AVA_STR_LEN   64
static char *last_ava = NULL;

static void
x509if_frame_end(void)
{
  object_identifier_id = NULL;
  top_of_dn = NULL;
  top_of_rdn = NULL;

  rdn_one_value = FALSE;
  dn_one_rdn = FALSE;
  doing_attr = FALSE;

  last_dn = NULL;
  last_rdn = NULL;
  last_ava = NULL;
}


/*--- Included file: packet-x509if-fn.c ---*/
#line 1 "../../asn1/x509if/packet-x509if-fn.c"
/*--- Cyclic dependencies ---*/

/* Refinement -> Refinement/and -> Refinement */
/* Refinement -> Refinement */
int dissect_x509if_Refinement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* ContextCombination -> ContextCombination/and -> ContextCombination */
/* ContextCombination -> ContextCombination */
int dissect_x509if_ContextCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* AttributeCombination -> AttributeCombination/and -> AttributeCombination */
/* AttributeCombination -> AttributeCombination */
int dissect_x509if_AttributeCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_x509if_T_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



static int
dissect_x509if_T_values_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 315 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_values_set_of[1] = {
  { &hf_x509if_values_item  , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_values_item },
};

static int
dissect_x509if_T_values(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_values_set_of, hf_index, ett_x509if_T_values);

  return offset;
}



static int
dissect_x509if_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 285 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback("unknown", tvb, offset, actx->pinfo, tree);



  return offset;
}



static int
dissect_x509if_T_contextType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



static int
dissect_x509if_T_contextValues_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 297 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_contextValues_set_of[1] = {
  { &hf_x509if_contextValues_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_contextValues_item },
};

static int
dissect_x509if_T_contextValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_contextValues_set_of, hf_index, ett_x509if_T_contextValues);

  return offset;
}



static int
dissect_x509if_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_Context(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Context_sequence, hf_index, ett_x509if_Context);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_Context_set_of[1] = {
  { &hf_x509if_contextList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Context },
};

static int
dissect_x509if_SET_SIZE_1_MAX_OF_Context(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_T_valuesWithContext_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_valuesWithContext_item_sequence, hf_index, ett_x509if_T_valuesWithContext_item);

  return offset;
}


static const ber_sequence_t T_valuesWithContext_set_of[1] = {
  { &hf_x509if_valuesWithContext_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_T_valuesWithContext_item },
};

static int
dissect_x509if_T_valuesWithContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 418 "../../asn1/x509if/x509if.cnf"
	doing_attr = TRUE;
	register_frame_end_routine (actx->pinfo, x509if_frame_end);

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Attribute_sequence, hf_index, ett_x509if_Attribute);



  return offset;
}



int
dissect_x509if_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



int
dissect_x509if_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 303 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}



static int
dissect_x509if_T_type_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



static int
dissect_x509if_T_assertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 309 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}



static int
dissect_x509if_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x509if_T_ca_contextType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



static int
dissect_x509if_T_ca_contextValues_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 186 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_ca_contextValues_set_of[1] = {
  { &hf_x509if_ca_contextValues_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_ca_contextValues_item },
};

static int
dissect_x509if_T_ca_contextValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContextAssertion_sequence, hf_index, ett_x509if_ContextAssertion);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_ContextAssertion_set_of[1] = {
  { &hf_x509if_selectedContexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_x509if_SET_SIZE_1_MAX_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_T_assertedContexts(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_AttributeValueAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 408 "../../asn1/x509if/x509if.cnf"

	ava_hf_index = hf_index;
	last_ava = ep_alloc(MAX_AVA_STR_LEN); *last_ava = '\0';
	register_frame_end_routine (actx->pinfo, x509if_frame_end);

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeValueAssertion_sequence, hf_index, ett_x509if_AttributeValueAssertion);


	ava_hf_index=-1;



  return offset;
}



static int
dissect_x509if_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_ContextAssertion_sequence_of[1] = {
  { &hf_x509if_ata_assertedContexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_AttributeTypeAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeTypeAssertion_sequence, hf_index, ett_x509if_AttributeTypeAssertion);

  return offset;
}



static int
dissect_x509if_T_type_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 192 "../../asn1/x509if/x509if.cnf"
  const char *fmt; 
  const char *name;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);


  if(object_identifier_id) {
    /* see if we can find a nice name */
    name = oid_resolved_from_string(object_identifier_id);
    if(!name) name = object_identifier_id;    

    if(last_rdn) { /* append it to the RDN */
      g_strlcat(last_rdn, name, MAX_RDN_STR_LEN);
      g_strlcat(last_rdn, "=", MAX_RDN_STR_LEN);

     /* append it to the tree */
     proto_item_append_text(tree, " (%s=", name);
    } else if(doing_attr) {
      /* append it to the parent item */
      proto_item_append_text(tree, " (%s)", name);
    }

    if((fmt = val_to_str(hf_index, fmt_vals, "")) && *fmt) {
      /* we have a format */
      last_ava = ep_alloc(MAX_AVA_STR_LEN); *last_ava = '\0';
      register_frame_end_routine (actx->pinfo, x509if_frame_end);

      g_snprintf(last_ava, MAX_AVA_STR_LEN, "%s %s", name, fmt);

      proto_item_append_text(tree, " %s", last_ava);

    }
  }



  return offset;
}



static int
dissect_x509if_T_atadv_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 226 "../../asn1/x509if/x509if.cnf"
  int old_offset = offset;
  tvbuff_t	*out_tvb;
  char  	*value = NULL;
  const char 	*fmt; 
  const char	*name = NULL;
  const char    *orig_oid = object_identifier_id;

  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);

  /* in dissecting the value we may have overridden the OID of the value - which is
     a problem if there are multiple values */
  object_identifier_id = orig_oid;

  /* try and dissect as a string */
  dissect_ber_octet_string(FALSE, actx, NULL, tvb, old_offset, hf_x509if_any_string, &out_tvb);
  
  /* should also try and dissect as an OID and integer */
  /* of course, if I can look up the syntax .... */

  if(out_tvb) {
    /* it was a string - format it */
    value = tvb_format_text(out_tvb, 0, tvb_length(out_tvb));

    if(last_rdn) {
      g_strlcat(last_rdn, value, MAX_RDN_STR_LEN);

      /* append it to the tree*/
      proto_item_append_text(tree, "%s)", value);
    }

    if((fmt = val_to_str(ava_hf_index, fmt_vals, "")) && *fmt) {
      /* we have a format */

      if (!last_ava) {
        last_ava = ep_alloc(MAX_AVA_STR_LEN);
      }

      if(!(name = oid_resolved_from_string(object_identifier_id)))
        name = object_identifier_id;
      g_snprintf(last_ava, MAX_AVA_STR_LEN, "%s %s %s", name, fmt, value);

      proto_item_append_text(tree, " %s", last_ava);

    }
  }



  return offset;
}



static int
dissect_x509if_T_distingAttrValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 330 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_valWithContext_item_sequence[] = {
  { &hf_x509if_distingAttrValue, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509if_T_distingAttrValue },
  { &hf_x509if_contextList  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_SET_SIZE_1_MAX_OF_Context },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_valWithContext_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_valWithContext_item_sequence, hf_index, ett_x509if_T_valWithContext_item);

  return offset;
}


static const ber_sequence_t T_valWithContext_set_of[1] = {
  { &hf_x509if_valueswithContext_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_T_valWithContext_item },
};

static int
dissect_x509if_T_valWithContext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_AttributeTypeAndDistinguishedValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeTypeAndDistinguishedValue_sequence, hf_index, ett_x509if_AttributeTypeAndDistinguishedValue);

  return offset;
}



static int
dissect_x509if_RelativeDistinguishedName_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 360 "../../asn1/x509if/x509if.cnf"

  if(!rdn_one_value) {
    top_of_rdn = tree;
  } else {

   if(last_rdn)  
     /* this is an additional value - delimit */
     g_strlcat(last_rdn, "+", MAX_RDN_STR_LEN);
  }

    offset = dissect_x509if_AttributeTypeAndDistinguishedValue(implicit_tag, tvb, offset, actx, tree, hf_index);


  rdn_one_value = TRUE;



  return offset;
}


static const ber_sequence_t RelativeDistinguishedName_set_of[1] = {
  { &hf_x509if_RelativeDistinguishedName_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RelativeDistinguishedName_item },
};

int
dissect_x509if_RelativeDistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 333 "../../asn1/x509if/x509if.cnf"
  char *temp_dn;

  rdn_one_value = FALSE;
  top_of_rdn = tree;
  last_rdn = ep_alloc(MAX_DN_STR_LEN); *last_rdn = '\0';
  register_frame_end_routine (actx->pinfo, x509if_frame_end);

    offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 RelativeDistinguishedName_set_of, hf_index, ett_x509if_RelativeDistinguishedName);


  /* we've finished - close the bracket */
  proto_item_append_text(top_of_rdn, " (%s)", last_rdn);

  /* now append this to the DN */
  if (last_dn) {
    if(*last_dn) {
      temp_dn = ep_alloc(MAX_DN_STR_LEN); /* is there a better way to use ep_alloc here ? */
      g_snprintf(temp_dn, MAX_DN_STR_LEN, "%s,%s", last_rdn, last_dn);
      last_dn[0] = '\0';
      g_strlcat(last_dn, temp_dn, MAX_DN_STR_LEN);
    } else {
      g_strlcat(last_dn, last_rdn, MAX_DN_STR_LEN);
    }
  }

  last_rdn = NULL; /* it will get freed when the next packet is dissected */



  return offset;
}



static int
dissect_x509if_RDNSequence_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 397 "../../asn1/x509if/x509if.cnf"

  if(!dn_one_rdn)  {
    /* this is the first element - record the top */
    top_of_dn = tree;
  } 

    offset = dissect_x509if_RelativeDistinguishedName(implicit_tag, tvb, offset, actx, tree, hf_index);


  dn_one_rdn = TRUE;



  return offset;
}


static const ber_sequence_t RDNSequence_sequence_of[1] = {
  { &hf_x509if_RDNSequence_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_RDNSequence_item },
};

int
dissect_x509if_RDNSequence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 375 "../../asn1/x509if/x509if.cnf"
  const char *fmt; 

  dn_one_rdn = FALSE; /* reset */
  last_dn = ep_alloc(MAX_DN_STR_LEN); *last_dn = '\0';
  top_of_dn = NULL;
  register_frame_end_routine (actx->pinfo, x509if_frame_end);


    offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RDNSequence_sequence_of, hf_index, ett_x509if_RDNSequence);


  /* we've finished - append the dn */
  proto_item_append_text(top_of_dn, " (%s)", last_dn);

 /* see if we should append this to the col info */
  if(check_col(actx->pinfo->cinfo, COL_INFO) &&
     (fmt = val_to_str(hf_index, fmt_vals, "")) && *fmt) {
      /* we have a format */
	col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s%s", fmt, last_dn);
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
dissect_x509if_Name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Name_choice, hf_index, ett_x509if_Name,
                                 NULL);

  return offset;
}



int
dissect_x509if_DistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509if_RDNSequence(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_x509if_LocalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_T_specificExclusions_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_specificExclusions_item_choice, hf_index, ett_x509if_T_specificExclusions_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_specificExclusions_set_of[1] = {
  { &hf_x509if_specificExclusions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_T_specificExclusions_item },
};

static int
dissect_x509if_T_specificExclusions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_specificExclusions_set_of, hf_index, ett_x509if_T_specificExclusions);

  return offset;
}



static int
dissect_x509if_BaseDistance(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Refinement_set_of[1] = {
  { &hf_x509if_refinement_and_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_Refinement },
};

static int
dissect_x509if_SET_OF_Refinement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_Refinement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Refinement_choice, hf_index, ett_x509if_Refinement,
                                 NULL);

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
dissect_x509if_SubtreeSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_T_chopSpecificExclusions_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_chopSpecificExclusions_item_choice, hf_index, ett_x509if_T_chopSpecificExclusions_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_chopSpecificExclusions_set_of[1] = {
  { &hf_x509if_chopSpecificExclusions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_T_chopSpecificExclusions_item },
};

static int
dissect_x509if_T_chopSpecificExclusions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_ChopSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_AttributeUsage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



int
dissect_x509if_RuleIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_RuleIdentifier_set_of[1] = {
  { &hf_x509if_superiorStructureRules_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509if_RuleIdentifier },
};

static int
dissect_x509if_SET_SIZE_1_MAX_OF_RuleIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_DITStructureRule(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DITStructureRule_sequence, hf_index, ett_x509if_DITStructureRule);

  return offset;
}


static const ber_sequence_t T_auxiliaries_set_of[1] = {
  { &hf_x509if_auxiliaries_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_auxiliaries(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_auxiliaries_set_of, hf_index, ett_x509if_T_auxiliaries);

  return offset;
}


static const ber_sequence_t T_mandatory_set_of[1] = {
  { &hf_x509if_mandatory_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_mandatory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_mandatory_set_of, hf_index, ett_x509if_T_mandatory);

  return offset;
}


static const ber_sequence_t T_optional_set_of[1] = {
  { &hf_x509if_optional_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_optional(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_optional_set_of, hf_index, ett_x509if_T_optional);

  return offset;
}


static const ber_sequence_t T_precluded_set_of[1] = {
  { &hf_x509if_precluded_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_precluded(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_DITContentRule(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DITContentRule_sequence, hf_index, ett_x509if_DITContentRule);

  return offset;
}


static const ber_sequence_t T_mandatoryContexts_set_of[1] = {
  { &hf_x509if_mandatoryContexts_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_mandatoryContexts(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_mandatoryContexts_set_of, hf_index, ett_x509if_T_mandatoryContexts);

  return offset;
}


static const ber_sequence_t T_optionalContexts_set_of[1] = {
  { &hf_x509if_optionalContexts_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_OBJECT_IDENTIFIER },
};

static int
dissect_x509if_T_optionalContexts(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_DITContextUse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DITContextUse_sequence, hf_index, ett_x509if_DITContextUse);

  return offset;
}



static int
dissect_x509if_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x509if_T_attributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



static int
dissect_x509if_T_ra_selectedValues_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 276 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_ra_selectedValues_sequence_of[1] = {
  { &hf_x509if_ra_selectedValues_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_ra_selectedValues_item },
};

static int
dissect_x509if_T_ra_selectedValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_ra_selectedValues_sequence_of, hf_index, ett_x509if_T_ra_selectedValues);

  return offset;
}



static int
dissect_x509if_T_entryType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



static int
dissect_x509if_T_ra_values_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 282 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_ra_values_sequence_of[1] = {
  { &hf_x509if_ra_values_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_ra_values_item },
};

static int
dissect_x509if_T_ra_values(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_T_defaultValues_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_defaultValues_item_sequence, hf_index, ett_x509if_T_defaultValues_item);

  return offset;
}


static const ber_sequence_t T_defaultValues_sequence_of[1] = {
  { &hf_x509if_defaultValues_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_T_defaultValues_item },
};

static int
dissect_x509if_T_defaultValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_defaultValues_sequence_of, hf_index, ett_x509if_T_defaultValues);

  return offset;
}



static int
dissect_x509if_T_contextType_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



static int
dissect_x509if_T_contextValue_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 321 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_contextValue_sequence_of[1] = {
  { &hf_x509if_contextValue_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_contextValue_item },
};

static int
dissect_x509if_T_contextValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_ContextProfile(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContextProfile_sequence, hf_index, ett_x509if_ContextProfile);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_0_MAX_OF_ContextProfile_sequence_of[1] = {
  { &hf_x509if_contexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextProfile },
};

static int
dissect_x509if_SEQUENCE_SIZE_0_MAX_OF_ContextProfile(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_0_MAX_OF_ContextProfile_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_0_MAX_OF_ContextProfile);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ContextCombination_sequence_of[1] = {
  { &hf_x509if_contextcombination_and_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_ContextCombination },
};

static int
dissect_x509if_SEQUENCE_OF_ContextCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_ContextCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ContextCombination_choice, hf_index, ett_x509if_ContextCombination,
                                 NULL);

  return offset;
}



static int
dissect_x509if_T_restrictionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



static int
dissect_x509if_T_restrictionValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 327 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t MatchingUse_sequence[] = {
  { &hf_x509if_restrictionType, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_T_restrictionType },
  { &hf_x509if_restrictionValue, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_restrictionValue },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509if_MatchingUse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MatchingUse_sequence, hf_index, ett_x509if_MatchingUse);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_MatchingUse_sequence_of[1] = {
  { &hf_x509if_matchingUse_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_MatchingUse },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MatchingUse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_RequestAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestAttribute_sequence, hf_index, ett_x509if_RequestAttribute);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_0_MAX_OF_RequestAttribute_sequence_of[1] = {
  { &hf_x509if_inputAttributeTypes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RequestAttribute },
};

static int
dissect_x509if_SEQUENCE_SIZE_0_MAX_OF_RequestAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_0_MAX_OF_RequestAttribute_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_0_MAX_OF_RequestAttribute);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeCombination_sequence_of[1] = {
  { &hf_x509if_and_item     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509if_AttributeCombination },
};

static int
dissect_x509if_SEQUENCE_OF_AttributeCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_AttributeCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AttributeCombination_choice, hf_index, ett_x509if_AttributeCombination,
                                 NULL);

  return offset;
}



static int
dissect_x509if_T_attributeType_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}



static int
dissect_x509if_T_selectedValues_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 291 "../../asn1/x509if/x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_selectedValues_sequence_of[1] = {
  { &hf_x509if_selectedValues_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_x509if_T_selectedValues_item },
};

static int
dissect_x509if_T_selectedValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_T_outputValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_outputValues_choice, hf_index, ett_x509if_T_outputValues,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_ContextProfile_sequence_of[1] = {
  { &hf_x509if_contexts_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextProfile },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ContextProfile(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_ResultAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResultAttribute_sequence, hf_index, ett_x509if_ResultAttribute);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_ResultAttribute_sequence_of[1] = {
  { &hf_x509if_outputAttributeTypes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ResultAttribute },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_ResultAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_ControlOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_Mapping(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Mapping_sequence, hf_index, ett_x509if_Mapping);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_Mapping_sequence_of[1] = {
  { &hf_x509if_mapping_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Mapping },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_Mapping(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_MRSubstitution(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MRSubstitution_sequence, hf_index, ett_x509if_MRSubstitution);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_MRSubstitution_sequence_of[1] = {
  { &hf_x509if_substitution_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_MRSubstitution },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MRSubstitution(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_MRMapping(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MRMapping_sequence, hf_index, ett_x509if_MRMapping);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_MRMapping_sequence_of[1] = {
  { &hf_x509if_tightenings_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_MRMapping },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_MRMapping(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_RelaxationPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RelaxationPolicy_sequence, hf_index, ett_x509if_RelaxationPolicy);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_AttributeType_sequence_of[1] = {
  { &hf_x509if_additionalControl_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_x509if_SEQUENCE_SIZE_1_MAX_OF_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_AttributeType_sequence_of, hf_index, ett_x509if_SEQUENCE_SIZE_1_MAX_OF_AttributeType);

  return offset;
}


static const asn_namedbit AllowedSubset_bits[] = {
  {  0, &hf_x509if_AllowedSubset_baseObject, -1, -1, "baseObject", NULL },
  {  1, &hf_x509if_AllowedSubset_oneLevel, -1, -1, "oneLevel", NULL },
  {  2, &hf_x509if_AllowedSubset_wholeSubtree, -1, -1, "wholeSubtree", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_x509if_AllowedSubset(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    AllowedSubset_bits, hf_index, ett_x509if_AllowedSubset,
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
dissect_x509if_ImposedSubset(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_EntryLimit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EntryLimit_sequence, hf_index, ett_x509if_EntryLimit);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_DirectoryString_set_of[1] = {
  { &hf_x509if_name_item    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509sat_DirectoryString },
};

static int
dissect_x509if_SET_SIZE_1_MAX_OF_DirectoryString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_SearchRuleDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchRuleDescription_sequence, hf_index, ett_x509if_SearchRuleDescription);

  return offset;
}



static int
dissect_x509if_HierarchyLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x509if_HierarchyBelow(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_SearchRule(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_x509if_SearchRuleId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SearchRuleId_sequence, hf_index, ett_x509if_SearchRuleId);

  return offset;
}

/*--- PDUs ---*/

static void dissect_DistinguishedName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509if_DistinguishedName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509if_DistinguishedName_PDU);
}
static void dissect_SubtreeSpecification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509if_SubtreeSpecification(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509if_SubtreeSpecification_PDU);
}
static void dissect_HierarchyLevel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509if_HierarchyLevel(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509if_HierarchyLevel_PDU);
}
static void dissect_HierarchyBelow_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509if_HierarchyBelow(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509if_HierarchyBelow_PDU);
}


/*--- End of included file: packet-x509if-fn.c ---*/
#line 90 "../../asn1/x509if/packet-x509if-template.c"

const char * x509if_get_last_dn(void)
{
  return last_dn;
}

gboolean x509if_register_fmt(int hf_index, const gchar *fmt)
{
  static int idx = 0;

  if(idx < (MAX_FMT_VALS - 1)) {

    fmt_vals[idx].value = hf_index;
    fmt_vals[idx].strptr = fmt;

    idx++;

    fmt_vals[idx].value = 0;
    fmt_vals[idx].strptr = NULL;

    return TRUE;

  } else 
    return FALSE; /* couldn't register it */

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
      { "Id", "x509if.id", FT_OID, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},
    { &hf_x509if_any_string, 
      { "AnyString", "x509if.any.String", FT_BYTES, BASE_NONE,
	    NULL, 0, "This is any String", HFILL }},
			 

/*--- Included file: packet-x509if-hfarr.c ---*/
#line 1 "../../asn1/x509if/packet-x509if-hfarr.c"
    { &hf_x509if_DistinguishedName_PDU,
      { "DistinguishedName", "x509if.DistinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_SubtreeSpecification_PDU,
      { "SubtreeSpecification", "x509if.SubtreeSpecification",
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
      { "values item", "x509if.values_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_valuesWithContext,
      { "valuesWithContext", "x509if.valuesWithContext",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_valuesWithContext_item,
      { "valuesWithContext item", "x509if.valuesWithContext_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_valuesWithContext_item", HFILL }},
    { &hf_x509if_value,
      { "value", "x509if.value",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contextList,
      { "contextList", "x509if.contextList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_Context", HFILL }},
    { &hf_x509if_contextList_item,
      { "Context", "x509if.Context",
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
      { "contextValues item", "x509if.contextValues_item",
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
      { "assertion", "x509if.assertion",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_assertedContexts,
      { "assertedContexts", "x509if.assertedContexts",
        FT_UINT32, BASE_DEC, VALS(x509if_T_assertedContexts_vals), 0,
        NULL, HFILL }},
    { &hf_x509if_allContexts,
      { "allContexts", "x509if.allContexts",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_selectedContexts,
      { "selectedContexts", "x509if.selectedContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_MAX_OF_ContextAssertion", HFILL }},
    { &hf_x509if_selectedContexts_item,
      { "ContextAssertion", "x509if.ContextAssertion",
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
      { "contextValues item", "x509if.contextValues_item",
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
      { "ContextAssertion", "x509if.ContextAssertion",
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
      { "RelativeDistinguishedName item", "x509if.RelativeDistinguishedName_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_type_03,
      { "type", "x509if.type",
        FT_OID, BASE_NONE, NULL, 0,
        "T_type_02", HFILL }},
    { &hf_x509if_atadv_value,
      { "value", "x509if.value",
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
      { "valuesWithContext item", "x509if.valuesWithContext_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_valWithContext_item", HFILL }},
    { &hf_x509if_distingAttrValue,
      { "distingAttrValue", "x509if.distingAttrValue",
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
        FT_UINT32, BASE_DEC, NULL, 0,
        "BaseDistance", HFILL }},
    { &hf_x509if_maximum,
      { "maximum", "x509if.maximum",
        FT_UINT32, BASE_DEC, NULL, 0,
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
      { "selectedValues item", "x509if.selectedValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ra_selectedValues_item", HFILL }},
    { &hf_x509if_defaultValues,
      { "defaultValues", "x509if.defaultValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_defaultValues_item,
      { "defaultValues item", "x509if.defaultValues_item",
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
      { "values item", "x509if.values_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ra_values_item", HFILL }},
    { &hf_x509if_contexts,
      { "contexts", "x509if.contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_MAX_OF_ContextProfile", HFILL }},
    { &hf_x509if_contexts_item,
      { "ContextProfile", "x509if.ContextProfile",
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
      { "MatchingUse", "x509if.MatchingUse",
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
      { "contextValue item", "x509if.contextValue_item",
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
      { "restrictionValue", "x509if.restrictionValue",
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
      { "selectedValues item", "x509if.selectedValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_matchedValuesOnly,
      { "matchedValuesOnly", "x509if.matchedValuesOnly",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_contexts_01,
      { "contexts", "x509if.contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_ContextProfile", HFILL }},
    { &hf_x509if_serviceControls,
      { "serviceControls", "x509if.serviceControls",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlOptions", HFILL }},
    { &hf_x509if_searchOptions,
      { "searchOptions", "x509if.searchOptions",
        FT_NONE, BASE_NONE, NULL, 0,
        "SearchControlOptions", HFILL }},
    { &hf_x509if_hierarchyOptions,
      { "hierarchyOptions", "x509if.hierarchyOptions",
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
      { "basic", "x509if.basic",
        FT_NONE, BASE_NONE, NULL, 0,
        "MRMapping", HFILL }},
    { &hf_x509if_tightenings,
      { "tightenings", "x509if.tightenings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_MRMapping", HFILL }},
    { &hf_x509if_tightenings_item,
      { "MRMapping", "x509if.MRMapping",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_relaxations,
      { "relaxations", "x509if.relaxations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_MRMapping", HFILL }},
    { &hf_x509if_relaxations_item,
      { "MRMapping", "x509if.MRMapping",
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
      { "Mapping", "x509if.Mapping",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_substitution,
      { "substitution", "x509if.substitution",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_MRSubstitution", HFILL }},
    { &hf_x509if_substitution_item,
      { "MRSubstitution", "x509if.MRSubstitution",
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
      { "RequestAttribute", "x509if.RequestAttribute",
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
      { "ResultAttribute", "x509if.ResultAttribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_defaultControls,
      { "defaultControls", "x509if.defaultControls",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlOptions", HFILL }},
    { &hf_x509if_mandatoryControls,
      { "mandatoryControls", "x509if.mandatoryControls",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlOptions", HFILL }},
    { &hf_x509if_searchRuleControls,
      { "searchRuleControls", "x509if.searchRuleControls",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlOptions", HFILL }},
    { &hf_x509if_familyGrouping,
      { "familyGrouping", "x509if.familyGrouping",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_familyReturn,
      { "familyReturn", "x509if.familyReturn",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509if_relaxation,
      { "relaxation", "x509if.relaxation",
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
      { "entryLimit", "x509if.entryLimit",
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
      { "baseObject", "x509if.baseObject",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509if_AllowedSubset_oneLevel,
      { "oneLevel", "x509if.oneLevel",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509if_AllowedSubset_wholeSubtree,
      { "wholeSubtree", "x509if.wholeSubtree",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},

/*--- End of included file: packet-x509if-hfarr.c ---*/
#line 135 "../../asn1/x509if/packet-x509if-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-x509if-ettarr.c ---*/
#line 1 "../../asn1/x509if/packet-x509if-ettarr.c"
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

/*--- End of included file: packet-x509if-ettarr.c ---*/
#line 140 "../../asn1/x509if/packet-x509if-template.c"
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

/*--- Included file: packet-x509if-dis-tab.c ---*/
#line 1 "../../asn1/x509if/packet-x509if-dis-tab.c"
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


/*--- End of included file: packet-x509if-dis-tab.c ---*/
#line 159 "../../asn1/x509if/packet-x509if-template.c"
}

