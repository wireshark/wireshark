/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-x509if.c                                                          */
/* ../../tools/asn2eth.py -X -b -e -p x509if -c x509if.cnf -s packet-x509if-template InformationFramework.asn */

/* Input file: packet-x509if-template.c */

#line 1 "packet-x509if-template.c"
/* packet-x509if.c
 * Routines for X.509 Information Framework packet dissection
 *  Ronnie Sahlberg 2004
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-x509if.h"
#include "packet-ber.h"
#include "packet-x509sat.h"
#include <epan/emem.h>
#include <epan/strutil.h>

#define PNAME  "X.509 Information Framework"
#define PSNAME "X509IF"
#define PFNAME "x509if"

/* Initialize the protocol and registered fields */
int proto_x509if = -1;
static int hf_x509if_object_identifier_id = -1;
static int hf_x509if_any_string = -1;

/*--- Included file: packet-x509if-hf.c ---*/
#line 1 "packet-x509if-hf.c"
static int hf_x509if_Name_PDU = -1;               /* Name */
static int hf_x509if_DistinguishedName_PDU = -1;  /* DistinguishedName */
static int hf_x509if_type = -1;                   /* AttributeId */
static int hf_x509if_values = -1;                 /* SET_OF_AttributeValue */
static int hf_x509if_values_item = -1;            /* AttributeValue */
static int hf_x509if_valuesWithContext = -1;      /* T_valuesWithContext */
static int hf_x509if_valuesWithContext_item = -1;  /* T_valuesWithContext_item */
static int hf_x509if_value = -1;                  /* ValuesWithContextValue */
static int hf_x509if_contextList = -1;            /* SET_OF_Context */
static int hf_x509if_contextList_item = -1;       /* Context */
static int hf_x509if_contextType = -1;            /* AttributeId */
static int hf_x509if_contextValues = -1;          /* SET_OF_AttributeValue */
static int hf_x509if_contextValues_item = -1;     /* AttributeValue */
static int hf_x509if_fallback = -1;               /* BOOLEAN */
static int hf_x509if_assertion = -1;              /* AttributeValue */
static int hf_x509if_assertedContexts = -1;       /* T_assertedContexts */
static int hf_x509if_allContexts = -1;            /* NULL */
static int hf_x509if_selectedContexts = -1;       /* SET_OF_ContextAssertion */
static int hf_x509if_selectedContexts_item = -1;  /* ContextAssertion */
static int hf_x509if_ca_contextType = -1;         /* ContextId */
static int hf_x509if_ca_contextValues = -1;       /* SET_OF_ContextValue */
static int hf_x509if_ca_contextValues_item = -1;  /* ContextValue */
static int hf_x509if_ata_assertedContexts = -1;   /* SEQUENCE_OF_ContextAssertion */
static int hf_x509if_assertedContexts_item = -1;  /* ContextAssertion */
static int hf_x509if_rdnSequence = -1;            /* RDNSequence */
static int hf_x509if_RDNSequence_item = -1;       /* RDNSequence_item */
static int hf_x509if_RelativeDistinguishedName_item = -1;  /* RelativeDistinguishedName_item */
static int hf_x509if_atadv_value = -1;            /* AttributeValue */
static int hf_x509if_primaryDistinguished = -1;   /* BOOLEAN */
static int hf_x509if_valueswithContext = -1;      /* T_valWithContext */
static int hf_x509if_valueswithContext_item = -1;  /* T_valWithContext_item */
static int hf_x509if_distingAttrValue = -1;       /* ValuesWithContextValue */
static int hf_x509if_base = -1;                   /* LocalName */
static int hf_x509if_specificExclusions = -1;     /* T_specificExclusions */
static int hf_x509if_specificExclusions_item = -1;  /* T_specificExclusions_item */
static int hf_x509if_chopBefore = -1;             /* LocalName */
static int hf_x509if_chopAfter = -1;              /* LocalName */
static int hf_x509if_minimum = -1;                /* BaseDistance */
static int hf_x509if_maximum = -1;                /* BaseDistance */
static int hf_x509if_specificationFilter = -1;    /* Refinement */
static int hf_x509if_chopSpecificExclusions = -1;  /* T_chopSpecificExclusions */
static int hf_x509if_chopSpecificExclusions_item = -1;  /* T_chopSpecificExclusions_item */
static int hf_x509if_item = -1;                   /* OBJECT_IDENTIFIER */
static int hf_x509if_refinement_and = -1;         /* SET_OF_Refinement */
static int hf_x509if_refinement_and_item = -1;    /* Refinement */
static int hf_x509if_refinement_or = -1;          /* SET_OF_Refinement */
static int hf_x509if_refinement_or_item = -1;     /* Refinement */
static int hf_x509if_refinement_not = -1;         /* Refinement */
static int hf_x509if_ruleIdentifier = -1;         /* RuleIdentifier */
static int hf_x509if_nameForm = -1;               /* OBJECT_IDENTIFIER */
static int hf_x509if_superiorStructureRules = -1;  /* SET_OF_RuleIdentifier */
static int hf_x509if_superiorStructureRules_item = -1;  /* RuleIdentifier */
static int hf_x509if_structuralObjectClass = -1;  /* OBJECT_IDENTIFIER */
static int hf_x509if_auxiliaries = -1;            /* T_auxiliaries */
static int hf_x509if_auxiliaries_item = -1;       /* OBJECT_IDENTIFIER */
static int hf_x509if_mandatory = -1;              /* SET_SIZE_1_MAX_OF_AttributeId */
static int hf_x509if_mandatory_item = -1;         /* AttributeId */
static int hf_x509if_optional = -1;               /* SET_SIZE_1_MAX_OF_AttributeId */
static int hf_x509if_optional_item = -1;          /* AttributeId */
static int hf_x509if_precluded = -1;              /* SET_SIZE_1_MAX_OF_AttributeId */
static int hf_x509if_precluded_item = -1;         /* AttributeId */
static int hf_x509if_attributeType = -1;          /* AttributeId */
static int hf_x509if_mandatoryContexts = -1;      /* T_mandatoryContexts */
static int hf_x509if_mandatoryContexts_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_x509if_optionalContexts = -1;       /* T_optionalContexts */
static int hf_x509if_optionalContexts_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_x509if_id = -1;                     /* INTEGER */
static int hf_x509if_dmdId = -1;                  /* OBJECT_IDENTIFIER */
static int hf_x509if_serviceType = -1;            /* OBJECT_IDENTIFIER */
static int hf_x509if_userClass = -1;              /* INTEGER */
static int hf_x509if_inputAttributeTypes = -1;    /* SEQUENCE_OF_RequestAttribute */
static int hf_x509if_inputAttributeTypes_item = -1;  /* RequestAttribute */
static int hf_x509if_attributeCombination = -1;   /* AttributeCombination */
static int hf_x509if_outputAttributeTypes = -1;   /* SEQUENCE_OF_ResultAttribute */
static int hf_x509if_outputAttributeTypes_item = -1;  /* ResultAttribute */
static int hf_x509if_defaultControls = -1;        /* ControlOptions */
static int hf_x509if_mandatoryControls = -1;      /* ControlOptions */
static int hf_x509if_searchRuleControls = -1;     /* ControlOptions */
static int hf_x509if_relaxation = -1;             /* RelaxationPolicy */
static int hf_x509if_additionalControl = -1;      /* SEQUENCE_OF_AttributeType */
static int hf_x509if_additionalControl_item = -1;  /* AttributeType */
static int hf_x509if_allowedSubset = -1;          /* AllowedSubset */
static int hf_x509if_imposedSubset = -1;          /* ImposedSubset */
static int hf_x509if_entryLimit = -1;             /* EntryLimit */
static int hf_x509if_name = -1;                   /* SET_OF_DirectoryString */
static int hf_x509if_name_item = -1;              /* DirectoryString */
static int hf_x509if_description = -1;            /* DirectoryString */
static int hf_x509if_obsolete = -1;               /* BOOLEAN */
static int hf_x509if_includeSubtypes = -1;        /* BOOLEAN */
static int hf_x509if_ra_selectedValues = -1;      /* SEQUENCE_OF_SelectedValues */
static int hf_x509if_ra_selectedValues_item = -1;  /* SelectedValues */
static int hf_x509if_defaultValues = -1;          /* T_defaultValues */
static int hf_x509if_defaultValues_item = -1;     /* T_defaultValues_item */
static int hf_x509if_entryType = -1;              /* DefaultValueType */
static int hf_x509if_ra_values = -1;              /* SEQUENCE_OF_DefaultValueValues */
static int hf_x509if_ra_values_item = -1;         /* DefaultValueValues */
static int hf_x509if_contexts = -1;               /* SEQUENCE_OF_ContextProfile */
static int hf_x509if_contexts_item = -1;          /* ContextProfile */
static int hf_x509if_contextCombination = -1;     /* ContextCombination */
static int hf_x509if_matchingUse = -1;            /* SEQUENCE_OF_MatchingUse */
static int hf_x509if_matchingUse_item = -1;       /* MatchingUse */
static int hf_x509if_contextValue = -1;           /* SEQUENCE_OF_AttributeValue */
static int hf_x509if_contextValue_item = -1;      /* AttributeValue */
static int hf_x509if_context = -1;                /* OBJECT_IDENTIFIER */
static int hf_x509if_contextcombination_and = -1;  /* SEQUENCE_OF_ContextCombination */
static int hf_x509if_contextcombination_and_item = -1;  /* ContextCombination */
static int hf_x509if_contextcombination_or = -1;  /* SEQUENCE_OF_ContextCombination */
static int hf_x509if_contextcombination_or_item = -1;  /* ContextCombination */
static int hf_x509if_contextcombination_not = -1;  /* ContextCombination */
static int hf_x509if_restrictionType = -1;        /* AttributeId */
static int hf_x509if_restrictionValue = -1;       /* AttributeValue */
static int hf_x509if_attribute = -1;              /* AttributeType */
static int hf_x509if_and = -1;                    /* SEQUENCE_OF_AttributeCombination */
static int hf_x509if_and_item = -1;               /* AttributeCombination */
static int hf_x509if_or = -1;                     /* SEQUENCE_OF_AttributeCombination */
static int hf_x509if_or_item = -1;                /* AttributeCombination */
static int hf_x509if_not = -1;                    /* AttributeCombination */
static int hf_x509if_outputValues = -1;           /* T_outputValues */
static int hf_x509if_selectedValues = -1;         /* SEQUENCE_OF_AttributeValue */
static int hf_x509if_selectedValues_item = -1;    /* AttributeValue */
static int hf_x509if_matchedValuesOnly = -1;      /* NULL */
static int hf_x509if_default = -1;                /* INTEGER */
static int hf_x509if_max = -1;                    /* INTEGER */
static int hf_x509if_basic = -1;                  /* MRMapping */
static int hf_x509if_tightenings = -1;            /* SEQUENCE_OF_MRMapping */
static int hf_x509if_tightenings_item = -1;       /* MRMapping */
static int hf_x509if_relaxations = -1;            /* SEQUENCE_OF_MRMapping */
static int hf_x509if_relaxations_item = -1;       /* MRMapping */
static int hf_x509if_maximum_relaxation = -1;     /* INTEGER */
static int hf_x509if_minimum_relaxation = -1;     /* INTEGER */
static int hf_x509if_mapping = -1;                /* SEQUENCE_OF_Mapping */
static int hf_x509if_mapping_item = -1;           /* Mapping */
static int hf_x509if_substitution = -1;           /* SEQUENCE_OF_MRSubstitution */
static int hf_x509if_substitution_item = -1;      /* MRSubstitution */
static int hf_x509if_mappingFunction = -1;        /* OBJECT_IDENTIFIER */
static int hf_x509if_level = -1;                  /* INTEGER */
static int hf_x509if_oldMatchingRule = -1;        /* OBJECT_IDENTIFIER */
static int hf_x509if_newMatchingRule = -1;        /* OBJECT_IDENTIFIER */
/* named bits */
static int hf_x509if_AllowedSubset_baseObject = -1;
static int hf_x509if_AllowedSubset_oneLevel = -1;
static int hf_x509if_AllowedSubset_wholeSubtree = -1;

/*--- End of included file: packet-x509if-hf.c ---*/
#line 52 "packet-x509if-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-x509if-ett.c ---*/
#line 1 "packet-x509if-ett.c"
static gint ett_x509if_Attribute = -1;
static gint ett_x509if_SET_OF_AttributeValue = -1;
static gint ett_x509if_T_valuesWithContext = -1;
static gint ett_x509if_T_valuesWithContext_item = -1;
static gint ett_x509if_SET_OF_Context = -1;
static gint ett_x509if_Context = -1;
static gint ett_x509if_AttributeValueAssertion = -1;
static gint ett_x509if_T_assertedContexts = -1;
static gint ett_x509if_SET_OF_ContextAssertion = -1;
static gint ett_x509if_ContextAssertion = -1;
static gint ett_x509if_SET_OF_ContextValue = -1;
static gint ett_x509if_AttributeTypeAssertion = -1;
static gint ett_x509if_SEQUENCE_OF_ContextAssertion = -1;
static gint ett_x509if_Name = -1;
static gint ett_x509if_RDNSequence = -1;
static gint ett_x509if_RelativeDistinguishedName = -1;
static gint ett_x509if_AttributeTypeAndDistinguishedValue = -1;
static gint ett_x509if_T_valWithContext = -1;
static gint ett_x509if_T_valWithContext_item = -1;
static gint ett_x509if_SubtreeSpecification = -1;
static gint ett_x509if_T_specificExclusions = -1;
static gint ett_x509if_T_specificExclusions_item = -1;
static gint ett_x509if_ChopSpecification = -1;
static gint ett_x509if_T_chopSpecificExclusions = -1;
static gint ett_x509if_T_chopSpecificExclusions_item = -1;
static gint ett_x509if_Refinement = -1;
static gint ett_x509if_SET_OF_Refinement = -1;
static gint ett_x509if_DITStructureRule = -1;
static gint ett_x509if_SET_OF_RuleIdentifier = -1;
static gint ett_x509if_DITContentRule = -1;
static gint ett_x509if_T_auxiliaries = -1;
static gint ett_x509if_SET_SIZE_1_MAX_OF_AttributeId = -1;
static gint ett_x509if_DITContextUse = -1;
static gint ett_x509if_T_mandatoryContexts = -1;
static gint ett_x509if_T_optionalContexts = -1;
static gint ett_x509if_SearchRuleDescription = -1;
static gint ett_x509if_SEQUENCE_OF_RequestAttribute = -1;
static gint ett_x509if_SEQUENCE_OF_ResultAttribute = -1;
static gint ett_x509if_SEQUENCE_OF_AttributeType = -1;
static gint ett_x509if_SET_OF_DirectoryString = -1;
static gint ett_x509if_SearchRule = -1;
static gint ett_x509if_SearchRuleId = -1;
static gint ett_x509if_AllowedSubset = -1;
static gint ett_x509if_RequestAttribute = -1;
static gint ett_x509if_SEQUENCE_OF_SelectedValues = -1;
static gint ett_x509if_T_defaultValues = -1;
static gint ett_x509if_T_defaultValues_item = -1;
static gint ett_x509if_SEQUENCE_OF_DefaultValueValues = -1;
static gint ett_x509if_SEQUENCE_OF_ContextProfile = -1;
static gint ett_x509if_SEQUENCE_OF_MatchingUse = -1;
static gint ett_x509if_ContextProfile = -1;
static gint ett_x509if_SEQUENCE_OF_AttributeValue = -1;
static gint ett_x509if_ContextCombination = -1;
static gint ett_x509if_SEQUENCE_OF_ContextCombination = -1;
static gint ett_x509if_MatchingUse = -1;
static gint ett_x509if_AttributeCombination = -1;
static gint ett_x509if_SEQUENCE_OF_AttributeCombination = -1;
static gint ett_x509if_ResultAttribute = -1;
static gint ett_x509if_T_outputValues = -1;
static gint ett_x509if_OutputValues = -1;
static gint ett_x509if_ControlOptions = -1;
static gint ett_x509if_EntryLimit = -1;
static gint ett_x509if_RelaxationPolicy = -1;
static gint ett_x509if_SEQUENCE_OF_MRMapping = -1;
static gint ett_x509if_MRMapping = -1;
static gint ett_x509if_SEQUENCE_OF_Mapping = -1;
static gint ett_x509if_SEQUENCE_OF_MRSubstitution = -1;
static gint ett_x509if_Mapping = -1;
static gint ett_x509if_MRSubstitution = -1;

/*--- End of included file: packet-x509if-ett.c ---*/
#line 55 "packet-x509if-template.c"

static const char *object_identifier_id;
static proto_tree *top_of_dn = NULL;
static proto_tree *top_of_rdn = NULL;

static gboolean rdn_one_value = FALSE; /* have we seen one value in an RDN yet */
static gboolean dn_one_rdn = FALSE; /* have we seen one RDN in a DN yet */
static gboolean doing_dn = TRUE;

#define MAX_RDN_STR_LEN   64
#define MAX_DN_STR_LEN    (20 * MAX_RDN_STR_LEN)

static char *last_dn = NULL;
static char *last_rdn = NULL;

static int ava_hf_index;
#define MAX_FMT_VALS   32
static value_string fmt_vals[MAX_FMT_VALS];
#define MAX_AVA_STR_LEN   64
static char *last_ava = NULL;


/*--- Included file: packet-x509if-fn.c ---*/
#line 1 "packet-x509if-fn.c"
/*--- Cyclic dependencies ---*/

/* Refinement -> Refinement/and -> Refinement */
/* Refinement -> Refinement */
int dissect_x509if_Refinement(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_specificationFilter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Refinement(FALSE, tvb, offset, pinfo, tree, hf_x509if_specificationFilter);
}
static int dissect_refinement_and_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Refinement(FALSE, tvb, offset, pinfo, tree, hf_x509if_refinement_and_item);
}
static int dissect_refinement_or_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Refinement(FALSE, tvb, offset, pinfo, tree, hf_x509if_refinement_or_item);
}
static int dissect_refinement_not(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Refinement(FALSE, tvb, offset, pinfo, tree, hf_x509if_refinement_not);
}

/* ContextCombination -> ContextCombination/and -> ContextCombination */
/* ContextCombination -> ContextCombination */
int dissect_x509if_ContextCombination(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_contextCombination(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextCombination);
}
static int dissect_contextcombination_and_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextcombination_and_item);
}
static int dissect_contextcombination_or_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextcombination_or_item);
}
static int dissect_contextcombination_not(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextcombination_not);
}

/* AttributeCombination -> AttributeCombination/and -> AttributeCombination */
/* AttributeCombination -> AttributeCombination */
int dissect_x509if_AttributeCombination(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_attributeCombination(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_attributeCombination);
}
static int dissect_and_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_and_item);
}
static int dissect_or_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_or_item);
}
static int dissect_not(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_not);
}


/*--- Fields for imported types ---*/

static int dissect_name_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_x509if_name_item);
}
static int dissect_description(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_x509if_description);
}



static int
dissect_x509if_AttributeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 112 "x509if.cnf"
  const char *fmt; 
  const char *name;

    offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);


  if(object_identifier_id) {
    /* see if we can find a nice name */
    name = get_ber_oid_name(object_identifier_id);
    if(!name) name = object_identifier_id;    

    if(doing_dn) { /* append it to the RDN */
      g_strlcat(last_rdn, name, MAX_RDN_STR_LEN);
      g_strlcat(last_rdn, "=", MAX_RDN_STR_LEN);

     /* append it to the tree */
     proto_item_append_text(tree, " (%s=", name);
    }

    if((fmt = val_to_str(hf_index, fmt_vals, "")) && *fmt) {
      /* we have a format */
      last_ava = ep_alloc(MAX_AVA_STR_LEN); *last_ava = '\0';

      g_snprintf(last_ava, MAX_AVA_STR_LEN, "%s %s", name, fmt);

      proto_item_append_text(tree, " %s", last_ava);

    }
  }



  return offset;
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_type);
}
static int dissect_contextType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextType);
}
static int dissect_mandatory_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_mandatory_item);
}
static int dissect_optional_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_optional_item);
}
static int dissect_precluded_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_precluded_item);
}
static int dissect_attributeType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_attributeType);
}
static int dissect_restrictionType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_restrictionType);
}



int
dissect_x509if_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 142 "x509if.cnf"
  int old_offset = offset;
  tvbuff_t	*out_tvb;
  char  	*value = NULL;
  const char 	*fmt; 
  const char	*name = NULL;

  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);

  /* try and dissect as a string */
  dissect_ber_octet_string(FALSE, pinfo, NULL, tvb, old_offset, hf_x509if_any_string, &out_tvb);
  
  /* should also try and dissect as an OID and integer */
  /* of course, if I can look up the syntax .... */

  if(out_tvb) {
    /* it was a string - format it */
    value = tvb_format_text(out_tvb, 0, tvb_length(out_tvb));

    if(doing_dn) {
      g_strlcat(last_rdn, value, MAX_RDN_STR_LEN);

      /* append it to the tree*/
      proto_item_append_text(tree, "%s)", value);
    }

    if((fmt = val_to_str(ava_hf_index, fmt_vals, "")) && *fmt) {
      /* we have a format */

    if(!(name = get_ber_oid_name(object_identifier_id)))
      name = object_identifier_id;
    g_snprintf(last_ava, MAX_AVA_STR_LEN, "%s %s %s", name, fmt, value);

    proto_item_append_text(tree, " %s", last_ava);

    }
  }



  return offset;
}
static int dissect_values_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_values_item);
}
static int dissect_contextValues_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextValues_item);
}
static int dissect_assertion(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_assertion);
}
static int dissect_atadv_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_atadv_value);
}
static int dissect_contextValue_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextValue_item);
}
static int dissect_restrictionValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_restrictionValue);
}
static int dissect_selectedValues_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_selectedValues_item);
}



static int
dissect_x509if_ValuesWithContextValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 189 "x509if.cnf"
  offset=call_ber_oid_callback("unknown", tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ValuesWithContextValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_value);
}
static int dissect_distingAttrValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ValuesWithContextValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_distingAttrValue);
}


static const ber_sequence_t SET_OF_AttributeValue_set_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_values_item },
};

static int
dissect_x509if_SET_OF_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AttributeValue_set_of, hf_index, ett_x509if_SET_OF_AttributeValue);

  return offset;
}
static int dissect_values(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_OF_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_values);
}
static int dissect_contextValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_OF_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextValues);
}



static int
dissect_x509if_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_fallback(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x509if_fallback);
}
static int dissect_primaryDistinguished(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x509if_primaryDistinguished);
}
static int dissect_obsolete(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x509if_obsolete);
}
static int dissect_includeSubtypes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x509if_includeSubtypes);
}


static const ber_sequence_t Context_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_contextType },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_contextValues },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_fallback },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_Context(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Context_sequence, hf_index, ett_x509if_Context);

  return offset;
}
static int dissect_contextList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Context(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextList_item);
}


static const ber_sequence_t SET_OF_Context_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_contextList_item },
};

static int
dissect_x509if_SET_OF_Context(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Context_set_of, hf_index, ett_x509if_SET_OF_Context);

  return offset;
}
static int dissect_contextList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_OF_Context(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextList);
}


static const ber_sequence_t T_valuesWithContext_item_sequence[] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_value },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_contextList },
  { 0, 0, 0, NULL }
};

static int
dissect_x509if_T_valuesWithContext_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_valuesWithContext_item_sequence, hf_index, ett_x509if_T_valuesWithContext_item);

  return offset;
}
static int dissect_valuesWithContext_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_valuesWithContext_item(FALSE, tvb, offset, pinfo, tree, hf_x509if_valuesWithContext_item);
}


static const ber_sequence_t T_valuesWithContext_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_valuesWithContext_item },
};

static int
dissect_x509if_T_valuesWithContext(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_valuesWithContext_set_of, hf_index, ett_x509if_T_valuesWithContext);

  return offset;
}
static int dissect_valuesWithContext(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_valuesWithContext(FALSE, tvb, offset, pinfo, tree, hf_x509if_valuesWithContext);
}


static const ber_sequence_t Attribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_values },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_valuesWithContext },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Attribute_sequence, hf_index, ett_x509if_Attribute);

  return offset;
}



int
dissect_x509if_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509if_AttributeId(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_additionalControl_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509if_additionalControl_item);
}
static int dissect_attribute(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509if_attribute);
}



static int
dissect_x509if_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_allContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_NULL(FALSE, tvb, offset, pinfo, tree, hf_x509if_allContexts);
}
static int dissect_matchedValuesOnly(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_NULL(FALSE, tvb, offset, pinfo, tree, hf_x509if_matchedValuesOnly);
}



static int
dissect_x509if_ContextId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}
static int dissect_ca_contextType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextId(FALSE, tvb, offset, pinfo, tree, hf_x509if_ca_contextType);
}



static int
dissect_x509if_ContextValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 106 "x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_ca_contextValues_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_ca_contextValues_item);
}


static const ber_sequence_t SET_OF_ContextValue_set_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ca_contextValues_item },
};

static int
dissect_x509if_SET_OF_ContextValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ContextValue_set_of, hf_index, ett_x509if_SET_OF_ContextValue);

  return offset;
}
static int dissect_ca_contextValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_OF_ContextValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_ca_contextValues);
}


static const ber_sequence_t ContextAssertion_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ca_contextType },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ca_contextValues },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ContextAssertion_sequence, hf_index, ett_x509if_ContextAssertion);

  return offset;
}
static int dissect_selectedContexts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_x509if_selectedContexts_item);
}
static int dissect_assertedContexts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_x509if_assertedContexts_item);
}


static const ber_sequence_t SET_OF_ContextAssertion_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_selectedContexts_item },
};

static int
dissect_x509if_SET_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ContextAssertion_set_of, hf_index, ett_x509if_SET_OF_ContextAssertion);

  return offset;
}
static int dissect_selectedContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_OF_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_x509if_selectedContexts);
}


static const value_string x509if_T_assertedContexts_vals[] = {
  {   0, "allContexts" },
  {   1, "selectedContexts" },
  { 0, NULL }
};

static const ber_choice_t T_assertedContexts_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_allContexts },
  {   1, BER_CLASS_CON, 1, 0, dissect_selectedContexts },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_assertedContexts(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_assertedContexts_choice, hf_index, ett_x509if_T_assertedContexts,
                                 NULL);

  return offset;
}
static int dissect_assertedContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_assertedContexts(FALSE, tvb, offset, pinfo, tree, hf_x509if_assertedContexts);
}


static const ber_sequence_t AttributeValueAssertion_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_assertion },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_assertedContexts },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_AttributeValueAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 262 "x509if.cnf"

	ava_hf_index = hf_index;
	last_ava = ep_alloc(MAX_AVA_STR_LEN); *last_ava = '\0';

	  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeValueAssertion_sequence, hf_index, ett_x509if_AttributeValueAssertion);


	ava_hf_index=-1;



  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ContextAssertion_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_assertedContexts_item },
};

static int
dissect_x509if_SEQUENCE_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_ContextAssertion_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_ContextAssertion);

  return offset;
}
static int dissect_ata_assertedContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_x509if_ata_assertedContexts);
}


static const ber_sequence_t AttributeTypeAssertion_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ata_assertedContexts },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_AttributeTypeAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeTypeAssertion_sequence, hf_index, ett_x509if_AttributeTypeAssertion);

  return offset;
}


static const ber_sequence_t T_valWithContext_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_distingAttrValue },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_contextList },
  { 0, 0, 0, NULL }
};

static int
dissect_x509if_T_valWithContext_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_valWithContext_item_sequence, hf_index, ett_x509if_T_valWithContext_item);

  return offset;
}
static int dissect_valueswithContext_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_valWithContext_item(FALSE, tvb, offset, pinfo, tree, hf_x509if_valueswithContext_item);
}


static const ber_sequence_t T_valWithContext_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_valueswithContext_item },
};

static int
dissect_x509if_T_valWithContext(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_valWithContext_set_of, hf_index, ett_x509if_T_valWithContext);

  return offset;
}
static int dissect_valueswithContext(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_valWithContext(FALSE, tvb, offset, pinfo, tree, hf_x509if_valueswithContext);
}


static const ber_sequence_t AttributeTypeAndDistinguishedValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_atadv_value },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_primaryDistinguished },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_valueswithContext },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_AttributeTypeAndDistinguishedValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeTypeAndDistinguishedValue_sequence, hf_index, ett_x509if_AttributeTypeAndDistinguishedValue);

  return offset;
}



static int
dissect_x509if_RelativeDistinguishedName_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 217 "x509if.cnf"

  if(!rdn_one_value) {
    top_of_rdn = tree;
  } else {

   if(doing_dn)  
     /* this is an additional value - delimit */
     g_strlcat(last_rdn, "+", MAX_RDN_STR_LEN);
  }

    offset = dissect_x509if_AttributeTypeAndDistinguishedValue(implicit_tag, tvb, offset, pinfo, tree, hf_index);


  rdn_one_value = TRUE;



  return offset;
}
static int dissect_RelativeDistinguishedName_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RelativeDistinguishedName_item(FALSE, tvb, offset, pinfo, tree, hf_x509if_RelativeDistinguishedName_item);
}


static const ber_sequence_t RelativeDistinguishedName_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RelativeDistinguishedName_item },
};

int
dissect_x509if_RelativeDistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 192 "x509if.cnf"
  char *temp_dn;

  rdn_one_value = FALSE;
  top_of_rdn = tree;
  last_rdn = ep_alloc(MAX_DN_STR_LEN); *last_rdn = '\0';
  doing_dn = TRUE;

    offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 RelativeDistinguishedName_set_of, hf_index, ett_x509if_RelativeDistinguishedName);


  /* we've finished - close the bracket */
  proto_item_append_text(top_of_rdn, " (%s)", last_rdn);

  /* now append this to the DN */
  if(*last_dn) {
     temp_dn = ep_alloc(MAX_DN_STR_LEN); /* is there a better way to use ep_alloc here ? */
     g_snprintf(temp_dn, MAX_DN_STR_LEN, "%s,%s", last_rdn, last_dn);
     last_dn[0] = '\0';
     g_strlcat(last_dn, temp_dn, MAX_DN_STR_LEN);
  } else
     g_strlcat(last_dn, last_rdn, MAX_DN_STR_LEN);

  doing_dn = FALSE;
  last_rdn = NULL; /* it will get freed when the next packet is dissected */



  return offset;
}



static int
dissect_x509if_RDNSequence_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 251 "x509if.cnf"

  if(!dn_one_rdn)  {
    /* this is the first element - record the top */
    top_of_dn = tree;
  } 

    offset = dissect_x509if_RelativeDistinguishedName(implicit_tag, tvb, offset, pinfo, tree, hf_index);


  dn_one_rdn = TRUE;



  return offset;
}
static int dissect_RDNSequence_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RDNSequence_item(FALSE, tvb, offset, pinfo, tree, hf_x509if_RDNSequence_item);
}


static const ber_sequence_t RDNSequence_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_RDNSequence_item },
};

int
dissect_x509if_RDNSequence(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 232 "x509if.cnf"
  const char *fmt; 

  dn_one_rdn = FALSE; /* reset */
  last_dn = ep_alloc(MAX_RDN_STR_LEN); *last_dn = '\0';
  top_of_dn = NULL;

    offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RDNSequence_sequence_of, hf_index, ett_x509if_RDNSequence);


  /* we've finished - append the dn */
  proto_item_append_text(top_of_dn, " (%s)", last_dn);

 /* see if we should append this to the col info */
  if(check_col(pinfo->cinfo, COL_INFO) &&
     (fmt = val_to_str(hf_index, fmt_vals, "")) && *fmt) {
      /* we have a format */
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s%s", fmt, last_dn);
    }



  return offset;
}
static int dissect_rdnSequence(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RDNSequence(FALSE, tvb, offset, pinfo, tree, hf_x509if_rdnSequence);
}


const value_string x509if_Name_vals[] = {
  {   0, "rdnSequence" },
  { 0, NULL }
};

static const ber_choice_t Name_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_rdnSequence },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509if_Name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Name_choice, hf_index, ett_x509if_Name,
                                 NULL);

  return offset;
}



int
dissect_x509if_DistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509if_RDNSequence(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



int
dissect_x509if_LocalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509if_RDNSequence(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_base(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_LocalName(FALSE, tvb, offset, pinfo, tree, hf_x509if_base);
}
static int dissect_chopBefore(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_LocalName(FALSE, tvb, offset, pinfo, tree, hf_x509if_chopBefore);
}
static int dissect_chopAfter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_LocalName(FALSE, tvb, offset, pinfo, tree, hf_x509if_chopAfter);
}


static const value_string x509if_T_specificExclusions_item_vals[] = {
  {   0, "chopBefore" },
  {   1, "chopAfter" },
  { 0, NULL }
};

static const ber_choice_t T_specificExclusions_item_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_chopBefore },
  {   1, BER_CLASS_CON, 1, 0, dissect_chopAfter },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_specificExclusions_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_specificExclusions_item_choice, hf_index, ett_x509if_T_specificExclusions_item,
                                 NULL);

  return offset;
}
static int dissect_specificExclusions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_specificExclusions_item(FALSE, tvb, offset, pinfo, tree, hf_x509if_specificExclusions_item);
}


static const ber_sequence_t T_specificExclusions_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_specificExclusions_item },
};

static int
dissect_x509if_T_specificExclusions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_specificExclusions_set_of, hf_index, ett_x509if_T_specificExclusions);

  return offset;
}
static int dissect_specificExclusions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_specificExclusions(FALSE, tvb, offset, pinfo, tree, hf_x509if_specificExclusions);
}



int
dissect_x509if_BaseDistance(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_minimum(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_BaseDistance(FALSE, tvb, offset, pinfo, tree, hf_x509if_minimum);
}
static int dissect_maximum(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_BaseDistance(FALSE, tvb, offset, pinfo, tree, hf_x509if_maximum);
}



static int
dissect_x509if_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_item);
}
static int dissect_nameForm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_nameForm);
}
static int dissect_structuralObjectClass(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_structuralObjectClass);
}
static int dissect_auxiliaries_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_auxiliaries_item);
}
static int dissect_mandatoryContexts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_mandatoryContexts_item);
}
static int dissect_optionalContexts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_optionalContexts_item);
}
static int dissect_dmdId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_dmdId);
}
static int dissect_serviceType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_serviceType);
}
static int dissect_context(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_context);
}
static int dissect_mappingFunction(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_mappingFunction);
}
static int dissect_oldMatchingRule(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_oldMatchingRule);
}
static int dissect_newMatchingRule(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509if_newMatchingRule);
}


static const ber_sequence_t SET_OF_Refinement_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_refinement_and_item },
};

static int
dissect_x509if_SET_OF_Refinement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Refinement_set_of, hf_index, ett_x509if_SET_OF_Refinement);

  return offset;
}
static int dissect_refinement_and(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_OF_Refinement(FALSE, tvb, offset, pinfo, tree, hf_x509if_refinement_and);
}
static int dissect_refinement_or(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_OF_Refinement(FALSE, tvb, offset, pinfo, tree, hf_x509if_refinement_or);
}


const value_string x509if_Refinement_vals[] = {
  {   0, "item" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t Refinement_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_item },
  {   1, BER_CLASS_CON, 1, 0, dissect_refinement_and },
  {   2, BER_CLASS_CON, 2, 0, dissect_refinement_or },
  {   3, BER_CLASS_CON, 3, 0, dissect_refinement_not },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509if_Refinement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Refinement_choice, hf_index, ett_x509if_Refinement,
                                 NULL);

  return offset;
}


static const ber_sequence_t SubtreeSpecification_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_base },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_specificExclusions },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_minimum },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_maximum },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_specificationFilter },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_SubtreeSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SubtreeSpecification_sequence, hf_index, ett_x509if_SubtreeSpecification);

  return offset;
}


static const value_string x509if_T_chopSpecificExclusions_item_vals[] = {
  {   0, "chopBefore" },
  {   1, "chopAfter" },
  { 0, NULL }
};

static const ber_choice_t T_chopSpecificExclusions_item_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_chopBefore },
  {   1, BER_CLASS_CON, 1, 0, dissect_chopAfter },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_chopSpecificExclusions_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_chopSpecificExclusions_item_choice, hf_index, ett_x509if_T_chopSpecificExclusions_item,
                                 NULL);

  return offset;
}
static int dissect_chopSpecificExclusions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_chopSpecificExclusions_item(FALSE, tvb, offset, pinfo, tree, hf_x509if_chopSpecificExclusions_item);
}


static const ber_sequence_t T_chopSpecificExclusions_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_chopSpecificExclusions_item },
};

static int
dissect_x509if_T_chopSpecificExclusions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_chopSpecificExclusions_set_of, hf_index, ett_x509if_T_chopSpecificExclusions);

  return offset;
}
static int dissect_chopSpecificExclusions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_chopSpecificExclusions(FALSE, tvb, offset, pinfo, tree, hf_x509if_chopSpecificExclusions);
}


static const ber_sequence_t ChopSpecification_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_chopSpecificExclusions },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_minimum },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_maximum },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_ChopSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ChopSpecification_sequence, hf_index, ett_x509if_ChopSpecification);

  return offset;
}


static const value_string x509if_ObjectClassKind_vals[] = {
  {   0, "abstract" },
  {   1, "structural" },
  {   2, "auxiliary" },
  { 0, NULL }
};


static int
dissect_x509if_ObjectClassKind(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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
dissect_x509if_AttributeUsage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



int
dissect_x509if_RuleIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ruleIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RuleIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x509if_ruleIdentifier);
}
static int dissect_superiorStructureRules_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RuleIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x509if_superiorStructureRules_item);
}


static const ber_sequence_t SET_OF_RuleIdentifier_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_superiorStructureRules_item },
};

static int
dissect_x509if_SET_OF_RuleIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_RuleIdentifier_set_of, hf_index, ett_x509if_SET_OF_RuleIdentifier);

  return offset;
}
static int dissect_superiorStructureRules(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_OF_RuleIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x509if_superiorStructureRules);
}


static const ber_sequence_t DITStructureRule_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ruleIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_nameForm },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_superiorStructureRules },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_DITStructureRule(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DITStructureRule_sequence, hf_index, ett_x509if_DITStructureRule);

  return offset;
}


static const ber_sequence_t T_auxiliaries_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_auxiliaries_item },
};

static int
dissect_x509if_T_auxiliaries(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_auxiliaries_set_of, hf_index, ett_x509if_T_auxiliaries);

  return offset;
}
static int dissect_auxiliaries(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_auxiliaries(FALSE, tvb, offset, pinfo, tree, hf_x509if_auxiliaries);
}


static const ber_sequence_t SET_SIZE_1_MAX_OF_AttributeId_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_mandatory_item },
};

static int
dissect_x509if_SET_SIZE_1_MAX_OF_AttributeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_SIZE_1_MAX_OF_AttributeId_set_of, hf_index, ett_x509if_SET_SIZE_1_MAX_OF_AttributeId);

  return offset;
}
static int dissect_mandatory(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_SIZE_1_MAX_OF_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_mandatory);
}
static int dissect_optional(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_SIZE_1_MAX_OF_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_optional);
}
static int dissect_precluded(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_SIZE_1_MAX_OF_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_x509if_precluded);
}


static const ber_sequence_t DITContentRule_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_structuralObjectClass },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_auxiliaries },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_mandatory },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_optional },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_precluded },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_DITContentRule(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DITContentRule_sequence, hf_index, ett_x509if_DITContentRule);

  return offset;
}


static const ber_sequence_t T_mandatoryContexts_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_mandatoryContexts_item },
};

static int
dissect_x509if_T_mandatoryContexts(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_mandatoryContexts_set_of, hf_index, ett_x509if_T_mandatoryContexts);

  return offset;
}
static int dissect_mandatoryContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_mandatoryContexts(FALSE, tvb, offset, pinfo, tree, hf_x509if_mandatoryContexts);
}


static const ber_sequence_t T_optionalContexts_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_optionalContexts_item },
};

static int
dissect_x509if_T_optionalContexts(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_optionalContexts_set_of, hf_index, ett_x509if_T_optionalContexts);

  return offset;
}
static int dissect_optionalContexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_optionalContexts(FALSE, tvb, offset, pinfo, tree, hf_x509if_optionalContexts);
}


static const ber_sequence_t DITContextUse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attributeType },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_mandatoryContexts },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_optionalContexts },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_DITContextUse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DITContextUse_sequence, hf_index, ett_x509if_DITContextUse);

  return offset;
}



static int
dissect_x509if_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509if_id);
}
static int dissect_userClass(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509if_userClass);
}
static int dissect_default(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509if_default);
}
static int dissect_max(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509if_max);
}
static int dissect_maximum_relaxation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509if_maximum_relaxation);
}
static int dissect_minimum_relaxation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509if_minimum_relaxation);
}
static int dissect_level(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509if_level);
}



static int
dissect_x509if_SelectedValues(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 180 "x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_ra_selectedValues_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SelectedValues(FALSE, tvb, offset, pinfo, tree, hf_x509if_ra_selectedValues_item);
}


static const ber_sequence_t SEQUENCE_OF_SelectedValues_sequence_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ra_selectedValues_item },
};

static int
dissect_x509if_SEQUENCE_OF_SelectedValues(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_SelectedValues_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_SelectedValues);

  return offset;
}
static int dissect_ra_selectedValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_SelectedValues(FALSE, tvb, offset, pinfo, tree, hf_x509if_ra_selectedValues);
}



static int
dissect_x509if_DefaultValueType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_x509if_object_identifier_id, &object_identifier_id);

  return offset;
}
static int dissect_entryType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DefaultValueType(FALSE, tvb, offset, pinfo, tree, hf_x509if_entryType);
}



static int
dissect_x509if_DefaultValueValues(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 186 "x509if.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_ra_values_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DefaultValueValues(FALSE, tvb, offset, pinfo, tree, hf_x509if_ra_values_item);
}


static const ber_sequence_t SEQUENCE_OF_DefaultValueValues_sequence_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ra_values_item },
};

static int
dissect_x509if_SEQUENCE_OF_DefaultValueValues(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_DefaultValueValues_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_DefaultValueValues);

  return offset;
}
static int dissect_ra_values(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_DefaultValueValues(FALSE, tvb, offset, pinfo, tree, hf_x509if_ra_values);
}


static const ber_sequence_t T_defaultValues_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_entryType },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ra_values },
  { 0, 0, 0, NULL }
};

static int
dissect_x509if_T_defaultValues_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_defaultValues_item_sequence, hf_index, ett_x509if_T_defaultValues_item);

  return offset;
}
static int dissect_defaultValues_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_defaultValues_item(FALSE, tvb, offset, pinfo, tree, hf_x509if_defaultValues_item);
}


static const ber_sequence_t T_defaultValues_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_defaultValues_item },
};

static int
dissect_x509if_T_defaultValues(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_defaultValues_sequence_of, hf_index, ett_x509if_T_defaultValues);

  return offset;
}
static int dissect_defaultValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_defaultValues(FALSE, tvb, offset, pinfo, tree, hf_x509if_defaultValues);
}


static const ber_sequence_t SEQUENCE_OF_AttributeValue_sequence_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_contextValue_item },
};

static int
dissect_x509if_SEQUENCE_OF_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeValue_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_AttributeValue);

  return offset;
}
static int dissect_contextValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextValue);
}
static int dissect_selectedValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_selectedValues);
}


static const ber_sequence_t ContextProfile_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_contextType },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_contextValue },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_ContextProfile(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ContextProfile_sequence, hf_index, ett_x509if_ContextProfile);

  return offset;
}
static int dissect_contexts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextProfile(FALSE, tvb, offset, pinfo, tree, hf_x509if_contexts_item);
}


static const ber_sequence_t SEQUENCE_OF_ContextProfile_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_contexts_item },
};

static int
dissect_x509if_SEQUENCE_OF_ContextProfile(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_ContextProfile_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_ContextProfile);

  return offset;
}
static int dissect_contexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_ContextProfile(FALSE, tvb, offset, pinfo, tree, hf_x509if_contexts);
}


static const ber_sequence_t SEQUENCE_OF_ContextCombination_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_contextcombination_and_item },
};

static int
dissect_x509if_SEQUENCE_OF_ContextCombination(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_ContextCombination_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_ContextCombination);

  return offset;
}
static int dissect_contextcombination_and(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_ContextCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextcombination_and);
}
static int dissect_contextcombination_or(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_ContextCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_contextcombination_or);
}


const value_string x509if_ContextCombination_vals[] = {
  {   0, "context" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t ContextCombination_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_context },
  {   1, BER_CLASS_CON, 1, 0, dissect_contextcombination_and },
  {   2, BER_CLASS_CON, 2, 0, dissect_contextcombination_or },
  {   3, BER_CLASS_CON, 3, 0, dissect_contextcombination_not },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509if_ContextCombination(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ContextCombination_choice, hf_index, ett_x509if_ContextCombination,
                                 NULL);

  return offset;
}


static const ber_sequence_t MatchingUse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_restrictionType },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_restrictionValue },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_MatchingUse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MatchingUse_sequence, hf_index, ett_x509if_MatchingUse);

  return offset;
}
static int dissect_matchingUse_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_MatchingUse(FALSE, tvb, offset, pinfo, tree, hf_x509if_matchingUse_item);
}


static const ber_sequence_t SEQUENCE_OF_MatchingUse_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_matchingUse_item },
};

static int
dissect_x509if_SEQUENCE_OF_MatchingUse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_MatchingUse_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_MatchingUse);

  return offset;
}
static int dissect_matchingUse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_MatchingUse(FALSE, tvb, offset, pinfo, tree, hf_x509if_matchingUse);
}


static const ber_sequence_t RequestAttribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attributeType },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_includeSubtypes },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_ra_selectedValues },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_defaultValues },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_contexts },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_contextCombination },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_matchingUse },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_RequestAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RequestAttribute_sequence, hf_index, ett_x509if_RequestAttribute);

  return offset;
}
static int dissect_inputAttributeTypes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RequestAttribute(FALSE, tvb, offset, pinfo, tree, hf_x509if_inputAttributeTypes_item);
}


static const ber_sequence_t SEQUENCE_OF_RequestAttribute_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_inputAttributeTypes_item },
};

static int
dissect_x509if_SEQUENCE_OF_RequestAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_RequestAttribute_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_RequestAttribute);

  return offset;
}
static int dissect_inputAttributeTypes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_RequestAttribute(FALSE, tvb, offset, pinfo, tree, hf_x509if_inputAttributeTypes);
}


static const ber_sequence_t SEQUENCE_OF_AttributeCombination_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_and_item },
};

static int
dissect_x509if_SEQUENCE_OF_AttributeCombination(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeCombination_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_AttributeCombination);

  return offset;
}
static int dissect_and(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_AttributeCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_and);
}
static int dissect_or(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_AttributeCombination(FALSE, tvb, offset, pinfo, tree, hf_x509if_or);
}


const value_string x509if_AttributeCombination_vals[] = {
  {   0, "attribute" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t AttributeCombination_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_attribute },
  {   1, BER_CLASS_CON, 1, 0, dissect_and },
  {   2, BER_CLASS_CON, 2, 0, dissect_or },
  {   3, BER_CLASS_CON, 3, 0, dissect_not },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509if_AttributeCombination(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AttributeCombination_choice, hf_index, ett_x509if_AttributeCombination,
                                 NULL);

  return offset;
}


static const value_string x509if_T_outputValues_vals[] = {
  {   0, "selectedValues" },
  {   1, "matchedValuesOnly" },
  { 0, NULL }
};

static const ber_choice_t T_outputValues_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_selectedValues },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_matchedValuesOnly },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509if_T_outputValues(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_outputValues_choice, hf_index, ett_x509if_T_outputValues,
                                 NULL);

  return offset;
}
static int dissect_outputValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_T_outputValues(FALSE, tvb, offset, pinfo, tree, hf_x509if_outputValues);
}


static const ber_sequence_t ResultAttribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attributeType },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_outputValues },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_contexts },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_ResultAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ResultAttribute_sequence, hf_index, ett_x509if_ResultAttribute);

  return offset;
}
static int dissect_outputAttributeTypes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ResultAttribute(FALSE, tvb, offset, pinfo, tree, hf_x509if_outputAttributeTypes_item);
}


static const ber_sequence_t SEQUENCE_OF_ResultAttribute_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_outputAttributeTypes_item },
};

static int
dissect_x509if_SEQUENCE_OF_ResultAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_ResultAttribute_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_ResultAttribute);

  return offset;
}
static int dissect_outputAttributeTypes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_ResultAttribute(FALSE, tvb, offset, pinfo, tree, hf_x509if_outputAttributeTypes);
}


static const ber_sequence_t ControlOptions_sequence[] = {
  { 0, 0, 0, NULL }
};

int
dissect_x509if_ControlOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ControlOptions_sequence, hf_index, ett_x509if_ControlOptions);

  return offset;
}
static int dissect_defaultControls(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ControlOptions(FALSE, tvb, offset, pinfo, tree, hf_x509if_defaultControls);
}
static int dissect_mandatoryControls(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ControlOptions(FALSE, tvb, offset, pinfo, tree, hf_x509if_mandatoryControls);
}
static int dissect_searchRuleControls(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ControlOptions(FALSE, tvb, offset, pinfo, tree, hf_x509if_searchRuleControls);
}


static const ber_sequence_t Mapping_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_mappingFunction },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_level },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_Mapping(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Mapping_sequence, hf_index, ett_x509if_Mapping);

  return offset;
}
static int dissect_mapping_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Mapping(FALSE, tvb, offset, pinfo, tree, hf_x509if_mapping_item);
}


static const ber_sequence_t SEQUENCE_OF_Mapping_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mapping_item },
};

static int
dissect_x509if_SEQUENCE_OF_Mapping(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Mapping_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_Mapping);

  return offset;
}
static int dissect_mapping(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_Mapping(FALSE, tvb, offset, pinfo, tree, hf_x509if_mapping);
}


static const ber_sequence_t MRSubstitution_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attribute },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_oldMatchingRule },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_newMatchingRule },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_MRSubstitution(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MRSubstitution_sequence, hf_index, ett_x509if_MRSubstitution);

  return offset;
}
static int dissect_substitution_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_MRSubstitution(FALSE, tvb, offset, pinfo, tree, hf_x509if_substitution_item);
}


static const ber_sequence_t SEQUENCE_OF_MRSubstitution_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_substitution_item },
};

static int
dissect_x509if_SEQUENCE_OF_MRSubstitution(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_MRSubstitution_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_MRSubstitution);

  return offset;
}
static int dissect_substitution(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_MRSubstitution(FALSE, tvb, offset, pinfo, tree, hf_x509if_substitution);
}


static const ber_sequence_t MRMapping_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_mapping },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_substitution },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_MRMapping(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MRMapping_sequence, hf_index, ett_x509if_MRMapping);

  return offset;
}
static int dissect_basic(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_MRMapping(FALSE, tvb, offset, pinfo, tree, hf_x509if_basic);
}
static int dissect_tightenings_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_MRMapping(FALSE, tvb, offset, pinfo, tree, hf_x509if_tightenings_item);
}
static int dissect_relaxations_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_MRMapping(FALSE, tvb, offset, pinfo, tree, hf_x509if_relaxations_item);
}


static const ber_sequence_t SEQUENCE_OF_MRMapping_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tightenings_item },
};

static int
dissect_x509if_SEQUENCE_OF_MRMapping(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_MRMapping_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_MRMapping);

  return offset;
}
static int dissect_tightenings(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_MRMapping(FALSE, tvb, offset, pinfo, tree, hf_x509if_tightenings);
}
static int dissect_relaxations(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_MRMapping(FALSE, tvb, offset, pinfo, tree, hf_x509if_relaxations);
}


static const ber_sequence_t RelaxationPolicy_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_basic },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_tightenings },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_relaxations },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_maximum_relaxation },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_minimum_relaxation },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_RelaxationPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RelaxationPolicy_sequence, hf_index, ett_x509if_RelaxationPolicy);

  return offset;
}
static int dissect_relaxation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RelaxationPolicy(FALSE, tvb, offset, pinfo, tree, hf_x509if_relaxation);
}


static const ber_sequence_t SEQUENCE_OF_AttributeType_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_additionalControl_item },
};

static int
dissect_x509if_SEQUENCE_OF_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeType_sequence_of, hf_index, ett_x509if_SEQUENCE_OF_AttributeType);

  return offset;
}
static int dissect_additionalControl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SEQUENCE_OF_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509if_additionalControl);
}


static const asn_namedbit AllowedSubset_bits[] = {
  {  0, &hf_x509if_AllowedSubset_baseObject, -1, -1, "baseObject", NULL },
  {  1, &hf_x509if_AllowedSubset_oneLevel, -1, -1, "oneLevel", NULL },
  {  2, &hf_x509if_AllowedSubset_wholeSubtree, -1, -1, "wholeSubtree", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_x509if_AllowedSubset(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    AllowedSubset_bits, hf_index, ett_x509if_AllowedSubset,
                                    NULL);

  return offset;
}
static int dissect_allowedSubset(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AllowedSubset(FALSE, tvb, offset, pinfo, tree, hf_x509if_allowedSubset);
}


const value_string x509if_ImposedSubset_vals[] = {
  {   0, "baseObject" },
  {   1, "oneLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


int
dissect_x509if_ImposedSubset(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_imposedSubset(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ImposedSubset(FALSE, tvb, offset, pinfo, tree, hf_x509if_imposedSubset);
}


static const ber_sequence_t EntryLimit_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_default },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_max },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_EntryLimit(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EntryLimit_sequence, hf_index, ett_x509if_EntryLimit);

  return offset;
}
static int dissect_entryLimit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_EntryLimit(FALSE, tvb, offset, pinfo, tree, hf_x509if_entryLimit);
}


static const ber_sequence_t SET_OF_DirectoryString_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_name_item },
};

static int
dissect_x509if_SET_OF_DirectoryString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_DirectoryString_set_of, hf_index, ett_x509if_SET_OF_DirectoryString);

  return offset;
}
static int dissect_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SET_OF_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_x509if_name);
}


static const ber_sequence_t SearchRuleDescription_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_id },
  { BER_CLASS_CON, 0, 0, dissect_dmdId },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_serviceType },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_userClass },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_inputAttributeTypes },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_attributeCombination },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_outputAttributeTypes },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_defaultControls },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_mandatoryControls },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_searchRuleControls },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_relaxation },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_additionalControl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_allowedSubset },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_imposedSubset },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL, dissect_entryLimit },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_name },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_description },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_obsolete },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_SearchRuleDescription(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SearchRuleDescription_sequence, hf_index, ett_x509if_SearchRuleDescription);

  return offset;
}


static const ber_sequence_t SearchRule_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_id },
  { BER_CLASS_CON, 0, 0, dissect_dmdId },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_serviceType },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_userClass },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_inputAttributeTypes },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_attributeCombination },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_outputAttributeTypes },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_defaultControls },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_mandatoryControls },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_searchRuleControls },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_relaxation },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_additionalControl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_allowedSubset },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_imposedSubset },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL, dissect_entryLimit },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_SearchRule(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SearchRule_sequence, hf_index, ett_x509if_SearchRule);

  return offset;
}


static const ber_sequence_t SearchRuleId_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_id },
  { BER_CLASS_CON, 0, 0, dissect_dmdId },
  { 0, 0, 0, NULL }
};

int
dissect_x509if_SearchRuleId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SearchRuleId_sequence, hf_index, ett_x509if_SearchRuleId);

  return offset;
}


const value_string x509if_OutputValues_vals[] = {
  {   0, "selectedValues" },
  {   1, "matchedValuesOnly" },
  { 0, NULL }
};

static const ber_choice_t OutputValues_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_selectedValues },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_matchedValuesOnly },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509if_OutputValues(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 OutputValues_choice, hf_index, ett_x509if_OutputValues,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_Name_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509if_Name(FALSE, tvb, 0, pinfo, tree, hf_x509if_Name_PDU);
}
static void dissect_DistinguishedName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509if_DistinguishedName(FALSE, tvb, 0, pinfo, tree, hf_x509if_DistinguishedName_PDU);
}


/*--- End of included file: packet-x509if-fn.c ---*/
#line 77 "packet-x509if-template.c"

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
      { "Id", "x509if.id", FT_STRING, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},
    { &hf_x509if_any_string, 
      { "AnyString", "x509if.any.String", FT_BYTES, BASE_HEX,
	    NULL, 0, "This is any String", HFILL }},
			 

/*--- Included file: packet-x509if-hfarr.c ---*/
#line 1 "packet-x509if-hfarr.c"
    { &hf_x509if_Name_PDU,
      { "Name", "x509if.Name",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_x509if_DistinguishedName_PDU,
      { "DistinguishedName", "x509if.DistinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_x509if_type,
      { "type", "x509if.type",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_values,
      { "values", "x509if.values",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Attribute/values", HFILL }},
    { &hf_x509if_values_item,
      { "Item", "x509if.values_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute/values/_item", HFILL }},
    { &hf_x509if_valuesWithContext,
      { "valuesWithContext", "x509if.valuesWithContext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Attribute/valuesWithContext", HFILL }},
    { &hf_x509if_valuesWithContext_item,
      { "Item", "x509if.valuesWithContext_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute/valuesWithContext/_item", HFILL }},
    { &hf_x509if_value,
      { "value", "x509if.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute/valuesWithContext/_item/value", HFILL }},
    { &hf_x509if_contextList,
      { "contextList", "x509if.contextList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_contextList_item,
      { "Item", "x509if.contextList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_contextType,
      { "contextType", "x509if.contextType",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_contextValues,
      { "contextValues", "x509if.contextValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Context/contextValues", HFILL }},
    { &hf_x509if_contextValues_item,
      { "Item", "x509if.contextValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Context/contextValues/_item", HFILL }},
    { &hf_x509if_fallback,
      { "fallback", "x509if.fallback",
        FT_BOOLEAN, 8, NULL, 0,
        "Context/fallback", HFILL }},
    { &hf_x509if_assertion,
      { "assertion", "x509if.assertion",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion/assertion", HFILL }},
    { &hf_x509if_assertedContexts,
      { "assertedContexts", "x509if.assertedContexts",
        FT_UINT32, BASE_DEC, VALS(x509if_T_assertedContexts_vals), 0,
        "AttributeValueAssertion/assertedContexts", HFILL }},
    { &hf_x509if_allContexts,
      { "allContexts", "x509if.allContexts",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion/assertedContexts/allContexts", HFILL }},
    { &hf_x509if_selectedContexts,
      { "selectedContexts", "x509if.selectedContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeValueAssertion/assertedContexts/selectedContexts", HFILL }},
    { &hf_x509if_selectedContexts_item,
      { "Item", "x509if.selectedContexts_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion/assertedContexts/selectedContexts/_item", HFILL }},
    { &hf_x509if_ca_contextType,
      { "contextType", "x509if.contextType",
        FT_OID, BASE_NONE, NULL, 0,
        "ContextAssertion/contextType", HFILL }},
    { &hf_x509if_ca_contextValues,
      { "contextValues", "x509if.contextValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContextAssertion/contextValues", HFILL }},
    { &hf_x509if_ca_contextValues_item,
      { "Item", "x509if.contextValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContextAssertion/contextValues/_item", HFILL }},
    { &hf_x509if_ata_assertedContexts,
      { "assertedContexts", "x509if.assertedContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeTypeAssertion/assertedContexts", HFILL }},
    { &hf_x509if_assertedContexts_item,
      { "Item", "x509if.assertedContexts_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeTypeAssertion/assertedContexts/_item", HFILL }},
    { &hf_x509if_rdnSequence,
      { "rdnSequence", "x509if.rdnSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name/rdnSequence", HFILL }},
    { &hf_x509if_RDNSequence_item,
      { "Item", "x509if.RDNSequence_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RDNSequence/_item", HFILL }},
    { &hf_x509if_RelativeDistinguishedName_item,
      { "Item", "x509if.RelativeDistinguishedName_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelativeDistinguishedName/_item", HFILL }},
    { &hf_x509if_atadv_value,
      { "value", "x509if.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeTypeAndDistinguishedValue/value", HFILL }},
    { &hf_x509if_primaryDistinguished,
      { "primaryDistinguished", "x509if.primaryDistinguished",
        FT_BOOLEAN, 8, NULL, 0,
        "AttributeTypeAndDistinguishedValue/primaryDistinguished", HFILL }},
    { &hf_x509if_valueswithContext,
      { "valuesWithContext", "x509if.valuesWithContext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeTypeAndDistinguishedValue/valuesWithContext", HFILL }},
    { &hf_x509if_valueswithContext_item,
      { "Item", "x509if.valuesWithContext_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeTypeAndDistinguishedValue/valuesWithContext/_item", HFILL }},
    { &hf_x509if_distingAttrValue,
      { "distingAttrValue", "x509if.distingAttrValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeTypeAndDistinguishedValue/valuesWithContext/_item/distingAttrValue", HFILL }},
    { &hf_x509if_base,
      { "base", "x509if.base",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubtreeSpecification/base", HFILL }},
    { &hf_x509if_specificExclusions,
      { "specificExclusions", "x509if.specificExclusions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubtreeSpecification/specificExclusions", HFILL }},
    { &hf_x509if_specificExclusions_item,
      { "Item", "x509if.specificExclusions_item",
        FT_UINT32, BASE_DEC, VALS(x509if_T_specificExclusions_item_vals), 0,
        "SubtreeSpecification/specificExclusions/_item", HFILL }},
    { &hf_x509if_chopBefore,
      { "chopBefore", "x509if.chopBefore",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_chopAfter,
      { "chopAfter", "x509if.chopAfter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_minimum,
      { "minimum", "x509if.minimum",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_maximum,
      { "maximum", "x509if.maximum",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_specificationFilter,
      { "specificationFilter", "x509if.specificationFilter",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        "SubtreeSpecification/specificationFilter", HFILL }},
    { &hf_x509if_chopSpecificExclusions,
      { "specificExclusions", "x509if.specificExclusions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChopSpecification/specificExclusions", HFILL }},
    { &hf_x509if_chopSpecificExclusions_item,
      { "Item", "x509if.specificExclusions_item",
        FT_UINT32, BASE_DEC, VALS(x509if_T_chopSpecificExclusions_item_vals), 0,
        "ChopSpecification/specificExclusions/_item", HFILL }},
    { &hf_x509if_item,
      { "item", "x509if.item",
        FT_OID, BASE_NONE, NULL, 0,
        "Refinement/item", HFILL }},
    { &hf_x509if_refinement_and,
      { "and", "x509if.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Refinement/and", HFILL }},
    { &hf_x509if_refinement_and_item,
      { "Item", "x509if.and_item",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        "Refinement/and/_item", HFILL }},
    { &hf_x509if_refinement_or,
      { "or", "x509if.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Refinement/or", HFILL }},
    { &hf_x509if_refinement_or_item,
      { "Item", "x509if.or_item",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        "Refinement/or/_item", HFILL }},
    { &hf_x509if_refinement_not,
      { "not", "x509if.not",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        "Refinement/not", HFILL }},
    { &hf_x509if_ruleIdentifier,
      { "ruleIdentifier", "x509if.ruleIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "DITStructureRule/ruleIdentifier", HFILL }},
    { &hf_x509if_nameForm,
      { "nameForm", "x509if.nameForm",
        FT_OID, BASE_NONE, NULL, 0,
        "DITStructureRule/nameForm", HFILL }},
    { &hf_x509if_superiorStructureRules,
      { "superiorStructureRules", "x509if.superiorStructureRules",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DITStructureRule/superiorStructureRules", HFILL }},
    { &hf_x509if_superiorStructureRules_item,
      { "Item", "x509if.superiorStructureRules_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "DITStructureRule/superiorStructureRules/_item", HFILL }},
    { &hf_x509if_structuralObjectClass,
      { "structuralObjectClass", "x509if.structuralObjectClass",
        FT_OID, BASE_NONE, NULL, 0,
        "DITContentRule/structuralObjectClass", HFILL }},
    { &hf_x509if_auxiliaries,
      { "auxiliaries", "x509if.auxiliaries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DITContentRule/auxiliaries", HFILL }},
    { &hf_x509if_auxiliaries_item,
      { "Item", "x509if.auxiliaries_item",
        FT_OID, BASE_NONE, NULL, 0,
        "DITContentRule/auxiliaries/_item", HFILL }},
    { &hf_x509if_mandatory,
      { "mandatory", "x509if.mandatory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DITContentRule/mandatory", HFILL }},
    { &hf_x509if_mandatory_item,
      { "Item", "x509if.mandatory_item",
        FT_OID, BASE_NONE, NULL, 0,
        "DITContentRule/mandatory/_item", HFILL }},
    { &hf_x509if_optional,
      { "optional", "x509if.optional",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DITContentRule/optional", HFILL }},
    { &hf_x509if_optional_item,
      { "Item", "x509if.optional_item",
        FT_OID, BASE_NONE, NULL, 0,
        "DITContentRule/optional/_item", HFILL }},
    { &hf_x509if_precluded,
      { "precluded", "x509if.precluded",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DITContentRule/precluded", HFILL }},
    { &hf_x509if_precluded_item,
      { "Item", "x509if.precluded_item",
        FT_OID, BASE_NONE, NULL, 0,
        "DITContentRule/precluded/_item", HFILL }},
    { &hf_x509if_attributeType,
      { "attributeType", "x509if.attributeType",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_mandatoryContexts,
      { "mandatoryContexts", "x509if.mandatoryContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DITContextUse/mandatoryContexts", HFILL }},
    { &hf_x509if_mandatoryContexts_item,
      { "Item", "x509if.mandatoryContexts_item",
        FT_OID, BASE_NONE, NULL, 0,
        "DITContextUse/mandatoryContexts/_item", HFILL }},
    { &hf_x509if_optionalContexts,
      { "optionalContexts", "x509if.optionalContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DITContextUse/optionalContexts", HFILL }},
    { &hf_x509if_optionalContexts_item,
      { "Item", "x509if.optionalContexts_item",
        FT_OID, BASE_NONE, NULL, 0,
        "DITContextUse/optionalContexts/_item", HFILL }},
    { &hf_x509if_id,
      { "id", "x509if.id",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_dmdId,
      { "dmdId", "x509if.dmdId",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_serviceType,
      { "serviceType", "x509if.serviceType",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_userClass,
      { "userClass", "x509if.userClass",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_inputAttributeTypes,
      { "inputAttributeTypes", "x509if.inputAttributeTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_inputAttributeTypes_item,
      { "Item", "x509if.inputAttributeTypes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_attributeCombination,
      { "attributeCombination", "x509if.attributeCombination",
        FT_UINT32, BASE_DEC, VALS(x509if_AttributeCombination_vals), 0,
        "", HFILL }},
    { &hf_x509if_outputAttributeTypes,
      { "outputAttributeTypes", "x509if.outputAttributeTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_outputAttributeTypes_item,
      { "Item", "x509if.outputAttributeTypes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_defaultControls,
      { "defaultControls", "x509if.defaultControls",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_mandatoryControls,
      { "mandatoryControls", "x509if.mandatoryControls",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_searchRuleControls,
      { "searchRuleControls", "x509if.searchRuleControls",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_relaxation,
      { "relaxation", "x509if.relaxation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_additionalControl,
      { "additionalControl", "x509if.additionalControl",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_additionalControl_item,
      { "Item", "x509if.additionalControl_item",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_allowedSubset,
      { "allowedSubset", "x509if.allowedSubset",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x509if_imposedSubset,
      { "imposedSubset", "x509if.imposedSubset",
        FT_UINT32, BASE_DEC, VALS(x509if_ImposedSubset_vals), 0,
        "", HFILL }},
    { &hf_x509if_entryLimit,
      { "entryLimit", "x509if.entryLimit",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_name,
      { "name", "x509if.name",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SearchRuleDescription/name", HFILL }},
    { &hf_x509if_name_item,
      { "Item", "x509if.name_item",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "SearchRuleDescription/name/_item", HFILL }},
    { &hf_x509if_description,
      { "description", "x509if.description",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "SearchRuleDescription/description", HFILL }},
    { &hf_x509if_obsolete,
      { "obsolete", "x509if.obsolete",
        FT_BOOLEAN, 8, NULL, 0,
        "SearchRuleDescription/obsolete", HFILL }},
    { &hf_x509if_includeSubtypes,
      { "includeSubtypes", "x509if.includeSubtypes",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestAttribute/includeSubtypes", HFILL }},
    { &hf_x509if_ra_selectedValues,
      { "selectedValues", "x509if.selectedValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestAttribute/selectedValues", HFILL }},
    { &hf_x509if_ra_selectedValues_item,
      { "Item", "x509if.selectedValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestAttribute/selectedValues/_item", HFILL }},
    { &hf_x509if_defaultValues,
      { "defaultValues", "x509if.defaultValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestAttribute/defaultValues", HFILL }},
    { &hf_x509if_defaultValues_item,
      { "Item", "x509if.defaultValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestAttribute/defaultValues/_item", HFILL }},
    { &hf_x509if_entryType,
      { "entryType", "x509if.entryType",
        FT_OID, BASE_NONE, NULL, 0,
        "RequestAttribute/defaultValues/_item/entryType", HFILL }},
    { &hf_x509if_ra_values,
      { "values", "x509if.values",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestAttribute/defaultValues/_item/values", HFILL }},
    { &hf_x509if_ra_values_item,
      { "Item", "x509if.values_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestAttribute/defaultValues/_item/values/_item", HFILL }},
    { &hf_x509if_contexts,
      { "contexts", "x509if.contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_contexts_item,
      { "Item", "x509if.contexts_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_contextCombination,
      { "contextCombination", "x509if.contextCombination",
        FT_UINT32, BASE_DEC, VALS(x509if_ContextCombination_vals), 0,
        "RequestAttribute/contextCombination", HFILL }},
    { &hf_x509if_matchingUse,
      { "matchingUse", "x509if.matchingUse",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestAttribute/matchingUse", HFILL }},
    { &hf_x509if_matchingUse_item,
      { "Item", "x509if.matchingUse_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestAttribute/matchingUse/_item", HFILL }},
    { &hf_x509if_contextValue,
      { "contextValue", "x509if.contextValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContextProfile/contextValue", HFILL }},
    { &hf_x509if_contextValue_item,
      { "Item", "x509if.contextValue_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContextProfile/contextValue/_item", HFILL }},
    { &hf_x509if_context,
      { "context", "x509if.context",
        FT_OID, BASE_NONE, NULL, 0,
        "ContextCombination/context", HFILL }},
    { &hf_x509if_contextcombination_and,
      { "and", "x509if.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContextCombination/and", HFILL }},
    { &hf_x509if_contextcombination_and_item,
      { "Item", "x509if.and_item",
        FT_UINT32, BASE_DEC, VALS(x509if_ContextCombination_vals), 0,
        "ContextCombination/and/_item", HFILL }},
    { &hf_x509if_contextcombination_or,
      { "or", "x509if.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContextCombination/or", HFILL }},
    { &hf_x509if_contextcombination_or_item,
      { "Item", "x509if.or_item",
        FT_UINT32, BASE_DEC, VALS(x509if_ContextCombination_vals), 0,
        "ContextCombination/or/_item", HFILL }},
    { &hf_x509if_contextcombination_not,
      { "not", "x509if.not",
        FT_UINT32, BASE_DEC, VALS(x509if_ContextCombination_vals), 0,
        "ContextCombination/not", HFILL }},
    { &hf_x509if_restrictionType,
      { "restrictionType", "x509if.restrictionType",
        FT_OID, BASE_NONE, NULL, 0,
        "MatchingUse/restrictionType", HFILL }},
    { &hf_x509if_restrictionValue,
      { "restrictionValue", "x509if.restrictionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "MatchingUse/restrictionValue", HFILL }},
    { &hf_x509if_attribute,
      { "attribute", "x509if.attribute",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_and,
      { "and", "x509if.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeCombination/and", HFILL }},
    { &hf_x509if_and_item,
      { "Item", "x509if.and_item",
        FT_UINT32, BASE_DEC, VALS(x509if_AttributeCombination_vals), 0,
        "AttributeCombination/and/_item", HFILL }},
    { &hf_x509if_or,
      { "or", "x509if.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeCombination/or", HFILL }},
    { &hf_x509if_or_item,
      { "Item", "x509if.or_item",
        FT_UINT32, BASE_DEC, VALS(x509if_AttributeCombination_vals), 0,
        "AttributeCombination/or/_item", HFILL }},
    { &hf_x509if_not,
      { "not", "x509if.not",
        FT_UINT32, BASE_DEC, VALS(x509if_AttributeCombination_vals), 0,
        "AttributeCombination/not", HFILL }},
    { &hf_x509if_outputValues,
      { "outputValues", "x509if.outputValues",
        FT_UINT32, BASE_DEC, VALS(x509if_T_outputValues_vals), 0,
        "ResultAttribute/outputValues", HFILL }},
    { &hf_x509if_selectedValues,
      { "selectedValues", "x509if.selectedValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509if_selectedValues_item,
      { "Item", "x509if.selectedValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_matchedValuesOnly,
      { "matchedValuesOnly", "x509if.matchedValuesOnly",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509if_default,
      { "default", "x509if.default",
        FT_INT32, BASE_DEC, NULL, 0,
        "EntryLimit/default", HFILL }},
    { &hf_x509if_max,
      { "max", "x509if.max",
        FT_INT32, BASE_DEC, NULL, 0,
        "EntryLimit/max", HFILL }},
    { &hf_x509if_basic,
      { "basic", "x509if.basic",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelaxationPolicy/basic", HFILL }},
    { &hf_x509if_tightenings,
      { "tightenings", "x509if.tightenings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelaxationPolicy/tightenings", HFILL }},
    { &hf_x509if_tightenings_item,
      { "Item", "x509if.tightenings_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelaxationPolicy/tightenings/_item", HFILL }},
    { &hf_x509if_relaxations,
      { "relaxations", "x509if.relaxations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelaxationPolicy/relaxations", HFILL }},
    { &hf_x509if_relaxations_item,
      { "Item", "x509if.relaxations_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelaxationPolicy/relaxations/_item", HFILL }},
    { &hf_x509if_maximum_relaxation,
      { "maximum", "x509if.maximum",
        FT_INT32, BASE_DEC, NULL, 0,
        "RelaxationPolicy/maximum", HFILL }},
    { &hf_x509if_minimum_relaxation,
      { "minimum", "x509if.minimum",
        FT_INT32, BASE_DEC, NULL, 0,
        "RelaxationPolicy/minimum", HFILL }},
    { &hf_x509if_mapping,
      { "mapping", "x509if.mapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MRMapping/mapping", HFILL }},
    { &hf_x509if_mapping_item,
      { "Item", "x509if.mapping_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MRMapping/mapping/_item", HFILL }},
    { &hf_x509if_substitution,
      { "substitution", "x509if.substitution",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MRMapping/substitution", HFILL }},
    { &hf_x509if_substitution_item,
      { "Item", "x509if.substitution_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MRMapping/substitution/_item", HFILL }},
    { &hf_x509if_mappingFunction,
      { "mappingFunction", "x509if.mappingFunction",
        FT_OID, BASE_NONE, NULL, 0,
        "Mapping/mappingFunction", HFILL }},
    { &hf_x509if_level,
      { "level", "x509if.level",
        FT_INT32, BASE_DEC, NULL, 0,
        "Mapping/level", HFILL }},
    { &hf_x509if_oldMatchingRule,
      { "oldMatchingRule", "x509if.oldMatchingRule",
        FT_OID, BASE_NONE, NULL, 0,
        "MRSubstitution/oldMatchingRule", HFILL }},
    { &hf_x509if_newMatchingRule,
      { "newMatchingRule", "x509if.newMatchingRule",
        FT_OID, BASE_NONE, NULL, 0,
        "MRSubstitution/newMatchingRule", HFILL }},
    { &hf_x509if_AllowedSubset_baseObject,
      { "baseObject", "x509if.baseObject",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509if_AllowedSubset_oneLevel,
      { "oneLevel", "x509if.oneLevel",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509if_AllowedSubset_wholeSubtree,
      { "wholeSubtree", "x509if.wholeSubtree",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},

/*--- End of included file: packet-x509if-hfarr.c ---*/
#line 122 "packet-x509if-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-x509if-ettarr.c ---*/
#line 1 "packet-x509if-ettarr.c"
    &ett_x509if_Attribute,
    &ett_x509if_SET_OF_AttributeValue,
    &ett_x509if_T_valuesWithContext,
    &ett_x509if_T_valuesWithContext_item,
    &ett_x509if_SET_OF_Context,
    &ett_x509if_Context,
    &ett_x509if_AttributeValueAssertion,
    &ett_x509if_T_assertedContexts,
    &ett_x509if_SET_OF_ContextAssertion,
    &ett_x509if_ContextAssertion,
    &ett_x509if_SET_OF_ContextValue,
    &ett_x509if_AttributeTypeAssertion,
    &ett_x509if_SEQUENCE_OF_ContextAssertion,
    &ett_x509if_Name,
    &ett_x509if_RDNSequence,
    &ett_x509if_RelativeDistinguishedName,
    &ett_x509if_AttributeTypeAndDistinguishedValue,
    &ett_x509if_T_valWithContext,
    &ett_x509if_T_valWithContext_item,
    &ett_x509if_SubtreeSpecification,
    &ett_x509if_T_specificExclusions,
    &ett_x509if_T_specificExclusions_item,
    &ett_x509if_ChopSpecification,
    &ett_x509if_T_chopSpecificExclusions,
    &ett_x509if_T_chopSpecificExclusions_item,
    &ett_x509if_Refinement,
    &ett_x509if_SET_OF_Refinement,
    &ett_x509if_DITStructureRule,
    &ett_x509if_SET_OF_RuleIdentifier,
    &ett_x509if_DITContentRule,
    &ett_x509if_T_auxiliaries,
    &ett_x509if_SET_SIZE_1_MAX_OF_AttributeId,
    &ett_x509if_DITContextUse,
    &ett_x509if_T_mandatoryContexts,
    &ett_x509if_T_optionalContexts,
    &ett_x509if_SearchRuleDescription,
    &ett_x509if_SEQUENCE_OF_RequestAttribute,
    &ett_x509if_SEQUENCE_OF_ResultAttribute,
    &ett_x509if_SEQUENCE_OF_AttributeType,
    &ett_x509if_SET_OF_DirectoryString,
    &ett_x509if_SearchRule,
    &ett_x509if_SearchRuleId,
    &ett_x509if_AllowedSubset,
    &ett_x509if_RequestAttribute,
    &ett_x509if_SEQUENCE_OF_SelectedValues,
    &ett_x509if_T_defaultValues,
    &ett_x509if_T_defaultValues_item,
    &ett_x509if_SEQUENCE_OF_DefaultValueValues,
    &ett_x509if_SEQUENCE_OF_ContextProfile,
    &ett_x509if_SEQUENCE_OF_MatchingUse,
    &ett_x509if_ContextProfile,
    &ett_x509if_SEQUENCE_OF_AttributeValue,
    &ett_x509if_ContextCombination,
    &ett_x509if_SEQUENCE_OF_ContextCombination,
    &ett_x509if_MatchingUse,
    &ett_x509if_AttributeCombination,
    &ett_x509if_SEQUENCE_OF_AttributeCombination,
    &ett_x509if_ResultAttribute,
    &ett_x509if_T_outputValues,
    &ett_x509if_OutputValues,
    &ett_x509if_ControlOptions,
    &ett_x509if_EntryLimit,
    &ett_x509if_RelaxationPolicy,
    &ett_x509if_SEQUENCE_OF_MRMapping,
    &ett_x509if_MRMapping,
    &ett_x509if_SEQUENCE_OF_Mapping,
    &ett_x509if_SEQUENCE_OF_MRSubstitution,
    &ett_x509if_Mapping,
    &ett_x509if_MRSubstitution,

/*--- End of included file: packet-x509if-ettarr.c ---*/
#line 127 "packet-x509if-template.c"
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

}

