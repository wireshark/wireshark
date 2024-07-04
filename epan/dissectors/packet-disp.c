/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-disp.c                                                              */
/* asn2wrs.py -b -q -L -p disp -c ./disp.cnf -s ./packet-disp-template -D . -O ../.. disp.asn */

/* packet-disp.c
 * Routines for X.525 (X.500 Directory Shadow Asbtract Service) and X.519 DISP packet dissection
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
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#include "packet-x509if.h"
#include "packet-x509af.h"
#include "packet-x509sat.h"
#include "packet-crmf.h"

#include "packet-dop.h"
#include "packet-dap.h"
#include "packet-dsp.h"
#include "packet-disp.h"


/* we don't have a separate dissector for X519 -
   and most of DISP is defined in X525 */
#define PNAME  "X.519 Directory Information Shadowing Protocol"
#define PSNAME "DISP"
#define PFNAME "disp"

void proto_register_disp(void);
void proto_reg_handoff_disp(void);

/* Initialize the protocol and registered fields */
static int proto_disp;

static int hf_disp_EstablishParameter_PDU;        /* EstablishParameter */
static int hf_disp_ModificationParameter_PDU;     /* ModificationParameter */
static int hf_disp_ShadowingAgreementInfo_PDU;    /* ShadowingAgreementInfo */
static int hf_disp_modifiedSecondaryShadows;      /* SET_OF_SupplierAndConsumers */
static int hf_disp_modifiedSecondaryShadows_item;  /* SupplierAndConsumers */
static int hf_disp_shadowSubject;                 /* UnitOfReplication */
static int hf_disp_updateMode;                    /* UpdateMode */
static int hf_disp_master;                        /* AccessPoint */
static int hf_disp_secondaryShadows;              /* BOOLEAN */
static int hf_disp_area;                          /* AreaSpecification */
static int hf_disp_replication_attributes;        /* AttributeSelection */
static int hf_disp_knowledge;                     /* Knowledge */
static int hf_disp_subordinates;                  /* BOOLEAN */
static int hf_disp_contextSelection;              /* ContextSelection */
static int hf_disp_supplyContexts;                /* T_supplyContexts */
static int hf_disp_allContexts;                   /* NULL */
static int hf_disp_selectedContexts;              /* T_selectedContexts */
static int hf_disp_selectedContexts_item;         /* OBJECT_IDENTIFIER */
static int hf_disp_contextPrefix;                 /* DistinguishedName */
static int hf_disp_replicationArea;               /* SubtreeSpecification */
static int hf_disp_knowledgeType;                 /* T_knowledgeType */
static int hf_disp_extendedKnowledge;             /* BOOLEAN */
static int hf_disp_AttributeSelection_item;       /* ClassAttributeSelection */
static int hf_disp_class;                         /* OBJECT_IDENTIFIER */
static int hf_disp_classAttributes;               /* ClassAttributes */
static int hf_disp_allAttributes;                 /* NULL */
static int hf_disp_include;                       /* AttributeTypes */
static int hf_disp_exclude;                       /* AttributeTypes */
static int hf_disp_AttributeTypes_item;           /* AttributeType */
static int hf_disp_supplierInitiated;             /* SupplierUpdateMode */
static int hf_disp_consumerInitiated;             /* ConsumerUpdateMode */
static int hf_disp_onChange;                      /* BOOLEAN */
static int hf_disp_scheduled;                     /* SchedulingParameters */
static int hf_disp_periodic;                      /* PeriodicStrategy */
static int hf_disp_othertimes;                    /* BOOLEAN */
static int hf_disp_beginTime;                     /* Time */
static int hf_disp_windowSize;                    /* INTEGER */
static int hf_disp_updateInterval;                /* INTEGER */
static int hf_disp_agreementID;                   /* AgreementID */
static int hf_disp_lastUpdate;                    /* Time */
static int hf_disp_updateStrategy;                /* T_updateStrategy */
static int hf_disp_standardUpdate;                /* StandardUpdate */
static int hf_disp_other;                         /* EXTERNAL */
static int hf_disp_securityParameters;            /* SecurityParameters */
static int hf_disp_unsignedCoordinateShadowUpdateArgument;  /* CoordinateShadowUpdateArgumentData */
static int hf_disp_signedCoordinateShadowUpdateArgument;  /* T_signedCoordinateShadowUpdateArgument */
static int hf_disp_coordinateShadowUpdateArgument;  /* CoordinateShadowUpdateArgumentData */
static int hf_disp_algorithmIdentifier;           /* AlgorithmIdentifier */
static int hf_disp_encrypted;                     /* BIT_STRING */
static int hf_disp_null;                          /* NULL */
static int hf_disp_information;                   /* Information */
static int hf_disp_performer;                     /* DistinguishedName */
static int hf_disp_aliasDereferenced;             /* BOOLEAN */
static int hf_disp_notification;                  /* SEQUENCE_OF_Attribute */
static int hf_disp_notification_item;             /* Attribute */
static int hf_disp_unsignedInformation;           /* InformationData */
static int hf_disp_signedInformation;             /* T_signedInformation */
static int hf_disp_information_data;              /* InformationData */
static int hf_disp_requestedStrategy;             /* T_requestedStrategy */
static int hf_disp_standard;                      /* T_standard */
static int hf_disp_unsignedRequestShadowUpdateArgument;  /* RequestShadowUpdateArgumentData */
static int hf_disp_signedRequestShadowUpdateArgument;  /* T_signedRequestShadowUpdateArgument */
static int hf_disp_requestShadowUpdateArgument;   /* RequestShadowUpdateArgumentData */
static int hf_disp_updateTime;                    /* Time */
static int hf_disp_updateWindow;                  /* UpdateWindow */
static int hf_disp_updatedInfo;                   /* RefreshInformation */
static int hf_disp_unsignedUpdateShadowArgument;  /* UpdateShadowArgumentData */
static int hf_disp_signedUpdateShadowArgument;    /* T_signedUpdateShadowArgument */
static int hf_disp_updateShadowArgument;          /* UpdateShadowArgumentData */
static int hf_disp_start;                         /* Time */
static int hf_disp_stop;                          /* Time */
static int hf_disp_noRefresh;                     /* NULL */
static int hf_disp_total;                         /* TotalRefresh */
static int hf_disp_incremental;                   /* IncrementalRefresh */
static int hf_disp_otherStrategy;                 /* EXTERNAL */
static int hf_disp_sDSE;                          /* SDSEContent */
static int hf_disp_subtree;                       /* SET_OF_Subtree */
static int hf_disp_subtree_item;                  /* Subtree */
static int hf_disp_sDSEType;                      /* SDSEType */
static int hf_disp_subComplete;                   /* BOOLEAN */
static int hf_disp_attComplete;                   /* BOOLEAN */
static int hf_disp_attributes;                    /* SET_OF_Attribute */
static int hf_disp_attributes_item;               /* Attribute */
static int hf_disp_attValIncomplete;              /* SET_OF_AttributeType */
static int hf_disp_attValIncomplete_item;         /* AttributeType */
static int hf_disp_rdn;                           /* RelativeDistinguishedName */
static int hf_disp_IncrementalRefresh_item;       /* IncrementalStepRefresh */
static int hf_disp_sDSEChanges;                   /* T_sDSEChanges */
static int hf_disp_add;                           /* SDSEContent */
static int hf_disp_remove;                        /* NULL */
static int hf_disp_modify;                        /* ContentChange */
static int hf_disp_subordinateUpdates;            /* SEQUENCE_OF_SubordinateChanges */
static int hf_disp_subordinateUpdates_item;       /* SubordinateChanges */
static int hf_disp_rename;                        /* T_rename */
static int hf_disp_newRDN;                        /* RelativeDistinguishedName */
static int hf_disp_newDN;                         /* DistinguishedName */
static int hf_disp_attributeChanges;              /* T_attributeChanges */
static int hf_disp_replace;                       /* SET_OF_Attribute */
static int hf_disp_replace_item;                  /* Attribute */
static int hf_disp_changes;                       /* SEQUENCE_OF_EntryModification */
static int hf_disp_changes_item;                  /* EntryModification */
static int hf_disp_subordinate;                   /* RelativeDistinguishedName */
static int hf_disp_subordinate_changes;           /* IncrementalStepRefresh */
static int hf_disp_problem;                       /* ShadowProblem */
static int hf_disp_unsignedShadowError;           /* ShadowErrorData */
static int hf_disp_signedShadowError;             /* T_signedShadowError */
static int hf_disp_shadowError;                   /* ShadowErrorData */

/* Initialize the subtree pointers */
static int ett_disp;
static int ett_disp_ModificationParameter;
static int ett_disp_SET_OF_SupplierAndConsumers;
static int ett_disp_ShadowingAgreementInfo;
static int ett_disp_UnitOfReplication;
static int ett_disp_T_supplyContexts;
static int ett_disp_T_selectedContexts;
static int ett_disp_AreaSpecification;
static int ett_disp_Knowledge;
static int ett_disp_AttributeSelection;
static int ett_disp_ClassAttributeSelection;
static int ett_disp_ClassAttributes;
static int ett_disp_AttributeTypes;
static int ett_disp_UpdateMode;
static int ett_disp_SupplierUpdateMode;
static int ett_disp_SchedulingParameters;
static int ett_disp_PeriodicStrategy;
static int ett_disp_CoordinateShadowUpdateArgumentData;
static int ett_disp_T_updateStrategy;
static int ett_disp_CoordinateShadowUpdateArgument;
static int ett_disp_T_signedCoordinateShadowUpdateArgument;
static int ett_disp_CoordinateShadowUpdateResult;
static int ett_disp_InformationData;
static int ett_disp_SEQUENCE_OF_Attribute;
static int ett_disp_Information;
static int ett_disp_T_signedInformation;
static int ett_disp_RequestShadowUpdateArgumentData;
static int ett_disp_T_requestedStrategy;
static int ett_disp_RequestShadowUpdateArgument;
static int ett_disp_T_signedRequestShadowUpdateArgument;
static int ett_disp_RequestShadowUpdateResult;
static int ett_disp_UpdateShadowArgumentData;
static int ett_disp_UpdateShadowArgument;
static int ett_disp_T_signedUpdateShadowArgument;
static int ett_disp_UpdateShadowResult;
static int ett_disp_UpdateWindow;
static int ett_disp_RefreshInformation;
static int ett_disp_TotalRefresh;
static int ett_disp_SET_OF_Subtree;
static int ett_disp_SDSEContent;
static int ett_disp_SET_OF_Attribute;
static int ett_disp_SET_OF_AttributeType;
static int ett_disp_Subtree;
static int ett_disp_IncrementalRefresh;
static int ett_disp_IncrementalStepRefresh;
static int ett_disp_T_sDSEChanges;
static int ett_disp_SEQUENCE_OF_SubordinateChanges;
static int ett_disp_ContentChange;
static int ett_disp_T_rename;
static int ett_disp_T_attributeChanges;
static int ett_disp_SEQUENCE_OF_EntryModification;
static int ett_disp_SubordinateChanges;
static int ett_disp_ShadowErrorData;
static int ett_disp_ShadowError;
static int ett_disp_T_signedShadowError;

static expert_field ei_disp_unsupported_opcode;
static expert_field ei_disp_unsupported_errcode;
static expert_field ei_disp_unsupported_pdu;
static expert_field ei_disp_zero_pdu;

static dissector_handle_t disp_handle;

/*--- Cyclic dependencies ---*/

/* Subtree -> Subtree/subtree -> Subtree */
static int dissect_disp_Subtree(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* IncrementalStepRefresh -> IncrementalStepRefresh/subordinateUpdates -> SubordinateChanges -> IncrementalStepRefresh */
static int dissect_disp_IncrementalStepRefresh(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_disp_DSAShadowBindArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_disp_DSAShadowBindResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_disp_DSAShadowBindError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_disp_EstablishParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_SupplierAndConsumers_set_of[1] = {
  { &hf_disp_modifiedSecondaryShadows_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dop_SupplierAndConsumers },
};

static int
dissect_disp_SET_OF_SupplierAndConsumers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_SupplierAndConsumers_set_of, hf_index, ett_disp_SET_OF_SupplierAndConsumers);

  return offset;
}


static const ber_sequence_t ModificationParameter_sequence[] = {
  { &hf_disp_modifiedSecondaryShadows, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_disp_SET_OF_SupplierAndConsumers },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_ModificationParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModificationParameter_sequence, hf_index, ett_disp_ModificationParameter);

  return offset;
}



int
dissect_disp_AgreementID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dop_OperationalBindingID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AreaSpecification_sequence[] = {
  { &hf_disp_contextPrefix  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_DistinguishedName },
  { &hf_disp_replicationArea, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_SubtreeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_AreaSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AreaSpecification_sequence, hf_index, ett_disp_AreaSpecification);

  return offset;
}



static int
dissect_disp_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_disp_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t AttributeTypes_set_of[1] = {
  { &hf_disp_AttributeTypes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_disp_AttributeTypes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AttributeTypes_set_of, hf_index, ett_disp_AttributeTypes);

  return offset;
}


static const value_string disp_ClassAttributes_vals[] = {
  {   0, "allAttributes" },
  {   1, "include" },
  {   2, "exclude" },
  { 0, NULL }
};

static const ber_choice_t ClassAttributes_choice[] = {
  {   0, &hf_disp_allAttributes  , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_disp_NULL },
  {   1, &hf_disp_include        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_AttributeTypes },
  {   2, &hf_disp_exclude        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_disp_AttributeTypes },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_ClassAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ClassAttributes_choice, hf_index, ett_disp_ClassAttributes,
                                 NULL);

  return offset;
}


static const ber_sequence_t ClassAttributeSelection_sequence[] = {
  { &hf_disp_class          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_OBJECT_IDENTIFIER },
  { &hf_disp_classAttributes, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_disp_ClassAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_ClassAttributeSelection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ClassAttributeSelection_sequence, hf_index, ett_disp_ClassAttributeSelection);

  return offset;
}


static const ber_sequence_t AttributeSelection_set_of[1] = {
  { &hf_disp_AttributeSelection_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_ClassAttributeSelection },
};

static int
dissect_disp_AttributeSelection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AttributeSelection_set_of, hf_index, ett_disp_AttributeSelection);

  return offset;
}


static const value_string disp_T_knowledgeType_vals[] = {
  {   0, "master" },
  {   1, "shadow" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_disp_T_knowledgeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_disp_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t Knowledge_sequence[] = {
  { &hf_disp_knowledgeType  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_disp_T_knowledgeType },
  { &hf_disp_extendedKnowledge, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_Knowledge(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Knowledge_sequence, hf_index, ett_disp_Knowledge);

  return offset;
}


static const ber_sequence_t T_selectedContexts_set_of[1] = {
  { &hf_disp_selectedContexts_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_disp_OBJECT_IDENTIFIER },
};

static int
dissect_disp_T_selectedContexts(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_selectedContexts_set_of, hf_index, ett_disp_T_selectedContexts);

  return offset;
}


static const value_string disp_T_supplyContexts_vals[] = {
  {   0, "allContexts" },
  {   1, "selectedContexts" },
  { 0, NULL }
};

static const ber_choice_t T_supplyContexts_choice[] = {
  {   0, &hf_disp_allContexts    , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_disp_NULL },
  {   1, &hf_disp_selectedContexts, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_disp_T_selectedContexts },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_supplyContexts(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_supplyContexts_choice, hf_index, ett_disp_T_supplyContexts,
                                 NULL);

  return offset;
}


static const ber_sequence_t UnitOfReplication_sequence[] = {
  { &hf_disp_area           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_AreaSpecification },
  { &hf_disp_replication_attributes, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_disp_AttributeSelection },
  { &hf_disp_knowledge      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_Knowledge },
  { &hf_disp_subordinates   , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_BOOLEAN },
  { &hf_disp_contextSelection, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_ContextSelection },
  { &hf_disp_supplyContexts , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_T_supplyContexts },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_UnitOfReplication(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UnitOfReplication_sequence, hf_index, ett_disp_UnitOfReplication);

  return offset;
}



static int
dissect_disp_Time(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_disp_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PeriodicStrategy_sequence[] = {
  { &hf_disp_beginTime      , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_Time },
  { &hf_disp_windowSize     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_disp_INTEGER },
  { &hf_disp_updateInterval , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_disp_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_PeriodicStrategy(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PeriodicStrategy_sequence, hf_index, ett_disp_PeriodicStrategy);

  return offset;
}


static const ber_sequence_t SchedulingParameters_sequence[] = {
  { &hf_disp_periodic       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_PeriodicStrategy },
  { &hf_disp_othertimes     , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_SchedulingParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SchedulingParameters_sequence, hf_index, ett_disp_SchedulingParameters);

  return offset;
}


static const value_string disp_SupplierUpdateMode_vals[] = {
  {   0, "onChange" },
  {   1, "scheduled" },
  { 0, NULL }
};

static const ber_choice_t SupplierUpdateMode_choice[] = {
  {   0, &hf_disp_onChange       , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_disp_BOOLEAN },
  {   1, &hf_disp_scheduled      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_SchedulingParameters },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_SupplierUpdateMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SupplierUpdateMode_choice, hf_index, ett_disp_SupplierUpdateMode,
                                 NULL);

  return offset;
}



static int
dissect_disp_ConsumerUpdateMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_disp_SchedulingParameters(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string disp_UpdateMode_vals[] = {
  {   0, "supplierInitiated" },
  {   1, "consumerInitiated" },
  { 0, NULL }
};

static const ber_choice_t UpdateMode_choice[] = {
  {   0, &hf_disp_supplierInitiated, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_SupplierUpdateMode },
  {   1, &hf_disp_consumerInitiated, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_disp_ConsumerUpdateMode },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_UpdateMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UpdateMode_choice, hf_index, ett_disp_UpdateMode,
                                 NULL);

  return offset;
}


static const ber_sequence_t ShadowingAgreementInfo_sequence[] = {
  { &hf_disp_shadowSubject  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_UnitOfReplication },
  { &hf_disp_updateMode     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_disp_UpdateMode },
  { &hf_disp_master         , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dsp_AccessPoint },
  { &hf_disp_secondaryShadows, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_ShadowingAgreementInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ShadowingAgreementInfo_sequence, hf_index, ett_disp_ShadowingAgreementInfo);

  return offset;
}


static const value_string disp_StandardUpdate_vals[] = {
  {   0, "noChanges" },
  {   1, "incremental" },
  {   2, "total" },
  { 0, NULL }
};


static int
dissect_disp_StandardUpdate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t update;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &update);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(update, disp_StandardUpdate_vals, "unknown(%d)"));


  return offset;
}



static int
dissect_disp_EXTERNAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const value_string disp_T_updateStrategy_vals[] = {
  {   0, "standard" },
  {   1, "other" },
  { 0, NULL }
};

static const ber_choice_t T_updateStrategy_choice[] = {
  {   0, &hf_disp_standardUpdate , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_disp_StandardUpdate },
  {   1, &hf_disp_other          , BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_disp_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_updateStrategy(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_updateStrategy_choice, hf_index, ett_disp_T_updateStrategy,
                                 NULL);

  return offset;
}


static const ber_sequence_t CoordinateShadowUpdateArgumentData_sequence[] = {
  { &hf_disp_agreementID    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_AgreementID },
  { &hf_disp_lastUpdate     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_Time },
  { &hf_disp_updateStrategy , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_disp_T_updateStrategy },
  { &hf_disp_securityParameters, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_SecurityParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_CoordinateShadowUpdateArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CoordinateShadowUpdateArgumentData_sequence, hf_index, ett_disp_CoordinateShadowUpdateArgumentData);

  return offset;
}



static int
dissect_disp_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t T_signedCoordinateShadowUpdateArgument_sequence[] = {
  { &hf_disp_coordinateShadowUpdateArgument, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_CoordinateShadowUpdateArgumentData },
  { &hf_disp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_disp_encrypted      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_disp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_signedCoordinateShadowUpdateArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedCoordinateShadowUpdateArgument_sequence, hf_index, ett_disp_T_signedCoordinateShadowUpdateArgument);

  return offset;
}


static const ber_choice_t CoordinateShadowUpdateArgument_choice[] = {
  {   0, &hf_disp_unsignedCoordinateShadowUpdateArgument, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_CoordinateShadowUpdateArgumentData },
  {   1, &hf_disp_signedCoordinateShadowUpdateArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_T_signedCoordinateShadowUpdateArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_CoordinateShadowUpdateArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CoordinateShadowUpdateArgument_choice, hf_index, ett_disp_CoordinateShadowUpdateArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Attribute_sequence_of[1] = {
  { &hf_disp_notification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_disp_SEQUENCE_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Attribute_sequence_of, hf_index, ett_disp_SEQUENCE_OF_Attribute);

  return offset;
}


static const ber_sequence_t InformationData_sequence[] = {
  { &hf_disp_agreementID    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_AgreementID },
  { &hf_disp_lastUpdate     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_Time },
  { &hf_disp_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dap_SecurityParameters },
  { &hf_disp_performer      , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_DistinguishedName },
  { &hf_disp_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_BOOLEAN },
  { &hf_disp_notification   , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_SEQUENCE_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_InformationData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InformationData_sequence, hf_index, ett_disp_InformationData);

  return offset;
}


static const ber_sequence_t T_signedInformation_sequence[] = {
  { &hf_disp_information_data, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_InformationData },
  { &hf_disp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_disp_encrypted      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_disp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_signedInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedInformation_sequence, hf_index, ett_disp_T_signedInformation);

  return offset;
}


static const value_string disp_Information_vals[] = {
  {   0, "unsignedInformation" },
  {   1, "signedInformation" },
  { 0, NULL }
};

static const ber_choice_t Information_choice[] = {
  {   0, &hf_disp_unsignedInformation, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_InformationData },
  {   1, &hf_disp_signedInformation, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_T_signedInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_Information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Information_choice, hf_index, ett_disp_Information,
                                 NULL);

  return offset;
}


static const value_string disp_CoordinateShadowUpdateResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t CoordinateShadowUpdateResult_choice[] = {
  {   0, &hf_disp_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_disp_NULL },
  {   1, &hf_disp_information    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_disp_Information },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_CoordinateShadowUpdateResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t update;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CoordinateShadowUpdateResult_choice, hf_index, ett_disp_CoordinateShadowUpdateResult,
                                 &update);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(update, disp_CoordinateShadowUpdateResult_vals, "unknown(%d)"));


  return offset;
}


static const value_string disp_T_standard_vals[] = {
  {   1, "incremental" },
  {   2, "total" },
  { 0, NULL }
};


static int
dissect_disp_T_standard(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t update;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &update);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(update, disp_T_standard_vals, "standard(%d"));


  return offset;
}


static const value_string disp_T_requestedStrategy_vals[] = {
  {   0, "standard" },
  {   1, "other" },
  { 0, NULL }
};

static const ber_choice_t T_requestedStrategy_choice[] = {
  {   0, &hf_disp_standard       , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_disp_T_standard },
  {   1, &hf_disp_other          , BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_disp_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_requestedStrategy(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_requestedStrategy_choice, hf_index, ett_disp_T_requestedStrategy,
                                 NULL);

  return offset;
}


static const ber_sequence_t RequestShadowUpdateArgumentData_sequence[] = {
  { &hf_disp_agreementID    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_AgreementID },
  { &hf_disp_lastUpdate     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_Time },
  { &hf_disp_requestedStrategy, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_disp_T_requestedStrategy },
  { &hf_disp_securityParameters, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_SecurityParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_RequestShadowUpdateArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestShadowUpdateArgumentData_sequence, hf_index, ett_disp_RequestShadowUpdateArgumentData);

  return offset;
}


static const ber_sequence_t T_signedRequestShadowUpdateArgument_sequence[] = {
  { &hf_disp_requestShadowUpdateArgument, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_RequestShadowUpdateArgumentData },
  { &hf_disp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_disp_encrypted      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_disp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_signedRequestShadowUpdateArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedRequestShadowUpdateArgument_sequence, hf_index, ett_disp_T_signedRequestShadowUpdateArgument);

  return offset;
}


static const ber_choice_t RequestShadowUpdateArgument_choice[] = {
  {   0, &hf_disp_unsignedRequestShadowUpdateArgument, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_RequestShadowUpdateArgumentData },
  {   1, &hf_disp_signedRequestShadowUpdateArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_T_signedRequestShadowUpdateArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_RequestShadowUpdateArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RequestShadowUpdateArgument_choice, hf_index, ett_disp_RequestShadowUpdateArgument,
                                 NULL);

  return offset;
}


static const value_string disp_RequestShadowUpdateResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t RequestShadowUpdateResult_choice[] = {
  {   0, &hf_disp_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_disp_NULL },
  {   1, &hf_disp_information    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_disp_Information },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_RequestShadowUpdateResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t update;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RequestShadowUpdateResult_choice, hf_index, ett_disp_RequestShadowUpdateResult,
                                 &update);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(update, disp_RequestShadowUpdateResult_vals, "unknown(%d)"));


  return offset;
}


static const ber_sequence_t UpdateWindow_sequence[] = {
  { &hf_disp_start          , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_disp_Time },
  { &hf_disp_stop           , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_disp_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_UpdateWindow(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateWindow_sequence, hf_index, ett_disp_UpdateWindow);

  return offset;
}



static int
dissect_disp_SDSEType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dop_DSEType(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { &hf_disp_attributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_disp_SET_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Attribute_set_of, hf_index, ett_disp_SET_OF_Attribute);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeType_set_of[1] = {
  { &hf_disp_attValIncomplete_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_disp_SET_OF_AttributeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AttributeType_set_of, hf_index, ett_disp_SET_OF_AttributeType);

  return offset;
}


static const ber_sequence_t SDSEContent_sequence[] = {
  { &hf_disp_sDSEType       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_disp_SDSEType },
  { &hf_disp_subComplete    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_BOOLEAN },
  { &hf_disp_attComplete    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_BOOLEAN },
  { &hf_disp_attributes     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_disp_SET_OF_Attribute },
  { &hf_disp_attValIncomplete, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_SET_OF_AttributeType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_SDSEContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SDSEContent_sequence, hf_index, ett_disp_SDSEContent);

  return offset;
}


static const ber_sequence_t SET_OF_Subtree_set_of[1] = {
  { &hf_disp_subtree_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_Subtree },
};

static int
dissect_disp_SET_OF_Subtree(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Subtree_set_of, hf_index, ett_disp_SET_OF_Subtree);

  return offset;
}


static const ber_sequence_t Subtree_sequence[] = {
  { &hf_disp_rdn            , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_RelativeDistinguishedName },
  { &hf_disp_sDSE           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_SDSEContent },
  { &hf_disp_subtree        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_SET_OF_Subtree },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_Subtree(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // Subtree -> Subtree/subtree -> Subtree
  actx->pinfo->dissection_depth += 2;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Subtree_sequence, hf_index, ett_disp_Subtree);

  actx->pinfo->dissection_depth -= 2;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t TotalRefresh_sequence[] = {
  { &hf_disp_sDSE           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_SDSEContent },
  { &hf_disp_subtree        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_SET_OF_Subtree },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_TotalRefresh(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TotalRefresh_sequence, hf_index, ett_disp_TotalRefresh);

  return offset;
}


static const value_string disp_T_rename_vals[] = {
  {   0, "newRDN" },
  {   1, "newDN" },
  { 0, NULL }
};

static const ber_choice_t T_rename_choice[] = {
  {   0, &hf_disp_newRDN         , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_RelativeDistinguishedName },
  {   1, &hf_disp_newDN          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_DistinguishedName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_rename(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_rename_choice, hf_index, ett_disp_T_rename,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EntryModification_sequence_of[1] = {
  { &hf_disp_changes_item   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dap_EntryModification },
};

static int
dissect_disp_SEQUENCE_OF_EntryModification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_EntryModification_sequence_of, hf_index, ett_disp_SEQUENCE_OF_EntryModification);

  return offset;
}


static const value_string disp_T_attributeChanges_vals[] = {
  {   0, "replace" },
  {   1, "changes" },
  { 0, NULL }
};

static const ber_choice_t T_attributeChanges_choice[] = {
  {   0, &hf_disp_replace        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_SET_OF_Attribute },
  {   1, &hf_disp_changes        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_disp_SEQUENCE_OF_EntryModification },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_attributeChanges(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_attributeChanges_choice, hf_index, ett_disp_T_attributeChanges,
                                 NULL);

  return offset;
}


static const ber_sequence_t ContentChange_sequence[] = {
  { &hf_disp_rename         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_disp_T_rename },
  { &hf_disp_attributeChanges, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_disp_T_attributeChanges },
  { &hf_disp_sDSEType       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_disp_SDSEType },
  { &hf_disp_subComplete    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_BOOLEAN },
  { &hf_disp_attComplete    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_BOOLEAN },
  { &hf_disp_attValIncomplete, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_SET_OF_AttributeType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_ContentChange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContentChange_sequence, hf_index, ett_disp_ContentChange);

  return offset;
}


static const value_string disp_T_sDSEChanges_vals[] = {
  {   0, "add" },
  {   1, "remove" },
  {   2, "modify" },
  { 0, NULL }
};

static const ber_choice_t T_sDSEChanges_choice[] = {
  {   0, &hf_disp_add            , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_SDSEContent },
  {   1, &hf_disp_remove         , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_disp_NULL },
  {   2, &hf_disp_modify         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_disp_ContentChange },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_sDSEChanges(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_sDSEChanges_choice, hf_index, ett_disp_T_sDSEChanges,
                                 NULL);

  return offset;
}


static const ber_sequence_t SubordinateChanges_sequence[] = {
  { &hf_disp_subordinate    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509if_RelativeDistinguishedName },
  { &hf_disp_subordinate_changes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_IncrementalStepRefresh },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_SubordinateChanges(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubordinateChanges_sequence, hf_index, ett_disp_SubordinateChanges);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SubordinateChanges_sequence_of[1] = {
  { &hf_disp_subordinateUpdates_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_SubordinateChanges },
};

static int
dissect_disp_SEQUENCE_OF_SubordinateChanges(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SubordinateChanges_sequence_of, hf_index, ett_disp_SEQUENCE_OF_SubordinateChanges);

  return offset;
}


static const ber_sequence_t IncrementalStepRefresh_sequence[] = {
  { &hf_disp_sDSEChanges    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_disp_T_sDSEChanges },
  { &hf_disp_subordinateUpdates, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_SEQUENCE_OF_SubordinateChanges },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_IncrementalStepRefresh(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // IncrementalStepRefresh -> IncrementalStepRefresh/subordinateUpdates -> SubordinateChanges -> IncrementalStepRefresh
  actx->pinfo->dissection_depth += 3;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IncrementalStepRefresh_sequence, hf_index, ett_disp_IncrementalStepRefresh);

  actx->pinfo->dissection_depth -= 3;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t IncrementalRefresh_sequence_of[1] = {
  { &hf_disp_IncrementalRefresh_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_IncrementalStepRefresh },
};

static int
dissect_disp_IncrementalRefresh(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      IncrementalRefresh_sequence_of, hf_index, ett_disp_IncrementalRefresh);

  return offset;
}


static const value_string disp_RefreshInformation_vals[] = {
  {   0, "noRefresh" },
  {   1, "total" },
  {   2, "incremental" },
  {   3, "otherStrategy" },
  { 0, NULL }
};

static const ber_choice_t RefreshInformation_choice[] = {
  {   0, &hf_disp_noRefresh      , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_disp_NULL },
  {   1, &hf_disp_total          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_TotalRefresh },
  {   2, &hf_disp_incremental    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_disp_IncrementalRefresh },
  {   3, &hf_disp_otherStrategy  , BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_disp_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_RefreshInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t update;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RefreshInformation_choice, hf_index, ett_disp_RefreshInformation,
                                 &update);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(update, disp_RefreshInformation_vals, "unknown(%d)"));


  return offset;
}


static const ber_sequence_t UpdateShadowArgumentData_sequence[] = {
  { &hf_disp_agreementID    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_AgreementID },
  { &hf_disp_updateTime     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_disp_Time },
  { &hf_disp_updateWindow   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_UpdateWindow },
  { &hf_disp_updatedInfo    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_disp_RefreshInformation },
  { &hf_disp_securityParameters, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dap_SecurityParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_UpdateShadowArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateShadowArgumentData_sequence, hf_index, ett_disp_UpdateShadowArgumentData);

  return offset;
}


static const ber_sequence_t T_signedUpdateShadowArgument_sequence[] = {
  { &hf_disp_updateShadowArgument, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_UpdateShadowArgumentData },
  { &hf_disp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_disp_encrypted      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_disp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_signedUpdateShadowArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedUpdateShadowArgument_sequence, hf_index, ett_disp_T_signedUpdateShadowArgument);

  return offset;
}


static const ber_choice_t UpdateShadowArgument_choice[] = {
  {   0, &hf_disp_unsignedUpdateShadowArgument, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_UpdateShadowArgumentData },
  {   1, &hf_disp_signedUpdateShadowArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_T_signedUpdateShadowArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_UpdateShadowArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UpdateShadowArgument_choice, hf_index, ett_disp_UpdateShadowArgument,
                                 NULL);

  return offset;
}


static const value_string disp_UpdateShadowResult_vals[] = {
  {   0, "null" },
  {   1, "information" },
  { 0, NULL }
};

static const ber_choice_t UpdateShadowResult_choice[] = {
  {   0, &hf_disp_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_disp_NULL },
  {   1, &hf_disp_information    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_disp_Information },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_UpdateShadowResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t update;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UpdateShadowResult_choice, hf_index, ett_disp_UpdateShadowResult,
                                 &update);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(update, disp_UpdateShadowResult_vals, "unknown(%d)"));


  return offset;
}


static const value_string disp_ShadowProblem_vals[] = {
  {   1, "invalidAgreementID" },
  {   2, "inactiveAgreement" },
  {   3, "invalidInformationReceived" },
  {   4, "unsupportedStrategy" },
  {   5, "missedPrevious" },
  {   6, "fullUpdateRequired" },
  {   7, "unwillingToPerform" },
  {   8, "unsuitableTiming" },
  {   9, "updateAlreadyReceived" },
  {  10, "invalidSequencing" },
  {  11, "insufficientResources" },
  { 0, NULL }
};


static int
dissect_disp_ShadowProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t problem;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &problem);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(problem, disp_ShadowProblem_vals, "ShadowProblem(%d)"));

  return offset;
}


static const ber_sequence_t ShadowErrorData_sequence[] = {
  { &hf_disp_problem        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_disp_ShadowProblem },
  { &hf_disp_lastUpdate     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_Time },
  { &hf_disp_updateWindow   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_UpdateWindow },
  { &hf_disp_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dap_SecurityParameters },
  { &hf_disp_performer      , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_DistinguishedName },
  { &hf_disp_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_BOOLEAN },
  { &hf_disp_notification   , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disp_SEQUENCE_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_ShadowErrorData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ShadowErrorData_sequence, hf_index, ett_disp_ShadowErrorData);

  return offset;
}


static const ber_sequence_t T_signedShadowError_sequence[] = {
  { &hf_disp_shadowError    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_ShadowErrorData },
  { &hf_disp_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_disp_encrypted      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_disp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_T_signedShadowError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedShadowError_sequence, hf_index, ett_disp_T_signedShadowError);

  return offset;
}


static const ber_choice_t ShadowError_choice[] = {
  {   0, &hf_disp_unsignedShadowError, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_ShadowErrorData },
  {   1, &hf_disp_signedShadowError, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_T_signedShadowError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_ShadowError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ShadowError_choice, hf_index, ett_disp_ShadowError,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_EstablishParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_disp_EstablishParameter(false, tvb, offset, &asn1_ctx, tree, hf_disp_EstablishParameter_PDU);
  return offset;
}
static int dissect_ModificationParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_disp_ModificationParameter(false, tvb, offset, &asn1_ctx, tree, hf_disp_ModificationParameter_PDU);
  return offset;
}
static int dissect_ShadowingAgreementInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_disp_ShadowingAgreementInfo(false, tvb, offset, &asn1_ctx, tree, hf_disp_ShadowingAgreementInfo_PDU);
  return offset;
}


/*
* Dissect DISP PDUs inside a ROS PDUs
*/
static int
dissect_disp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	int offset = 0;
	int old_offset;
	proto_item *item;
	proto_tree *tree;
	struct SESSION_DATA_STRUCTURE* session;
	int (*disp_dissector)(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	const char *disp_op_name;
	asn1_ctx_t asn1_ctx;

	/* do we have operation information from the ROS dissector */
	if (data == NULL)
		return 0;
	session  = (struct SESSION_DATA_STRUCTURE*)data;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	asn1_ctx.private_data = session;

	item = proto_tree_add_item(parent_tree, proto_disp, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_disp);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DISP");
  	col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  disp_dissector = dissect_disp_DSAShadowBindArgument;
	  disp_op_name = "Shadow-Bind-Argument";
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  disp_dissector = dissect_disp_DSAShadowBindResult;
	  disp_op_name = "Shadow-Bind-Result";
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  disp_dissector = dissect_disp_DSAShadowBindError;
	  disp_op_name = "Shadow-Bind-Error";
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* requestShadowUpdate */
	    disp_dissector = dissect_disp_RequestShadowUpdateArgument;
	    disp_op_name = "Request-Shadow-Update-Argument";
	    break;
	  case 2: /* updateShadow*/
	    disp_dissector = dissect_disp_UpdateShadowArgument;
	    disp_op_name = "Update-Shadow-Argument";
	    break;
	  case 3: /* coordinateShadowUpdate */
	    disp_dissector = dissect_disp_CoordinateShadowUpdateArgument;
	    disp_op_name = "Coordinate-Shadow-Update-Argument";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_disp_unsupported_opcode, tvb, offset, -1,
	        "Unsupported DISP opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* requestShadowUpdate */
	    disp_dissector = dissect_disp_RequestShadowUpdateResult;
	    disp_op_name = "Request-Shadow-Result";
	    break;
	  case 2: /* updateShadow */
	    disp_dissector = dissect_disp_UpdateShadowResult;
	    disp_op_name = "Update-Shadow-Result";
	    break;
	  case 3: /* coordinateShadowUpdate */
	    disp_dissector = dissect_disp_CoordinateShadowUpdateResult;
	    disp_op_name = "Coordinate-Shadow-Update-Result";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_disp_unsupported_opcode, tvb, offset, -1,
	        "Unsupported DISP opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* shadowError */
	    disp_dissector = dissect_disp_ShadowError;
	    disp_op_name = "Shadow-Error";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_disp_unsupported_errcode, tvb, offset, -1,
	            "Unsupported DISP errcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	default:
	  proto_tree_add_expert(tree, pinfo, &ei_disp_unsupported_pdu, tvb, offset, -1);
	  return tvb_captured_length(tvb);
	}

	if(disp_dissector) {
	  col_set_str(pinfo->cinfo, COL_INFO, disp_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*disp_dissector)(false, tvb, offset, &asn1_ctx, tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_expert(tree, pinfo, &ei_disp_zero_pdu, tvb, offset, -1);
	      break;
	    }
	  }
	}

	return tvb_captured_length(tvb);
}


/*--- proto_register_disp -------------------------------------------*/
void proto_register_disp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    { &hf_disp_EstablishParameter_PDU,
      { "EstablishParameter", "disp.EstablishParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_ModificationParameter_PDU,
      { "ModificationParameter", "disp.ModificationParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_ShadowingAgreementInfo_PDU,
      { "ShadowingAgreementInfo", "disp.ShadowingAgreementInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_modifiedSecondaryShadows,
      { "secondaryShadows", "disp.modifiedSecondaryShadows",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SupplierAndConsumers", HFILL }},
    { &hf_disp_modifiedSecondaryShadows_item,
      { "SupplierAndConsumers", "disp.SupplierAndConsumers_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_shadowSubject,
      { "shadowSubject", "disp.shadowSubject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnitOfReplication", HFILL }},
    { &hf_disp_updateMode,
      { "updateMode", "disp.updateMode",
        FT_UINT32, BASE_DEC, VALS(disp_UpdateMode_vals), 0,
        NULL, HFILL }},
    { &hf_disp_master,
      { "master", "disp.master_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessPoint", HFILL }},
    { &hf_disp_secondaryShadows,
      { "secondaryShadows", "disp.secondaryShadows",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_area,
      { "area", "disp.area_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AreaSpecification", HFILL }},
    { &hf_disp_replication_attributes,
      { "attributes", "disp.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeSelection", HFILL }},
    { &hf_disp_knowledge,
      { "knowledge", "disp.knowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_subordinates,
      { "subordinates", "disp.subordinates",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_contextSelection,
      { "contextSelection", "disp.contextSelection",
        FT_UINT32, BASE_DEC, VALS(dap_ContextSelection_vals), 0,
        NULL, HFILL }},
    { &hf_disp_supplyContexts,
      { "supplyContexts", "disp.supplyContexts",
        FT_UINT32, BASE_DEC, VALS(disp_T_supplyContexts_vals), 0,
        NULL, HFILL }},
    { &hf_disp_allContexts,
      { "allContexts", "disp.allContexts_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_selectedContexts,
      { "selectedContexts", "disp.selectedContexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_selectedContexts_item,
      { "selectedContexts item", "disp.selectedContexts_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_disp_contextPrefix,
      { "contextPrefix", "disp.contextPrefix",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_disp_replicationArea,
      { "replicationArea", "disp.replicationArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubtreeSpecification", HFILL }},
    { &hf_disp_knowledgeType,
      { "knowledgeType", "disp.knowledgeType",
        FT_UINT32, BASE_DEC, VALS(disp_T_knowledgeType_vals), 0,
        NULL, HFILL }},
    { &hf_disp_extendedKnowledge,
      { "extendedKnowledge", "disp.extendedKnowledge",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_AttributeSelection_item,
      { "ClassAttributeSelection", "disp.ClassAttributeSelection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_class,
      { "class", "disp.class",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_disp_classAttributes,
      { "classAttributes", "disp.classAttributes",
        FT_UINT32, BASE_DEC, VALS(disp_ClassAttributes_vals), 0,
        NULL, HFILL }},
    { &hf_disp_allAttributes,
      { "allAttributes", "disp.allAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_include,
      { "include", "disp.include",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeTypes", HFILL }},
    { &hf_disp_exclude,
      { "exclude", "disp.exclude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeTypes", HFILL }},
    { &hf_disp_AttributeTypes_item,
      { "AttributeType", "disp.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_supplierInitiated,
      { "supplierInitiated", "disp.supplierInitiated",
        FT_UINT32, BASE_DEC, VALS(disp_SupplierUpdateMode_vals), 0,
        "SupplierUpdateMode", HFILL }},
    { &hf_disp_consumerInitiated,
      { "consumerInitiated", "disp.consumerInitiated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConsumerUpdateMode", HFILL }},
    { &hf_disp_onChange,
      { "onChange", "disp.onChange",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_scheduled,
      { "scheduled", "disp.scheduled_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SchedulingParameters", HFILL }},
    { &hf_disp_periodic,
      { "periodic", "disp.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PeriodicStrategy", HFILL }},
    { &hf_disp_othertimes,
      { "othertimes", "disp.othertimes",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_beginTime,
      { "beginTime", "disp.beginTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_disp_windowSize,
      { "windowSize", "disp.windowSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_disp_updateInterval,
      { "updateInterval", "disp.updateInterval",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_disp_agreementID,
      { "agreementID", "disp.agreementID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_lastUpdate,
      { "lastUpdate", "disp.lastUpdate",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_disp_updateStrategy,
      { "updateStrategy", "disp.updateStrategy",
        FT_UINT32, BASE_DEC, VALS(disp_T_updateStrategy_vals), 0,
        NULL, HFILL }},
    { &hf_disp_standardUpdate,
      { "standard", "disp.standard",
        FT_UINT32, BASE_DEC, VALS(disp_StandardUpdate_vals), 0,
        "StandardUpdate", HFILL }},
    { &hf_disp_other,
      { "other", "disp.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_disp_securityParameters,
      { "securityParameters", "disp.securityParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_unsignedCoordinateShadowUpdateArgument,
      { "unsignedCoordinateShadowUpdateArgument", "disp.unsignedCoordinateShadowUpdateArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CoordinateShadowUpdateArgumentData", HFILL }},
    { &hf_disp_signedCoordinateShadowUpdateArgument,
      { "signedCoordinateShadowUpdateArgument", "disp.signedCoordinateShadowUpdateArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_coordinateShadowUpdateArgument,
      { "coordinateShadowUpdateArgument", "disp.coordinateShadowUpdateArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CoordinateShadowUpdateArgumentData", HFILL }},
    { &hf_disp_algorithmIdentifier,
      { "algorithmIdentifier", "disp.algorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_encrypted,
      { "encrypted", "disp.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_disp_null,
      { "null", "disp.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_information,
      { "information", "disp.information",
        FT_UINT32, BASE_DEC, VALS(disp_Information_vals), 0,
        NULL, HFILL }},
    { &hf_disp_performer,
      { "performer", "disp.performer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_disp_aliasDereferenced,
      { "aliasDereferenced", "disp.aliasDereferenced",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_notification,
      { "notification", "disp.notification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Attribute", HFILL }},
    { &hf_disp_notification_item,
      { "Attribute", "disp.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_unsignedInformation,
      { "unsignedInformation", "disp.unsignedInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformationData", HFILL }},
    { &hf_disp_signedInformation,
      { "signedInformation", "disp.signedInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_information_data,
      { "information", "disp.information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformationData", HFILL }},
    { &hf_disp_requestedStrategy,
      { "requestedStrategy", "disp.requestedStrategy",
        FT_UINT32, BASE_DEC, VALS(disp_T_requestedStrategy_vals), 0,
        NULL, HFILL }},
    { &hf_disp_standard,
      { "standard", "disp.standard",
        FT_UINT32, BASE_DEC, VALS(disp_T_standard_vals), 0,
        NULL, HFILL }},
    { &hf_disp_unsignedRequestShadowUpdateArgument,
      { "unsignedRequestShadowUpdateArgument", "disp.unsignedRequestShadowUpdateArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestShadowUpdateArgumentData", HFILL }},
    { &hf_disp_signedRequestShadowUpdateArgument,
      { "signedRequestShadowUpdateArgument", "disp.signedRequestShadowUpdateArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_requestShadowUpdateArgument,
      { "requestShadowUpdateArgument", "disp.requestShadowUpdateArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestShadowUpdateArgumentData", HFILL }},
    { &hf_disp_updateTime,
      { "updateTime", "disp.updateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_disp_updateWindow,
      { "updateWindow", "disp.updateWindow_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_updatedInfo,
      { "updatedInfo", "disp.updatedInfo",
        FT_UINT32, BASE_DEC, VALS(disp_RefreshInformation_vals), 0,
        "RefreshInformation", HFILL }},
    { &hf_disp_unsignedUpdateShadowArgument,
      { "unsignedUpdateShadowArgument", "disp.unsignedUpdateShadowArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateShadowArgumentData", HFILL }},
    { &hf_disp_signedUpdateShadowArgument,
      { "signedUpdateShadowArgument", "disp.signedUpdateShadowArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_updateShadowArgument,
      { "updateShadowArgument", "disp.updateShadowArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateShadowArgumentData", HFILL }},
    { &hf_disp_start,
      { "start", "disp.start",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_disp_stop,
      { "stop", "disp.stop",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_disp_noRefresh,
      { "noRefresh", "disp.noRefresh_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_total,
      { "total", "disp.total_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TotalRefresh", HFILL }},
    { &hf_disp_incremental,
      { "incremental", "disp.incremental",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IncrementalRefresh", HFILL }},
    { &hf_disp_otherStrategy,
      { "otherStrategy", "disp.otherStrategy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_disp_sDSE,
      { "sDSE", "disp.sDSE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SDSEContent", HFILL }},
    { &hf_disp_subtree,
      { "subtree", "disp.subtree",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Subtree", HFILL }},
    { &hf_disp_subtree_item,
      { "Subtree", "disp.Subtree_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_sDSEType,
      { "sDSEType", "disp.sDSEType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_subComplete,
      { "subComplete", "disp.subComplete",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_attComplete,
      { "attComplete", "disp.attComplete",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_attributes,
      { "attributes", "disp.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_disp_attributes_item,
      { "Attribute", "disp.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_attValIncomplete,
      { "attValIncomplete", "disp.attValIncomplete",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeType", HFILL }},
    { &hf_disp_attValIncomplete_item,
      { "AttributeType", "disp.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_rdn,
      { "rdn", "disp.rdn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelativeDistinguishedName", HFILL }},
    { &hf_disp_IncrementalRefresh_item,
      { "IncrementalStepRefresh", "disp.IncrementalStepRefresh_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_sDSEChanges,
      { "sDSEChanges", "disp.sDSEChanges",
        FT_UINT32, BASE_DEC, VALS(disp_T_sDSEChanges_vals), 0,
        NULL, HFILL }},
    { &hf_disp_add,
      { "add", "disp.add_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SDSEContent", HFILL }},
    { &hf_disp_remove,
      { "remove", "disp.remove_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_modify,
      { "modify", "disp.modify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentChange", HFILL }},
    { &hf_disp_subordinateUpdates,
      { "subordinateUpdates", "disp.subordinateUpdates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SubordinateChanges", HFILL }},
    { &hf_disp_subordinateUpdates_item,
      { "SubordinateChanges", "disp.SubordinateChanges_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_rename,
      { "rename", "disp.rename",
        FT_UINT32, BASE_DEC, VALS(disp_T_rename_vals), 0,
        NULL, HFILL }},
    { &hf_disp_newRDN,
      { "newRDN", "disp.newRDN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelativeDistinguishedName", HFILL }},
    { &hf_disp_newDN,
      { "newDN", "disp.newDN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_disp_attributeChanges,
      { "attributeChanges", "disp.attributeChanges",
        FT_UINT32, BASE_DEC, VALS(disp_T_attributeChanges_vals), 0,
        NULL, HFILL }},
    { &hf_disp_replace,
      { "replace", "disp.replace",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_disp_replace_item,
      { "Attribute", "disp.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_changes,
      { "changes", "disp.changes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EntryModification", HFILL }},
    { &hf_disp_changes_item,
      { "EntryModification", "disp.EntryModification",
        FT_UINT32, BASE_DEC, VALS(dap_EntryModification_vals), 0,
        NULL, HFILL }},
    { &hf_disp_subordinate,
      { "subordinate", "disp.subordinate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelativeDistinguishedName", HFILL }},
    { &hf_disp_subordinate_changes,
      { "changes", "disp.changes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IncrementalStepRefresh", HFILL }},
    { &hf_disp_problem,
      { "problem", "disp.problem",
        FT_INT32, BASE_DEC, VALS(disp_ShadowProblem_vals), 0,
        "ShadowProblem", HFILL }},
    { &hf_disp_unsignedShadowError,
      { "unsignedShadowError", "disp.unsignedShadowError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ShadowErrorData", HFILL }},
    { &hf_disp_signedShadowError,
      { "signedShadowError", "disp.signedShadowError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_shadowError,
      { "shadowError", "disp.shadowError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ShadowErrorData", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_disp,
    &ett_disp_ModificationParameter,
    &ett_disp_SET_OF_SupplierAndConsumers,
    &ett_disp_ShadowingAgreementInfo,
    &ett_disp_UnitOfReplication,
    &ett_disp_T_supplyContexts,
    &ett_disp_T_selectedContexts,
    &ett_disp_AreaSpecification,
    &ett_disp_Knowledge,
    &ett_disp_AttributeSelection,
    &ett_disp_ClassAttributeSelection,
    &ett_disp_ClassAttributes,
    &ett_disp_AttributeTypes,
    &ett_disp_UpdateMode,
    &ett_disp_SupplierUpdateMode,
    &ett_disp_SchedulingParameters,
    &ett_disp_PeriodicStrategy,
    &ett_disp_CoordinateShadowUpdateArgumentData,
    &ett_disp_T_updateStrategy,
    &ett_disp_CoordinateShadowUpdateArgument,
    &ett_disp_T_signedCoordinateShadowUpdateArgument,
    &ett_disp_CoordinateShadowUpdateResult,
    &ett_disp_InformationData,
    &ett_disp_SEQUENCE_OF_Attribute,
    &ett_disp_Information,
    &ett_disp_T_signedInformation,
    &ett_disp_RequestShadowUpdateArgumentData,
    &ett_disp_T_requestedStrategy,
    &ett_disp_RequestShadowUpdateArgument,
    &ett_disp_T_signedRequestShadowUpdateArgument,
    &ett_disp_RequestShadowUpdateResult,
    &ett_disp_UpdateShadowArgumentData,
    &ett_disp_UpdateShadowArgument,
    &ett_disp_T_signedUpdateShadowArgument,
    &ett_disp_UpdateShadowResult,
    &ett_disp_UpdateWindow,
    &ett_disp_RefreshInformation,
    &ett_disp_TotalRefresh,
    &ett_disp_SET_OF_Subtree,
    &ett_disp_SDSEContent,
    &ett_disp_SET_OF_Attribute,
    &ett_disp_SET_OF_AttributeType,
    &ett_disp_Subtree,
    &ett_disp_IncrementalRefresh,
    &ett_disp_IncrementalStepRefresh,
    &ett_disp_T_sDSEChanges,
    &ett_disp_SEQUENCE_OF_SubordinateChanges,
    &ett_disp_ContentChange,
    &ett_disp_T_rename,
    &ett_disp_T_attributeChanges,
    &ett_disp_SEQUENCE_OF_EntryModification,
    &ett_disp_SubordinateChanges,
    &ett_disp_ShadowErrorData,
    &ett_disp_ShadowError,
    &ett_disp_T_signedShadowError,
  };

  static ei_register_info ei[] = {
    { &ei_disp_unsupported_opcode, { "disp.unsupported_opcode", PI_UNDECODED, PI_WARN, "Unsupported DISP opcode", EXPFILL }},
    { &ei_disp_unsupported_errcode, { "disp.unsupported_errcode", PI_UNDECODED, PI_WARN, "Unsupported DISP errcode", EXPFILL }},
    { &ei_disp_unsupported_pdu, { "disp.unsupported_pdu", PI_UNDECODED, PI_WARN, "Unsupported DISP PDU", EXPFILL }},
    { &ei_disp_zero_pdu, { "disp.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte DISP PDU", EXPFILL }},
  };

  module_t *disp_module;
  expert_module_t* expert_disp;

  /* Register protocol */
  proto_disp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  disp_handle = register_dissector("disp", dissect_disp, proto_disp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_disp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_disp = expert_register_protocol(proto_disp);
  expert_register_field_array(expert_disp, ei, array_length(ei));

  /* Register our configuration options for DISP, particularly our port */

  disp_module = prefs_register_protocol_subtree("OSI/X.500", proto_disp, NULL);

  prefs_register_obsolete_preference(disp_module, "tcp.port");

  prefs_register_static_text_preference(disp_module, "tcp_port_info",
            "The TCP ports used by the DISP protocol should be added to the TPKT preference \"TPKT TCP ports\", or by selecting \"TPKT\" as the \"Transport\" protocol in the \"Decode As\" dialog.",
            "DISP TCP Port preference moved information");

}


/*--- proto_reg_handoff_disp --- */
void proto_reg_handoff_disp(void) {
  dissector_add_string("dop.oid", "agreement.2.5.19.1", create_dissector_handle(dissect_ShadowingAgreementInfo_PDU, proto_disp));
  dissector_add_string("dop.oid", "establish.rolea.2.5.19.1", create_dissector_handle(dissect_EstablishParameter_PDU, proto_disp));
  dissector_add_string("dop.oid", "establish.roleb.2.5.19.1", create_dissector_handle(dissect_EstablishParameter_PDU, proto_disp));
  dissector_add_string("dop.oid", "modify.rolea.2.5.19.1", create_dissector_handle(dissect_ModificationParameter_PDU, proto_disp));
  dissector_add_string("dop.oid", "modify.roleb.2.5.19.1", create_dissector_handle(dissect_ModificationParameter_PDU, proto_disp));


  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-shadow-consumer-initiated","2.5.3.4");
  oid_add_from_string("id-ac-shadow-supplier-initiated","2.5.3.5");
  oid_add_from_string("id-ac-reliable-shadow-consumer-initiated","2.5.3.6");
  oid_add_from_string("id-ac-reliable-shadow-supplier-initiated","2.5.3.7");

  /* ABSTRACT SYNTAXES */
  register_ros_oid_dissector_handle("2.5.9.3", disp_handle, 0, "id-as-directory-shadow", false);
  register_rtse_oid_dissector_handle("2.5.9.5", disp_handle, 0, "id-as-directory-reliable-shadow", false);
  register_rtse_oid_dissector_handle("2.5.9.6", disp_handle, 0, "id-as-directory-reliable-binding", false);

  /* OPERATIONAL BINDING */
  oid_add_from_string("id-op-binding-shadow","2.5.1.0.5.1");

  /* DNs */
  x509if_register_fmt(hf_disp_contextPrefix, "cp=");

}
