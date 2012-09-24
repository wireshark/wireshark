/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-disp.c                                                              */
/* ../../tools/asn2wrs.py -b -p disp -c ./disp.cnf -s ./packet-disp-template -D . -O ../../epan/dissectors disp.asn */

/* Input file: packet-disp-template.c */

#line 1 "../../asn1/disp/packet-disp-template.c"
/* packet-disp.c
 * Routines for X.525 (X.500 Directory Shadow Asbtract Service) and X.519 DISP packet dissection
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

static guint global_disp_tcp_port = 102;
static dissector_handle_t tpkt_handle;
static void prefs_register_disp(void); /* forward declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
static int proto_disp = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;


/*--- Included file: packet-disp-hf.c ---*/
#line 1 "../../asn1/disp/packet-disp-hf.c"
static int hf_disp_EstablishParameter_PDU = -1;   /* EstablishParameter */
static int hf_disp_ModificationParameter_PDU = -1;  /* ModificationParameter */
static int hf_disp_ShadowingAgreementInfo_PDU = -1;  /* ShadowingAgreementInfo */
static int hf_disp_modifiedSecondaryShadows = -1;  /* SET_OF_SupplierAndConsumers */
static int hf_disp_modifiedSecondaryShadows_item = -1;  /* SupplierAndConsumers */
static int hf_disp_shadowSubject = -1;            /* UnitOfReplication */
static int hf_disp_updateMode = -1;               /* UpdateMode */
static int hf_disp_master = -1;                   /* AccessPoint */
static int hf_disp_secondaryShadows = -1;         /* BOOLEAN */
static int hf_disp_area = -1;                     /* AreaSpecification */
static int hf_disp_replication_attributes = -1;   /* AttributeSelection */
static int hf_disp_knowledge = -1;                /* Knowledge */
static int hf_disp_subordinates = -1;             /* BOOLEAN */
static int hf_disp_contextSelection = -1;         /* ContextSelection */
static int hf_disp_supplyContexts = -1;           /* T_supplyContexts */
static int hf_disp_allContexts = -1;              /* NULL */
static int hf_disp_selectedContexts = -1;         /* T_selectedContexts */
static int hf_disp_selectedContexts_item = -1;    /* OBJECT_IDENTIFIER */
static int hf_disp_contextPrefix = -1;            /* DistinguishedName */
static int hf_disp_replicationArea = -1;          /* SubtreeSpecification */
static int hf_disp_knowledgeType = -1;            /* T_knowledgeType */
static int hf_disp_extendedKnowledge = -1;        /* BOOLEAN */
static int hf_disp_AttributeSelection_item = -1;  /* ClassAttributeSelection */
static int hf_disp_class = -1;                    /* OBJECT_IDENTIFIER */
static int hf_disp_classAttributes = -1;          /* ClassAttributes */
static int hf_disp_allAttributes = -1;            /* NULL */
static int hf_disp_include = -1;                  /* AttributeTypes */
static int hf_disp_exclude = -1;                  /* AttributeTypes */
static int hf_disp_AttributeTypes_item = -1;      /* AttributeType */
static int hf_disp_supplierInitiated = -1;        /* SupplierUpdateMode */
static int hf_disp_consumerInitiated = -1;        /* ConsumerUpdateMode */
static int hf_disp_onChange = -1;                 /* BOOLEAN */
static int hf_disp_scheduled = -1;                /* SchedulingParameters */
static int hf_disp_periodic = -1;                 /* PeriodicStrategy */
static int hf_disp_othertimes = -1;               /* BOOLEAN */
static int hf_disp_beginTime = -1;                /* Time */
static int hf_disp_windowSize = -1;               /* INTEGER */
static int hf_disp_updateInterval = -1;           /* INTEGER */
static int hf_disp_agreementID = -1;              /* AgreementID */
static int hf_disp_lastUpdate = -1;               /* Time */
static int hf_disp_updateStrategy = -1;           /* T_updateStrategy */
static int hf_disp_standardUpdate = -1;           /* StandardUpdate */
static int hf_disp_other = -1;                    /* EXTERNAL */
static int hf_disp_securityParameters = -1;       /* SecurityParameters */
static int hf_disp_unsignedCoordinateShadowUpdateArgument = -1;  /* CoordinateShadowUpdateArgumentData */
static int hf_disp_signedCoordinateShadowUpdateArgument = -1;  /* T_signedCoordinateShadowUpdateArgument */
static int hf_disp_coordinateShadowUpdateArgument = -1;  /* CoordinateShadowUpdateArgumentData */
static int hf_disp_algorithmIdentifier = -1;      /* AlgorithmIdentifier */
static int hf_disp_encrypted = -1;                /* BIT_STRING */
static int hf_disp_null = -1;                     /* NULL */
static int hf_disp_information = -1;              /* Information */
static int hf_disp_performer = -1;                /* DistinguishedName */
static int hf_disp_aliasDereferenced = -1;        /* BOOLEAN */
static int hf_disp_notification = -1;             /* SEQUENCE_OF_Attribute */
static int hf_disp_notification_item = -1;        /* Attribute */
static int hf_disp_unsignedInformation = -1;      /* InformationData */
static int hf_disp_signedInformation = -1;        /* T_signedInformation */
static int hf_disp_information_data = -1;         /* InformationData */
static int hf_disp_requestedStrategy = -1;        /* T_requestedStrategy */
static int hf_disp_standard = -1;                 /* T_standard */
static int hf_disp_unsignedRequestShadowUpdateArgument = -1;  /* RequestShadowUpdateArgumentData */
static int hf_disp_signedRequestShadowUpdateArgument = -1;  /* T_signedRequestShadowUpdateArgument */
static int hf_disp_requestShadowUpdateArgument = -1;  /* RequestShadowUpdateArgumentData */
static int hf_disp_updateTime = -1;               /* Time */
static int hf_disp_updateWindow = -1;             /* UpdateWindow */
static int hf_disp_updatedInfo = -1;              /* RefreshInformation */
static int hf_disp_unsignedUpdateShadowArgument = -1;  /* UpdateShadowArgumentData */
static int hf_disp_signedUpdateShadowArgument = -1;  /* T_signedUpdateShadowArgument */
static int hf_disp_updateShadowArgument = -1;     /* UpdateShadowArgumentData */
static int hf_disp_start = -1;                    /* Time */
static int hf_disp_stop = -1;                     /* Time */
static int hf_disp_noRefresh = -1;                /* NULL */
static int hf_disp_total = -1;                    /* TotalRefresh */
static int hf_disp_incremental = -1;              /* IncrementalRefresh */
static int hf_disp_otherStrategy = -1;            /* EXTERNAL */
static int hf_disp_sDSE = -1;                     /* SDSEContent */
static int hf_disp_subtree = -1;                  /* SET_OF_Subtree */
static int hf_disp_subtree_item = -1;             /* Subtree */
static int hf_disp_sDSEType = -1;                 /* SDSEType */
static int hf_disp_subComplete = -1;              /* BOOLEAN */
static int hf_disp_attComplete = -1;              /* BOOLEAN */
static int hf_disp_attributes = -1;               /* SET_OF_Attribute */
static int hf_disp_attributes_item = -1;          /* Attribute */
static int hf_disp_attValIncomplete = -1;         /* SET_OF_AttributeType */
static int hf_disp_attValIncomplete_item = -1;    /* AttributeType */
static int hf_disp_rdn = -1;                      /* RelativeDistinguishedName */
static int hf_disp_IncrementalRefresh_item = -1;  /* IncrementalStepRefresh */
static int hf_disp_sDSEChanges = -1;              /* T_sDSEChanges */
static int hf_disp_add = -1;                      /* SDSEContent */
static int hf_disp_remove = -1;                   /* NULL */
static int hf_disp_modify = -1;                   /* ContentChange */
static int hf_disp_subordinateUpdates = -1;       /* SEQUENCE_OF_SubordinateChanges */
static int hf_disp_subordinateUpdates_item = -1;  /* SubordinateChanges */
static int hf_disp_rename = -1;                   /* T_rename */
static int hf_disp_newRDN = -1;                   /* RelativeDistinguishedName */
static int hf_disp_newDN = -1;                    /* DistinguishedName */
static int hf_disp_attributeChanges = -1;         /* T_attributeChanges */
static int hf_disp_replace = -1;                  /* SET_OF_Attribute */
static int hf_disp_replace_item = -1;             /* Attribute */
static int hf_disp_changes = -1;                  /* SEQUENCE_OF_EntryModification */
static int hf_disp_changes_item = -1;             /* EntryModification */
static int hf_disp_subordinate = -1;              /* RelativeDistinguishedName */
static int hf_disp_subordinate_changes = -1;      /* IncrementalStepRefresh */
static int hf_disp_problem = -1;                  /* ShadowProblem */
static int hf_disp_unsignedShadowError = -1;      /* ShadowErrorData */
static int hf_disp_signedShadowError = -1;        /* T_signedShadowError */
static int hf_disp_shadowError = -1;              /* ShadowErrorData */

/*--- End of included file: packet-disp-hf.c ---*/
#line 67 "../../asn1/disp/packet-disp-template.c"

/* Initialize the subtree pointers */
static gint ett_disp = -1;

/*--- Included file: packet-disp-ett.c ---*/
#line 1 "../../asn1/disp/packet-disp-ett.c"
static gint ett_disp_ModificationParameter = -1;
static gint ett_disp_SET_OF_SupplierAndConsumers = -1;
static gint ett_disp_ShadowingAgreementInfo = -1;
static gint ett_disp_UnitOfReplication = -1;
static gint ett_disp_T_supplyContexts = -1;
static gint ett_disp_T_selectedContexts = -1;
static gint ett_disp_AreaSpecification = -1;
static gint ett_disp_Knowledge = -1;
static gint ett_disp_AttributeSelection = -1;
static gint ett_disp_ClassAttributeSelection = -1;
static gint ett_disp_ClassAttributes = -1;
static gint ett_disp_AttributeTypes = -1;
static gint ett_disp_UpdateMode = -1;
static gint ett_disp_SupplierUpdateMode = -1;
static gint ett_disp_SchedulingParameters = -1;
static gint ett_disp_PeriodicStrategy = -1;
static gint ett_disp_CoordinateShadowUpdateArgumentData = -1;
static gint ett_disp_T_updateStrategy = -1;
static gint ett_disp_CoordinateShadowUpdateArgument = -1;
static gint ett_disp_T_signedCoordinateShadowUpdateArgument = -1;
static gint ett_disp_CoordinateShadowUpdateResult = -1;
static gint ett_disp_InformationData = -1;
static gint ett_disp_SEQUENCE_OF_Attribute = -1;
static gint ett_disp_Information = -1;
static gint ett_disp_T_signedInformation = -1;
static gint ett_disp_RequestShadowUpdateArgumentData = -1;
static gint ett_disp_T_requestedStrategy = -1;
static gint ett_disp_RequestShadowUpdateArgument = -1;
static gint ett_disp_T_signedRequestShadowUpdateArgument = -1;
static gint ett_disp_RequestShadowUpdateResult = -1;
static gint ett_disp_UpdateShadowArgumentData = -1;
static gint ett_disp_UpdateShadowArgument = -1;
static gint ett_disp_T_signedUpdateShadowArgument = -1;
static gint ett_disp_UpdateShadowResult = -1;
static gint ett_disp_UpdateWindow = -1;
static gint ett_disp_RefreshInformation = -1;
static gint ett_disp_TotalRefresh = -1;
static gint ett_disp_SET_OF_Subtree = -1;
static gint ett_disp_SDSEContent = -1;
static gint ett_disp_SET_OF_Attribute = -1;
static gint ett_disp_SET_OF_AttributeType = -1;
static gint ett_disp_Subtree = -1;
static gint ett_disp_IncrementalRefresh = -1;
static gint ett_disp_IncrementalStepRefresh = -1;
static gint ett_disp_T_sDSEChanges = -1;
static gint ett_disp_SEQUENCE_OF_SubordinateChanges = -1;
static gint ett_disp_ContentChange = -1;
static gint ett_disp_T_rename = -1;
static gint ett_disp_T_attributeChanges = -1;
static gint ett_disp_SEQUENCE_OF_EntryModification = -1;
static gint ett_disp_SubordinateChanges = -1;
static gint ett_disp_ShadowErrorData = -1;
static gint ett_disp_ShadowError = -1;
static gint ett_disp_T_signedShadowError = -1;

/*--- End of included file: packet-disp-ett.c ---*/
#line 71 "../../asn1/disp/packet-disp-template.c"


/*--- Included file: packet-disp-fn.c ---*/
#line 1 "../../asn1/disp/packet-disp-fn.c"
/*--- Cyclic dependencies ---*/

/* Subtree -> Subtree/subtree -> Subtree */
static int dissect_disp_Subtree(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* IncrementalStepRefresh -> IncrementalStepRefresh/subordinateUpdates -> SubordinateChanges -> IncrementalStepRefresh */
static int dissect_disp_IncrementalStepRefresh(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_disp_DSAShadowBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_disp_DSAShadowBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_disp_DSAShadowBindError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_disp_EstablishParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_SupplierAndConsumers_set_of[1] = {
  { &hf_disp_modifiedSecondaryShadows_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dop_SupplierAndConsumers },
};

static int
dissect_disp_SET_OF_SupplierAndConsumers(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_SupplierAndConsumers_set_of, hf_index, ett_disp_SET_OF_SupplierAndConsumers);

  return offset;
}


static const ber_sequence_t ModificationParameter_sequence[] = {
  { &hf_disp_modifiedSecondaryShadows, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_disp_SET_OF_SupplierAndConsumers },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_ModificationParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModificationParameter_sequence, hf_index, ett_disp_ModificationParameter);

  return offset;
}



int
dissect_disp_AgreementID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dop_OperationalBindingID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AreaSpecification_sequence[] = {
  { &hf_disp_contextPrefix  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_DistinguishedName },
  { &hf_disp_replicationArea, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_SubtreeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_AreaSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AreaSpecification_sequence, hf_index, ett_disp_AreaSpecification);

  return offset;
}



static int
dissect_disp_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_disp_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t AttributeTypes_set_of[1] = {
  { &hf_disp_AttributeTypes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_disp_AttributeTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_ClassAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_ClassAttributeSelection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ClassAttributeSelection_sequence, hf_index, ett_disp_ClassAttributeSelection);

  return offset;
}


static const ber_sequence_t AttributeSelection_set_of[1] = {
  { &hf_disp_AttributeSelection_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_ClassAttributeSelection },
};

static int
dissect_disp_AttributeSelection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_knowledgeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_disp_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t Knowledge_sequence[] = {
  { &hf_disp_knowledgeType  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_disp_T_knowledgeType },
  { &hf_disp_extendedKnowledge, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_Knowledge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Knowledge_sequence, hf_index, ett_disp_Knowledge);

  return offset;
}


static const ber_sequence_t T_selectedContexts_set_of[1] = {
  { &hf_disp_selectedContexts_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_disp_OBJECT_IDENTIFIER },
};

static int
dissect_disp_T_selectedContexts(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_supplyContexts(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_UnitOfReplication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UnitOfReplication_sequence, hf_index, ett_disp_UnitOfReplication);

  return offset;
}



static int
dissect_disp_Time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_disp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_PeriodicStrategy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_SchedulingParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_SupplierUpdateMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SupplierUpdateMode_choice, hf_index, ett_disp_SupplierUpdateMode,
                                 NULL);

  return offset;
}



static int
dissect_disp_ConsumerUpdateMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_UpdateMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_ShadowingAgreementInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_StandardUpdate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 58 "../../asn1/disp/disp.cnf"
  guint32 update;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &update);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", val_to_str(update, disp_StandardUpdate_vals, "unknown(%d)"));



  return offset;
}



static int
dissect_disp_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_updateStrategy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_CoordinateShadowUpdateArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CoordinateShadowUpdateArgumentData_sequence, hf_index, ett_disp_CoordinateShadowUpdateArgumentData);

  return offset;
}



static int
dissect_disp_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
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
dissect_disp_T_signedCoordinateShadowUpdateArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedCoordinateShadowUpdateArgument_sequence, hf_index, ett_disp_T_signedCoordinateShadowUpdateArgument);

  return offset;
}


static const value_string disp_CoordinateShadowUpdateArgument_vals[] = {
  {   0, "unsignedCoordinateShadowUpdateArgument" },
  {   1, "signedCoordinateShadowUpdateArgument" },
  { 0, NULL }
};

static const ber_choice_t CoordinateShadowUpdateArgument_choice[] = {
  {   0, &hf_disp_unsignedCoordinateShadowUpdateArgument, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_CoordinateShadowUpdateArgumentData },
  {   1, &hf_disp_signedCoordinateShadowUpdateArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_T_signedCoordinateShadowUpdateArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_CoordinateShadowUpdateArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CoordinateShadowUpdateArgument_choice, hf_index, ett_disp_CoordinateShadowUpdateArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Attribute_sequence_of[1] = {
  { &hf_disp_notification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_disp_SEQUENCE_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_InformationData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_signedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_Information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_CoordinateShadowUpdateResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 68 "../../asn1/disp/disp.cnf"
  guint32 update;

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
dissect_disp_T_standard(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 38 "../../asn1/disp/disp.cnf"
  guint32 update;

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
dissect_disp_T_requestedStrategy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_RequestShadowUpdateArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_signedRequestShadowUpdateArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedRequestShadowUpdateArgument_sequence, hf_index, ett_disp_T_signedRequestShadowUpdateArgument);

  return offset;
}


static const value_string disp_RequestShadowUpdateArgument_vals[] = {
  {   0, "unsignedRequestShadowUpdateArgument" },
  {   1, "signedRequestShadowUpdateArgument" },
  { 0, NULL }
};

static const ber_choice_t RequestShadowUpdateArgument_choice[] = {
  {   0, &hf_disp_unsignedRequestShadowUpdateArgument, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_RequestShadowUpdateArgumentData },
  {   1, &hf_disp_signedRequestShadowUpdateArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_T_signedRequestShadowUpdateArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_RequestShadowUpdateArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_RequestShadowUpdateResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 78 "../../asn1/disp/disp.cnf"
  guint32 update;

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
dissect_disp_UpdateWindow(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateWindow_sequence, hf_index, ett_disp_UpdateWindow);

  return offset;
}



static int
dissect_disp_SDSEType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dop_DSEType(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { &hf_disp_attributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_disp_SET_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Attribute_set_of, hf_index, ett_disp_SET_OF_Attribute);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeType_set_of[1] = {
  { &hf_disp_attValIncomplete_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_disp_SET_OF_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_SDSEContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SDSEContent_sequence, hf_index, ett_disp_SDSEContent);

  return offset;
}


static const ber_sequence_t SET_OF_Subtree_set_of[1] = {
  { &hf_disp_subtree_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_Subtree },
};

static int
dissect_disp_SET_OF_Subtree(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_Subtree(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Subtree_sequence, hf_index, ett_disp_Subtree);

  return offset;
}


static const ber_sequence_t TotalRefresh_sequence[] = {
  { &hf_disp_sDSE           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_SDSEContent },
  { &hf_disp_subtree        , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_disp_SET_OF_Subtree },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_TotalRefresh(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_rename(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_rename_choice, hf_index, ett_disp_T_rename,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EntryModification_sequence_of[1] = {
  { &hf_disp_changes_item   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dap_EntryModification },
};

static int
dissect_disp_SEQUENCE_OF_EntryModification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_attributeChanges(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_ContentChange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_sDSEChanges(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_SubordinateChanges(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubordinateChanges_sequence, hf_index, ett_disp_SubordinateChanges);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SubordinateChanges_sequence_of[1] = {
  { &hf_disp_subordinateUpdates_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_SubordinateChanges },
};

static int
dissect_disp_SEQUENCE_OF_SubordinateChanges(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_IncrementalStepRefresh(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IncrementalStepRefresh_sequence, hf_index, ett_disp_IncrementalStepRefresh);

  return offset;
}


static const ber_sequence_t IncrementalRefresh_sequence_of[1] = {
  { &hf_disp_IncrementalRefresh_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_IncrementalStepRefresh },
};

static int
dissect_disp_IncrementalRefresh(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_RefreshInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 48 "../../asn1/disp/disp.cnf"
  guint32 update;

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
dissect_disp_UpdateShadowArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_signedUpdateShadowArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedUpdateShadowArgument_sequence, hf_index, ett_disp_T_signedUpdateShadowArgument);

  return offset;
}


static const value_string disp_UpdateShadowArgument_vals[] = {
  {   0, "unsignedUpdateShadowArgument" },
  {   1, "signedUpdateShadowArgument" },
  { 0, NULL }
};

static const ber_choice_t UpdateShadowArgument_choice[] = {
  {   0, &hf_disp_unsignedUpdateShadowArgument, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_UpdateShadowArgumentData },
  {   1, &hf_disp_signedUpdateShadowArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_T_signedUpdateShadowArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_UpdateShadowArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_UpdateShadowResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 88 "../../asn1/disp/disp.cnf"
  guint32 update;

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
dissect_disp_ShadowProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 98 "../../asn1/disp/disp.cnf"
  guint32 problem;

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
dissect_disp_ShadowErrorData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_disp_T_signedShadowError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedShadowError_sequence, hf_index, ett_disp_T_signedShadowError);

  return offset;
}


static const value_string disp_ShadowError_vals[] = {
  {   0, "unsignedShadowError" },
  {   1, "signedShadowError" },
  { 0, NULL }
};

static const ber_choice_t ShadowError_choice[] = {
  {   0, &hf_disp_unsignedShadowError, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_disp_ShadowErrorData },
  {   1, &hf_disp_signedShadowError, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_disp_T_signedShadowError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_disp_ShadowError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ShadowError_choice, hf_index, ett_disp_ShadowError,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_EstablishParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_disp_EstablishParameter(FALSE, tvb, 0, &asn1_ctx, tree, hf_disp_EstablishParameter_PDU);
}
static void dissect_ModificationParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_disp_ModificationParameter(FALSE, tvb, 0, &asn1_ctx, tree, hf_disp_ModificationParameter_PDU);
}
static void dissect_ShadowingAgreementInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_disp_ShadowingAgreementInfo(FALSE, tvb, 0, &asn1_ctx, tree, hf_disp_ShadowingAgreementInfo_PDU);
}


/*--- End of included file: packet-disp-fn.c ---*/
#line 73 "../../asn1/disp/packet-disp-template.c"

/*
* Dissect DISP PDUs inside a ROS PDUs
*/
static void
dissect_disp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*disp_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	char *disp_op_name;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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
		item = proto_tree_add_item(parent_tree, proto_disp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_disp);
	}
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
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DISP opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
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
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DISP opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
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
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DISP errcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DISP PDU");
	  return;
	}

	if(disp_dissector) {
	  col_set_str(pinfo->cinfo, COL_INFO, disp_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*disp_dissector)(FALSE, tvb, offset, &asn1_ctx, tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DISP PDU");
	      break;
	    }
	  }
	}
}


/*--- proto_register_disp -------------------------------------------*/
void proto_register_disp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-disp-hfarr.c ---*/
#line 1 "../../asn1/disp/packet-disp-hfarr.c"
    { &hf_disp_EstablishParameter_PDU,
      { "EstablishParameter", "disp.EstablishParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_ModificationParameter_PDU,
      { "ModificationParameter", "disp.ModificationParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_ShadowingAgreementInfo_PDU,
      { "ShadowingAgreementInfo", "disp.ShadowingAgreementInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_modifiedSecondaryShadows,
      { "secondaryShadows", "disp.secondaryShadows",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SupplierAndConsumers", HFILL }},
    { &hf_disp_modifiedSecondaryShadows_item,
      { "SupplierAndConsumers", "disp.SupplierAndConsumers",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_shadowSubject,
      { "shadowSubject", "disp.shadowSubject",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnitOfReplication", HFILL }},
    { &hf_disp_updateMode,
      { "updateMode", "disp.updateMode",
        FT_UINT32, BASE_DEC, VALS(disp_UpdateMode_vals), 0,
        NULL, HFILL }},
    { &hf_disp_master,
      { "master", "disp.master",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessPoint", HFILL }},
    { &hf_disp_secondaryShadows,
      { "secondaryShadows", "disp.secondaryShadows",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_area,
      { "area", "disp.area",
        FT_NONE, BASE_NONE, NULL, 0,
        "AreaSpecification", HFILL }},
    { &hf_disp_replication_attributes,
      { "attributes", "disp.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributeSelection", HFILL }},
    { &hf_disp_knowledge,
      { "knowledge", "disp.knowledge",
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
      { "allContexts", "disp.allContexts",
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
      { "replicationArea", "disp.replicationArea",
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
      { "ClassAttributeSelection", "disp.ClassAttributeSelection",
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
      { "allAttributes", "disp.allAttributes",
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
      { "consumerInitiated", "disp.consumerInitiated",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConsumerUpdateMode", HFILL }},
    { &hf_disp_onChange,
      { "onChange", "disp.onChange",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_disp_scheduled,
      { "scheduled", "disp.scheduled",
        FT_NONE, BASE_NONE, NULL, 0,
        "SchedulingParameters", HFILL }},
    { &hf_disp_periodic,
      { "periodic", "disp.periodic",
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
      { "agreementID", "disp.agreementID",
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
      { "other", "disp.other",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_disp_securityParameters,
      { "securityParameters", "disp.securityParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_unsignedCoordinateShadowUpdateArgument,
      { "unsignedCoordinateShadowUpdateArgument", "disp.unsignedCoordinateShadowUpdateArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "CoordinateShadowUpdateArgumentData", HFILL }},
    { &hf_disp_signedCoordinateShadowUpdateArgument,
      { "signedCoordinateShadowUpdateArgument", "disp.signedCoordinateShadowUpdateArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_coordinateShadowUpdateArgument,
      { "coordinateShadowUpdateArgument", "disp.coordinateShadowUpdateArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "CoordinateShadowUpdateArgumentData", HFILL }},
    { &hf_disp_algorithmIdentifier,
      { "algorithmIdentifier", "disp.algorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_encrypted,
      { "encrypted", "disp.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_disp_null,
      { "null", "disp.null",
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
      { "Attribute", "disp.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_unsignedInformation,
      { "unsignedInformation", "disp.unsignedInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformationData", HFILL }},
    { &hf_disp_signedInformation,
      { "signedInformation", "disp.signedInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_information_data,
      { "information", "disp.information",
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
      { "unsignedRequestShadowUpdateArgument", "disp.unsignedRequestShadowUpdateArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestShadowUpdateArgumentData", HFILL }},
    { &hf_disp_signedRequestShadowUpdateArgument,
      { "signedRequestShadowUpdateArgument", "disp.signedRequestShadowUpdateArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_requestShadowUpdateArgument,
      { "requestShadowUpdateArgument", "disp.requestShadowUpdateArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestShadowUpdateArgumentData", HFILL }},
    { &hf_disp_updateTime,
      { "updateTime", "disp.updateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_disp_updateWindow,
      { "updateWindow", "disp.updateWindow",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_updatedInfo,
      { "updatedInfo", "disp.updatedInfo",
        FT_UINT32, BASE_DEC, VALS(disp_RefreshInformation_vals), 0,
        "RefreshInformation", HFILL }},
    { &hf_disp_unsignedUpdateShadowArgument,
      { "unsignedUpdateShadowArgument", "disp.unsignedUpdateShadowArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateShadowArgumentData", HFILL }},
    { &hf_disp_signedUpdateShadowArgument,
      { "signedUpdateShadowArgument", "disp.signedUpdateShadowArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_updateShadowArgument,
      { "updateShadowArgument", "disp.updateShadowArgument",
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
      { "noRefresh", "disp.noRefresh",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_total,
      { "total", "disp.total",
        FT_NONE, BASE_NONE, NULL, 0,
        "TotalRefresh", HFILL }},
    { &hf_disp_incremental,
      { "incremental", "disp.incremental",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IncrementalRefresh", HFILL }},
    { &hf_disp_otherStrategy,
      { "otherStrategy", "disp.otherStrategy",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_disp_sDSE,
      { "sDSE", "disp.sDSE",
        FT_NONE, BASE_NONE, NULL, 0,
        "SDSEContent", HFILL }},
    { &hf_disp_subtree,
      { "subtree", "disp.subtree",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Subtree", HFILL }},
    { &hf_disp_subtree_item,
      { "Subtree", "disp.Subtree",
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
      { "Attribute", "disp.Attribute",
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
      { "IncrementalStepRefresh", "disp.IncrementalStepRefresh",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_sDSEChanges,
      { "sDSEChanges", "disp.sDSEChanges",
        FT_UINT32, BASE_DEC, VALS(disp_T_sDSEChanges_vals), 0,
        NULL, HFILL }},
    { &hf_disp_add,
      { "add", "disp.add",
        FT_NONE, BASE_NONE, NULL, 0,
        "SDSEContent", HFILL }},
    { &hf_disp_remove,
      { "remove", "disp.remove",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_modify,
      { "modify", "disp.modify",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentChange", HFILL }},
    { &hf_disp_subordinateUpdates,
      { "subordinateUpdates", "disp.subordinateUpdates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SubordinateChanges", HFILL }},
    { &hf_disp_subordinateUpdates_item,
      { "SubordinateChanges", "disp.SubordinateChanges",
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
      { "Attribute", "disp.Attribute",
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
      { "changes", "disp.changes",
        FT_NONE, BASE_NONE, NULL, 0,
        "IncrementalStepRefresh", HFILL }},
    { &hf_disp_problem,
      { "problem", "disp.problem",
        FT_INT32, BASE_DEC, VALS(disp_ShadowProblem_vals), 0,
        "ShadowProblem", HFILL }},
    { &hf_disp_unsignedShadowError,
      { "unsignedShadowError", "disp.unsignedShadowError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ShadowErrorData", HFILL }},
    { &hf_disp_signedShadowError,
      { "signedShadowError", "disp.signedShadowError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_disp_shadowError,
      { "shadowError", "disp.shadowError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ShadowErrorData", HFILL }},

/*--- End of included file: packet-disp-hfarr.c ---*/
#line 200 "../../asn1/disp/packet-disp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_disp,

/*--- Included file: packet-disp-ettarr.c ---*/
#line 1 "../../asn1/disp/packet-disp-ettarr.c"
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

/*--- End of included file: packet-disp-ettarr.c ---*/
#line 206 "../../asn1/disp/packet-disp-template.c"
  };
  module_t *disp_module;

  /* Register protocol */
  proto_disp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("disp", dissect_disp, proto_disp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_disp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DISP, particularly our port */

  disp_module = prefs_register_protocol_subtree("OSI/X.500", proto_disp, prefs_register_disp);

  prefs_register_uint_preference(disp_module, "tcp.port", "DISP TCP Port",
				 "Set the port for DISP operations (if other"
				 " than the default of 102)",
				 10, &global_disp_tcp_port);

}


/*--- proto_reg_handoff_disp --- */
void proto_reg_handoff_disp(void) {
  dissector_handle_t disp_handle;


/*--- Included file: packet-disp-dis-tab.c ---*/
#line 1 "../../asn1/disp/packet-disp-dis-tab.c"
  dissector_add_string("dop.oid", "agreement.2.5.19.1", create_dissector_handle(dissect_ShadowingAgreementInfo_PDU, proto_disp));
  dissector_add_string("dop.oid", "establish.rolea.2.5.19.1", create_dissector_handle(dissect_EstablishParameter_PDU, proto_disp));
  dissector_add_string("dop.oid", "establish.roleb.2.5.19.1", create_dissector_handle(dissect_EstablishParameter_PDU, proto_disp));
  dissector_add_string("dop.oid", "modify.rolea.2.5.19.1", create_dissector_handle(dissect_ModificationParameter_PDU, proto_disp));
  dissector_add_string("dop.oid", "modify.roleb.2.5.19.1", create_dissector_handle(dissect_ModificationParameter_PDU, proto_disp));


/*--- End of included file: packet-disp-dis-tab.c ---*/
#line 234 "../../asn1/disp/packet-disp-template.c"

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-shadow-consumer-initiated","2.5.3.4");
  oid_add_from_string("id-ac-shadow-supplier-initiated","2.5.3.5");
  oid_add_from_string("id-ac-reliable-shadow-consumer-initiated","2.5.3.6");
  oid_add_from_string("id-ac-reliable-shadow-supplier-initiated","2.5.3.7");

  /* ABSTRACT SYNTAXES */

  disp_handle = find_dissector("disp");

  register_ros_oid_dissector_handle("2.5.9.3", disp_handle, 0, "id-as-directory-shadow", FALSE);
  register_rtse_oid_dissector_handle("2.5.9.5", disp_handle, 0, "id-as-directory-reliable-shadow", FALSE);
  register_rtse_oid_dissector_handle("2.5.9.6", disp_handle, 0, "id-as-directory-reliable-binding", FALSE);

  /* OPERATIONAL BINDING */
  oid_add_from_string("id-op-binding-shadow","2.5.1.0.5.1");

  tpkt_handle = find_dissector("tpkt");

  /* DNs */
  x509if_register_fmt(hf_disp_contextPrefix, "cp=");

}


static void
prefs_register_disp(void)
{
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete_uint("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_disp_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add_uint("tcp.port", global_disp_tcp_port, tpkt_handle);

}
