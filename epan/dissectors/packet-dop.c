/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-dop.c                                                               */
/* asn2wrs.py -b -q -L -p dop -c ./dop.cnf -s ./packet-dop-template -D . -O ../.. dop.asn */

/* packet-dop.c
 * Routines for X.501 (DSA Operational Attributes)  packet dissection
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
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"

#include "packet-x509sat.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-dap.h"
#include "packet-dsp.h"
#include "packet-crmf.h"


#include "packet-dop.h"

#define PNAME  "X.501 Directory Operational Binding Management Protocol"
#define PSNAME "DOP"
#define PFNAME "dop"

void proto_register_dop(void);
void proto_reg_handoff_dop(void);

/* Initialize the protocol and registered fields */
static int proto_dop;

static const char *binding_type; /* binding_type */

static int call_dop_oid_callback(const char *base_string, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, const char *col_info, void* data);

static int hf_dop_DSEType_PDU;                    /* DSEType */
static int hf_dop_SupplierInformation_PDU;        /* SupplierInformation */
static int hf_dop_ConsumerInformation_PDU;        /* ConsumerInformation */
static int hf_dop_SupplierAndConsumers_PDU;       /* SupplierAndConsumers */
static int hf_dop_HierarchicalAgreement_PDU;      /* HierarchicalAgreement */
static int hf_dop_SuperiorToSubordinate_PDU;      /* SuperiorToSubordinate */
static int hf_dop_SubordinateToSuperior_PDU;      /* SubordinateToSuperior */
static int hf_dop_SuperiorToSubordinateModification_PDU;  /* SuperiorToSubordinateModification */
static int hf_dop_NonSpecificHierarchicalAgreement_PDU;  /* NonSpecificHierarchicalAgreement */
static int hf_dop_NHOBSuperiorToSubordinate_PDU;  /* NHOBSuperiorToSubordinate */
static int hf_dop_NHOBSubordinateToSuperior_PDU;  /* NHOBSubordinateToSuperior */
static int hf_dop_ACIItem_PDU;                    /* ACIItem */
static int hf_dop_ae_title;                       /* Name */
static int hf_dop_address;                        /* PresentationAddress */
static int hf_dop_protocolInformation;            /* SET_OF_ProtocolInformation */
static int hf_dop_protocolInformation_item;       /* ProtocolInformation */
static int hf_dop_agreementID;                    /* OperationalBindingID */
static int hf_dop_supplier_is_master;             /* BOOLEAN */
static int hf_dop_non_supplying_master;           /* AccessPoint */
static int hf_dop_consumers;                      /* SET_OF_AccessPoint */
static int hf_dop_consumers_item;                 /* AccessPoint */
static int hf_dop_bindingType;                    /* BindingType */
static int hf_dop_bindingID;                      /* OperationalBindingID */
static int hf_dop_accessPoint;                    /* AccessPoint */
static int hf_dop_establishInitiator;             /* EstablishArgumentInitiator */
static int hf_dop_establishSymmetric;             /* EstablishSymmetric */
static int hf_dop_establishRoleAInitiates;        /* EstablishRoleAInitiates */
static int hf_dop_establishRoleBInitiates;        /* EstablishRoleBInitiates */
static int hf_dop_agreement;                      /* T_agreement */
static int hf_dop_valid;                          /* Validity */
static int hf_dop_securityParameters;             /* SecurityParameters */
static int hf_dop_unsignedEstablishOperationalBindingArgument;  /* EstablishOperationalBindingArgumentData */
static int hf_dop_signedEstablishOperationalBindingArgument;  /* T_signedEstablishOperationalBindingArgument */
static int hf_dop_establishOperationalBindingArgument;  /* EstablishOperationalBindingArgumentData */
static int hf_dop_algorithmIdentifier;            /* AlgorithmIdentifier */
static int hf_dop_encrypted;                      /* BIT_STRING */
static int hf_dop_identifier;                     /* T_identifier */
static int hf_dop_version;                        /* T_version */
static int hf_dop_validFrom;                      /* T_validFrom */
static int hf_dop_now;                            /* NULL */
static int hf_dop_time;                           /* Time */
static int hf_dop_validUntil;                     /* T_validUntil */
static int hf_dop_explicitTermination;            /* NULL */
static int hf_dop_utcTime;                        /* UTCTime */
static int hf_dop_generalizedTime;                /* GeneralizedTime */
static int hf_dop_initiator;                      /* T_initiator */
static int hf_dop_symmetric;                      /* T_symmetric */
static int hf_dop_roleA_replies;                  /* T_roleA_replies */
static int hf_dop_roleB_replies;                  /* T_roleB_replies */
static int hf_dop_performer;                      /* DistinguishedName */
static int hf_dop_aliasDereferenced;              /* BOOLEAN */
static int hf_dop_notification;                   /* SEQUENCE_SIZE_1_MAX_OF_Attribute */
static int hf_dop_notification_item;              /* Attribute */
static int hf_dop_modifyInitiator;                /* ModifyArgumentInitiator */
static int hf_dop_modifySymmetric;                /* ModifySymmetric */
static int hf_dop_modifyRoleAInitiates;           /* ModifyRoleAInitiates */
static int hf_dop_modifyRoleBInitiates;           /* ModifyRoleBInitiates */
static int hf_dop_newBindingID;                   /* OperationalBindingID */
static int hf_dop_argumentNewAgreement;           /* ArgumentNewAgreement */
static int hf_dop_unsignedModifyOperationalBindingArgument;  /* ModifyOperationalBindingArgumentData */
static int hf_dop_signedModifyOperationalBindingArgument;  /* T_signedModifyOperationalBindingArgument */
static int hf_dop_modifyOperationalBindingArgument;  /* ModifyOperationalBindingArgumentData */
static int hf_dop_null;                           /* NULL */
static int hf_dop_protectedModifyResult;          /* ProtectedModifyResult */
static int hf_dop_modifyOperationalBindingResultData;  /* ModifyOperationalBindingResultData */
static int hf_dop_resultNewAgreement;             /* ResultNewAgreement */
static int hf_dop_terminateInitiator;             /* TerminateArgumentInitiator */
static int hf_dop_terminateSymmetric;             /* TerminateSymmetric */
static int hf_dop_terminateRoleAInitiates;        /* TerminateRoleAInitiates */
static int hf_dop_terminateRoleBInitiates;        /* TerminateRoleBInitiates */
static int hf_dop_terminateAtTime;                /* Time */
static int hf_dop_unsignedTerminateOperationalBindingArgument;  /* TerminateOperationalBindingArgumentData */
static int hf_dop_signedTerminateOperationalBindingArgument;  /* T_signedTerminateOperationalBindingArgument */
static int hf_dop_terminateOperationalBindingArgument;  /* TerminateOperationalBindingArgumentData */
static int hf_dop_protectedTerminateResult;       /* ProtectedTerminateResult */
static int hf_dop_terminateOperationalBindingResultData;  /* TerminateOperationalBindingResultData */
static int hf_dop_terminateAtGeneralizedTime;     /* GeneralizedTime */
static int hf_dop_problem;                        /* T_problem */
static int hf_dop_agreementProposal;              /* T_agreementProposal */
static int hf_dop_retryAt;                        /* Time */
static int hf_dop_rdn;                            /* RelativeDistinguishedName */
static int hf_dop_immediateSuperior;              /* DistinguishedName */
static int hf_dop_contextPrefixInfo;              /* DITcontext */
static int hf_dop_entryInfo;                      /* SET_OF_Attribute */
static int hf_dop_entryInfo_item;                 /* Attribute */
static int hf_dop_immediateSuperiorInfo;          /* SET_OF_Attribute */
static int hf_dop_immediateSuperiorInfo_item;     /* Attribute */
static int hf_dop_DITcontext_item;                /* Vertex */
static int hf_dop_admPointInfo;                   /* SET_OF_Attribute */
static int hf_dop_admPointInfo_item;              /* Attribute */
static int hf_dop_subentries;                     /* SET_OF_SubentryInfo */
static int hf_dop_subentries_item;                /* SubentryInfo */
static int hf_dop_accessPoints;                   /* MasterAndShadowAccessPoints */
static int hf_dop_info;                           /* SET_OF_Attribute */
static int hf_dop_info_item;                      /* Attribute */
static int hf_dop_alias;                          /* BOOLEAN */
static int hf_dop_identificationTag;              /* DirectoryString */
static int hf_dop_precedence;                     /* Precedence */
static int hf_dop_authenticationLevel;            /* AuthenticationLevel */
static int hf_dop_itemOrUserFirst;                /* T_itemOrUserFirst */
static int hf_dop_itemFirst;                      /* T_itemFirst */
static int hf_dop_protectedItems;                 /* ProtectedItems */
static int hf_dop_itemPermissions;                /* SET_OF_ItemPermission */
static int hf_dop_itemPermissions_item;           /* ItemPermission */
static int hf_dop_userFirst;                      /* T_userFirst */
static int hf_dop_userClasses;                    /* UserClasses */
static int hf_dop_userPermissions;                /* SET_OF_UserPermission */
static int hf_dop_userPermissions_item;           /* UserPermission */
static int hf_dop_entry;                          /* NULL */
static int hf_dop_allUserAttributeTypes;          /* NULL */
static int hf_dop_attributeType;                  /* SET_OF_AttributeType */
static int hf_dop_attributeType_item;             /* AttributeType */
static int hf_dop_allAttributeValues;             /* SET_OF_AttributeType */
static int hf_dop_allAttributeValues_item;        /* AttributeType */
static int hf_dop_allUserAttributeTypesAndValues;  /* NULL */
static int hf_dop_attributeValue;                 /* SET_OF_AttributeTypeAndValue */
static int hf_dop_attributeValue_item;            /* AttributeTypeAndValue */
static int hf_dop_selfValue;                      /* SET_OF_AttributeType */
static int hf_dop_selfValue_item;                 /* AttributeType */
static int hf_dop_rangeOfValues;                  /* Filter */
static int hf_dop_maxValueCount;                  /* SET_OF_MaxValueCount */
static int hf_dop_maxValueCount_item;             /* MaxValueCount */
static int hf_dop_maxImmSub;                      /* INTEGER */
static int hf_dop_restrictedBy;                   /* SET_OF_RestrictedValue */
static int hf_dop_restrictedBy_item;              /* RestrictedValue */
static int hf_dop_contexts;                       /* SET_OF_ContextAssertion */
static int hf_dop_contexts_item;                  /* ContextAssertion */
static int hf_dop_classes;                        /* Refinement */
static int hf_dop_type;                           /* AttributeType */
static int hf_dop_maxCount;                       /* INTEGER */
static int hf_dop_valuesIn;                       /* AttributeType */
static int hf_dop_allUsers;                       /* NULL */
static int hf_dop_thisEntry;                      /* NULL */
static int hf_dop_name;                           /* SET_OF_NameAndOptionalUID */
static int hf_dop_name_item;                      /* NameAndOptionalUID */
static int hf_dop_userGroup;                      /* SET_OF_NameAndOptionalUID */
static int hf_dop_userGroup_item;                 /* NameAndOptionalUID */
static int hf_dop_subtree;                        /* SET_OF_SubtreeSpecification */
static int hf_dop_subtree_item;                   /* SubtreeSpecification */
static int hf_dop_grantsAndDenials;               /* GrantsAndDenials */
static int hf_dop_basicLevels;                    /* T_basicLevels */
static int hf_dop_level;                          /* T_level */
static int hf_dop_localQualifier;                 /* INTEGER */
static int hf_dop_signed;                         /* BOOLEAN */
static int hf_dop_other;                          /* EXTERNAL */
/* named bits */
static int hf_dop_DSEType_root;
static int hf_dop_DSEType_glue;
static int hf_dop_DSEType_cp;
static int hf_dop_DSEType_entry;
static int hf_dop_DSEType_alias;
static int hf_dop_DSEType_subr;
static int hf_dop_DSEType_nssr;
static int hf_dop_DSEType_supr;
static int hf_dop_DSEType_xr;
static int hf_dop_DSEType_admPoint;
static int hf_dop_DSEType_subentry;
static int hf_dop_DSEType_shadow;
static int hf_dop_DSEType_spare_bit12;
static int hf_dop_DSEType_immSupr;
static int hf_dop_DSEType_rhob;
static int hf_dop_DSEType_sa;
static int hf_dop_DSEType_dsSubentry;
static int hf_dop_DSEType_familyMember;
static int hf_dop_DSEType_ditBridge;
static int hf_dop_DSEType_writeableCopy;
static int hf_dop_GrantsAndDenials_grantAdd;
static int hf_dop_GrantsAndDenials_denyAdd;
static int hf_dop_GrantsAndDenials_grantDiscloseOnError;
static int hf_dop_GrantsAndDenials_denyDiscloseOnError;
static int hf_dop_GrantsAndDenials_grantRead;
static int hf_dop_GrantsAndDenials_denyRead;
static int hf_dop_GrantsAndDenials_grantRemove;
static int hf_dop_GrantsAndDenials_denyRemove;
static int hf_dop_GrantsAndDenials_grantBrowse;
static int hf_dop_GrantsAndDenials_denyBrowse;
static int hf_dop_GrantsAndDenials_grantExport;
static int hf_dop_GrantsAndDenials_denyExport;
static int hf_dop_GrantsAndDenials_grantImport;
static int hf_dop_GrantsAndDenials_denyImport;
static int hf_dop_GrantsAndDenials_grantModify;
static int hf_dop_GrantsAndDenials_denyModify;
static int hf_dop_GrantsAndDenials_grantRename;
static int hf_dop_GrantsAndDenials_denyRename;
static int hf_dop_GrantsAndDenials_grantReturnDN;
static int hf_dop_GrantsAndDenials_denyReturnDN;
static int hf_dop_GrantsAndDenials_grantCompare;
static int hf_dop_GrantsAndDenials_denyCompare;
static int hf_dop_GrantsAndDenials_grantFilterMatch;
static int hf_dop_GrantsAndDenials_denyFilterMatch;
static int hf_dop_GrantsAndDenials_grantInvoke;
static int hf_dop_GrantsAndDenials_denyInvoke;

/* Initialize the subtree pointers */
static int ett_dop;
static int ett_dop_unknown;
static int ett_dop_DSEType;
static int ett_dop_SupplierOrConsumer;
static int ett_dop_SET_OF_ProtocolInformation;
static int ett_dop_SupplierInformation;
static int ett_dop_SupplierAndConsumers;
static int ett_dop_SET_OF_AccessPoint;
static int ett_dop_EstablishOperationalBindingArgumentData;
static int ett_dop_EstablishArgumentInitiator;
static int ett_dop_EstablishOperationalBindingArgument;
static int ett_dop_T_signedEstablishOperationalBindingArgument;
static int ett_dop_OperationalBindingID;
static int ett_dop_Validity;
static int ett_dop_T_validFrom;
static int ett_dop_T_validUntil;
static int ett_dop_Time;
static int ett_dop_EstablishOperationalBindingResult;
static int ett_dop_T_initiator;
static int ett_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute;
static int ett_dop_ModifyOperationalBindingArgumentData;
static int ett_dop_ModifyArgumentInitiator;
static int ett_dop_ModifyOperationalBindingArgument;
static int ett_dop_T_signedModifyOperationalBindingArgument;
static int ett_dop_ModifyOperationalBindingResult;
static int ett_dop_ProtectedModifyResult;
static int ett_dop_ModifyOperationalBindingResultData;
static int ett_dop_TerminateOperationalBindingArgumentData;
static int ett_dop_TerminateArgumentInitiator;
static int ett_dop_TerminateOperationalBindingArgument;
static int ett_dop_T_signedTerminateOperationalBindingArgument;
static int ett_dop_TerminateOperationalBindingResult;
static int ett_dop_ProtectedTerminateResult;
static int ett_dop_TerminateOperationalBindingResultData;
static int ett_dop_OpBindingErrorParam;
static int ett_dop_HierarchicalAgreement;
static int ett_dop_SuperiorToSubordinate;
static int ett_dop_SET_OF_Attribute;
static int ett_dop_DITcontext;
static int ett_dop_Vertex;
static int ett_dop_SET_OF_SubentryInfo;
static int ett_dop_SubentryInfo;
static int ett_dop_SubordinateToSuperior;
static int ett_dop_SuperiorToSubordinateModification;
static int ett_dop_NonSpecificHierarchicalAgreement;
static int ett_dop_NHOBSuperiorToSubordinate;
static int ett_dop_NHOBSubordinateToSuperior;
static int ett_dop_ACIItem;
static int ett_dop_T_itemOrUserFirst;
static int ett_dop_T_itemFirst;
static int ett_dop_SET_OF_ItemPermission;
static int ett_dop_T_userFirst;
static int ett_dop_SET_OF_UserPermission;
static int ett_dop_ProtectedItems;
static int ett_dop_SET_OF_AttributeType;
static int ett_dop_SET_OF_AttributeTypeAndValue;
static int ett_dop_SET_OF_MaxValueCount;
static int ett_dop_SET_OF_RestrictedValue;
static int ett_dop_SET_OF_ContextAssertion;
static int ett_dop_MaxValueCount;
static int ett_dop_RestrictedValue;
static int ett_dop_UserClasses;
static int ett_dop_SET_OF_NameAndOptionalUID;
static int ett_dop_SET_OF_SubtreeSpecification;
static int ett_dop_ItemPermission;
static int ett_dop_UserPermission;
static int ett_dop_AuthenticationLevel;
static int ett_dop_T_basicLevels;
static int ett_dop_GrantsAndDenials;

static expert_field ei_dop_unknown_binding_parameter;
static expert_field ei_dop_unsupported_opcode;
static expert_field ei_dop_unsupported_errcode;
static expert_field ei_dop_unsupported_pdu;
static expert_field ei_dop_zero_pdu;

static dissector_handle_t dop_handle;

/* Dissector table */
static dissector_table_t dop_dissector_table;

static void append_oid(packet_info *pinfo, const char *oid)
{
  	const char *name = NULL;

    name = oid_resolved_from_string(pinfo->pool, oid);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name ? name : oid);
}


static int * const DSEType_bits[] = {
  &hf_dop_DSEType_root,
  &hf_dop_DSEType_glue,
  &hf_dop_DSEType_cp,
  &hf_dop_DSEType_entry,
  &hf_dop_DSEType_alias,
  &hf_dop_DSEType_subr,
  &hf_dop_DSEType_nssr,
  &hf_dop_DSEType_supr,
  &hf_dop_DSEType_xr,
  &hf_dop_DSEType_admPoint,
  &hf_dop_DSEType_subentry,
  &hf_dop_DSEType_shadow,
  &hf_dop_DSEType_spare_bit12,
  &hf_dop_DSEType_immSupr,
  &hf_dop_DSEType_rhob,
  &hf_dop_DSEType_sa,
  &hf_dop_DSEType_dsSubentry,
  &hf_dop_DSEType_familyMember,
  &hf_dop_DSEType_ditBridge,
  &hf_dop_DSEType_writeableCopy,
  NULL
};

int
dissect_dop_DSEType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    DSEType_bits, 20, hf_index, ett_dop_DSEType,
                                    NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ProtocolInformation_set_of[1] = {
  { &hf_dop_protocolInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_ProtocolInformation },
};

static int
dissect_dop_SET_OF_ProtocolInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ProtocolInformation_set_of, hf_index, ett_dop_SET_OF_ProtocolInformation);

  return offset;
}



static int
dissect_dop_T_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	uint32_t	value;

	  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &value);


	col_append_fstr(actx->pinfo->cinfo, COL_INFO, " id=%d", value);




  return offset;
}



static int
dissect_dop_T_version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	uint32_t	value;

	  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &value);


	col_append_fstr(actx->pinfo->cinfo, COL_INFO, ",%d", value);


  return offset;
}


static const ber_sequence_t OperationalBindingID_sequence[] = {
  { &hf_dop_identifier      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_dop_T_identifier },
  { &hf_dop_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_dop_T_version },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dop_OperationalBindingID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OperationalBindingID_sequence, hf_index, ett_dop_OperationalBindingID);

  return offset;
}


static const ber_sequence_t SupplierOrConsumer_set[] = {
  { &hf_dop_ae_title        , BER_CLASS_CON, 0, 0, dissect_x509if_Name },
  { &hf_dop_address         , BER_CLASS_CON, 1, 0, dissect_x509sat_PresentationAddress },
  { &hf_dop_protocolInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_ProtocolInformation },
  { &hf_dop_agreementID     , BER_CLASS_CON, 3, 0, dissect_dop_OperationalBindingID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_SupplierOrConsumer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SupplierOrConsumer_set, hf_index, ett_dop_SupplierOrConsumer);

  return offset;
}



static int
dissect_dop_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SupplierInformation_set[] = {
  { &hf_dop_ae_title        , BER_CLASS_CON, 0, 0, dissect_x509if_Name },
  { &hf_dop_address         , BER_CLASS_CON, 1, 0, dissect_x509sat_PresentationAddress },
  { &hf_dop_protocolInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_ProtocolInformation },
  { &hf_dop_agreementID     , BER_CLASS_CON, 3, 0, dissect_dop_OperationalBindingID },
  { &hf_dop_supplier_is_master, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dop_BOOLEAN },
  { &hf_dop_non_supplying_master, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_dsp_AccessPoint },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_SupplierInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SupplierInformation_set, hf_index, ett_dop_SupplierInformation);

  return offset;
}



static int
dissect_dop_ConsumerInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dop_SupplierOrConsumer(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_AccessPoint_set_of[1] = {
  { &hf_dop_consumers_item  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_AccessPoint },
};

static int
dissect_dop_SET_OF_AccessPoint(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AccessPoint_set_of, hf_index, ett_dop_SET_OF_AccessPoint);

  return offset;
}


static const ber_sequence_t SupplierAndConsumers_set[] = {
  { &hf_dop_ae_title        , BER_CLASS_CON, 0, 0, dissect_x509if_Name },
  { &hf_dop_address         , BER_CLASS_CON, 1, 0, dissect_x509sat_PresentationAddress },
  { &hf_dop_protocolInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_ProtocolInformation },
  { &hf_dop_consumers       , BER_CLASS_CON, 3, 0, dissect_dop_SET_OF_AccessPoint },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_dop_SupplierAndConsumers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SupplierAndConsumers_set, hf_index, ett_dop_SupplierAndConsumers);

  return offset;
}



static int
dissect_dop_DSAOperationalManagementBindArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dop_DSAOperationalManagementBindResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dop_DSAOperationalManagementBindError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dop_BindingType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &binding_type);

  append_oid(actx->pinfo, binding_type);
  return offset;
}



static int
dissect_dop_EstablishSymmetric(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("establish.symmetric", tvb, offset, actx->pinfo, tree, "symmetric", actx->private_data);


  return offset;
}



static int
dissect_dop_EstablishRoleAInitiates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("establish.rolea", tvb, offset, actx->pinfo, tree, "roleA", actx->private_data);


  return offset;
}



static int
dissect_dop_EstablishRoleBInitiates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("establish.roleb", tvb, offset, actx->pinfo, tree, "roleB", actx->private_data);


  return offset;
}


static const value_string dop_EstablishArgumentInitiator_vals[] = {
  {   3, "symmetric" },
  {   4, "roleA-initiates" },
  {   5, "roleB-initiates" },
  { 0, NULL }
};

static const ber_choice_t EstablishArgumentInitiator_choice[] = {
  {   3, &hf_dop_establishSymmetric, BER_CLASS_CON, 3, 0, dissect_dop_EstablishSymmetric },
  {   4, &hf_dop_establishRoleAInitiates, BER_CLASS_CON, 4, 0, dissect_dop_EstablishRoleAInitiates },
  {   5, &hf_dop_establishRoleBInitiates, BER_CLASS_CON, 5, 0, dissect_dop_EstablishRoleBInitiates },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_EstablishArgumentInitiator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EstablishArgumentInitiator_choice, hf_index, ett_dop_EstablishArgumentInitiator,
                                 NULL);

  return offset;
}



static int
dissect_dop_T_agreement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("agreement", tvb, offset, actx->pinfo, tree, NULL, actx->private_data);


  return offset;
}



static int
dissect_dop_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_dop_UTCTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index, NULL, NULL);

  return offset;
}



static int
dissect_dop_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string dop_Time_vals[] = {
  {   0, "utcTime" },
  {   1, "generalizedTime" },
  { 0, NULL }
};

static const ber_choice_t Time_choice[] = {
  {   0, &hf_dop_utcTime         , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_dop_UTCTime },
  {   1, &hf_dop_generalizedTime , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_dop_GeneralizedTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_Time(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Time_choice, hf_index, ett_dop_Time,
                                 NULL);

  return offset;
}


static const value_string dop_T_validFrom_vals[] = {
  {   0, "now" },
  {   1, "time" },
  { 0, NULL }
};

static const ber_choice_t T_validFrom_choice[] = {
  {   0, &hf_dop_now             , BER_CLASS_CON, 0, 0, dissect_dop_NULL },
  {   1, &hf_dop_time            , BER_CLASS_CON, 1, 0, dissect_dop_Time },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_validFrom(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_validFrom_choice, hf_index, ett_dop_T_validFrom,
                                 NULL);

  return offset;
}


static const value_string dop_T_validUntil_vals[] = {
  {   0, "explicitTermination" },
  {   1, "time" },
  { 0, NULL }
};

static const ber_choice_t T_validUntil_choice[] = {
  {   0, &hf_dop_explicitTermination, BER_CLASS_CON, 0, 0, dissect_dop_NULL },
  {   1, &hf_dop_time            , BER_CLASS_CON, 1, 0, dissect_dop_Time },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_validUntil(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_validUntil_choice, hf_index, ett_dop_T_validUntil,
                                 NULL);

  return offset;
}


static const ber_sequence_t Validity_sequence[] = {
  { &hf_dop_validFrom       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dop_T_validFrom },
  { &hf_dop_validUntil      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dop_T_validUntil },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_Validity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Validity_sequence, hf_index, ett_dop_Validity);

  return offset;
}


static const ber_sequence_t EstablishOperationalBindingArgumentData_sequence[] = {
  { &hf_dop_bindingType     , BER_CLASS_CON, 0, 0, dissect_dop_BindingType },
  { &hf_dop_bindingID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dop_OperationalBindingID },
  { &hf_dop_accessPoint     , BER_CLASS_CON, 2, 0, dissect_dsp_AccessPoint },
  { &hf_dop_establishInitiator, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dop_EstablishArgumentInitiator },
  { &hf_dop_agreement       , BER_CLASS_CON, 6, 0, dissect_dop_T_agreement },
  { &hf_dop_valid           , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_dop_Validity },
  { &hf_dop_securityParameters, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_EstablishOperationalBindingArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EstablishOperationalBindingArgumentData_sequence, hf_index, ett_dop_EstablishOperationalBindingArgumentData);

  return offset;
}



static int
dissect_dop_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t T_signedEstablishOperationalBindingArgument_sequence[] = {
  { &hf_dop_establishOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_EstablishOperationalBindingArgumentData },
  { &hf_dop_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dop_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dop_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_signedEstablishOperationalBindingArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedEstablishOperationalBindingArgument_sequence, hf_index, ett_dop_T_signedEstablishOperationalBindingArgument);

  return offset;
}


static const ber_choice_t EstablishOperationalBindingArgument_choice[] = {
  {   0, &hf_dop_unsignedEstablishOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_EstablishOperationalBindingArgumentData },
  {   1, &hf_dop_signedEstablishOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_T_signedEstablishOperationalBindingArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_EstablishOperationalBindingArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EstablishOperationalBindingArgument_choice, hf_index, ett_dop_EstablishOperationalBindingArgument,
                                 NULL);

  return offset;
}



static int
dissect_dop_T_symmetric(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("establish.symmetric", tvb, offset, actx->pinfo, tree, "symmetric", actx->private_data);


  return offset;
}



static int
dissect_dop_T_roleA_replies(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("establish.rolea", tvb, offset, actx->pinfo, tree, "roleA", actx->private_data);


  return offset;
}



static int
dissect_dop_T_roleB_replies(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("establish.roleb", tvb, offset, actx->pinfo, tree, "roleB", actx->private_data);


  return offset;
}


static const value_string dop_T_initiator_vals[] = {
  {   3, "symmetric" },
  {   4, "roleA-replies" },
  {   5, "roleB-replies" },
  { 0, NULL }
};

static const ber_choice_t T_initiator_choice[] = {
  {   3, &hf_dop_symmetric       , BER_CLASS_CON, 3, 0, dissect_dop_T_symmetric },
  {   4, &hf_dop_roleA_replies   , BER_CLASS_CON, 4, 0, dissect_dop_T_roleA_replies },
  {   5, &hf_dop_roleB_replies   , BER_CLASS_CON, 5, 0, dissect_dop_T_roleB_replies },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_initiator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_initiator_choice, hf_index, ett_dop_T_initiator,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_Attribute_sequence_of[1] = {
  { &hf_dop_notification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_Attribute_sequence_of, hf_index, ett_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute);

  return offset;
}


static const ber_sequence_t EstablishOperationalBindingResult_sequence[] = {
  { &hf_dop_bindingType     , BER_CLASS_CON, 0, 0, dissect_dop_BindingType },
  { &hf_dop_bindingID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dop_OperationalBindingID },
  { &hf_dop_accessPoint     , BER_CLASS_CON, 2, 0, dissect_dsp_AccessPoint },
  { &hf_dop_initiator       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dop_T_initiator },
  { &hf_dop_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dop_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dop_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dop_BOOLEAN },
  { &hf_dop_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_EstablishOperationalBindingResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EstablishOperationalBindingResult_sequence, hf_index, ett_dop_EstablishOperationalBindingResult);

  return offset;
}



static int
dissect_dop_ModifySymmetric(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("modify.symmetric", tvb, offset, actx->pinfo, tree, "symmetric", actx->private_data);


  return offset;
}



static int
dissect_dop_ModifyRoleAInitiates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("modify.rolea", tvb, offset, actx->pinfo, tree, "roleA", actx->private_data);


  return offset;
}



static int
dissect_dop_ModifyRoleBInitiates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("modify.roleb", tvb, offset, actx->pinfo, tree, "roleB", actx->private_data);


  return offset;
}


static const value_string dop_ModifyArgumentInitiator_vals[] = {
  {   3, "symmetric" },
  {   4, "roleA-initiates" },
  {   5, "roleB-initiates" },
  { 0, NULL }
};

static const ber_choice_t ModifyArgumentInitiator_choice[] = {
  {   3, &hf_dop_modifySymmetric , BER_CLASS_CON, 3, 0, dissect_dop_ModifySymmetric },
  {   4, &hf_dop_modifyRoleAInitiates, BER_CLASS_CON, 4, 0, dissect_dop_ModifyRoleAInitiates },
  {   5, &hf_dop_modifyRoleBInitiates, BER_CLASS_CON, 5, 0, dissect_dop_ModifyRoleBInitiates },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyArgumentInitiator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyArgumentInitiator_choice, hf_index, ett_dop_ModifyArgumentInitiator,
                                 NULL);

  return offset;
}



static int
dissect_dop_ArgumentNewAgreement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("agreement", tvb, offset, actx->pinfo, tree, NULL, actx->private_data);



  return offset;
}


static const ber_sequence_t ModifyOperationalBindingArgumentData_sequence[] = {
  { &hf_dop_bindingType     , BER_CLASS_CON, 0, 0, dissect_dop_BindingType },
  { &hf_dop_bindingID       , BER_CLASS_CON, 1, 0, dissect_dop_OperationalBindingID },
  { &hf_dop_accessPoint     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dsp_AccessPoint },
  { &hf_dop_modifyInitiator , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dop_ModifyArgumentInitiator },
  { &hf_dop_newBindingID    , BER_CLASS_CON, 6, 0, dissect_dop_OperationalBindingID },
  { &hf_dop_argumentNewAgreement, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_dop_ArgumentNewAgreement },
  { &hf_dop_valid           , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_dop_Validity },
  { &hf_dop_securityParameters, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyOperationalBindingArgumentData_sequence, hf_index, ett_dop_ModifyOperationalBindingArgumentData);

  return offset;
}


static const ber_sequence_t T_signedModifyOperationalBindingArgument_sequence[] = {
  { &hf_dop_modifyOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_ModifyOperationalBindingArgumentData },
  { &hf_dop_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dop_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dop_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_signedModifyOperationalBindingArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedModifyOperationalBindingArgument_sequence, hf_index, ett_dop_T_signedModifyOperationalBindingArgument);

  return offset;
}


static const ber_choice_t ModifyOperationalBindingArgument_choice[] = {
  {   0, &hf_dop_unsignedModifyOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_ModifyOperationalBindingArgumentData },
  {   1, &hf_dop_signedModifyOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_T_signedModifyOperationalBindingArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyOperationalBindingArgument_choice, hf_index, ett_dop_ModifyOperationalBindingArgument,
                                 NULL);

  return offset;
}



static int
dissect_dop_ResultNewAgreement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("agreement", tvb, offset, actx->pinfo, tree, NULL, actx->private_data);


  return offset;
}


static const ber_sequence_t ModifyOperationalBindingResultData_sequence[] = {
  { &hf_dop_newBindingID    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_OperationalBindingID },
  { &hf_dop_bindingType     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dop_BindingType },
  { &hf_dop_resultNewAgreement, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_dop_ResultNewAgreement },
  { &hf_dop_valid           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dop_Validity },
  { &hf_dop_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dop_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dop_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dop_BOOLEAN },
  { &hf_dop_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModifyOperationalBindingResultData_sequence, hf_index, ett_dop_ModifyOperationalBindingResultData);

  return offset;
}


static const ber_sequence_t ProtectedModifyResult_sequence[] = {
  { &hf_dop_modifyOperationalBindingResultData, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_ModifyOperationalBindingResultData },
  { &hf_dop_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dop_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dop_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ProtectedModifyResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtectedModifyResult_sequence, hf_index, ett_dop_ProtectedModifyResult);

  return offset;
}


static const ber_choice_t ModifyOperationalBindingResult_choice[] = {
  {   0, &hf_dop_null            , BER_CLASS_CON, 0, 0, dissect_dop_NULL },
  {   1, &hf_dop_protectedModifyResult, BER_CLASS_CON, 1, 0, dissect_dop_ProtectedModifyResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyOperationalBindingResult_choice, hf_index, ett_dop_ModifyOperationalBindingResult,
                                 NULL);

  return offset;
}



static int
dissect_dop_TerminateSymmetric(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("terminate.symmetric", tvb, offset, actx->pinfo, tree, "symmetric", actx->private_data);


  return offset;
}



static int
dissect_dop_TerminateRoleAInitiates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("terminate.rolea", tvb, offset, actx->pinfo, tree, "roleA", actx->private_data);


  return offset;
}



static int
dissect_dop_TerminateRoleBInitiates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("terminate.roleb", tvb, offset, actx->pinfo, tree, "roleB", actx->private_data);


  return offset;
}


static const value_string dop_TerminateArgumentInitiator_vals[] = {
  {   2, "symmetric" },
  {   3, "roleA-initiates" },
  {   4, "roleB-initiates" },
  { 0, NULL }
};

static const ber_choice_t TerminateArgumentInitiator_choice[] = {
  {   2, &hf_dop_terminateSymmetric, BER_CLASS_CON, 2, 0, dissect_dop_TerminateSymmetric },
  {   3, &hf_dop_terminateRoleAInitiates, BER_CLASS_CON, 3, 0, dissect_dop_TerminateRoleAInitiates },
  {   4, &hf_dop_terminateRoleBInitiates, BER_CLASS_CON, 4, 0, dissect_dop_TerminateRoleBInitiates },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateArgumentInitiator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TerminateArgumentInitiator_choice, hf_index, ett_dop_TerminateArgumentInitiator,
                                 NULL);

  return offset;
}


static const ber_sequence_t TerminateOperationalBindingArgumentData_sequence[] = {
  { &hf_dop_bindingType     , BER_CLASS_CON, 0, 0, dissect_dop_BindingType },
  { &hf_dop_bindingID       , BER_CLASS_CON, 1, 0, dissect_dop_OperationalBindingID },
  { &hf_dop_terminateInitiator, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dop_TerminateArgumentInitiator },
  { &hf_dop_terminateAtTime , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dop_Time },
  { &hf_dop_securityParameters, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingArgumentData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminateOperationalBindingArgumentData_sequence, hf_index, ett_dop_TerminateOperationalBindingArgumentData);

  return offset;
}


static const ber_sequence_t T_signedTerminateOperationalBindingArgument_sequence[] = {
  { &hf_dop_terminateOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_TerminateOperationalBindingArgumentData },
  { &hf_dop_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dop_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dop_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_signedTerminateOperationalBindingArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedTerminateOperationalBindingArgument_sequence, hf_index, ett_dop_T_signedTerminateOperationalBindingArgument);

  return offset;
}


static const ber_choice_t TerminateOperationalBindingArgument_choice[] = {
  {   0, &hf_dop_unsignedTerminateOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_TerminateOperationalBindingArgumentData },
  {   1, &hf_dop_signedTerminateOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_T_signedTerminateOperationalBindingArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TerminateOperationalBindingArgument_choice, hf_index, ett_dop_TerminateOperationalBindingArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t TerminateOperationalBindingResultData_sequence[] = {
  { &hf_dop_bindingID       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_OperationalBindingID },
  { &hf_dop_bindingType     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_dop_BindingType },
  { &hf_dop_terminateAtGeneralizedTime, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dop_GeneralizedTime },
  { &hf_dop_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dop_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dop_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dop_BOOLEAN },
  { &hf_dop_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminateOperationalBindingResultData_sequence, hf_index, ett_dop_TerminateOperationalBindingResultData);

  return offset;
}


static const ber_sequence_t ProtectedTerminateResult_sequence[] = {
  { &hf_dop_terminateOperationalBindingResultData, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_TerminateOperationalBindingResultData },
  { &hf_dop_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_dop_encrypted       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dop_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ProtectedTerminateResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtectedTerminateResult_sequence, hf_index, ett_dop_ProtectedTerminateResult);

  return offset;
}


static const ber_choice_t TerminateOperationalBindingResult_choice[] = {
  {   0, &hf_dop_null            , BER_CLASS_CON, 0, 0, dissect_dop_NULL },
  {   1, &hf_dop_protectedTerminateResult, BER_CLASS_CON, 1, 0, dissect_dop_ProtectedTerminateResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TerminateOperationalBindingResult_choice, hf_index, ett_dop_TerminateOperationalBindingResult,
                                 NULL);

  return offset;
}


static const value_string dop_T_problem_vals[] = {
  {   0, "invalidID" },
  {   1, "duplicateID" },
  {   2, "unsupportedBindingType" },
  {   3, "notAllowedForRole" },
  {   4, "parametersMissing" },
  {   5, "roleAssignment" },
  {   6, "invalidStartTime" },
  {   7, "invalidEndTime" },
  {   8, "invalidAgreement" },
  {   9, "currentlyNotDecidable" },
  {  10, "modificationNotAllowed" },
  { 0, NULL }
};


static int
dissect_dop_T_problem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dop_T_agreementProposal(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = call_dop_oid_callback("agreement", tvb, offset, actx->pinfo, tree, NULL, actx->private_data);


  return offset;
}


static const ber_sequence_t OpBindingErrorParam_sequence[] = {
  { &hf_dop_problem         , BER_CLASS_CON, 0, 0, dissect_dop_T_problem },
  { &hf_dop_bindingType     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dop_BindingType },
  { &hf_dop_agreementProposal, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_T_agreementProposal },
  { &hf_dop_retryAt         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_dop_Time },
  { &hf_dop_securityParameters, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_dap_SecurityParameters },
  { &hf_dop_performer       , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_x509if_DistinguishedName },
  { &hf_dop_aliasDereferenced, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_dop_BOOLEAN },
  { &hf_dop_notification    , BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_OpBindingErrorParam(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OpBindingErrorParam_sequence, hf_index, ett_dop_OpBindingErrorParam);

  return offset;
}


static const ber_sequence_t HierarchicalAgreement_sequence[] = {
  { &hf_dop_rdn             , BER_CLASS_CON, 0, 0, dissect_x509if_RelativeDistinguishedName },
  { &hf_dop_immediateSuperior, BER_CLASS_CON, 1, 0, dissect_x509if_DistinguishedName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_HierarchicalAgreement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HierarchicalAgreement_sequence, hf_index, ett_dop_HierarchicalAgreement);

  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { &hf_dop_entryInfo_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dop_SET_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Attribute_set_of, hf_index, ett_dop_SET_OF_Attribute);

  return offset;
}


static const ber_sequence_t SubentryInfo_sequence[] = {
  { &hf_dop_rdn             , BER_CLASS_CON, 0, 0, dissect_x509if_RelativeDistinguishedName },
  { &hf_dop_info            , BER_CLASS_CON, 1, 0, dissect_dop_SET_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_SubentryInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubentryInfo_sequence, hf_index, ett_dop_SubentryInfo);

  return offset;
}


static const ber_sequence_t SET_OF_SubentryInfo_set_of[1] = {
  { &hf_dop_subentries_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_SubentryInfo },
};

static int
dissect_dop_SET_OF_SubentryInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_SubentryInfo_set_of, hf_index, ett_dop_SET_OF_SubentryInfo);

  return offset;
}


static const ber_sequence_t Vertex_sequence[] = {
  { &hf_dop_rdn             , BER_CLASS_CON, 0, 0, dissect_x509if_RelativeDistinguishedName },
  { &hf_dop_admPointInfo    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_Attribute },
  { &hf_dop_subentries      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_SubentryInfo },
  { &hf_dop_accessPoints    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dsp_MasterAndShadowAccessPoints },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_Vertex(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Vertex_sequence, hf_index, ett_dop_Vertex);

  return offset;
}


static const ber_sequence_t DITcontext_sequence_of[1] = {
  { &hf_dop_DITcontext_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_Vertex },
};

static int
dissect_dop_DITcontext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      DITcontext_sequence_of, hf_index, ett_dop_DITcontext);

  return offset;
}


static const ber_sequence_t SuperiorToSubordinate_sequence[] = {
  { &hf_dop_contextPrefixInfo, BER_CLASS_CON, 0, 0, dissect_dop_DITcontext },
  { &hf_dop_entryInfo       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_Attribute },
  { &hf_dop_immediateSuperiorInfo, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_SuperiorToSubordinate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SuperiorToSubordinate_sequence, hf_index, ett_dop_SuperiorToSubordinate);

  return offset;
}


static const ber_sequence_t SubordinateToSuperior_sequence[] = {
  { &hf_dop_accessPoints    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dsp_MasterAndShadowAccessPoints },
  { &hf_dop_alias           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dop_BOOLEAN },
  { &hf_dop_entryInfo       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_Attribute },
  { &hf_dop_subentries      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_SubentryInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_SubordinateToSuperior(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubordinateToSuperior_sequence, hf_index, ett_dop_SubordinateToSuperior);

  return offset;
}


static const ber_sequence_t SuperiorToSubordinateModification_sequence[] = {
  { &hf_dop_contextPrefixInfo, BER_CLASS_CON, 0, 0, dissect_dop_DITcontext },
  { &hf_dop_immediateSuperiorInfo, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_SuperiorToSubordinateModification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SuperiorToSubordinateModification_sequence, hf_index, ett_dop_SuperiorToSubordinateModification);

  return offset;
}


static const ber_sequence_t NonSpecificHierarchicalAgreement_sequence[] = {
  { &hf_dop_immediateSuperior, BER_CLASS_CON, 1, 0, dissect_x509if_DistinguishedName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_NonSpecificHierarchicalAgreement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NonSpecificHierarchicalAgreement_sequence, hf_index, ett_dop_NonSpecificHierarchicalAgreement);

  return offset;
}


static const ber_sequence_t NHOBSuperiorToSubordinate_sequence[] = {
  { &hf_dop_contextPrefixInfo, BER_CLASS_CON, 0, 0, dissect_dop_DITcontext },
  { &hf_dop_immediateSuperiorInfo, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_NHOBSuperiorToSubordinate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NHOBSuperiorToSubordinate_sequence, hf_index, ett_dop_NHOBSuperiorToSubordinate);

  return offset;
}


static const ber_sequence_t NHOBSubordinateToSuperior_sequence[] = {
  { &hf_dop_accessPoints    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dsp_MasterAndShadowAccessPoints },
  { &hf_dop_subentries      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_SubentryInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_NHOBSubordinateToSuperior(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NHOBSubordinateToSuperior_sequence, hf_index, ett_dop_NHOBSubordinateToSuperior);

  return offset;
}



static int
dissect_dop_Precedence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t precedence = 0;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &precedence);


  proto_item_append_text(tree, " precedence=%d", precedence);


  return offset;
}


static const value_string dop_T_level_vals[] = {
  {   0, "none" },
  {   1, "simple" },
  {   2, "strong" },
  { 0, NULL }
};


static int
dissect_dop_T_level(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dop_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_basicLevels_sequence[] = {
  { &hf_dop_level           , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_dop_T_level },
  { &hf_dop_localQualifier  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dop_INTEGER },
  { &hf_dop_signed          , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dop_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_basicLevels(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_basicLevels_sequence, hf_index, ett_dop_T_basicLevels);

  return offset;
}



static int
dissect_dop_EXTERNAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const value_string dop_AuthenticationLevel_vals[] = {
  {   0, "basicLevels" },
  {   1, "other" },
  { 0, NULL }
};

static const ber_choice_t AuthenticationLevel_choice[] = {
  {   0, &hf_dop_basicLevels     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_T_basicLevels },
  {   1, &hf_dop_other           , BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_dop_EXTERNAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_AuthenticationLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticationLevel_choice, hf_index, ett_dop_AuthenticationLevel,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeType_set_of[1] = {
  { &hf_dop_attributeType_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_dop_SET_OF_AttributeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AttributeType_set_of, hf_index, ett_dop_SET_OF_AttributeType);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeTypeAndValue_set_of[1] = {
  { &hf_dop_attributeValue_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_AttributeTypeAndValue },
};

static int
dissect_dop_SET_OF_AttributeTypeAndValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AttributeTypeAndValue_set_of, hf_index, ett_dop_SET_OF_AttributeTypeAndValue);

  return offset;
}


static const ber_sequence_t MaxValueCount_sequence[] = {
  { &hf_dop_type            , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  { &hf_dop_maxCount        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_dop_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_MaxValueCount(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MaxValueCount_sequence, hf_index, ett_dop_MaxValueCount);

  return offset;
}


static const ber_sequence_t SET_OF_MaxValueCount_set_of[1] = {
  { &hf_dop_maxValueCount_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_MaxValueCount },
};

static int
dissect_dop_SET_OF_MaxValueCount(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_MaxValueCount_set_of, hf_index, ett_dop_SET_OF_MaxValueCount);

  return offset;
}


static const ber_sequence_t RestrictedValue_sequence[] = {
  { &hf_dop_type            , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  { &hf_dop_valuesIn        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_RestrictedValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RestrictedValue_sequence, hf_index, ett_dop_RestrictedValue);

  return offset;
}


static const ber_sequence_t SET_OF_RestrictedValue_set_of[1] = {
  { &hf_dop_restrictedBy_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_RestrictedValue },
};

static int
dissect_dop_SET_OF_RestrictedValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_RestrictedValue_set_of, hf_index, ett_dop_SET_OF_RestrictedValue);

  return offset;
}


static const ber_sequence_t SET_OF_ContextAssertion_set_of[1] = {
  { &hf_dop_contexts_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_dop_SET_OF_ContextAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ContextAssertion_set_of, hf_index, ett_dop_SET_OF_ContextAssertion);

  return offset;
}


static const ber_sequence_t ProtectedItems_sequence[] = {
  { &hf_dop_entry           , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dop_NULL },
  { &hf_dop_allUserAttributeTypes, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dop_NULL },
  { &hf_dop_attributeType   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_AttributeType },
  { &hf_dop_allAttributeValues, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_AttributeType },
  { &hf_dop_allUserAttributeTypesAndValues, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dop_NULL },
  { &hf_dop_attributeValue  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_AttributeTypeAndValue },
  { &hf_dop_selfValue       , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_AttributeType },
  { &hf_dop_rangeOfValues   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_dap_Filter },
  { &hf_dop_maxValueCount   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_MaxValueCount },
  { &hf_dop_maxImmSub       , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_dop_INTEGER },
  { &hf_dop_restrictedBy    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_RestrictedValue },
  { &hf_dop_contexts        , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_ContextAssertion },
  { &hf_dop_classes         , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_x509if_Refinement },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ProtectedItems(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtectedItems_sequence, hf_index, ett_dop_ProtectedItems);

  return offset;
}


static const ber_sequence_t SET_OF_NameAndOptionalUID_set_of[1] = {
  { &hf_dop_name_item       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_NameAndOptionalUID },
};

static int
dissect_dop_SET_OF_NameAndOptionalUID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_NameAndOptionalUID_set_of, hf_index, ett_dop_SET_OF_NameAndOptionalUID);

  return offset;
}


static const ber_sequence_t SET_OF_SubtreeSpecification_set_of[1] = {
  { &hf_dop_subtree_item    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_SubtreeSpecification },
};

static int
dissect_dop_SET_OF_SubtreeSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_SubtreeSpecification_set_of, hf_index, ett_dop_SET_OF_SubtreeSpecification);

  return offset;
}


static const ber_sequence_t UserClasses_sequence[] = {
  { &hf_dop_allUsers        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_dop_NULL },
  { &hf_dop_thisEntry       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_dop_NULL },
  { &hf_dop_name            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_NameAndOptionalUID },
  { &hf_dop_userGroup       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_NameAndOptionalUID },
  { &hf_dop_subtree         , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_dop_SET_OF_SubtreeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_UserClasses(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserClasses_sequence, hf_index, ett_dop_UserClasses);

  return offset;
}


static int * const GrantsAndDenials_bits[] = {
  &hf_dop_GrantsAndDenials_grantAdd,
  &hf_dop_GrantsAndDenials_denyAdd,
  &hf_dop_GrantsAndDenials_grantDiscloseOnError,
  &hf_dop_GrantsAndDenials_denyDiscloseOnError,
  &hf_dop_GrantsAndDenials_grantRead,
  &hf_dop_GrantsAndDenials_denyRead,
  &hf_dop_GrantsAndDenials_grantRemove,
  &hf_dop_GrantsAndDenials_denyRemove,
  &hf_dop_GrantsAndDenials_grantBrowse,
  &hf_dop_GrantsAndDenials_denyBrowse,
  &hf_dop_GrantsAndDenials_grantExport,
  &hf_dop_GrantsAndDenials_denyExport,
  &hf_dop_GrantsAndDenials_grantImport,
  &hf_dop_GrantsAndDenials_denyImport,
  &hf_dop_GrantsAndDenials_grantModify,
  &hf_dop_GrantsAndDenials_denyModify,
  &hf_dop_GrantsAndDenials_grantRename,
  &hf_dop_GrantsAndDenials_denyRename,
  &hf_dop_GrantsAndDenials_grantReturnDN,
  &hf_dop_GrantsAndDenials_denyReturnDN,
  &hf_dop_GrantsAndDenials_grantCompare,
  &hf_dop_GrantsAndDenials_denyCompare,
  &hf_dop_GrantsAndDenials_grantFilterMatch,
  &hf_dop_GrantsAndDenials_denyFilterMatch,
  &hf_dop_GrantsAndDenials_grantInvoke,
  &hf_dop_GrantsAndDenials_denyInvoke,
  NULL
};

static int
dissect_dop_GrantsAndDenials(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    GrantsAndDenials_bits, 26, hf_index, ett_dop_GrantsAndDenials,
                                    NULL);

  return offset;
}


static const ber_sequence_t ItemPermission_sequence[] = {
  { &hf_dop_precedence      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dop_Precedence },
  { &hf_dop_userClasses     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_UserClasses },
  { &hf_dop_grantsAndDenials, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dop_GrantsAndDenials },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ItemPermission(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ItemPermission_sequence, hf_index, ett_dop_ItemPermission);

  return offset;
}


static const ber_sequence_t SET_OF_ItemPermission_set_of[1] = {
  { &hf_dop_itemPermissions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_ItemPermission },
};

static int
dissect_dop_SET_OF_ItemPermission(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ItemPermission_set_of, hf_index, ett_dop_SET_OF_ItemPermission);

  return offset;
}


static const ber_sequence_t T_itemFirst_sequence[] = {
  { &hf_dop_protectedItems  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_ProtectedItems },
  { &hf_dop_itemPermissions , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dop_SET_OF_ItemPermission },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_itemFirst(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_itemFirst_sequence, hf_index, ett_dop_T_itemFirst);

  return offset;
}


static const ber_sequence_t UserPermission_sequence[] = {
  { &hf_dop_precedence      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_dop_Precedence },
  { &hf_dop_protectedItems  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_ProtectedItems },
  { &hf_dop_grantsAndDenials, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_dop_GrantsAndDenials },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_UserPermission(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserPermission_sequence, hf_index, ett_dop_UserPermission);

  return offset;
}


static const ber_sequence_t SET_OF_UserPermission_set_of[1] = {
  { &hf_dop_userPermissions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_UserPermission },
};

static int
dissect_dop_SET_OF_UserPermission(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_UserPermission_set_of, hf_index, ett_dop_SET_OF_UserPermission);

  return offset;
}


static const ber_sequence_t T_userFirst_sequence[] = {
  { &hf_dop_userClasses     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_UserClasses },
  { &hf_dop_userPermissions , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dop_SET_OF_UserPermission },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_userFirst(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_userFirst_sequence, hf_index, ett_dop_T_userFirst);

  return offset;
}


static const value_string dop_T_itemOrUserFirst_vals[] = {
  {   0, "itemFirst" },
  {   1, "userFirst" },
  { 0, NULL }
};

static const ber_choice_t T_itemOrUserFirst_choice[] = {
  {   0, &hf_dop_itemFirst       , BER_CLASS_CON, 0, 0, dissect_dop_T_itemFirst },
  {   1, &hf_dop_userFirst       , BER_CLASS_CON, 1, 0, dissect_dop_T_userFirst },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_T_itemOrUserFirst(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_itemOrUserFirst_choice, hf_index, ett_dop_T_itemOrUserFirst,
                                 NULL);

  return offset;
}


static const ber_sequence_t ACIItem_sequence[] = {
  { &hf_dop_identificationTag, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509sat_DirectoryString },
  { &hf_dop_precedence      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_dop_Precedence },
  { &hf_dop_authenticationLevel, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dop_AuthenticationLevel },
  { &hf_dop_itemOrUserFirst , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_dop_T_itemOrUserFirst },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ACIItem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ACIItem_sequence, hf_index, ett_dop_ACIItem);

  return offset;
}

/*--- PDUs ---*/

static int dissect_DSEType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_DSEType(false, tvb, offset, &asn1_ctx, tree, hf_dop_DSEType_PDU);
  return offset;
}
static int dissect_SupplierInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_SupplierInformation(false, tvb, offset, &asn1_ctx, tree, hf_dop_SupplierInformation_PDU);
  return offset;
}
static int dissect_ConsumerInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_ConsumerInformation(false, tvb, offset, &asn1_ctx, tree, hf_dop_ConsumerInformation_PDU);
  return offset;
}
static int dissect_SupplierAndConsumers_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_SupplierAndConsumers(false, tvb, offset, &asn1_ctx, tree, hf_dop_SupplierAndConsumers_PDU);
  return offset;
}
static int dissect_HierarchicalAgreement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_HierarchicalAgreement(false, tvb, offset, &asn1_ctx, tree, hf_dop_HierarchicalAgreement_PDU);
  return offset;
}
static int dissect_SuperiorToSubordinate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_SuperiorToSubordinate(false, tvb, offset, &asn1_ctx, tree, hf_dop_SuperiorToSubordinate_PDU);
  return offset;
}
static int dissect_SubordinateToSuperior_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_SubordinateToSuperior(false, tvb, offset, &asn1_ctx, tree, hf_dop_SubordinateToSuperior_PDU);
  return offset;
}
static int dissect_SuperiorToSubordinateModification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_SuperiorToSubordinateModification(false, tvb, offset, &asn1_ctx, tree, hf_dop_SuperiorToSubordinateModification_PDU);
  return offset;
}
static int dissect_NonSpecificHierarchicalAgreement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_NonSpecificHierarchicalAgreement(false, tvb, offset, &asn1_ctx, tree, hf_dop_NonSpecificHierarchicalAgreement_PDU);
  return offset;
}
static int dissect_NHOBSuperiorToSubordinate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_NHOBSuperiorToSubordinate(false, tvb, offset, &asn1_ctx, tree, hf_dop_NHOBSuperiorToSubordinate_PDU);
  return offset;
}
static int dissect_NHOBSubordinateToSuperior_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_NHOBSubordinateToSuperior(false, tvb, offset, &asn1_ctx, tree, hf_dop_NHOBSubordinateToSuperior_PDU);
  return offset;
}
static int dissect_ACIItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_dop_ACIItem(false, tvb, offset, &asn1_ctx, tree, hf_dop_ACIItem_PDU);
  return offset;
}


static int
call_dop_oid_callback(const char *base_string, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, const char *col_info, void* data)
{
  char* binding_param;

  binding_param = wmem_strdup_printf(pinfo->pool, "%s.%s", base_string, binding_type ? binding_type : "");

  col_append_fstr(pinfo->cinfo, COL_INFO, " %s", col_info);

  if (dissector_try_string(dop_dissector_table, binding_param, tvb, pinfo, tree, data)) {
     offset = tvb_reported_length (tvb);
  } else {
     proto_item *item;
     proto_tree *next_tree;

     next_tree = proto_tree_add_subtree_format(tree, tvb, 0, -1, ett_dop_unknown, &item,
         "Dissector for parameter %s OID:%s not implemented. Contact Wireshark developers if you want this supported", base_string, binding_type ? binding_type : "<empty>");

     offset = dissect_unknown_ber(pinfo, tvb, offset, next_tree);
     expert_add_info(pinfo, item, &ei_dop_unknown_binding_parameter);
   }

   return offset;
}


/*
* Dissect DOP PDUs inside a ROS PDUs
*/
static int
dissect_dop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	int offset = 0;
	int old_offset;
	proto_item *item;
	proto_tree *tree;
	struct SESSION_DATA_STRUCTURE* session;
	int (*dop_dissector)(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	const char *dop_op_name;
	asn1_ctx_t asn1_ctx;

	/* do we have operation information from the ROS dissector? */
	if (data == NULL)
		return 0;
	session = (struct SESSION_DATA_STRUCTURE*)data;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	item = proto_tree_add_item(parent_tree, proto_dop, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_dop);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DOP");
  	col_clear(pinfo->cinfo, COL_INFO);

	asn1_ctx.private_data = session;

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  dop_dissector = dissect_dop_DSAOperationalManagementBindArgument;
	  dop_op_name = "DSA-Operational-Bind-Argument";
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  dop_dissector = dissect_dop_DSAOperationalManagementBindResult;
	  dop_op_name = "DSA-Operational-Bind-Result";
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  dop_dissector = dissect_dop_DSAOperationalManagementBindError;
	  dop_op_name = "DSA-Operational-Management-Bind-Error";
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 100: /* establish */
	    dop_dissector = dissect_dop_EstablishOperationalBindingArgument;
	    dop_op_name = "Establish-Operational-Binding-Argument";
	    break;
	  case 101: /* terminate */
	    dop_dissector = dissect_dop_TerminateOperationalBindingArgument;
	    dop_op_name = "Terminate-Operational-Binding-Argument";
	    break;
	  case 102: /* modify */
	    dop_dissector = dissect_dop_ModifyOperationalBindingArgument;
	    dop_op_name = "Modify-Operational-Binding-Argument";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_dop_unsupported_opcode, tvb, offset, -1,
	        "Unsupported DOP Argument opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 100: /* establish */
	    dop_dissector = dissect_dop_EstablishOperationalBindingResult;
	    dop_op_name = "Establish-Operational-Binding-Result";
	    break;
	  case 101: /* terminate */
	    dop_dissector = dissect_dop_TerminateOperationalBindingResult;
	    dop_op_name = "Terminate-Operational-Binding-Result";
	    break;
	  case 102: /* modify */
	    dop_dissector = dissect_dop_ModifyOperationalBindingResult;
	    dop_op_name = "Modify-Operational-Binding-Result";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_dop_unsupported_opcode, tvb, offset, -1,
	            "Unsupported DOP Result opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 100: /* operational-binding */
	    dop_dissector = dissect_dop_OpBindingErrorParam;
	    dop_op_name = "Operational-Binding-Error";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_dop_unsupported_errcode, tvb, offset, -1,
	        "Unsupported DOP Error opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	default:
	  proto_tree_add_expert(tree, pinfo, &ei_dop_unsupported_pdu, tvb, offset, -1);
	  return tvb_captured_length(tvb);
	}

	if(dop_dissector) {
      col_set_str(pinfo->cinfo, COL_INFO, dop_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dop_dissector)(false, tvb, offset, &asn1_ctx, tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_expert(tree, pinfo, &ei_dop_zero_pdu, tvb, offset, -1);
	      break;
	    }
	  }
	}

	return tvb_captured_length(tvb);
}



/*--- proto_register_dop -------------------------------------------*/
void proto_register_dop(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    { &hf_dop_DSEType_PDU,
      { "DSEType", "dop.DSEType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SupplierInformation_PDU,
      { "SupplierInformation", "dop.SupplierInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_ConsumerInformation_PDU,
      { "ConsumerInformation", "dop.ConsumerInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SupplierAndConsumers_PDU,
      { "SupplierAndConsumers", "dop.SupplierAndConsumers_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_HierarchicalAgreement_PDU,
      { "HierarchicalAgreement", "dop.HierarchicalAgreement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SuperiorToSubordinate_PDU,
      { "SuperiorToSubordinate", "dop.SuperiorToSubordinate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SubordinateToSuperior_PDU,
      { "SubordinateToSuperior", "dop.SubordinateToSuperior_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SuperiorToSubordinateModification_PDU,
      { "SuperiorToSubordinateModification", "dop.SuperiorToSubordinateModification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_NonSpecificHierarchicalAgreement_PDU,
      { "NonSpecificHierarchicalAgreement", "dop.NonSpecificHierarchicalAgreement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_NHOBSuperiorToSubordinate_PDU,
      { "NHOBSuperiorToSubordinate", "dop.NHOBSuperiorToSubordinate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_NHOBSubordinateToSuperior_PDU,
      { "NHOBSubordinateToSuperior", "dop.NHOBSubordinateToSuperior_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_ACIItem_PDU,
      { "ACIItem", "dop.ACIItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_ae_title,
      { "ae-title", "dop.ae_title",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dop_address,
      { "address", "dop.address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentationAddress", HFILL }},
    { &hf_dop_protocolInformation,
      { "protocolInformation", "dop.protocolInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ProtocolInformation", HFILL }},
    { &hf_dop_protocolInformation_item,
      { "ProtocolInformation", "dop.ProtocolInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_agreementID,
      { "agreementID", "dop.agreementID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OperationalBindingID", HFILL }},
    { &hf_dop_supplier_is_master,
      { "supplier-is-master", "dop.supplier_is_master",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dop_non_supplying_master,
      { "non-supplying-master", "dop.non_supplying_master_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessPoint", HFILL }},
    { &hf_dop_consumers,
      { "consumers", "dop.consumers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AccessPoint", HFILL }},
    { &hf_dop_consumers_item,
      { "AccessPoint", "dop.AccessPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_bindingType,
      { "bindingType", "dop.bindingType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_bindingID,
      { "bindingID", "dop.bindingID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OperationalBindingID", HFILL }},
    { &hf_dop_accessPoint,
      { "accessPoint", "dop.accessPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_establishInitiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_EstablishArgumentInitiator_vals), 0,
        "EstablishArgumentInitiator", HFILL }},
    { &hf_dop_establishSymmetric,
      { "symmetric", "dop.symmetric_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishSymmetric", HFILL }},
    { &hf_dop_establishRoleAInitiates,
      { "roleA-initiates", "dop.roleA_initiates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishRoleAInitiates", HFILL }},
    { &hf_dop_establishRoleBInitiates,
      { "roleB-initiates", "dop.roleB_initiates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishRoleBInitiates", HFILL }},
    { &hf_dop_agreement,
      { "agreement", "dop.agreement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_valid,
      { "valid", "dop.valid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Validity", HFILL }},
    { &hf_dop_securityParameters,
      { "securityParameters", "dop.securityParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_unsignedEstablishOperationalBindingArgument,
      { "unsignedEstablishOperationalBindingArgument", "dop.unsignedEstablishOperationalBindingArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgumentData", HFILL }},
    { &hf_dop_signedEstablishOperationalBindingArgument,
      { "signedEstablishOperationalBindingArgument", "dop.signedEstablishOperationalBindingArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_establishOperationalBindingArgument,
      { "establishOperationalBindingArgument", "dop.establishOperationalBindingArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgumentData", HFILL }},
    { &hf_dop_algorithmIdentifier,
      { "algorithmIdentifier", "dop.algorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_encrypted,
      { "encrypted", "dop.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_dop_identifier,
      { "identifier", "dop.identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_version,
      { "version", "dop.version",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_validFrom,
      { "validFrom", "dop.validFrom",
        FT_UINT32, BASE_DEC, VALS(dop_T_validFrom_vals), 0,
        NULL, HFILL }},
    { &hf_dop_now,
      { "now", "dop.now_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_time,
      { "time", "dop.time",
        FT_UINT32, BASE_DEC, VALS(dop_Time_vals), 0,
        NULL, HFILL }},
    { &hf_dop_validUntil,
      { "validUntil", "dop.validUntil",
        FT_UINT32, BASE_DEC, VALS(dop_T_validUntil_vals), 0,
        NULL, HFILL }},
    { &hf_dop_explicitTermination,
      { "explicitTermination", "dop.explicitTermination_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_utcTime,
      { "utcTime", "dop.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_generalizedTime,
      { "generalizedTime", "dop.generalizedTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_initiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_T_initiator_vals), 0,
        NULL, HFILL }},
    { &hf_dop_symmetric,
      { "symmetric", "dop.symmetric_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_roleA_replies,
      { "roleA-replies", "dop.roleA_replies_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_roleB_replies,
      { "roleB-replies", "dop.roleB_replies_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_performer,
      { "performer", "dop.performer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dop_aliasDereferenced,
      { "aliasDereferenced", "dop.aliasDereferenced",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dop_notification,
      { "notification", "dop.notification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_Attribute", HFILL }},
    { &hf_dop_notification_item,
      { "Attribute", "dop.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_modifyInitiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_ModifyArgumentInitiator_vals), 0,
        "ModifyArgumentInitiator", HFILL }},
    { &hf_dop_modifySymmetric,
      { "symmetric", "dop.symmetric_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifySymmetric", HFILL }},
    { &hf_dop_modifyRoleAInitiates,
      { "roleA-initiates", "dop.roleA_initiates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyRoleAInitiates", HFILL }},
    { &hf_dop_modifyRoleBInitiates,
      { "roleB-initiates", "dop.roleB_initiates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyRoleBInitiates", HFILL }},
    { &hf_dop_newBindingID,
      { "newBindingID", "dop.newBindingID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OperationalBindingID", HFILL }},
    { &hf_dop_argumentNewAgreement,
      { "newAgreement", "dop.newAgreement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArgumentNewAgreement", HFILL }},
    { &hf_dop_unsignedModifyOperationalBindingArgument,
      { "unsignedModifyOperationalBindingArgument", "dop.unsignedModifyOperationalBindingArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgumentData", HFILL }},
    { &hf_dop_signedModifyOperationalBindingArgument,
      { "signedModifyOperationalBindingArgument", "dop.signedModifyOperationalBindingArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_modifyOperationalBindingArgument,
      { "modifyOperationalBindingArgument", "dop.modifyOperationalBindingArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgumentData", HFILL }},
    { &hf_dop_null,
      { "null", "dop.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_protectedModifyResult,
      { "protected", "dop.protected_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedModifyResult", HFILL }},
    { &hf_dop_modifyOperationalBindingResultData,
      { "modifyOperationalBindingResultData", "dop.modifyOperationalBindingResultData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_resultNewAgreement,
      { "newAgreement", "dop.newAgreement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResultNewAgreement", HFILL }},
    { &hf_dop_terminateInitiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_TerminateArgumentInitiator_vals), 0,
        "TerminateArgumentInitiator", HFILL }},
    { &hf_dop_terminateSymmetric,
      { "symmetric", "dop.symmetric_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateSymmetric", HFILL }},
    { &hf_dop_terminateRoleAInitiates,
      { "roleA-initiates", "dop.roleA_initiates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateRoleAInitiates", HFILL }},
    { &hf_dop_terminateRoleBInitiates,
      { "roleB-initiates", "dop.roleB_initiates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateRoleBInitiates", HFILL }},
    { &hf_dop_terminateAtTime,
      { "terminateAt", "dop.terminateAtTime",
        FT_UINT32, BASE_DEC, VALS(dop_Time_vals), 0,
        "Time", HFILL }},
    { &hf_dop_unsignedTerminateOperationalBindingArgument,
      { "unsignedTerminateOperationalBindingArgument", "dop.unsignedTerminateOperationalBindingArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgumentData", HFILL }},
    { &hf_dop_signedTerminateOperationalBindingArgument,
      { "signedTerminateOperationalBindingArgument", "dop.signedTerminateOperationalBindingArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_terminateOperationalBindingArgument,
      { "terminateOperationalBindingArgument", "dop.terminateOperationalBindingArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgumentData", HFILL }},
    { &hf_dop_protectedTerminateResult,
      { "protected", "dop.protected_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedTerminateResult", HFILL }},
    { &hf_dop_terminateOperationalBindingResultData,
      { "terminateOperationalBindingResultData", "dop.terminateOperationalBindingResultData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_terminateAtGeneralizedTime,
      { "terminateAt", "dop.terminateAtGeneralizedTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_dop_problem,
      { "problem", "dop.problem",
        FT_UINT32, BASE_DEC, VALS(dop_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_dop_agreementProposal,
      { "agreementProposal", "dop.agreementProposal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_retryAt,
      { "retryAt", "dop.retryAt",
        FT_UINT32, BASE_DEC, VALS(dop_Time_vals), 0,
        "Time", HFILL }},
    { &hf_dop_rdn,
      { "rdn", "dop.rdn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelativeDistinguishedName", HFILL }},
    { &hf_dop_immediateSuperior,
      { "immediateSuperior", "dop.immediateSuperior",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_dop_contextPrefixInfo,
      { "contextPrefixInfo", "dop.contextPrefixInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DITcontext", HFILL }},
    { &hf_dop_entryInfo,
      { "entryInfo", "dop.entryInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_dop_entryInfo_item,
      { "Attribute", "dop.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_immediateSuperiorInfo,
      { "immediateSuperiorInfo", "dop.immediateSuperiorInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_dop_immediateSuperiorInfo_item,
      { "Attribute", "dop.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_DITcontext_item,
      { "Vertex", "dop.Vertex_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_admPointInfo,
      { "admPointInfo", "dop.admPointInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_dop_admPointInfo_item,
      { "Attribute", "dop.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_subentries,
      { "subentries", "dop.subentries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SubentryInfo", HFILL }},
    { &hf_dop_subentries_item,
      { "SubentryInfo", "dop.SubentryInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_accessPoints,
      { "accessPoints", "dop.accessPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MasterAndShadowAccessPoints", HFILL }},
    { &hf_dop_info,
      { "info", "dop.info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_dop_info_item,
      { "Attribute", "dop.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_alias,
      { "alias", "dop.alias",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dop_identificationTag,
      { "identificationTag", "dop.identificationTag",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_dop_precedence,
      { "precedence", "dop.precedence",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_authenticationLevel,
      { "authenticationLevel", "dop.authenticationLevel",
        FT_UINT32, BASE_DEC, VALS(dop_AuthenticationLevel_vals), 0,
        NULL, HFILL }},
    { &hf_dop_itemOrUserFirst,
      { "itemOrUserFirst", "dop.itemOrUserFirst",
        FT_UINT32, BASE_DEC, VALS(dop_T_itemOrUserFirst_vals), 0,
        NULL, HFILL }},
    { &hf_dop_itemFirst,
      { "itemFirst", "dop.itemFirst_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_protectedItems,
      { "protectedItems", "dop.protectedItems_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_itemPermissions,
      { "itemPermissions", "dop.itemPermissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ItemPermission", HFILL }},
    { &hf_dop_itemPermissions_item,
      { "ItemPermission", "dop.ItemPermission_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_userFirst,
      { "userFirst", "dop.userFirst_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_userClasses,
      { "userClasses", "dop.userClasses_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_userPermissions,
      { "userPermissions", "dop.userPermissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserPermission", HFILL }},
    { &hf_dop_userPermissions_item,
      { "UserPermission", "dop.UserPermission_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_entry,
      { "entry", "dop.entry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_allUserAttributeTypes,
      { "allUserAttributeTypes", "dop.allUserAttributeTypes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_attributeType,
      { "attributeType", "dop.attributeType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeType", HFILL }},
    { &hf_dop_attributeType_item,
      { "AttributeType", "dop.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_allAttributeValues,
      { "allAttributeValues", "dop.allAttributeValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeType", HFILL }},
    { &hf_dop_allAttributeValues_item,
      { "AttributeType", "dop.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_allUserAttributeTypesAndValues,
      { "allUserAttributeTypesAndValues", "dop.allUserAttributeTypesAndValues_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_attributeValue,
      { "attributeValue", "dop.attributeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeTypeAndValue", HFILL }},
    { &hf_dop_attributeValue_item,
      { "AttributeTypeAndValue", "dop.AttributeTypeAndValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_selfValue,
      { "selfValue", "dop.selfValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeType", HFILL }},
    { &hf_dop_selfValue_item,
      { "AttributeType", "dop.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_rangeOfValues,
      { "rangeOfValues", "dop.rangeOfValues",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "Filter", HFILL }},
    { &hf_dop_maxValueCount,
      { "maxValueCount", "dop.maxValueCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_MaxValueCount", HFILL }},
    { &hf_dop_maxValueCount_item,
      { "MaxValueCount", "dop.MaxValueCount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_maxImmSub,
      { "maxImmSub", "dop.maxImmSub",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dop_restrictedBy,
      { "restrictedBy", "dop.restrictedBy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_RestrictedValue", HFILL }},
    { &hf_dop_restrictedBy_item,
      { "RestrictedValue", "dop.RestrictedValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_contexts,
      { "contexts", "dop.contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ContextAssertion", HFILL }},
    { &hf_dop_contexts_item,
      { "ContextAssertion", "dop.ContextAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_classes,
      { "classes", "dop.classes",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        "Refinement", HFILL }},
    { &hf_dop_type,
      { "type", "dop.type",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dop_maxCount,
      { "maxCount", "dop.maxCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dop_valuesIn,
      { "valuesIn", "dop.valuesIn",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_dop_allUsers,
      { "allUsers", "dop.allUsers_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_thisEntry,
      { "thisEntry", "dop.thisEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_name,
      { "name", "dop.name",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_NameAndOptionalUID", HFILL }},
    { &hf_dop_name_item,
      { "NameAndOptionalUID", "dop.NameAndOptionalUID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_userGroup,
      { "userGroup", "dop.userGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_NameAndOptionalUID", HFILL }},
    { &hf_dop_userGroup_item,
      { "NameAndOptionalUID", "dop.NameAndOptionalUID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_subtree,
      { "subtree", "dop.subtree",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SubtreeSpecification", HFILL }},
    { &hf_dop_subtree_item,
      { "SubtreeSpecification", "dop.SubtreeSpecification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_grantsAndDenials,
      { "grantsAndDenials", "dop.grantsAndDenials",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_basicLevels,
      { "basicLevels", "dop.basicLevels_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_level,
      { "level", "dop.level",
        FT_UINT32, BASE_DEC, VALS(dop_T_level_vals), 0,
        NULL, HFILL }},
    { &hf_dop_localQualifier,
      { "localQualifier", "dop.localQualifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_dop_signed,
      { "signed", "dop.signed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dop_other,
      { "other", "dop.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_dop_DSEType_root,
      { "root", "dop.DSEType.root",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_DSEType_glue,
      { "glue", "dop.DSEType.glue",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_DSEType_cp,
      { "cp", "dop.DSEType.cp",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_DSEType_entry,
      { "entry", "dop.DSEType.entry",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_DSEType_alias,
      { "alias", "dop.DSEType.alias",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dop_DSEType_subr,
      { "subr", "dop.DSEType.subr",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_DSEType_nssr,
      { "nssr", "dop.DSEType.nssr",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_DSEType_supr,
      { "supr", "dop.DSEType.supr",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_DSEType_xr,
      { "xr", "dop.DSEType.xr",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_DSEType_admPoint,
      { "admPoint", "dop.DSEType.admPoint",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_DSEType_subentry,
      { "subentry", "dop.DSEType.subentry",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_DSEType_shadow,
      { "shadow", "dop.DSEType.shadow",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_DSEType_spare_bit12,
      { "spare_bit12", "dop.DSEType.spare.bit12",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dop_DSEType_immSupr,
      { "immSupr", "dop.DSEType.immSupr",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_DSEType_rhob,
      { "rhob", "dop.DSEType.rhob",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_DSEType_sa,
      { "sa", "dop.DSEType.sa",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_DSEType_dsSubentry,
      { "dsSubentry", "dop.DSEType.dsSubentry",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_DSEType_familyMember,
      { "familyMember", "dop.DSEType.familyMember",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_DSEType_ditBridge,
      { "ditBridge", "dop.DSEType.ditBridge",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_DSEType_writeableCopy,
      { "writeableCopy", "dop.DSEType.writeableCopy",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantAdd,
      { "grantAdd", "dop.GrantsAndDenials.grantAdd",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyAdd,
      { "denyAdd", "dop.GrantsAndDenials.denyAdd",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantDiscloseOnError,
      { "grantDiscloseOnError", "dop.GrantsAndDenials.grantDiscloseOnError",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyDiscloseOnError,
      { "denyDiscloseOnError", "dop.GrantsAndDenials.denyDiscloseOnError",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantRead,
      { "grantRead", "dop.GrantsAndDenials.grantRead",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyRead,
      { "denyRead", "dop.GrantsAndDenials.denyRead",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantRemove,
      { "grantRemove", "dop.GrantsAndDenials.grantRemove",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyRemove,
      { "denyRemove", "dop.GrantsAndDenials.denyRemove",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantBrowse,
      { "grantBrowse", "dop.GrantsAndDenials.grantBrowse",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyBrowse,
      { "denyBrowse", "dop.GrantsAndDenials.denyBrowse",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantExport,
      { "grantExport", "dop.GrantsAndDenials.grantExport",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyExport,
      { "denyExport", "dop.GrantsAndDenials.denyExport",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantImport,
      { "grantImport", "dop.GrantsAndDenials.grantImport",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyImport,
      { "denyImport", "dop.GrantsAndDenials.denyImport",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantModify,
      { "grantModify", "dop.GrantsAndDenials.grantModify",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyModify,
      { "denyModify", "dop.GrantsAndDenials.denyModify",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantRename,
      { "grantRename", "dop.GrantsAndDenials.grantRename",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyRename,
      { "denyRename", "dop.GrantsAndDenials.denyRename",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantReturnDN,
      { "grantReturnDN", "dop.GrantsAndDenials.grantReturnDN",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyReturnDN,
      { "denyReturnDN", "dop.GrantsAndDenials.denyReturnDN",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantCompare,
      { "grantCompare", "dop.GrantsAndDenials.grantCompare",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyCompare,
      { "denyCompare", "dop.GrantsAndDenials.denyCompare",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantFilterMatch,
      { "grantFilterMatch", "dop.GrantsAndDenials.grantFilterMatch",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyFilterMatch,
      { "denyFilterMatch", "dop.GrantsAndDenials.denyFilterMatch",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantInvoke,
      { "grantInvoke", "dop.GrantsAndDenials.grantInvoke",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyInvoke,
      { "denyInvoke", "dop.GrantsAndDenials.denyInvoke",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_dop,
    &ett_dop_unknown,
    &ett_dop_DSEType,
    &ett_dop_SupplierOrConsumer,
    &ett_dop_SET_OF_ProtocolInformation,
    &ett_dop_SupplierInformation,
    &ett_dop_SupplierAndConsumers,
    &ett_dop_SET_OF_AccessPoint,
    &ett_dop_EstablishOperationalBindingArgumentData,
    &ett_dop_EstablishArgumentInitiator,
    &ett_dop_EstablishOperationalBindingArgument,
    &ett_dop_T_signedEstablishOperationalBindingArgument,
    &ett_dop_OperationalBindingID,
    &ett_dop_Validity,
    &ett_dop_T_validFrom,
    &ett_dop_T_validUntil,
    &ett_dop_Time,
    &ett_dop_EstablishOperationalBindingResult,
    &ett_dop_T_initiator,
    &ett_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute,
    &ett_dop_ModifyOperationalBindingArgumentData,
    &ett_dop_ModifyArgumentInitiator,
    &ett_dop_ModifyOperationalBindingArgument,
    &ett_dop_T_signedModifyOperationalBindingArgument,
    &ett_dop_ModifyOperationalBindingResult,
    &ett_dop_ProtectedModifyResult,
    &ett_dop_ModifyOperationalBindingResultData,
    &ett_dop_TerminateOperationalBindingArgumentData,
    &ett_dop_TerminateArgumentInitiator,
    &ett_dop_TerminateOperationalBindingArgument,
    &ett_dop_T_signedTerminateOperationalBindingArgument,
    &ett_dop_TerminateOperationalBindingResult,
    &ett_dop_ProtectedTerminateResult,
    &ett_dop_TerminateOperationalBindingResultData,
    &ett_dop_OpBindingErrorParam,
    &ett_dop_HierarchicalAgreement,
    &ett_dop_SuperiorToSubordinate,
    &ett_dop_SET_OF_Attribute,
    &ett_dop_DITcontext,
    &ett_dop_Vertex,
    &ett_dop_SET_OF_SubentryInfo,
    &ett_dop_SubentryInfo,
    &ett_dop_SubordinateToSuperior,
    &ett_dop_SuperiorToSubordinateModification,
    &ett_dop_NonSpecificHierarchicalAgreement,
    &ett_dop_NHOBSuperiorToSubordinate,
    &ett_dop_NHOBSubordinateToSuperior,
    &ett_dop_ACIItem,
    &ett_dop_T_itemOrUserFirst,
    &ett_dop_T_itemFirst,
    &ett_dop_SET_OF_ItemPermission,
    &ett_dop_T_userFirst,
    &ett_dop_SET_OF_UserPermission,
    &ett_dop_ProtectedItems,
    &ett_dop_SET_OF_AttributeType,
    &ett_dop_SET_OF_AttributeTypeAndValue,
    &ett_dop_SET_OF_MaxValueCount,
    &ett_dop_SET_OF_RestrictedValue,
    &ett_dop_SET_OF_ContextAssertion,
    &ett_dop_MaxValueCount,
    &ett_dop_RestrictedValue,
    &ett_dop_UserClasses,
    &ett_dop_SET_OF_NameAndOptionalUID,
    &ett_dop_SET_OF_SubtreeSpecification,
    &ett_dop_ItemPermission,
    &ett_dop_UserPermission,
    &ett_dop_AuthenticationLevel,
    &ett_dop_T_basicLevels,
    &ett_dop_GrantsAndDenials,
  };

  static ei_register_info ei[] = {
     { &ei_dop_unknown_binding_parameter, { "dop.unknown_binding_parameter", PI_UNDECODED, PI_WARN, "Unknown binding-parameter", EXPFILL }},
     { &ei_dop_unsupported_opcode, { "dop.unsupported_opcode", PI_UNDECODED, PI_WARN, "Unsupported DOP opcode", EXPFILL }},
     { &ei_dop_unsupported_errcode, { "dop.unsupported_errcode", PI_UNDECODED, PI_WARN, "Unsupported DOP errcode", EXPFILL }},
     { &ei_dop_unsupported_pdu, { "dop.unsupported_pdu", PI_UNDECODED, PI_WARN, "Unsupported DOP PDU", EXPFILL }},
     { &ei_dop_zero_pdu, { "dop.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte DOP PDU", EXPFILL }},
  };

  expert_module_t* expert_dop;
  module_t *dop_module;

  /* Register protocol */
  proto_dop = proto_register_protocol(PNAME, PSNAME, PFNAME);

  dop_handle = register_dissector("dop", dissect_dop, proto_dop);

  dop_dissector_table = register_dissector_table("dop.oid", "DOP OID", proto_dop, FT_STRING, STRING_CASE_SENSITIVE);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dop = expert_register_protocol(proto_dop);
  expert_register_field_array(expert_dop, ei, array_length(ei));

  /* Register our configuration options for DOP, particularly our port */

  dop_module = prefs_register_protocol_subtree("OSI/X.500", proto_dop, NULL);

  prefs_register_obsolete_preference(dop_module, "tcp.port");

  prefs_register_static_text_preference(dop_module, "tcp_port_info",
            "The TCP ports used by the DOP protocol should be added to the TPKT preference \"TPKT TCP ports\", or by selecting \"TPKT\" as the \"Transport\" protocol in the \"Decode As\" dialog.",
            "DOP TCP Port preference moved information");

}


/*--- proto_reg_handoff_dop --- */
void proto_reg_handoff_dop(void) {

  register_ber_oid_dissector("2.5.12.0", dissect_DSEType_PDU, proto_dop, "id-doa-dseType");
  register_ber_oid_dissector("2.5.12.5", dissect_SupplierInformation_PDU, proto_dop, "id-doa-supplierKnowledge");
  register_ber_oid_dissector("2.5.12.6", dissect_ConsumerInformation_PDU, proto_dop, "id-doa-consumerKnowledge");
  register_ber_oid_dissector("2.5.12.7", dissect_SupplierAndConsumers_PDU, proto_dop, "id-doa-secondaryShadows");
  dissector_add_string("dop.oid", "agreement.2.5.19.2", create_dissector_handle(dissect_HierarchicalAgreement_PDU, proto_dop));
  dissector_add_string("dop.oid", "establish.rolea.2.5.19.2", create_dissector_handle(dissect_SuperiorToSubordinate_PDU, proto_dop));
  dissector_add_string("dop.oid", "modify.rolea.2.5.19.2", create_dissector_handle(dissect_SuperiorToSubordinateModification_PDU, proto_dop));
  dissector_add_string("dop.oid", "establish.roleb.2.5.19.2", create_dissector_handle(dissect_SubordinateToSuperior_PDU, proto_dop));
  dissector_add_string("dop.oid", "modify.roleb.2.5.19.2", create_dissector_handle(dissect_SubordinateToSuperior_PDU, proto_dop));
  dissector_add_string("dop.oid", "agreement.2.5.19.3", create_dissector_handle(dissect_NonSpecificHierarchicalAgreement_PDU, proto_dop));
  dissector_add_string("dop.oid", "establish.rolea.2.5.19.3", create_dissector_handle(dissect_NHOBSuperiorToSubordinate_PDU, proto_dop));
  dissector_add_string("dop.oid", "modify.rolea.2.5.19.3", create_dissector_handle(dissect_NHOBSuperiorToSubordinate_PDU, proto_dop));
  dissector_add_string("dop.oid", "establish.roleb.2.5.19.3", create_dissector_handle(dissect_NHOBSubordinateToSuperior_PDU, proto_dop));
  dissector_add_string("dop.oid", "modify.roleb.2.5.19.3", create_dissector_handle(dissect_NHOBSubordinateToSuperior_PDU, proto_dop));
  register_ber_oid_dissector("2.5.24.4", dissect_ACIItem_PDU, proto_dop, "id-aca-prescriptiveACI");
  register_ber_oid_dissector("2.5.24.5", dissect_ACIItem_PDU, proto_dop, "id-aca-entryACI");
  register_ber_oid_dissector("2.5.24.6", dissect_ACIItem_PDU, proto_dop, "id-aca-subentryACI");

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-directory-operational-binding-management","2.5.3.3");

  /* ABSTRACT SYNTAXES */

  /* Register DOP with ROS (with no use of RTSE) */
  register_ros_oid_dissector_handle("2.5.9.4", dop_handle, 0, "id-as-directory-operational-binding-management", false);

  /* BINDING TYPES */

  oid_add_from_string("shadow-agreement","2.5.19.1");
  oid_add_from_string("hierarchical-agreement","2.5.19.2");
  oid_add_from_string("non-specific-hierarchical-agreement","2.5.19.3");

  /* ACCESS CONTROL SCHEMES */
  oid_add_from_string("basic-ACS","2.5.28.1");
  oid_add_from_string("simplified-ACS","2.5.28.2");
  oid_add_from_string("ruleBased-ACS","2.5.28.3");
  oid_add_from_string("ruleAndBasic-ACS","2.5.28.4");
  oid_add_from_string("ruleAndSimple-ACS","2.5.28.5");

  /* ADMINISTRATIVE ROLES */
  oid_add_from_string("id-ar-autonomousArea","2.5.23.1");
  oid_add_from_string("id-ar-accessControlSpecificArea","2.5.23.2");
  oid_add_from_string("id-ar-accessControlInnerArea","2.5.23.3");
  oid_add_from_string("id-ar-subschemaAdminSpecificArea","2.5.23.4");
  oid_add_from_string("id-ar-collectiveAttributeSpecificArea","2.5.23.5");
  oid_add_from_string("id-ar-collectiveAttributeInnerArea","2.5.23.6");
  oid_add_from_string("id-ar-contextDefaultSpecificArea","2.5.23.7");
  oid_add_from_string("id-ar-serviceSpecificArea","2.5.23.8");
}
