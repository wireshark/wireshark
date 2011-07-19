/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-dop.c                                                               */
/* ../../tools/asn2wrs.py -b -e -p dop -c ./dop.cnf -s ./packet-dop-template -D . dop.asn */

/* Input file: packet-dop-template.c */

#line 1 "../../asn1/dop/packet-dop-template.c"
/* packet-dop.c
 * Routines for X.501 (DSA Operational Attributes)  packet dissection
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

static guint global_dop_tcp_port = 102;
static dissector_handle_t tpkt_handle;
static void prefs_register_dop(void); /* forward declaration for use in preferences registration */

/* Initialize the protocol and registered fields */
static int proto_dop = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;
static const char *binding_type = NULL; /* binding_type */

static int call_dop_oid_callback(char *base_string, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *col_info);


/*--- Included file: packet-dop-hf.c ---*/
#line 1 "../../asn1/dop/packet-dop-hf.c"
static int hf_dop_DSEType_PDU = -1;               /* DSEType */
static int hf_dop_SupplierInformation_PDU = -1;   /* SupplierInformation */
static int hf_dop_ConsumerInformation_PDU = -1;   /* ConsumerInformation */
static int hf_dop_SupplierAndConsumers_PDU = -1;  /* SupplierAndConsumers */
static int hf_dop_HierarchicalAgreement_PDU = -1;  /* HierarchicalAgreement */
static int hf_dop_SuperiorToSubordinate_PDU = -1;  /* SuperiorToSubordinate */
static int hf_dop_SubordinateToSuperior_PDU = -1;  /* SubordinateToSuperior */
static int hf_dop_SuperiorToSubordinateModification_PDU = -1;  /* SuperiorToSubordinateModification */
static int hf_dop_NonSpecificHierarchicalAgreement_PDU = -1;  /* NonSpecificHierarchicalAgreement */
static int hf_dop_NHOBSuperiorToSubordinate_PDU = -1;  /* NHOBSuperiorToSubordinate */
static int hf_dop_NHOBSubordinateToSuperior_PDU = -1;  /* NHOBSubordinateToSuperior */
static int hf_dop_ACIItem_PDU = -1;               /* ACIItem */
static int hf_dop_ae_title = -1;                  /* Name */
static int hf_dop_address = -1;                   /* PresentationAddress */
static int hf_dop_protocolInformation = -1;       /* SET_OF_ProtocolInformation */
static int hf_dop_protocolInformation_item = -1;  /* ProtocolInformation */
static int hf_dop_agreementID = -1;               /* OperationalBindingID */
static int hf_dop_supplier_is_master = -1;        /* BOOLEAN */
static int hf_dop_non_supplying_master = -1;      /* AccessPoint */
static int hf_dop_consumers = -1;                 /* SET_OF_AccessPoint */
static int hf_dop_consumers_item = -1;            /* AccessPoint */
static int hf_dop_bindingType = -1;               /* BindingType */
static int hf_dop_bindingID = -1;                 /* OperationalBindingID */
static int hf_dop_accessPoint = -1;               /* AccessPoint */
static int hf_dop_establishInitiator = -1;        /* EstablishArgumentInitiator */
static int hf_dop_establishSymmetric = -1;        /* EstablishSymmetric */
static int hf_dop_establishRoleAInitiates = -1;   /* EstablishRoleAInitiates */
static int hf_dop_establishRoleBInitiates = -1;   /* EstablishRoleBInitiates */
static int hf_dop_agreement = -1;                 /* T_agreement */
static int hf_dop_valid = -1;                     /* Validity */
static int hf_dop_securityParameters = -1;        /* SecurityParameters */
static int hf_dop_unsignedEstablishOperationalBindingArgument = -1;  /* EstablishOperationalBindingArgumentData */
static int hf_dop_signedEstablishOperationalBindingArgument = -1;  /* T_signedEstablishOperationalBindingArgument */
static int hf_dop_establishOperationalBindingArgument = -1;  /* EstablishOperationalBindingArgumentData */
static int hf_dop_algorithmIdentifier = -1;       /* AlgorithmIdentifier */
static int hf_dop_encrypted = -1;                 /* BIT_STRING */
static int hf_dop_identifier = -1;                /* T_identifier */
static int hf_dop_version = -1;                   /* T_version */
static int hf_dop_validFrom = -1;                 /* T_validFrom */
static int hf_dop_now = -1;                       /* NULL */
static int hf_dop_time = -1;                      /* Time */
static int hf_dop_validUntil = -1;                /* T_validUntil */
static int hf_dop_explicitTermination = -1;       /* NULL */
static int hf_dop_utcTime = -1;                   /* UTCTime */
static int hf_dop_generalizedTime = -1;           /* GeneralizedTime */
static int hf_dop_initiator = -1;                 /* T_initiator */
static int hf_dop_symmetric = -1;                 /* T_symmetric */
static int hf_dop_roleA_replies = -1;             /* T_roleA_replies */
static int hf_dop_roleB_replies = -1;             /* T_roleB_replies */
static int hf_dop_performer = -1;                 /* DistinguishedName */
static int hf_dop_aliasDereferenced = -1;         /* BOOLEAN */
static int hf_dop_notification = -1;              /* SEQUENCE_SIZE_1_MAX_OF_Attribute */
static int hf_dop_notification_item = -1;         /* Attribute */
static int hf_dop_modifyInitiator = -1;           /* ModifyArgumentInitiator */
static int hf_dop_modifySymmetric = -1;           /* ModifySymmetric */
static int hf_dop_modifyRoleAInitiates = -1;      /* ModifyRoleAInitiates */
static int hf_dop_modifyRoleBInitiates = -1;      /* ModifyRoleBInitiates */
static int hf_dop_newBindingID = -1;              /* OperationalBindingID */
static int hf_dop_argumentNewAgreement = -1;      /* ArgumentNewAgreement */
static int hf_dop_unsignedModifyOperationalBindingArgument = -1;  /* ModifyOperationalBindingArgumentData */
static int hf_dop_signedModifyOperationalBindingArgument = -1;  /* T_signedModifyOperationalBindingArgument */
static int hf_dop_modifyOperationalBindingArgument = -1;  /* ModifyOperationalBindingArgumentData */
static int hf_dop_null = -1;                      /* NULL */
static int hf_dop_protectedModifyResult = -1;     /* ProtectedModifyResult */
static int hf_dop_modifyOperationalBindingResultData = -1;  /* ModifyOperationalBindingResultData */
static int hf_dop_resultNewAgreement = -1;        /* ResultNewAgreement */
static int hf_dop_terminateInitiator = -1;        /* TerminateArgumentInitiator */
static int hf_dop_terminateSymmetric = -1;        /* TerminateSymmetric */
static int hf_dop_terminateRoleAInitiates = -1;   /* TerminateRoleAInitiates */
static int hf_dop_terminateRoleBInitiates = -1;   /* TerminateRoleBInitiates */
static int hf_dop_terminateAtTime = -1;           /* Time */
static int hf_dop_unsignedTerminateOperationalBindingArgument = -1;  /* TerminateOperationalBindingArgumentData */
static int hf_dop_signedTerminateOperationalBindingArgument = -1;  /* T_signedTerminateOperationalBindingArgument */
static int hf_dop_terminateOperationalBindingArgument = -1;  /* TerminateOperationalBindingArgumentData */
static int hf_dop_protectedTerminateResult = -1;  /* ProtectedTerminateResult */
static int hf_dop_terminateOperationalBindingResultData = -1;  /* TerminateOperationalBindingResultData */
static int hf_dop_terminateAtGeneralizedTime = -1;  /* GeneralizedTime */
static int hf_dop_problem = -1;                   /* T_problem */
static int hf_dop_agreementProposal = -1;         /* T_agreementProposal */
static int hf_dop_retryAt = -1;                   /* Time */
static int hf_dop_rdn = -1;                       /* RelativeDistinguishedName */
static int hf_dop_immediateSuperior = -1;         /* DistinguishedName */
static int hf_dop_contextPrefixInfo = -1;         /* DITcontext */
static int hf_dop_entryInfo = -1;                 /* SET_OF_Attribute */
static int hf_dop_entryInfo_item = -1;            /* Attribute */
static int hf_dop_immediateSuperiorInfo = -1;     /* SET_OF_Attribute */
static int hf_dop_immediateSuperiorInfo_item = -1;  /* Attribute */
static int hf_dop_DITcontext_item = -1;           /* Vertex */
static int hf_dop_admPointInfo = -1;              /* SET_OF_Attribute */
static int hf_dop_admPointInfo_item = -1;         /* Attribute */
static int hf_dop_subentries = -1;                /* SET_OF_SubentryInfo */
static int hf_dop_subentries_item = -1;           /* SubentryInfo */
static int hf_dop_accessPoints = -1;              /* MasterAndShadowAccessPoints */
static int hf_dop_info = -1;                      /* SET_OF_Attribute */
static int hf_dop_info_item = -1;                 /* Attribute */
static int hf_dop_alias = -1;                     /* BOOLEAN */
static int hf_dop_identificationTag = -1;         /* DirectoryString */
static int hf_dop_precedence = -1;                /* Precedence */
static int hf_dop_authenticationLevel = -1;       /* AuthenticationLevel */
static int hf_dop_itemOrUserFirst = -1;           /* T_itemOrUserFirst */
static int hf_dop_itemFirst = -1;                 /* T_itemFirst */
static int hf_dop_protectedItems = -1;            /* ProtectedItems */
static int hf_dop_itemPermissions = -1;           /* SET_OF_ItemPermission */
static int hf_dop_itemPermissions_item = -1;      /* ItemPermission */
static int hf_dop_userFirst = -1;                 /* T_userFirst */
static int hf_dop_userClasses = -1;               /* UserClasses */
static int hf_dop_userPermissions = -1;           /* SET_OF_UserPermission */
static int hf_dop_userPermissions_item = -1;      /* UserPermission */
static int hf_dop_entry = -1;                     /* NULL */
static int hf_dop_allUserAttributeTypes = -1;     /* NULL */
static int hf_dop_attributeType = -1;             /* SET_OF_AttributeType */
static int hf_dop_attributeType_item = -1;        /* AttributeType */
static int hf_dop_allAttributeValues = -1;        /* SET_OF_AttributeType */
static int hf_dop_allAttributeValues_item = -1;   /* AttributeType */
static int hf_dop_allUserAttributeTypesAndValues = -1;  /* NULL */
static int hf_dop_attributeValue = -1;            /* SET_OF_AttributeTypeAndValue */
static int hf_dop_attributeValue_item = -1;       /* AttributeTypeAndValue */
static int hf_dop_selfValue = -1;                 /* SET_OF_AttributeType */
static int hf_dop_selfValue_item = -1;            /* AttributeType */
static int hf_dop_rangeOfValues = -1;             /* Filter */
static int hf_dop_maxValueCount = -1;             /* SET_OF_MaxValueCount */
static int hf_dop_maxValueCount_item = -1;        /* MaxValueCount */
static int hf_dop_maxImmSub = -1;                 /* INTEGER */
static int hf_dop_restrictedBy = -1;              /* SET_OF_RestrictedValue */
static int hf_dop_restrictedBy_item = -1;         /* RestrictedValue */
static int hf_dop_contexts = -1;                  /* SET_OF_ContextAssertion */
static int hf_dop_contexts_item = -1;             /* ContextAssertion */
static int hf_dop_classes = -1;                   /* Refinement */
static int hf_dop_type = -1;                      /* AttributeType */
static int hf_dop_maxCount = -1;                  /* INTEGER */
static int hf_dop_valuesIn = -1;                  /* AttributeType */
static int hf_dop_allUsers = -1;                  /* NULL */
static int hf_dop_thisEntry = -1;                 /* NULL */
static int hf_dop_name = -1;                      /* SET_OF_NameAndOptionalUID */
static int hf_dop_name_item = -1;                 /* NameAndOptionalUID */
static int hf_dop_userGroup = -1;                 /* SET_OF_NameAndOptionalUID */
static int hf_dop_userGroup_item = -1;            /* NameAndOptionalUID */
static int hf_dop_subtree = -1;                   /* SET_OF_SubtreeSpecification */
static int hf_dop_subtree_item = -1;              /* SubtreeSpecification */
static int hf_dop_grantsAndDenials = -1;          /* GrantsAndDenials */
static int hf_dop_basicLevels = -1;               /* T_basicLevels */
static int hf_dop_level = -1;                     /* T_level */
static int hf_dop_localQualifier = -1;            /* INTEGER */
static int hf_dop_signed = -1;                    /* BOOLEAN */
static int hf_dop_other = -1;                     /* EXTERNAL */
/* named bits */
static int hf_dop_DSEType_root = -1;
static int hf_dop_DSEType_glue = -1;
static int hf_dop_DSEType_cp = -1;
static int hf_dop_DSEType_entry = -1;
static int hf_dop_DSEType_alias = -1;
static int hf_dop_DSEType_subr = -1;
static int hf_dop_DSEType_nssr = -1;
static int hf_dop_DSEType_supr = -1;
static int hf_dop_DSEType_xr = -1;
static int hf_dop_DSEType_admPoint = -1;
static int hf_dop_DSEType_subentry = -1;
static int hf_dop_DSEType_shadow = -1;
static int hf_dop_DSEType_immSupr = -1;
static int hf_dop_DSEType_rhob = -1;
static int hf_dop_DSEType_sa = -1;
static int hf_dop_DSEType_dsSubentry = -1;
static int hf_dop_DSEType_familyMember = -1;
static int hf_dop_DSEType_ditBridge = -1;
static int hf_dop_DSEType_writeableCopy = -1;
static int hf_dop_GrantsAndDenials_grantAdd = -1;
static int hf_dop_GrantsAndDenials_denyAdd = -1;
static int hf_dop_GrantsAndDenials_grantDiscloseOnError = -1;
static int hf_dop_GrantsAndDenials_denyDiscloseOnError = -1;
static int hf_dop_GrantsAndDenials_grantRead = -1;
static int hf_dop_GrantsAndDenials_denyRead = -1;
static int hf_dop_GrantsAndDenials_grantRemove = -1;
static int hf_dop_GrantsAndDenials_denyRemove = -1;
static int hf_dop_GrantsAndDenials_grantBrowse = -1;
static int hf_dop_GrantsAndDenials_denyBrowse = -1;
static int hf_dop_GrantsAndDenials_grantExport = -1;
static int hf_dop_GrantsAndDenials_denyExport = -1;
static int hf_dop_GrantsAndDenials_grantImport = -1;
static int hf_dop_GrantsAndDenials_denyImport = -1;
static int hf_dop_GrantsAndDenials_grantModify = -1;
static int hf_dop_GrantsAndDenials_denyModify = -1;
static int hf_dop_GrantsAndDenials_grantRename = -1;
static int hf_dop_GrantsAndDenials_denyRename = -1;
static int hf_dop_GrantsAndDenials_grantReturnDN = -1;
static int hf_dop_GrantsAndDenials_denyReturnDN = -1;
static int hf_dop_GrantsAndDenials_grantCompare = -1;
static int hf_dop_GrantsAndDenials_denyCompare = -1;
static int hf_dop_GrantsAndDenials_grantFilterMatch = -1;
static int hf_dop_GrantsAndDenials_denyFilterMatch = -1;
static int hf_dop_GrantsAndDenials_grantInvoke = -1;
static int hf_dop_GrantsAndDenials_denyInvoke = -1;

/*--- End of included file: packet-dop-hf.c ---*/
#line 68 "../../asn1/dop/packet-dop-template.c"

/* Initialize the subtree pointers */
static gint ett_dop = -1;
static gint ett_dop_unknown = -1;

/*--- Included file: packet-dop-ett.c ---*/
#line 1 "../../asn1/dop/packet-dop-ett.c"
static gint ett_dop_DSEType = -1;
static gint ett_dop_SupplierOrConsumer = -1;
static gint ett_dop_SET_OF_ProtocolInformation = -1;
static gint ett_dop_SupplierInformation = -1;
static gint ett_dop_SupplierAndConsumers = -1;
static gint ett_dop_SET_OF_AccessPoint = -1;
static gint ett_dop_EstablishOperationalBindingArgumentData = -1;
static gint ett_dop_EstablishArgumentInitiator = -1;
static gint ett_dop_EstablishOperationalBindingArgument = -1;
static gint ett_dop_T_signedEstablishOperationalBindingArgument = -1;
static gint ett_dop_OperationalBindingID = -1;
static gint ett_dop_Validity = -1;
static gint ett_dop_T_validFrom = -1;
static gint ett_dop_T_validUntil = -1;
static gint ett_dop_Time = -1;
static gint ett_dop_EstablishOperationalBindingResult = -1;
static gint ett_dop_T_initiator = -1;
static gint ett_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute = -1;
static gint ett_dop_ModifyOperationalBindingArgumentData = -1;
static gint ett_dop_ModifyArgumentInitiator = -1;
static gint ett_dop_ModifyOperationalBindingArgument = -1;
static gint ett_dop_T_signedModifyOperationalBindingArgument = -1;
static gint ett_dop_ModifyOperationalBindingResult = -1;
static gint ett_dop_ProtectedModifyResult = -1;
static gint ett_dop_ModifyOperationalBindingResultData = -1;
static gint ett_dop_TerminateOperationalBindingArgumentData = -1;
static gint ett_dop_TerminateArgumentInitiator = -1;
static gint ett_dop_TerminateOperationalBindingArgument = -1;
static gint ett_dop_T_signedTerminateOperationalBindingArgument = -1;
static gint ett_dop_TerminateOperationalBindingResult = -1;
static gint ett_dop_ProtectedTerminateResult = -1;
static gint ett_dop_TerminateOperationalBindingResultData = -1;
static gint ett_dop_OpBindingErrorParam = -1;
static gint ett_dop_HierarchicalAgreement = -1;
static gint ett_dop_SuperiorToSubordinate = -1;
static gint ett_dop_SET_OF_Attribute = -1;
static gint ett_dop_DITcontext = -1;
static gint ett_dop_Vertex = -1;
static gint ett_dop_SET_OF_SubentryInfo = -1;
static gint ett_dop_SubentryInfo = -1;
static gint ett_dop_SubordinateToSuperior = -1;
static gint ett_dop_SuperiorToSubordinateModification = -1;
static gint ett_dop_NonSpecificHierarchicalAgreement = -1;
static gint ett_dop_NHOBSuperiorToSubordinate = -1;
static gint ett_dop_NHOBSubordinateToSuperior = -1;
static gint ett_dop_ACIItem = -1;
static gint ett_dop_T_itemOrUserFirst = -1;
static gint ett_dop_T_itemFirst = -1;
static gint ett_dop_SET_OF_ItemPermission = -1;
static gint ett_dop_T_userFirst = -1;
static gint ett_dop_SET_OF_UserPermission = -1;
static gint ett_dop_ProtectedItems = -1;
static gint ett_dop_SET_OF_AttributeType = -1;
static gint ett_dop_SET_OF_AttributeTypeAndValue = -1;
static gint ett_dop_SET_OF_MaxValueCount = -1;
static gint ett_dop_SET_OF_RestrictedValue = -1;
static gint ett_dop_SET_OF_ContextAssertion = -1;
static gint ett_dop_MaxValueCount = -1;
static gint ett_dop_RestrictedValue = -1;
static gint ett_dop_UserClasses = -1;
static gint ett_dop_SET_OF_NameAndOptionalUID = -1;
static gint ett_dop_SET_OF_SubtreeSpecification = -1;
static gint ett_dop_ItemPermission = -1;
static gint ett_dop_UserPermission = -1;
static gint ett_dop_AuthenticationLevel = -1;
static gint ett_dop_T_basicLevels = -1;
static gint ett_dop_GrantsAndDenials = -1;

/*--- End of included file: packet-dop-ett.c ---*/
#line 73 "../../asn1/dop/packet-dop-template.c"

/* Dissector table */
static dissector_table_t dop_dissector_table;

static void append_oid(packet_info *pinfo, const char *oid)
{
  	const char *name = NULL;

    name = oid_resolved_from_string(oid);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name ? name : oid);
}


/*--- Included file: packet-dop-fn.c ---*/
#line 1 "../../asn1/dop/packet-dop-fn.c"

static const asn_namedbit DSEType_bits[] = {
  {  0, &hf_dop_DSEType_root, -1, -1, "root", NULL },
  {  1, &hf_dop_DSEType_glue, -1, -1, "glue", NULL },
  {  2, &hf_dop_DSEType_cp, -1, -1, "cp", NULL },
  {  3, &hf_dop_DSEType_entry, -1, -1, "entry", NULL },
  {  4, &hf_dop_DSEType_alias, -1, -1, "alias", NULL },
  {  5, &hf_dop_DSEType_subr, -1, -1, "subr", NULL },
  {  6, &hf_dop_DSEType_nssr, -1, -1, "nssr", NULL },
  {  7, &hf_dop_DSEType_supr, -1, -1, "supr", NULL },
  {  8, &hf_dop_DSEType_xr, -1, -1, "xr", NULL },
  {  9, &hf_dop_DSEType_admPoint, -1, -1, "admPoint", NULL },
  { 10, &hf_dop_DSEType_subentry, -1, -1, "subentry", NULL },
  { 11, &hf_dop_DSEType_shadow, -1, -1, "shadow", NULL },
  { 13, &hf_dop_DSEType_immSupr, -1, -1, "immSupr", NULL },
  { 14, &hf_dop_DSEType_rhob, -1, -1, "rhob", NULL },
  { 15, &hf_dop_DSEType_sa, -1, -1, "sa", NULL },
  { 16, &hf_dop_DSEType_dsSubentry, -1, -1, "dsSubentry", NULL },
  { 17, &hf_dop_DSEType_familyMember, -1, -1, "familyMember", NULL },
  { 18, &hf_dop_DSEType_ditBridge, -1, -1, "ditBridge", NULL },
  { 19, &hf_dop_DSEType_writeableCopy, -1, -1, "writeableCopy", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_dop_DSEType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    DSEType_bits, hf_index, ett_dop_DSEType,
                                    NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ProtocolInformation_set_of[1] = {
  { &hf_dop_protocolInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_ProtocolInformation },
};

static int
dissect_dop_SET_OF_ProtocolInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ProtocolInformation_set_of, hf_index, ett_dop_SET_OF_ProtocolInformation);

  return offset;
}



static int
dissect_dop_T_identifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 172 "../../asn1/dop/dop.cnf"
	guint32	value;

	  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &value);


	col_append_fstr(actx->pinfo->cinfo, COL_INFO, " id=%d", value);





  return offset;
}



static int
dissect_dop_T_version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 181 "../../asn1/dop/dop.cnf"
	guint32	value;

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
dissect_dop_OperationalBindingID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_SupplierOrConsumer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SupplierOrConsumer_set, hf_index, ett_dop_SupplierOrConsumer);

  return offset;
}



static int
dissect_dop_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_SupplierInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SupplierInformation_set, hf_index, ett_dop_SupplierInformation);

  return offset;
}



static int
dissect_dop_ConsumerInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dop_SupplierOrConsumer(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_AccessPoint_set_of[1] = {
  { &hf_dop_consumers_item  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_dsp_AccessPoint },
};

static int
dissect_dop_SET_OF_AccessPoint(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_SupplierAndConsumers(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SupplierAndConsumers_set, hf_index, ett_dop_SupplierAndConsumers);

  return offset;
}



static int
dissect_dop_DSAOperationalManagementBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dop_DSAOperationalManagementBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dop_DSAOperationalManagementBindError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_dop_BindingType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &binding_type);

#line 103 "../../asn1/dop/dop.cnf"
  append_oid(actx->pinfo, binding_type);

  return offset;
}



static int
dissect_dop_EstablishSymmetric(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 107 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("establish.symmetric", tvb, offset, actx->pinfo, tree, "symmetric");



  return offset;
}



static int
dissect_dop_EstablishRoleAInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 111 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("establish.rolea", tvb, offset, actx->pinfo, tree, "roleA");



  return offset;
}



static int
dissect_dop_EstablishRoleBInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 115 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("establish.roleb", tvb, offset, actx->pinfo, tree, "roleB");



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
dissect_dop_EstablishArgumentInitiator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EstablishArgumentInitiator_choice, hf_index, ett_dop_EstablishArgumentInitiator,
                                 NULL);

  return offset;
}



static int
dissect_dop_T_agreement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 143 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("agreement", tvb, offset, actx->pinfo, tree, NULL);



  return offset;
}



static int
dissect_dop_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_dop_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_dop_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_Time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_T_validFrom(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_T_validUntil(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_Validity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_EstablishOperationalBindingArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EstablishOperationalBindingArgumentData_sequence, hf_index, ett_dop_EstablishOperationalBindingArgumentData);

  return offset;
}



static int
dissect_dop_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
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
dissect_dop_T_signedEstablishOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedEstablishOperationalBindingArgument_sequence, hf_index, ett_dop_T_signedEstablishOperationalBindingArgument);

  return offset;
}


static const value_string dop_EstablishOperationalBindingArgument_vals[] = {
  {   0, "unsignedEstablishOperationalBindingArgument" },
  {   1, "signedEstablishOperationalBindingArgument" },
  { 0, NULL }
};

static const ber_choice_t EstablishOperationalBindingArgument_choice[] = {
  {   0, &hf_dop_unsignedEstablishOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_EstablishOperationalBindingArgumentData },
  {   1, &hf_dop_signedEstablishOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_T_signedEstablishOperationalBindingArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_EstablishOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EstablishOperationalBindingArgument_choice, hf_index, ett_dop_EstablishOperationalBindingArgument,
                                 NULL);

  return offset;
}



static int
dissect_dop_T_symmetric(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 147 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("establish.symmetric", tvb, offset, actx->pinfo, tree, "symmetric"); 



  return offset;
}



static int
dissect_dop_T_roleA_replies(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 151 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("establish.rolea", tvb, offset, actx->pinfo, tree, "roleA");



  return offset;
}



static int
dissect_dop_T_roleB_replies(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 155 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("establish.roleb", tvb, offset, actx->pinfo, tree, "roleB");



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
dissect_dop_T_initiator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_initiator_choice, hf_index, ett_dop_T_initiator,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_Attribute_sequence_of[1] = {
  { &hf_dop_notification_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_EstablishOperationalBindingResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EstablishOperationalBindingResult_sequence, hf_index, ett_dop_EstablishOperationalBindingResult);

  return offset;
}



static int
dissect_dop_ModifySymmetric(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 119 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("modify.symmetric", tvb, offset, actx->pinfo, tree, "symmetric");



  return offset;
}



static int
dissect_dop_ModifyRoleAInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 123 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("modify.rolea", tvb, offset, actx->pinfo, tree, "roleA");



  return offset;
}



static int
dissect_dop_ModifyRoleBInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 127 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("modify.roleb", tvb, offset, actx->pinfo, tree, "roleB");



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
dissect_dop_ModifyArgumentInitiator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyArgumentInitiator_choice, hf_index, ett_dop_ModifyArgumentInitiator,
                                 NULL);

  return offset;
}



static int
dissect_dop_ArgumentNewAgreement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 167 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("agreement", tvb, offset, actx->pinfo, tree, NULL);




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
dissect_dop_ModifyOperationalBindingArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_T_signedModifyOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedModifyOperationalBindingArgument_sequence, hf_index, ett_dop_T_signedModifyOperationalBindingArgument);

  return offset;
}


static const value_string dop_ModifyOperationalBindingArgument_vals[] = {
  {   0, "unsignedModifyOperationalBindingArgument" },
  {   1, "signedModifyOperationalBindingArgument" },
  { 0, NULL }
};

static const ber_choice_t ModifyOperationalBindingArgument_choice[] = {
  {   0, &hf_dop_unsignedModifyOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_ModifyOperationalBindingArgumentData },
  {   1, &hf_dop_signedModifyOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_T_signedModifyOperationalBindingArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyOperationalBindingArgument_choice, hf_index, ett_dop_ModifyOperationalBindingArgument,
                                 NULL);

  return offset;
}



static int
dissect_dop_ResultNewAgreement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 163 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("agreement", tvb, offset, actx->pinfo, tree, NULL);



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
dissect_dop_ModifyOperationalBindingResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_ProtectedModifyResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtectedModifyResult_sequence, hf_index, ett_dop_ProtectedModifyResult);

  return offset;
}


static const value_string dop_ModifyOperationalBindingResult_vals[] = {
  {   0, "null" },
  {   1, "protected" },
  { 0, NULL }
};

static const ber_choice_t ModifyOperationalBindingResult_choice[] = {
  {   0, &hf_dop_null            , BER_CLASS_CON, 0, 0, dissect_dop_NULL },
  {   1, &hf_dop_protectedModifyResult, BER_CLASS_CON, 1, 0, dissect_dop_ProtectedModifyResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ModifyOperationalBindingResult_choice, hf_index, ett_dop_ModifyOperationalBindingResult,
                                 NULL);

  return offset;
}



static int
dissect_dop_TerminateSymmetric(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 131 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("terminate.symmetric", tvb, offset, actx->pinfo, tree, "symmetric");



  return offset;
}



static int
dissect_dop_TerminateRoleAInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 135 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("terminate.rolea", tvb, offset, actx->pinfo, tree, "roleA");



  return offset;
}



static int
dissect_dop_TerminateRoleBInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 139 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("terminate.roleb", tvb, offset, actx->pinfo, tree, "roleB");



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
dissect_dop_TerminateArgumentInitiator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_TerminateOperationalBindingArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_T_signedTerminateOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedTerminateOperationalBindingArgument_sequence, hf_index, ett_dop_T_signedTerminateOperationalBindingArgument);

  return offset;
}


static const value_string dop_TerminateOperationalBindingArgument_vals[] = {
  {   0, "unsignedTerminateOperationalBindingArgument" },
  {   1, "signedTerminateOperationalBindingArgument" },
  { 0, NULL }
};

static const ber_choice_t TerminateOperationalBindingArgument_choice[] = {
  {   0, &hf_dop_unsignedTerminateOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_TerminateOperationalBindingArgumentData },
  {   1, &hf_dop_signedTerminateOperationalBindingArgument, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_T_signedTerminateOperationalBindingArgument },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_TerminateOperationalBindingResultData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_ProtectedTerminateResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtectedTerminateResult_sequence, hf_index, ett_dop_ProtectedTerminateResult);

  return offset;
}


static const value_string dop_TerminateOperationalBindingResult_vals[] = {
  {   0, "null" },
  {   1, "protected" },
  { 0, NULL }
};

static const ber_choice_t TerminateOperationalBindingResult_choice[] = {
  {   0, &hf_dop_null            , BER_CLASS_CON, 0, 0, dissect_dop_NULL },
  {   1, &hf_dop_protectedTerminateResult, BER_CLASS_CON, 1, 0, dissect_dop_ProtectedTerminateResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dop_T_agreementProposal(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 159 "../../asn1/dop/dop.cnf"

  offset = call_dop_oid_callback("agreement", tvb, offset, actx->pinfo, tree, NULL);



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
dissect_dop_OpBindingErrorParam(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_HierarchicalAgreement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HierarchicalAgreement_sequence, hf_index, ett_dop_HierarchicalAgreement);

  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { &hf_dop_entryInfo_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_dop_SET_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_SubentryInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubentryInfo_sequence, hf_index, ett_dop_SubentryInfo);

  return offset;
}


static const ber_sequence_t SET_OF_SubentryInfo_set_of[1] = {
  { &hf_dop_subentries_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_SubentryInfo },
};

static int
dissect_dop_SET_OF_SubentryInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_Vertex(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Vertex_sequence, hf_index, ett_dop_Vertex);

  return offset;
}


static const ber_sequence_t DITcontext_sequence_of[1] = {
  { &hf_dop_DITcontext_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_Vertex },
};

static int
dissect_dop_DITcontext(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_SuperiorToSubordinate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_SubordinateToSuperior(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_SuperiorToSubordinateModification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SuperiorToSubordinateModification_sequence, hf_index, ett_dop_SuperiorToSubordinateModification);

  return offset;
}


static const ber_sequence_t NonSpecificHierarchicalAgreement_sequence[] = {
  { &hf_dop_immediateSuperior, BER_CLASS_CON, 1, 0, dissect_x509if_DistinguishedName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_dop_NonSpecificHierarchicalAgreement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_NHOBSuperiorToSubordinate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_NHOBSubordinateToSuperior(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NHOBSubordinateToSuperior_sequence, hf_index, ett_dop_NHOBSubordinateToSuperior);

  return offset;
}



static int
dissect_dop_Precedence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 190 "../../asn1/dop/dop.cnf"
  guint32 precedence = 0;

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
dissect_dop_T_level(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_dop_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_T_basicLevels(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_basicLevels_sequence, hf_index, ett_dop_T_basicLevels);

  return offset;
}



static int
dissect_dop_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_AuthenticationLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticationLevel_choice, hf_index, ett_dop_AuthenticationLevel,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeType_set_of[1] = {
  { &hf_dop_attributeType_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_dop_SET_OF_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AttributeType_set_of, hf_index, ett_dop_SET_OF_AttributeType);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeTypeAndValue_set_of[1] = {
  { &hf_dop_attributeValue_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_AttributeTypeAndValue },
};

static int
dissect_dop_SET_OF_AttributeTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_MaxValueCount(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MaxValueCount_sequence, hf_index, ett_dop_MaxValueCount);

  return offset;
}


static const ber_sequence_t SET_OF_MaxValueCount_set_of[1] = {
  { &hf_dop_maxValueCount_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_MaxValueCount },
};

static int
dissect_dop_SET_OF_MaxValueCount(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_RestrictedValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RestrictedValue_sequence, hf_index, ett_dop_RestrictedValue);

  return offset;
}


static const ber_sequence_t SET_OF_RestrictedValue_set_of[1] = {
  { &hf_dop_restrictedBy_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_RestrictedValue },
};

static int
dissect_dop_SET_OF_RestrictedValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_RestrictedValue_set_of, hf_index, ett_dop_SET_OF_RestrictedValue);

  return offset;
}


static const ber_sequence_t SET_OF_ContextAssertion_set_of[1] = {
  { &hf_dop_contexts_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_ContextAssertion },
};

static int
dissect_dop_SET_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_ProtectedItems(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtectedItems_sequence, hf_index, ett_dop_ProtectedItems);

  return offset;
}


static const ber_sequence_t SET_OF_NameAndOptionalUID_set_of[1] = {
  { &hf_dop_name_item       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_NameAndOptionalUID },
};

static int
dissect_dop_SET_OF_NameAndOptionalUID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_NameAndOptionalUID_set_of, hf_index, ett_dop_SET_OF_NameAndOptionalUID);

  return offset;
}


static const ber_sequence_t SET_OF_SubtreeSpecification_set_of[1] = {
  { &hf_dop_subtree_item    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_SubtreeSpecification },
};

static int
dissect_dop_SET_OF_SubtreeSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_UserClasses(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserClasses_sequence, hf_index, ett_dop_UserClasses);

  return offset;
}


static const asn_namedbit GrantsAndDenials_bits[] = {
  {  0, &hf_dop_GrantsAndDenials_grantAdd, -1, -1, "grantAdd", NULL },
  {  1, &hf_dop_GrantsAndDenials_denyAdd, -1, -1, "denyAdd", NULL },
  {  2, &hf_dop_GrantsAndDenials_grantDiscloseOnError, -1, -1, "grantDiscloseOnError", NULL },
  {  3, &hf_dop_GrantsAndDenials_denyDiscloseOnError, -1, -1, "denyDiscloseOnError", NULL },
  {  4, &hf_dop_GrantsAndDenials_grantRead, -1, -1, "grantRead", NULL },
  {  5, &hf_dop_GrantsAndDenials_denyRead, -1, -1, "denyRead", NULL },
  {  6, &hf_dop_GrantsAndDenials_grantRemove, -1, -1, "grantRemove", NULL },
  {  7, &hf_dop_GrantsAndDenials_denyRemove, -1, -1, "denyRemove", NULL },
  {  8, &hf_dop_GrantsAndDenials_grantBrowse, -1, -1, "grantBrowse", NULL },
  {  9, &hf_dop_GrantsAndDenials_denyBrowse, -1, -1, "denyBrowse", NULL },
  { 10, &hf_dop_GrantsAndDenials_grantExport, -1, -1, "grantExport", NULL },
  { 11, &hf_dop_GrantsAndDenials_denyExport, -1, -1, "denyExport", NULL },
  { 12, &hf_dop_GrantsAndDenials_grantImport, -1, -1, "grantImport", NULL },
  { 13, &hf_dop_GrantsAndDenials_denyImport, -1, -1, "denyImport", NULL },
  { 14, &hf_dop_GrantsAndDenials_grantModify, -1, -1, "grantModify", NULL },
  { 15, &hf_dop_GrantsAndDenials_denyModify, -1, -1, "denyModify", NULL },
  { 16, &hf_dop_GrantsAndDenials_grantRename, -1, -1, "grantRename", NULL },
  { 17, &hf_dop_GrantsAndDenials_denyRename, -1, -1, "denyRename", NULL },
  { 18, &hf_dop_GrantsAndDenials_grantReturnDN, -1, -1, "grantReturnDN", NULL },
  { 19, &hf_dop_GrantsAndDenials_denyReturnDN, -1, -1, "denyReturnDN", NULL },
  { 20, &hf_dop_GrantsAndDenials_grantCompare, -1, -1, "grantCompare", NULL },
  { 21, &hf_dop_GrantsAndDenials_denyCompare, -1, -1, "denyCompare", NULL },
  { 22, &hf_dop_GrantsAndDenials_grantFilterMatch, -1, -1, "grantFilterMatch", NULL },
  { 23, &hf_dop_GrantsAndDenials_denyFilterMatch, -1, -1, "denyFilterMatch", NULL },
  { 24, &hf_dop_GrantsAndDenials_grantInvoke, -1, -1, "grantInvoke", NULL },
  { 25, &hf_dop_GrantsAndDenials_denyInvoke, -1, -1, "denyInvoke", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_dop_GrantsAndDenials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    GrantsAndDenials_bits, hf_index, ett_dop_GrantsAndDenials,
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
dissect_dop_ItemPermission(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ItemPermission_sequence, hf_index, ett_dop_ItemPermission);

  return offset;
}


static const ber_sequence_t SET_OF_ItemPermission_set_of[1] = {
  { &hf_dop_itemPermissions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_ItemPermission },
};

static int
dissect_dop_SET_OF_ItemPermission(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_T_itemFirst(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_UserPermission(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserPermission_sequence, hf_index, ett_dop_UserPermission);

  return offset;
}


static const ber_sequence_t SET_OF_UserPermission_set_of[1] = {
  { &hf_dop_userPermissions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dop_UserPermission },
};

static int
dissect_dop_SET_OF_UserPermission(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_T_userFirst(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_T_itemOrUserFirst(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_dop_ACIItem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ACIItem_sequence, hf_index, ett_dop_ACIItem);

  return offset;
}

/*--- PDUs ---*/

static void dissect_DSEType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_DSEType(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_DSEType_PDU);
}
static void dissect_SupplierInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_SupplierInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_SupplierInformation_PDU);
}
static void dissect_ConsumerInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_ConsumerInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_ConsumerInformation_PDU);
}
static void dissect_SupplierAndConsumers_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_SupplierAndConsumers(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_SupplierAndConsumers_PDU);
}
static void dissect_HierarchicalAgreement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_HierarchicalAgreement(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_HierarchicalAgreement_PDU);
}
static void dissect_SuperiorToSubordinate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_SuperiorToSubordinate(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_SuperiorToSubordinate_PDU);
}
static void dissect_SubordinateToSuperior_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_SubordinateToSuperior(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_SubordinateToSuperior_PDU);
}
static void dissect_SuperiorToSubordinateModification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_SuperiorToSubordinateModification(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_SuperiorToSubordinateModification_PDU);
}
static void dissect_NonSpecificHierarchicalAgreement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_NonSpecificHierarchicalAgreement(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_NonSpecificHierarchicalAgreement_PDU);
}
static void dissect_NHOBSuperiorToSubordinate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_NHOBSuperiorToSubordinate(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_NHOBSuperiorToSubordinate_PDU);
}
static void dissect_NHOBSubordinateToSuperior_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_NHOBSubordinateToSuperior(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_NHOBSubordinateToSuperior_PDU);
}
static void dissect_ACIItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_dop_ACIItem(FALSE, tvb, 0, &asn1_ctx, tree, hf_dop_ACIItem_PDU);
}


/*--- End of included file: packet-dop-fn.c ---*/
#line 86 "../../asn1/dop/packet-dop-template.c"

static int
call_dop_oid_callback(char *base_string, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *col_info)
{
  char* binding_param;

  binding_param = ep_strdup_printf("%s.%s", base_string, binding_type ? binding_type : "");

  col_append_fstr(pinfo->cinfo, COL_INFO, " %s", col_info);

  if (dissector_try_string(dop_dissector_table, binding_param, tvb, pinfo, tree)) {
     offset += tvb_length_remaining (tvb, offset);
  } else {
     proto_item *item=NULL;
     proto_tree *next_tree=NULL;

     item = proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), "Dissector for parameter %s OID:%s not implemented. Contact Wireshark developers if you want this supported", base_string, binding_type ? binding_type : "<empty>");
     if (item) {
        next_tree = proto_item_add_subtree(item, ett_dop_unknown);
     }
     offset = dissect_unknown_ber(pinfo, tvb, offset, next_tree);
     expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "Unknown binding-parameter");
   }

   return offset;
}


/*
* Dissect DOP PDUs inside a ROS PDUs
*/
static void
dissect_dop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*dop_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	char *dop_op_name;
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
		item = proto_tree_add_item(parent_tree, proto_dop, tvb, 0, -1, ENC_BIG_ENDIAN);
		tree = proto_item_add_subtree(item, ett_dop);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DOP");
  	col_clear(pinfo->cinfo, COL_INFO);

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
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DOP Argument opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
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
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DOP Result opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
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
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DOP Error opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DOP PDU");
	  return;
	}

	if(dop_dissector) {
      col_set_str(pinfo->cinfo, COL_INFO, dop_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dop_dissector)(FALSE, tvb, offset, &asn1_ctx, tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DOP PDU");
	      break;
	    }
	  }
	}
}



/*--- proto_register_dop -------------------------------------------*/
void proto_register_dop(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-dop-hfarr.c ---*/
#line 1 "../../asn1/dop/packet-dop-hfarr.c"
    { &hf_dop_DSEType_PDU,
      { "DSEType", "dop.DSEType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SupplierInformation_PDU,
      { "SupplierInformation", "dop.SupplierInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_ConsumerInformation_PDU,
      { "ConsumerInformation", "dop.ConsumerInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SupplierAndConsumers_PDU,
      { "SupplierAndConsumers", "dop.SupplierAndConsumers",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_HierarchicalAgreement_PDU,
      { "HierarchicalAgreement", "dop.HierarchicalAgreement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SuperiorToSubordinate_PDU,
      { "SuperiorToSubordinate", "dop.SuperiorToSubordinate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SubordinateToSuperior_PDU,
      { "SubordinateToSuperior", "dop.SubordinateToSuperior",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_SuperiorToSubordinateModification_PDU,
      { "SuperiorToSubordinateModification", "dop.SuperiorToSubordinateModification",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_NonSpecificHierarchicalAgreement_PDU,
      { "NonSpecificHierarchicalAgreement", "dop.NonSpecificHierarchicalAgreement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_NHOBSuperiorToSubordinate_PDU,
      { "NHOBSuperiorToSubordinate", "dop.NHOBSuperiorToSubordinate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_NHOBSubordinateToSuperior_PDU,
      { "NHOBSubordinateToSuperior", "dop.NHOBSubordinateToSuperior",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_ACIItem_PDU,
      { "ACIItem", "dop.ACIItem",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_ae_title,
      { "ae-title", "dop.ae_title",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_dop_address,
      { "address", "dop.address",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentationAddress", HFILL }},
    { &hf_dop_protocolInformation,
      { "protocolInformation", "dop.protocolInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ProtocolInformation", HFILL }},
    { &hf_dop_protocolInformation_item,
      { "ProtocolInformation", "dop.ProtocolInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_agreementID,
      { "agreementID", "dop.agreementID",
        FT_NONE, BASE_NONE, NULL, 0,
        "OperationalBindingID", HFILL }},
    { &hf_dop_supplier_is_master,
      { "supplier-is-master", "dop.supplier_is_master",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_dop_non_supplying_master,
      { "non-supplying-master", "dop.non_supplying_master",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccessPoint", HFILL }},
    { &hf_dop_consumers,
      { "consumers", "dop.consumers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AccessPoint", HFILL }},
    { &hf_dop_consumers_item,
      { "AccessPoint", "dop.AccessPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_bindingType,
      { "bindingType", "dop.bindingType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_bindingID,
      { "bindingID", "dop.bindingID",
        FT_NONE, BASE_NONE, NULL, 0,
        "OperationalBindingID", HFILL }},
    { &hf_dop_accessPoint,
      { "accessPoint", "dop.accessPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_establishInitiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_EstablishArgumentInitiator_vals), 0,
        "EstablishArgumentInitiator", HFILL }},
    { &hf_dop_establishSymmetric,
      { "symmetric", "dop.symmetric",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishSymmetric", HFILL }},
    { &hf_dop_establishRoleAInitiates,
      { "roleA-initiates", "dop.roleA_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishRoleAInitiates", HFILL }},
    { &hf_dop_establishRoleBInitiates,
      { "roleB-initiates", "dop.roleB_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishRoleBInitiates", HFILL }},
    { &hf_dop_agreement,
      { "agreement", "dop.agreement",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_valid,
      { "valid", "dop.valid",
        FT_NONE, BASE_NONE, NULL, 0,
        "Validity", HFILL }},
    { &hf_dop_securityParameters,
      { "securityParameters", "dop.securityParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_unsignedEstablishOperationalBindingArgument,
      { "unsignedEstablishOperationalBindingArgument", "dop.unsignedEstablishOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgumentData", HFILL }},
    { &hf_dop_signedEstablishOperationalBindingArgument,
      { "signedEstablishOperationalBindingArgument", "dop.signedEstablishOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_establishOperationalBindingArgument,
      { "establishOperationalBindingArgument", "dop.establishOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgumentData", HFILL }},
    { &hf_dop_algorithmIdentifier,
      { "algorithmIdentifier", "dop.algorithmIdentifier",
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
      { "now", "dop.now",
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
      { "explicitTermination", "dop.explicitTermination",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_utcTime,
      { "utcTime", "dop.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_generalizedTime,
      { "generalizedTime", "dop.generalizedTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_initiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_T_initiator_vals), 0,
        NULL, HFILL }},
    { &hf_dop_symmetric,
      { "symmetric", "dop.symmetric",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_roleA_replies,
      { "roleA-replies", "dop.roleA_replies",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_roleB_replies,
      { "roleB-replies", "dop.roleB_replies",
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
      { "Attribute", "dop.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_modifyInitiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_ModifyArgumentInitiator_vals), 0,
        "ModifyArgumentInitiator", HFILL }},
    { &hf_dop_modifySymmetric,
      { "symmetric", "dop.symmetric",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifySymmetric", HFILL }},
    { &hf_dop_modifyRoleAInitiates,
      { "roleA-initiates", "dop.roleA_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyRoleAInitiates", HFILL }},
    { &hf_dop_modifyRoleBInitiates,
      { "roleB-initiates", "dop.roleB_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyRoleBInitiates", HFILL }},
    { &hf_dop_newBindingID,
      { "newBindingID", "dop.newBindingID",
        FT_NONE, BASE_NONE, NULL, 0,
        "OperationalBindingID", HFILL }},
    { &hf_dop_argumentNewAgreement,
      { "newAgreement", "dop.newAgreement",
        FT_NONE, BASE_NONE, NULL, 0,
        "ArgumentNewAgreement", HFILL }},
    { &hf_dop_unsignedModifyOperationalBindingArgument,
      { "unsignedModifyOperationalBindingArgument", "dop.unsignedModifyOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgumentData", HFILL }},
    { &hf_dop_signedModifyOperationalBindingArgument,
      { "signedModifyOperationalBindingArgument", "dop.signedModifyOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_modifyOperationalBindingArgument,
      { "modifyOperationalBindingArgument", "dop.modifyOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgumentData", HFILL }},
    { &hf_dop_null,
      { "null", "dop.null",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_protectedModifyResult,
      { "protected", "dop.protected",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedModifyResult", HFILL }},
    { &hf_dop_modifyOperationalBindingResultData,
      { "modifyOperationalBindingResultData", "dop.modifyOperationalBindingResultData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_resultNewAgreement,
      { "newAgreement", "dop.newAgreement",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResultNewAgreement", HFILL }},
    { &hf_dop_terminateInitiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_TerminateArgumentInitiator_vals), 0,
        "TerminateArgumentInitiator", HFILL }},
    { &hf_dop_terminateSymmetric,
      { "symmetric", "dop.symmetric",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateSymmetric", HFILL }},
    { &hf_dop_terminateRoleAInitiates,
      { "roleA-initiates", "dop.roleA_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateRoleAInitiates", HFILL }},
    { &hf_dop_terminateRoleBInitiates,
      { "roleB-initiates", "dop.roleB_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateRoleBInitiates", HFILL }},
    { &hf_dop_terminateAtTime,
      { "terminateAt", "dop.terminateAt",
        FT_UINT32, BASE_DEC, VALS(dop_Time_vals), 0,
        "Time", HFILL }},
    { &hf_dop_unsignedTerminateOperationalBindingArgument,
      { "unsignedTerminateOperationalBindingArgument", "dop.unsignedTerminateOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgumentData", HFILL }},
    { &hf_dop_signedTerminateOperationalBindingArgument,
      { "signedTerminateOperationalBindingArgument", "dop.signedTerminateOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_terminateOperationalBindingArgument,
      { "terminateOperationalBindingArgument", "dop.terminateOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgumentData", HFILL }},
    { &hf_dop_protectedTerminateResult,
      { "protected", "dop.protected",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedTerminateResult", HFILL }},
    { &hf_dop_terminateOperationalBindingResultData,
      { "terminateOperationalBindingResultData", "dop.terminateOperationalBindingResultData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_terminateAtGeneralizedTime,
      { "terminateAt", "dop.terminateAt",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_dop_problem,
      { "problem", "dop.problem",
        FT_UINT32, BASE_DEC, VALS(dop_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_dop_agreementProposal,
      { "agreementProposal", "dop.agreementProposal",
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
      { "Attribute", "dop.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_immediateSuperiorInfo,
      { "immediateSuperiorInfo", "dop.immediateSuperiorInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_dop_immediateSuperiorInfo_item,
      { "Attribute", "dop.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_DITcontext_item,
      { "Vertex", "dop.Vertex",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_admPointInfo,
      { "admPointInfo", "dop.admPointInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_dop_admPointInfo_item,
      { "Attribute", "dop.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_subentries,
      { "subentries", "dop.subentries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SubentryInfo", HFILL }},
    { &hf_dop_subentries_item,
      { "SubentryInfo", "dop.SubentryInfo",
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
      { "Attribute", "dop.Attribute",
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
      { "itemFirst", "dop.itemFirst",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_protectedItems,
      { "protectedItems", "dop.protectedItems",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_itemPermissions,
      { "itemPermissions", "dop.itemPermissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ItemPermission", HFILL }},
    { &hf_dop_itemPermissions_item,
      { "ItemPermission", "dop.ItemPermission",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_userFirst,
      { "userFirst", "dop.userFirst",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_userClasses,
      { "userClasses", "dop.userClasses",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_userPermissions,
      { "userPermissions", "dop.userPermissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_UserPermission", HFILL }},
    { &hf_dop_userPermissions_item,
      { "UserPermission", "dop.UserPermission",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_entry,
      { "entry", "dop.entry",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_allUserAttributeTypes,
      { "allUserAttributeTypes", "dop.allUserAttributeTypes",
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
      { "allUserAttributeTypesAndValues", "dop.allUserAttributeTypesAndValues",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_attributeValue,
      { "attributeValue", "dop.attributeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeTypeAndValue", HFILL }},
    { &hf_dop_attributeValue_item,
      { "AttributeTypeAndValue", "dop.AttributeTypeAndValue",
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
      { "MaxValueCount", "dop.MaxValueCount",
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
      { "RestrictedValue", "dop.RestrictedValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_contexts,
      { "contexts", "dop.contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ContextAssertion", HFILL }},
    { &hf_dop_contexts_item,
      { "ContextAssertion", "dop.ContextAssertion",
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
      { "allUsers", "dop.allUsers",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_thisEntry,
      { "thisEntry", "dop.thisEntry",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_name,
      { "name", "dop.name",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_NameAndOptionalUID", HFILL }},
    { &hf_dop_name_item,
      { "NameAndOptionalUID", "dop.NameAndOptionalUID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_userGroup,
      { "userGroup", "dop.userGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_NameAndOptionalUID", HFILL }},
    { &hf_dop_userGroup_item,
      { "NameAndOptionalUID", "dop.NameAndOptionalUID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_subtree,
      { "subtree", "dop.subtree",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SubtreeSpecification", HFILL }},
    { &hf_dop_subtree_item,
      { "SubtreeSpecification", "dop.SubtreeSpecification",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_grantsAndDenials,
      { "grantsAndDenials", "dop.grantsAndDenials",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_dop_basicLevels,
      { "basicLevels", "dop.basicLevels",
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
      { "other", "dop.other",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_dop_DSEType_root,
      { "root", "dop.root",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_DSEType_glue,
      { "glue", "dop.glue",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_DSEType_cp,
      { "cp", "dop.cp",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_DSEType_entry,
      { "entry", "dop.entry",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_DSEType_alias,
      { "alias", "dop.alias",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dop_DSEType_subr,
      { "subr", "dop.subr",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_DSEType_nssr,
      { "nssr", "dop.nssr",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_DSEType_supr,
      { "supr", "dop.supr",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_DSEType_xr,
      { "xr", "dop.xr",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_DSEType_admPoint,
      { "admPoint", "dop.admPoint",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_DSEType_subentry,
      { "subentry", "dop.subentry",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_DSEType_shadow,
      { "shadow", "dop.shadow",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_DSEType_immSupr,
      { "immSupr", "dop.immSupr",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_DSEType_rhob,
      { "rhob", "dop.rhob",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_DSEType_sa,
      { "sa", "dop.sa",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_DSEType_dsSubentry,
      { "dsSubentry", "dop.dsSubentry",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_DSEType_familyMember,
      { "familyMember", "dop.familyMember",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_DSEType_ditBridge,
      { "ditBridge", "dop.ditBridge",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_DSEType_writeableCopy,
      { "writeableCopy", "dop.writeableCopy",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantAdd,
      { "grantAdd", "dop.grantAdd",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyAdd,
      { "denyAdd", "dop.denyAdd",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantDiscloseOnError,
      { "grantDiscloseOnError", "dop.grantDiscloseOnError",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyDiscloseOnError,
      { "denyDiscloseOnError", "dop.denyDiscloseOnError",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantRead,
      { "grantRead", "dop.grantRead",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyRead,
      { "denyRead", "dop.denyRead",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantRemove,
      { "grantRemove", "dop.grantRemove",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyRemove,
      { "denyRemove", "dop.denyRemove",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantBrowse,
      { "grantBrowse", "dop.grantBrowse",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyBrowse,
      { "denyBrowse", "dop.denyBrowse",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantExport,
      { "grantExport", "dop.grantExport",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyExport,
      { "denyExport", "dop.denyExport",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantImport,
      { "grantImport", "dop.grantImport",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyImport,
      { "denyImport", "dop.denyImport",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantModify,
      { "grantModify", "dop.grantModify",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyModify,
      { "denyModify", "dop.denyModify",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantRename,
      { "grantRename", "dop.grantRename",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyRename,
      { "denyRename", "dop.denyRename",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantReturnDN,
      { "grantReturnDN", "dop.grantReturnDN",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyReturnDN,
      { "denyReturnDN", "dop.denyReturnDN",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantCompare,
      { "grantCompare", "dop.grantCompare",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyCompare,
      { "denyCompare", "dop.denyCompare",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantFilterMatch,
      { "grantFilterMatch", "dop.grantFilterMatch",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyFilterMatch,
      { "denyFilterMatch", "dop.denyFilterMatch",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_grantInvoke,
      { "grantInvoke", "dop.grantInvoke",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_dop_GrantsAndDenials_denyInvoke,
      { "denyInvoke", "dop.denyInvoke",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

/*--- End of included file: packet-dop-hfarr.c ---*/
#line 241 "../../asn1/dop/packet-dop-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_dop,
    &ett_dop_unknown,

/*--- Included file: packet-dop-ettarr.c ---*/
#line 1 "../../asn1/dop/packet-dop-ettarr.c"
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

/*--- End of included file: packet-dop-ettarr.c ---*/
#line 248 "../../asn1/dop/packet-dop-template.c"
  };

  module_t *dop_module;

  /* Register protocol */
  proto_dop = proto_register_protocol(PNAME, PSNAME, PFNAME);

  register_dissector("dop", dissect_dop, proto_dop);

  dop_dissector_table = register_dissector_table("dop.oid", "DOP OID Dissectors", FT_STRING, BASE_NONE);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DOP, particularly our port */

  dop_module = prefs_register_protocol_subtree("OSI/X.500", proto_dop, prefs_register_dop);

  prefs_register_uint_preference(dop_module, "tcp.port", "DOP TCP Port",
				 "Set the port for DOP operations (if other"
				 " than the default of 102)",
				 10, &global_dop_tcp_port);


}


/*--- proto_reg_handoff_dop --- */
void proto_reg_handoff_dop(void) {
  dissector_handle_t dop_handle;


/*--- Included file: packet-dop-dis-tab.c ---*/
#line 1 "../../asn1/dop/packet-dop-dis-tab.c"
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


/*--- End of included file: packet-dop-dis-tab.c ---*/
#line 281 "../../asn1/dop/packet-dop-template.c"
  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-directory-operational-binding-management","2.5.3.3");

  /* ABSTRACT SYNTAXES */

  /* Register DOP with ROS (with no use of RTSE) */
  dop_handle = find_dissector("dop");
  register_ros_oid_dissector_handle("2.5.9.4", dop_handle, 0, "id-as-directory-operational-binding-management", FALSE);

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

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");

}

static void
prefs_register_dop(void)
{
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete_uint("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_dop_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add_uint("tcp.port", tcp_port, tpkt_handle);

}
