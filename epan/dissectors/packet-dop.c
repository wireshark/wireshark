/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-dop.c                                                             */
/* ../../tools/asn2wrs.py -b -e -p dop -c dop.cnf -s packet-dop-template dop.asn */

/* Input file: packet-dop-template.c */

#line 1 "packet-dop-template.c"
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

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
static guint tcp_port = 0;
static dissector_handle_t tpkt_handle = NULL;
void prefs_register_dop(void); /* forwad declaration for use in preferences registration */

/* Initialize the protocol and registered fields */
int proto_dop = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;
static const char *binding_type = NULL; /* binding_type */

static int call_dop_oid_callback(char *base_oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *col_info);


/*--- Included file: packet-dop-hf.c ---*/
#line 1 "packet-dop-hf.c"
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
static int hf_dop_bindingType = -1;               /* OBJECT_IDENTIFIER */
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
static int hf_dop_identifier = -1;                /* INTEGER */
static int hf_dop_version = -1;                   /* INTEGER */
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
#line 70 "packet-dop-template.c"

/* Initialize the subtree pointers */
static gint ett_dop = -1;

/*--- Included file: packet-dop-ett.c ---*/
#line 1 "packet-dop-ett.c"
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
#line 74 "packet-dop-template.c"


/*--- Included file: packet-dop-fn.c ---*/
#line 1 "packet-dop-fn.c"
/*--- Fields for imported types ---*/

static int dissect_ae_title(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_dop_ae_title);
}
static int dissect_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PresentationAddress(FALSE, tvb, offset, pinfo, tree, hf_dop_address);
}
static int dissect_protocolInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_ProtocolInformation(FALSE, tvb, offset, pinfo, tree, hf_dop_protocolInformation_item);
}
static int dissect_non_supplying_master(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_AccessPoint(FALSE, tvb, offset, pinfo, tree, hf_dop_non_supplying_master);
}
static int dissect_consumers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_AccessPoint(FALSE, tvb, offset, pinfo, tree, hf_dop_consumers_item);
}
static int dissect_accessPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_AccessPoint(FALSE, tvb, offset, pinfo, tree, hf_dop_accessPoint);
}
static int dissect_securityParameters(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_SecurityParameters(FALSE, tvb, offset, pinfo, tree, hf_dop_securityParameters);
}
static int dissect_algorithmIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_dop_algorithmIdentifier);
}
static int dissect_performer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dop_performer);
}
static int dissect_notification_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_notification_item);
}
static int dissect_rdn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RelativeDistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dop_rdn);
}
static int dissect_immediateSuperior(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_dop_immediateSuperior);
}
static int dissect_entryInfo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_entryInfo_item);
}
static int dissect_immediateSuperiorInfo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_immediateSuperiorInfo_item);
}
static int dissect_admPointInfo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_admPointInfo_item);
}
static int dissect_accessPoints(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_MasterAndShadowAccessPoints(FALSE, tvb, offset, pinfo, tree, hf_dop_accessPoints);
}
static int dissect_info_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_info_item);
}
static int dissect_identificationTag(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_dop_identificationTag);
}
static int dissect_attributeType_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dop_attributeType_item);
}
static int dissect_allAttributeValues_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dop_allAttributeValues_item);
}
static int dissect_attributeValue_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_AttributeTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_dop_attributeValue_item);
}
static int dissect_selfValue_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dop_selfValue_item);
}
static int dissect_rangeOfValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_Filter(FALSE, tvb, offset, pinfo, tree, hf_dop_rangeOfValues);
}
static int dissect_contexts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_dop_contexts_item);
}
static int dissect_classes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Refinement(FALSE, tvb, offset, pinfo, tree, hf_dop_classes);
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dop_type);
}
static int dissect_valuesIn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dop_valuesIn);
}
static int dissect_name_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NameAndOptionalUID(FALSE, tvb, offset, pinfo, tree, hf_dop_name_item);
}
static int dissect_userGroup_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NameAndOptionalUID(FALSE, tvb, offset, pinfo, tree, hf_dop_userGroup_item);
}
static int dissect_subtree_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_SubtreeSpecification(FALSE, tvb, offset, pinfo, tree, hf_dop_subtree_item);
}
static int dissect_other(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(FALSE, tvb, offset, pinfo, tree, hf_dop_other);
}


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
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_dop_DSEType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    DSEType_bits, hf_index, ett_dop_DSEType,
                                    NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ProtocolInformation_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_protocolInformation_item },
};

static int
dissect_dop_SET_OF_ProtocolInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ProtocolInformation_set_of, hf_index, ett_dop_SET_OF_ProtocolInformation);

  return offset;
}
static int dissect_protocolInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_ProtocolInformation(FALSE, tvb, offset, pinfo, tree, hf_dop_protocolInformation);
}



static int
dissect_dop_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 172 "dop.cnf"
	guint32	value;

	  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &value);


	if (check_col(pinfo->cinfo, COL_INFO)) {
		if(hf_index == hf_dop_identifier) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " id=%d", value);
		} else if (hf_index == hf_dop_version) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ",%d", value);
		}
  	}



  return offset;
}
static int dissect_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dop_identifier);
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dop_version);
}
static int dissect_maxImmSub(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dop_maxImmSub);
}
static int dissect_maxCount(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dop_maxCount);
}
static int dissect_localQualifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_dop_localQualifier);
}


static const ber_sequence_t OperationalBindingID_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { 0, 0, 0, NULL }
};

int
dissect_dop_OperationalBindingID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OperationalBindingID_sequence, hf_index, ett_dop_OperationalBindingID);

  return offset;
}
static int dissect_agreementID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_OperationalBindingID(FALSE, tvb, offset, pinfo, tree, hf_dop_agreementID);
}
static int dissect_bindingID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_OperationalBindingID(FALSE, tvb, offset, pinfo, tree, hf_dop_bindingID);
}
static int dissect_newBindingID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_OperationalBindingID(FALSE, tvb, offset, pinfo, tree, hf_dop_newBindingID);
}


static const ber_sequence_t SupplierOrConsumer_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_ae_title },
  { BER_CLASS_CON, 1, 0, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_protocolInformation },
  { BER_CLASS_CON, 3, 0, dissect_agreementID },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_SupplierOrConsumer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SupplierOrConsumer_set, hf_index, ett_dop_SupplierOrConsumer);

  return offset;
}



static int
dissect_dop_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_supplier_is_master(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dop_supplier_is_master);
}
static int dissect_aliasDereferenced(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dop_aliasDereferenced);
}
static int dissect_alias(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dop_alias);
}
static int dissect_signed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_dop_signed);
}


static const ber_sequence_t SupplierInformation_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_ae_title },
  { BER_CLASS_CON, 1, 0, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_protocolInformation },
  { BER_CLASS_CON, 3, 0, dissect_agreementID },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_supplier_is_master },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_non_supplying_master },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_SupplierInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SupplierInformation_set, hf_index, ett_dop_SupplierInformation);

  return offset;
}



static int
dissect_dop_ConsumerInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dop_SupplierOrConsumer(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_AccessPoint_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_consumers_item },
};

static int
dissect_dop_SET_OF_AccessPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AccessPoint_set_of, hf_index, ett_dop_SET_OF_AccessPoint);

  return offset;
}
static int dissect_consumers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_AccessPoint(FALSE, tvb, offset, pinfo, tree, hf_dop_consumers);
}


static const ber_sequence_t SupplierAndConsumers_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_ae_title },
  { BER_CLASS_CON, 1, 0, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_protocolInformation },
  { BER_CLASS_CON, 3, 0, dissect_consumers },
  { 0, 0, 0, NULL }
};

int
dissect_dop_SupplierAndConsumers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SupplierAndConsumers_set, hf_index, ett_dop_SupplierAndConsumers);

  return offset;
}



static int
dissect_dop_DSAOperationalManagementBindArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_dop_DSAOperationalManagementBindResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindArgument(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_dop_DSAOperationalManagementBindError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_dap_DirectoryBindError(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_dop_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 94 "dop.cnf"
  const char *name;

    offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &binding_type);


  if(check_col(pinfo->cinfo, COL_INFO)) {
    name = get_ber_oid_name(binding_type);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name ? name : binding_type);
  }



  return offset;
}
static int dissect_bindingType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_dop_bindingType);
}



static int
dissect_dop_EstablishSymmetric(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 104 "dop.cnf"

  offset = call_dop_oid_callback("dop.establish.symmetric", tvb, offset, pinfo, tree, "symmetric");



  return offset;
}
static int dissect_establishSymmetric(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_EstablishSymmetric(FALSE, tvb, offset, pinfo, tree, hf_dop_establishSymmetric);
}



static int
dissect_dop_EstablishRoleAInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 108 "dop.cnf"

  offset = call_dop_oid_callback("dop.establish.rolea", tvb, offset, pinfo, tree, "roleA");



  return offset;
}
static int dissect_establishRoleAInitiates(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_EstablishRoleAInitiates(FALSE, tvb, offset, pinfo, tree, hf_dop_establishRoleAInitiates);
}



static int
dissect_dop_EstablishRoleBInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 112 "dop.cnf"

  offset = call_dop_oid_callback("dop.establish.roleb", tvb, offset, pinfo, tree, "roleB");



  return offset;
}
static int dissect_establishRoleBInitiates(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_EstablishRoleBInitiates(FALSE, tvb, offset, pinfo, tree, hf_dop_establishRoleBInitiates);
}


static const value_string dop_EstablishArgumentInitiator_vals[] = {
  {   3, "symmetric" },
  {   4, "roleA-initiates" },
  {   5, "roleB-initiates" },
  { 0, NULL }
};

static const ber_choice_t EstablishArgumentInitiator_choice[] = {
  {   3, BER_CLASS_CON, 3, 0, dissect_establishSymmetric },
  {   4, BER_CLASS_CON, 4, 0, dissect_establishRoleAInitiates },
  {   5, BER_CLASS_CON, 5, 0, dissect_establishRoleBInitiates },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_EstablishArgumentInitiator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 EstablishArgumentInitiator_choice, hf_index, ett_dop_EstablishArgumentInitiator,
                                 NULL);

  return offset;
}
static int dissect_establishInitiator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_EstablishArgumentInitiator(FALSE, tvb, offset, pinfo, tree, hf_dop_establishInitiator);
}



static int
dissect_dop_T_agreement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 140 "dop.cnf"

  offset = call_dop_oid_callback("dop.agreement", tvb, offset, pinfo, tree, NULL);



  return offset;
}
static int dissect_agreement(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_agreement(FALSE, tvb, offset, pinfo, tree, hf_dop_agreement);
}



static int
dissect_dop_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_now(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_NULL(FALSE, tvb, offset, pinfo, tree, hf_dop_now);
}
static int dissect_explicitTermination(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_NULL(FALSE, tvb, offset, pinfo, tree, hf_dop_explicitTermination);
}
static int dissect_null(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_NULL(FALSE, tvb, offset, pinfo, tree, hf_dop_null);
}
static int dissect_entry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_NULL(FALSE, tvb, offset, pinfo, tree, hf_dop_entry);
}
static int dissect_allUserAttributeTypes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_NULL(FALSE, tvb, offset, pinfo, tree, hf_dop_allUserAttributeTypes);
}
static int dissect_allUserAttributeTypesAndValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_NULL(FALSE, tvb, offset, pinfo, tree, hf_dop_allUserAttributeTypesAndValues);
}
static int dissect_allUsers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_NULL(FALSE, tvb, offset, pinfo, tree, hf_dop_allUsers);
}
static int dissect_thisEntry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_NULL(FALSE, tvb, offset, pinfo, tree, hf_dop_thisEntry);
}



static int
dissect_dop_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_utcTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_UTCTime(FALSE, tvb, offset, pinfo, tree, hf_dop_utcTime);
}



static int
dissect_dop_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_generalizedTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_dop_generalizedTime);
}
static int dissect_terminateAtGeneralizedTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_dop_terminateAtGeneralizedTime);
}


static const value_string dop_Time_vals[] = {
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
dissect_dop_Time(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Time_choice, hf_index, ett_dop_Time,
                                 NULL);

  return offset;
}
static int dissect_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_Time(FALSE, tvb, offset, pinfo, tree, hf_dop_time);
}
static int dissect_terminateAtTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_Time(FALSE, tvb, offset, pinfo, tree, hf_dop_terminateAtTime);
}
static int dissect_retryAt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_Time(FALSE, tvb, offset, pinfo, tree, hf_dop_retryAt);
}


static const value_string dop_T_validFrom_vals[] = {
  {   0, "now" },
  {   1, "time" },
  { 0, NULL }
};

static const ber_choice_t T_validFrom_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_now },
  {   1, BER_CLASS_CON, 1, 0, dissect_time },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_T_validFrom(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_validFrom_choice, hf_index, ett_dop_T_validFrom,
                                 NULL);

  return offset;
}
static int dissect_validFrom(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_validFrom(FALSE, tvb, offset, pinfo, tree, hf_dop_validFrom);
}


static const value_string dop_T_validUntil_vals[] = {
  {   0, "explicitTermination" },
  {   1, "time" },
  { 0, NULL }
};

static const ber_choice_t T_validUntil_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_explicitTermination },
  {   1, BER_CLASS_CON, 1, 0, dissect_time },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_T_validUntil(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_validUntil_choice, hf_index, ett_dop_T_validUntil,
                                 NULL);

  return offset;
}
static int dissect_validUntil(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_validUntil(FALSE, tvb, offset, pinfo, tree, hf_dop_validUntil);
}


static const ber_sequence_t Validity_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_validFrom },
  { BER_CLASS_CON, 1, 0, dissect_validUntil },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_Validity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Validity_sequence, hf_index, ett_dop_Validity);

  return offset;
}
static int dissect_valid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_Validity(FALSE, tvb, offset, pinfo, tree, hf_dop_valid);
}


static const ber_sequence_t EstablishOperationalBindingArgumentData_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_bindingType },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_bindingID },
  { BER_CLASS_CON, 2, 0, dissect_accessPoint },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_establishInitiator },
  { BER_CLASS_CON, 6, 0, dissect_agreement },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_valid },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_EstablishOperationalBindingArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EstablishOperationalBindingArgumentData_sequence, hf_index, ett_dop_EstablishOperationalBindingArgumentData);

  return offset;
}
static int dissect_unsignedEstablishOperationalBindingArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_EstablishOperationalBindingArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dop_unsignedEstablishOperationalBindingArgument);
}
static int dissect_establishOperationalBindingArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_EstablishOperationalBindingArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dop_establishOperationalBindingArgument);
}



static int
dissect_dop_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_encrypted(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_dop_encrypted);
}


static const ber_sequence_t T_signedEstablishOperationalBindingArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_establishOperationalBindingArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_T_signedEstablishOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedEstablishOperationalBindingArgument_sequence, hf_index, ett_dop_T_signedEstablishOperationalBindingArgument);

  return offset;
}
static int dissect_signedEstablishOperationalBindingArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_signedEstablishOperationalBindingArgument(FALSE, tvb, offset, pinfo, tree, hf_dop_signedEstablishOperationalBindingArgument);
}


static const value_string dop_EstablishOperationalBindingArgument_vals[] = {
  {   0, "unsignedEstablishOperationalBindingArgument" },
  {   1, "signedEstablishOperationalBindingArgument" },
  { 0, NULL }
};

static const ber_choice_t EstablishOperationalBindingArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_unsignedEstablishOperationalBindingArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedEstablishOperationalBindingArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_EstablishOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 EstablishOperationalBindingArgument_choice, hf_index, ett_dop_EstablishOperationalBindingArgument,
                                 NULL);

  return offset;
}



static int
dissect_dop_T_symmetric(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 144 "dop.cnf"

  offset = call_dop_oid_callback("dop.establish.symmetric", tvb, offset, pinfo, tree, "symmetric"); 



  return offset;
}
static int dissect_symmetric(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_symmetric(FALSE, tvb, offset, pinfo, tree, hf_dop_symmetric);
}



static int
dissect_dop_T_roleA_replies(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 148 "dop.cnf"

  offset = call_dop_oid_callback("dop.establish.rolea", tvb, offset, pinfo, tree, "roleA");



  return offset;
}
static int dissect_roleA_replies(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_roleA_replies(FALSE, tvb, offset, pinfo, tree, hf_dop_roleA_replies);
}



static int
dissect_dop_T_roleB_replies(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 152 "dop.cnf"

  offset = call_dop_oid_callback("dop.establish.roleb", tvb, offset, pinfo, tree, "roleB");



  return offset;
}
static int dissect_roleB_replies(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_roleB_replies(FALSE, tvb, offset, pinfo, tree, hf_dop_roleB_replies);
}


static const value_string dop_T_initiator_vals[] = {
  {   3, "symmetric" },
  {   4, "roleA-replies" },
  {   5, "roleB-replies" },
  { 0, NULL }
};

static const ber_choice_t T_initiator_choice[] = {
  {   3, BER_CLASS_CON, 3, 0, dissect_symmetric },
  {   4, BER_CLASS_CON, 4, 0, dissect_roleA_replies },
  {   5, BER_CLASS_CON, 5, 0, dissect_roleB_replies },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_T_initiator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_initiator_choice, hf_index, ett_dop_T_initiator,
                                 NULL);

  return offset;
}
static int dissect_initiator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_initiator(FALSE, tvb, offset, pinfo, tree, hf_dop_initiator);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_Attribute_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_notification_item },
};

static int
dissect_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_Attribute_sequence_of, hf_index, ett_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute);

  return offset;
}
static int dissect_notification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SEQUENCE_SIZE_1_MAX_OF_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_notification);
}


static const ber_sequence_t EstablishOperationalBindingResult_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_bindingType },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_bindingID },
  { BER_CLASS_CON, 2, 0, dissect_accessPoint },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_initiator },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_EstablishOperationalBindingResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EstablishOperationalBindingResult_sequence, hf_index, ett_dop_EstablishOperationalBindingResult);

  return offset;
}



static int
dissect_dop_ModifySymmetric(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 116 "dop.cnf"

  offset = call_dop_oid_callback("dop.modify.symmetric", tvb, offset, pinfo, tree, "symmetric");



  return offset;
}
static int dissect_modifySymmetric(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ModifySymmetric(FALSE, tvb, offset, pinfo, tree, hf_dop_modifySymmetric);
}



static int
dissect_dop_ModifyRoleAInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 120 "dop.cnf"

  offset = call_dop_oid_callback("dop.modify.rolea", tvb, offset, pinfo, tree, "roleA");



  return offset;
}
static int dissect_modifyRoleAInitiates(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ModifyRoleAInitiates(FALSE, tvb, offset, pinfo, tree, hf_dop_modifyRoleAInitiates);
}



static int
dissect_dop_ModifyRoleBInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 124 "dop.cnf"

  offset = call_dop_oid_callback("dop.modify.roleb", tvb, offset, pinfo, tree, "roleB");



  return offset;
}
static int dissect_modifyRoleBInitiates(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ModifyRoleBInitiates(FALSE, tvb, offset, pinfo, tree, hf_dop_modifyRoleBInitiates);
}


static const value_string dop_ModifyArgumentInitiator_vals[] = {
  {   3, "symmetric" },
  {   4, "roleA-initiates" },
  {   5, "roleB-initiates" },
  { 0, NULL }
};

static const ber_choice_t ModifyArgumentInitiator_choice[] = {
  {   3, BER_CLASS_CON, 3, 0, dissect_modifySymmetric },
  {   4, BER_CLASS_CON, 4, 0, dissect_modifyRoleAInitiates },
  {   5, BER_CLASS_CON, 5, 0, dissect_modifyRoleBInitiates },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyArgumentInitiator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ModifyArgumentInitiator_choice, hf_index, ett_dop_ModifyArgumentInitiator,
                                 NULL);

  return offset;
}
static int dissect_modifyInitiator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ModifyArgumentInitiator(FALSE, tvb, offset, pinfo, tree, hf_dop_modifyInitiator);
}



static int
dissect_dop_ArgumentNewAgreement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 164 "dop.cnf"

  offset = call_dop_oid_callback("dop.agreement", tvb, offset, pinfo, tree, NULL);




  return offset;
}
static int dissect_argumentNewAgreement(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ArgumentNewAgreement(FALSE, tvb, offset, pinfo, tree, hf_dop_argumentNewAgreement);
}


static const ber_sequence_t ModifyOperationalBindingArgumentData_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_bindingType },
  { BER_CLASS_CON, 1, 0, dissect_bindingID },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_accessPoint },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_modifyInitiator },
  { BER_CLASS_CON, 6, 0, dissect_newBindingID },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_argumentNewAgreement },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_valid },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModifyOperationalBindingArgumentData_sequence, hf_index, ett_dop_ModifyOperationalBindingArgumentData);

  return offset;
}
static int dissect_unsignedModifyOperationalBindingArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ModifyOperationalBindingArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dop_unsignedModifyOperationalBindingArgument);
}
static int dissect_modifyOperationalBindingArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ModifyOperationalBindingArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dop_modifyOperationalBindingArgument);
}


static const ber_sequence_t T_signedModifyOperationalBindingArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_modifyOperationalBindingArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_T_signedModifyOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedModifyOperationalBindingArgument_sequence, hf_index, ett_dop_T_signedModifyOperationalBindingArgument);

  return offset;
}
static int dissect_signedModifyOperationalBindingArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_signedModifyOperationalBindingArgument(FALSE, tvb, offset, pinfo, tree, hf_dop_signedModifyOperationalBindingArgument);
}


static const value_string dop_ModifyOperationalBindingArgument_vals[] = {
  {   0, "unsignedModifyOperationalBindingArgument" },
  {   1, "signedModifyOperationalBindingArgument" },
  { 0, NULL }
};

static const ber_choice_t ModifyOperationalBindingArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_unsignedModifyOperationalBindingArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedModifyOperationalBindingArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ModifyOperationalBindingArgument_choice, hf_index, ett_dop_ModifyOperationalBindingArgument,
                                 NULL);

  return offset;
}



static int
dissect_dop_ResultNewAgreement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 160 "dop.cnf"

  offset = call_dop_oid_callback("dop.agreement", tvb, offset, pinfo, tree, NULL);



  return offset;
}
static int dissect_resultNewAgreement(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ResultNewAgreement(FALSE, tvb, offset, pinfo, tree, hf_dop_resultNewAgreement);
}


static const ber_sequence_t ModifyOperationalBindingResultData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_newBindingID },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_bindingType },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_resultNewAgreement },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_valid },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModifyOperationalBindingResultData_sequence, hf_index, ett_dop_ModifyOperationalBindingResultData);

  return offset;
}
static int dissect_modifyOperationalBindingResultData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ModifyOperationalBindingResultData(FALSE, tvb, offset, pinfo, tree, hf_dop_modifyOperationalBindingResultData);
}


static const ber_sequence_t ProtectedModifyResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_modifyOperationalBindingResultData },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_ProtectedModifyResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ProtectedModifyResult_sequence, hf_index, ett_dop_ProtectedModifyResult);

  return offset;
}
static int dissect_protectedModifyResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ProtectedModifyResult(FALSE, tvb, offset, pinfo, tree, hf_dop_protectedModifyResult);
}


static const value_string dop_ModifyOperationalBindingResult_vals[] = {
  {   0, "null" },
  {   1, "protected" },
  { 0, NULL }
};

static const ber_choice_t ModifyOperationalBindingResult_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_null },
  {   1, BER_CLASS_CON, 1, 0, dissect_protectedModifyResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_ModifyOperationalBindingResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ModifyOperationalBindingResult_choice, hf_index, ett_dop_ModifyOperationalBindingResult,
                                 NULL);

  return offset;
}



static int
dissect_dop_TerminateSymmetric(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 128 "dop.cnf"

  offset = call_dop_oid_callback("dop.terminate.symmetric", tvb, offset, pinfo, tree, "symmetric");



  return offset;
}
static int dissect_terminateSymmetric(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_TerminateSymmetric(FALSE, tvb, offset, pinfo, tree, hf_dop_terminateSymmetric);
}



static int
dissect_dop_TerminateRoleAInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 132 "dop.cnf"

  offset = call_dop_oid_callback("dop.terminate.rolea", tvb, offset, pinfo, tree, "roleA");



  return offset;
}
static int dissect_terminateRoleAInitiates(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_TerminateRoleAInitiates(FALSE, tvb, offset, pinfo, tree, hf_dop_terminateRoleAInitiates);
}



static int
dissect_dop_TerminateRoleBInitiates(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 136 "dop.cnf"

  offset = call_dop_oid_callback("dop.terminate.roleb", tvb, offset, pinfo, tree, "roleB");



  return offset;
}
static int dissect_terminateRoleBInitiates(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_TerminateRoleBInitiates(FALSE, tvb, offset, pinfo, tree, hf_dop_terminateRoleBInitiates);
}


static const value_string dop_TerminateArgumentInitiator_vals[] = {
  {   2, "symmetric" },
  {   3, "roleA-initiates" },
  {   4, "roleB-initiates" },
  { 0, NULL }
};

static const ber_choice_t TerminateArgumentInitiator_choice[] = {
  {   2, BER_CLASS_CON, 2, 0, dissect_terminateSymmetric },
  {   3, BER_CLASS_CON, 3, 0, dissect_terminateRoleAInitiates },
  {   4, BER_CLASS_CON, 4, 0, dissect_terminateRoleBInitiates },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateArgumentInitiator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 TerminateArgumentInitiator_choice, hf_index, ett_dop_TerminateArgumentInitiator,
                                 NULL);

  return offset;
}
static int dissect_terminateInitiator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_TerminateArgumentInitiator(FALSE, tvb, offset, pinfo, tree, hf_dop_terminateInitiator);
}


static const ber_sequence_t TerminateOperationalBindingArgumentData_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_bindingType },
  { BER_CLASS_CON, 1, 0, dissect_bindingID },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_terminateInitiator },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_terminateAtTime },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingArgumentData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TerminateOperationalBindingArgumentData_sequence, hf_index, ett_dop_TerminateOperationalBindingArgumentData);

  return offset;
}
static int dissect_unsignedTerminateOperationalBindingArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_TerminateOperationalBindingArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dop_unsignedTerminateOperationalBindingArgument);
}
static int dissect_terminateOperationalBindingArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_TerminateOperationalBindingArgumentData(FALSE, tvb, offset, pinfo, tree, hf_dop_terminateOperationalBindingArgument);
}


static const ber_sequence_t T_signedTerminateOperationalBindingArgument_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_terminateOperationalBindingArgument },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_T_signedTerminateOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_signedTerminateOperationalBindingArgument_sequence, hf_index, ett_dop_T_signedTerminateOperationalBindingArgument);

  return offset;
}
static int dissect_signedTerminateOperationalBindingArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_signedTerminateOperationalBindingArgument(FALSE, tvb, offset, pinfo, tree, hf_dop_signedTerminateOperationalBindingArgument);
}


static const value_string dop_TerminateOperationalBindingArgument_vals[] = {
  {   0, "unsignedTerminateOperationalBindingArgument" },
  {   1, "signedTerminateOperationalBindingArgument" },
  { 0, NULL }
};

static const ber_choice_t TerminateOperationalBindingArgument_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_unsignedTerminateOperationalBindingArgument },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signedTerminateOperationalBindingArgument },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 TerminateOperationalBindingArgument_choice, hf_index, ett_dop_TerminateOperationalBindingArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t TerminateOperationalBindingResultData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_bindingID },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_bindingType },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_terminateAtGeneralizedTime },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingResultData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TerminateOperationalBindingResultData_sequence, hf_index, ett_dop_TerminateOperationalBindingResultData);

  return offset;
}
static int dissect_terminateOperationalBindingResultData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_TerminateOperationalBindingResultData(FALSE, tvb, offset, pinfo, tree, hf_dop_terminateOperationalBindingResultData);
}


static const ber_sequence_t ProtectedTerminateResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_terminateOperationalBindingResultData },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_ProtectedTerminateResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ProtectedTerminateResult_sequence, hf_index, ett_dop_ProtectedTerminateResult);

  return offset;
}
static int dissect_protectedTerminateResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ProtectedTerminateResult(FALSE, tvb, offset, pinfo, tree, hf_dop_protectedTerminateResult);
}


static const value_string dop_TerminateOperationalBindingResult_vals[] = {
  {   0, "null" },
  {   1, "protected" },
  { 0, NULL }
};

static const ber_choice_t TerminateOperationalBindingResult_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_null },
  {   1, BER_CLASS_CON, 1, 0, dissect_protectedTerminateResult },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_TerminateOperationalBindingResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
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
dissect_dop_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_problem(FALSE, tvb, offset, pinfo, tree, hf_dop_problem);
}



static int
dissect_dop_T_agreementProposal(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 156 "dop.cnf"

  offset = call_dop_oid_callback("dop.agreement", tvb, offset, pinfo, tree, NULL);



  return offset;
}
static int dissect_agreementProposal(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_agreementProposal(FALSE, tvb, offset, pinfo, tree, hf_dop_agreementProposal);
}


static const ber_sequence_t OpBindingErrorParam_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_problem },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_bindingType },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_agreementProposal },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_retryAt },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL, dissect_securityParameters },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL, dissect_performer },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL, dissect_aliasDereferenced },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL, dissect_notification },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_OpBindingErrorParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OpBindingErrorParam_sequence, hf_index, ett_dop_OpBindingErrorParam);

  return offset;
}


static const ber_sequence_t HierarchicalAgreement_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_rdn },
  { BER_CLASS_CON, 1, 0, dissect_immediateSuperior },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_HierarchicalAgreement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   HierarchicalAgreement_sequence, hf_index, ett_dop_HierarchicalAgreement);

  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_entryInfo_item },
};

static int
dissect_dop_SET_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Attribute_set_of, hf_index, ett_dop_SET_OF_Attribute);

  return offset;
}
static int dissect_entryInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_entryInfo);
}
static int dissect_immediateSuperiorInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_immediateSuperiorInfo);
}
static int dissect_admPointInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_admPointInfo);
}
static int dissect_info(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_Attribute(FALSE, tvb, offset, pinfo, tree, hf_dop_info);
}


static const ber_sequence_t SubentryInfo_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_rdn },
  { BER_CLASS_CON, 1, 0, dissect_info },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_SubentryInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SubentryInfo_sequence, hf_index, ett_dop_SubentryInfo);

  return offset;
}
static int dissect_subentries_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SubentryInfo(FALSE, tvb, offset, pinfo, tree, hf_dop_subentries_item);
}


static const ber_sequence_t SET_OF_SubentryInfo_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_subentries_item },
};

static int
dissect_dop_SET_OF_SubentryInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_SubentryInfo_set_of, hf_index, ett_dop_SET_OF_SubentryInfo);

  return offset;
}
static int dissect_subentries(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_SubentryInfo(FALSE, tvb, offset, pinfo, tree, hf_dop_subentries);
}


static const ber_sequence_t Vertex_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_rdn },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_admPointInfo },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_subentries },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_accessPoints },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_Vertex(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Vertex_sequence, hf_index, ett_dop_Vertex);

  return offset;
}
static int dissect_DITcontext_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_Vertex(FALSE, tvb, offset, pinfo, tree, hf_dop_DITcontext_item);
}


static const ber_sequence_t DITcontext_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_DITcontext_item },
};

static int
dissect_dop_DITcontext(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      DITcontext_sequence_of, hf_index, ett_dop_DITcontext);

  return offset;
}
static int dissect_contextPrefixInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_DITcontext(FALSE, tvb, offset, pinfo, tree, hf_dop_contextPrefixInfo);
}


static const ber_sequence_t SuperiorToSubordinate_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_contextPrefixInfo },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_entryInfo },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_immediateSuperiorInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_SuperiorToSubordinate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SuperiorToSubordinate_sequence, hf_index, ett_dop_SuperiorToSubordinate);

  return offset;
}


static const ber_sequence_t SubordinateToSuperior_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_accessPoints },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_alias },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_entryInfo },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_subentries },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_SubordinateToSuperior(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SubordinateToSuperior_sequence, hf_index, ett_dop_SubordinateToSuperior);

  return offset;
}


static const ber_sequence_t SuperiorToSubordinateModification_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_contextPrefixInfo },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_immediateSuperiorInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_SuperiorToSubordinateModification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SuperiorToSubordinateModification_sequence, hf_index, ett_dop_SuperiorToSubordinateModification);

  return offset;
}


static const ber_sequence_t NonSpecificHierarchicalAgreement_sequence[] = {
  { BER_CLASS_CON, 1, 0, dissect_immediateSuperior },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_NonSpecificHierarchicalAgreement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NonSpecificHierarchicalAgreement_sequence, hf_index, ett_dop_NonSpecificHierarchicalAgreement);

  return offset;
}


static const ber_sequence_t NHOBSuperiorToSubordinate_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_contextPrefixInfo },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_immediateSuperiorInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_NHOBSuperiorToSubordinate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NHOBSuperiorToSubordinate_sequence, hf_index, ett_dop_NHOBSuperiorToSubordinate);

  return offset;
}


static const ber_sequence_t NHOBSubordinateToSuperior_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_accessPoints },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_subentries },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_NHOBSubordinateToSuperior(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NHOBSubordinateToSuperior_sequence, hf_index, ett_dop_NHOBSubordinateToSuperior);

  return offset;
}



static int
dissect_dop_Precedence(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 187 "dop.cnf"
  guint32 precedence = 0;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &precedence);


  proto_item_append_text(tree, " precedence=%d", precedence);



  return offset;
}
static int dissect_precedence(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_Precedence(FALSE, tvb, offset, pinfo, tree, hf_dop_precedence);
}


static const value_string dop_T_level_vals[] = {
  {   0, "none" },
  {   1, "simple" },
  {   2, "strong" },
  { 0, NULL }
};


static int
dissect_dop_T_level(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_level(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_level(FALSE, tvb, offset, pinfo, tree, hf_dop_level);
}


static const ber_sequence_t T_basicLevels_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_level },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_localQualifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_signed },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_T_basicLevels(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_basicLevels_sequence, hf_index, ett_dop_T_basicLevels);

  return offset;
}
static int dissect_basicLevels(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_basicLevels(FALSE, tvb, offset, pinfo, tree, hf_dop_basicLevels);
}


static const value_string dop_AuthenticationLevel_vals[] = {
  {   0, "basicLevels" },
  {   1, "other" },
  { 0, NULL }
};

static const ber_choice_t AuthenticationLevel_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_basicLevels },
  {   1, BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_other },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_AuthenticationLevel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AuthenticationLevel_choice, hf_index, ett_dop_AuthenticationLevel,
                                 NULL);

  return offset;
}
static int dissect_authenticationLevel(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_AuthenticationLevel(FALSE, tvb, offset, pinfo, tree, hf_dop_authenticationLevel);
}


static const ber_sequence_t SET_OF_AttributeType_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attributeType_item },
};

static int
dissect_dop_SET_OF_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AttributeType_set_of, hf_index, ett_dop_SET_OF_AttributeType);

  return offset;
}
static int dissect_attributeType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dop_attributeType);
}
static int dissect_allAttributeValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dop_allAttributeValues);
}
static int dissect_selfValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_dop_selfValue);
}


static const ber_sequence_t SET_OF_AttributeTypeAndValue_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_attributeValue_item },
};

static int
dissect_dop_SET_OF_AttributeTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AttributeTypeAndValue_set_of, hf_index, ett_dop_SET_OF_AttributeTypeAndValue);

  return offset;
}
static int dissect_attributeValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_AttributeTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_dop_attributeValue);
}


static const ber_sequence_t MaxValueCount_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_maxCount },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_MaxValueCount(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MaxValueCount_sequence, hf_index, ett_dop_MaxValueCount);

  return offset;
}
static int dissect_maxValueCount_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_MaxValueCount(FALSE, tvb, offset, pinfo, tree, hf_dop_maxValueCount_item);
}


static const ber_sequence_t SET_OF_MaxValueCount_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_maxValueCount_item },
};

static int
dissect_dop_SET_OF_MaxValueCount(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_MaxValueCount_set_of, hf_index, ett_dop_SET_OF_MaxValueCount);

  return offset;
}
static int dissect_maxValueCount(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_MaxValueCount(FALSE, tvb, offset, pinfo, tree, hf_dop_maxValueCount);
}


static const ber_sequence_t RestrictedValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_valuesIn },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_RestrictedValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RestrictedValue_sequence, hf_index, ett_dop_RestrictedValue);

  return offset;
}
static int dissect_restrictedBy_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_RestrictedValue(FALSE, tvb, offset, pinfo, tree, hf_dop_restrictedBy_item);
}


static const ber_sequence_t SET_OF_RestrictedValue_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_restrictedBy_item },
};

static int
dissect_dop_SET_OF_RestrictedValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_RestrictedValue_set_of, hf_index, ett_dop_SET_OF_RestrictedValue);

  return offset;
}
static int dissect_restrictedBy(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_RestrictedValue(FALSE, tvb, offset, pinfo, tree, hf_dop_restrictedBy);
}


static const ber_sequence_t SET_OF_ContextAssertion_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_contexts_item },
};

static int
dissect_dop_SET_OF_ContextAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ContextAssertion_set_of, hf_index, ett_dop_SET_OF_ContextAssertion);

  return offset;
}
static int dissect_contexts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_ContextAssertion(FALSE, tvb, offset, pinfo, tree, hf_dop_contexts);
}


static const ber_sequence_t ProtectedItems_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_entry },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_allUserAttributeTypes },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_attributeType },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_allAttributeValues },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_allUserAttributeTypesAndValues },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_attributeValue },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_selfValue },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_rangeOfValues },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_maxValueCount },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_maxImmSub },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_restrictedBy },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_contexts },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_classes },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_ProtectedItems(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ProtectedItems_sequence, hf_index, ett_dop_ProtectedItems);

  return offset;
}
static int dissect_protectedItems(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ProtectedItems(FALSE, tvb, offset, pinfo, tree, hf_dop_protectedItems);
}


static const ber_sequence_t SET_OF_NameAndOptionalUID_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_name_item },
};

static int
dissect_dop_SET_OF_NameAndOptionalUID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_NameAndOptionalUID_set_of, hf_index, ett_dop_SET_OF_NameAndOptionalUID);

  return offset;
}
static int dissect_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_NameAndOptionalUID(FALSE, tvb, offset, pinfo, tree, hf_dop_name);
}
static int dissect_userGroup(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_NameAndOptionalUID(FALSE, tvb, offset, pinfo, tree, hf_dop_userGroup);
}


static const ber_sequence_t SET_OF_SubtreeSpecification_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_subtree_item },
};

static int
dissect_dop_SET_OF_SubtreeSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_SubtreeSpecification_set_of, hf_index, ett_dop_SET_OF_SubtreeSpecification);

  return offset;
}
static int dissect_subtree(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_SubtreeSpecification(FALSE, tvb, offset, pinfo, tree, hf_dop_subtree);
}


static const ber_sequence_t UserClasses_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_allUsers },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_thisEntry },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_name },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_userGroup },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_subtree },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_UserClasses(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UserClasses_sequence, hf_index, ett_dop_UserClasses);

  return offset;
}
static int dissect_userClasses(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_UserClasses(FALSE, tvb, offset, pinfo, tree, hf_dop_userClasses);
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
dissect_dop_GrantsAndDenials(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    GrantsAndDenials_bits, hf_index, ett_dop_GrantsAndDenials,
                                    NULL);

  return offset;
}
static int dissect_grantsAndDenials(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_GrantsAndDenials(FALSE, tvb, offset, pinfo, tree, hf_dop_grantsAndDenials);
}


static const ber_sequence_t ItemPermission_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_precedence },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_userClasses },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_grantsAndDenials },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_ItemPermission(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ItemPermission_sequence, hf_index, ett_dop_ItemPermission);

  return offset;
}
static int dissect_itemPermissions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_ItemPermission(FALSE, tvb, offset, pinfo, tree, hf_dop_itemPermissions_item);
}


static const ber_sequence_t SET_OF_ItemPermission_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_itemPermissions_item },
};

static int
dissect_dop_SET_OF_ItemPermission(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ItemPermission_set_of, hf_index, ett_dop_SET_OF_ItemPermission);

  return offset;
}
static int dissect_itemPermissions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_ItemPermission(FALSE, tvb, offset, pinfo, tree, hf_dop_itemPermissions);
}


static const ber_sequence_t T_itemFirst_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_protectedItems },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_itemPermissions },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_T_itemFirst(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_itemFirst_sequence, hf_index, ett_dop_T_itemFirst);

  return offset;
}
static int dissect_itemFirst(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_itemFirst(FALSE, tvb, offset, pinfo, tree, hf_dop_itemFirst);
}


static const ber_sequence_t UserPermission_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_precedence },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_protectedItems },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_grantsAndDenials },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_UserPermission(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UserPermission_sequence, hf_index, ett_dop_UserPermission);

  return offset;
}
static int dissect_userPermissions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_UserPermission(FALSE, tvb, offset, pinfo, tree, hf_dop_userPermissions_item);
}


static const ber_sequence_t SET_OF_UserPermission_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_userPermissions_item },
};

static int
dissect_dop_SET_OF_UserPermission(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_UserPermission_set_of, hf_index, ett_dop_SET_OF_UserPermission);

  return offset;
}
static int dissect_userPermissions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_SET_OF_UserPermission(FALSE, tvb, offset, pinfo, tree, hf_dop_userPermissions);
}


static const ber_sequence_t T_userFirst_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_userClasses },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_userPermissions },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_T_userFirst(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_userFirst_sequence, hf_index, ett_dop_T_userFirst);

  return offset;
}
static int dissect_userFirst(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_userFirst(FALSE, tvb, offset, pinfo, tree, hf_dop_userFirst);
}


static const value_string dop_T_itemOrUserFirst_vals[] = {
  {   0, "itemFirst" },
  {   1, "userFirst" },
  { 0, NULL }
};

static const ber_choice_t T_itemOrUserFirst_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_itemFirst },
  {   1, BER_CLASS_CON, 1, 0, dissect_userFirst },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_dop_T_itemOrUserFirst(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_itemOrUserFirst_choice, hf_index, ett_dop_T_itemOrUserFirst,
                                 NULL);

  return offset;
}
static int dissect_itemOrUserFirst(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dop_T_itemOrUserFirst(FALSE, tvb, offset, pinfo, tree, hf_dop_itemOrUserFirst);
}


static const ber_sequence_t ACIItem_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_identificationTag },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_precedence },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_authenticationLevel },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_itemOrUserFirst },
  { 0, 0, 0, NULL }
};

static int
dissect_dop_ACIItem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ACIItem_sequence, hf_index, ett_dop_ACIItem);

  return offset;
}

/*--- PDUs ---*/

static void dissect_DSEType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_DSEType(FALSE, tvb, 0, pinfo, tree, hf_dop_DSEType_PDU);
}
static void dissect_SupplierInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_SupplierInformation(FALSE, tvb, 0, pinfo, tree, hf_dop_SupplierInformation_PDU);
}
static void dissect_ConsumerInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_ConsumerInformation(FALSE, tvb, 0, pinfo, tree, hf_dop_ConsumerInformation_PDU);
}
static void dissect_SupplierAndConsumers_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_SupplierAndConsumers(FALSE, tvb, 0, pinfo, tree, hf_dop_SupplierAndConsumers_PDU);
}
static void dissect_HierarchicalAgreement_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_HierarchicalAgreement(FALSE, tvb, 0, pinfo, tree, hf_dop_HierarchicalAgreement_PDU);
}
static void dissect_SuperiorToSubordinate_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_SuperiorToSubordinate(FALSE, tvb, 0, pinfo, tree, hf_dop_SuperiorToSubordinate_PDU);
}
static void dissect_SubordinateToSuperior_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_SubordinateToSuperior(FALSE, tvb, 0, pinfo, tree, hf_dop_SubordinateToSuperior_PDU);
}
static void dissect_SuperiorToSubordinateModification_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_SuperiorToSubordinateModification(FALSE, tvb, 0, pinfo, tree, hf_dop_SuperiorToSubordinateModification_PDU);
}
static void dissect_NonSpecificHierarchicalAgreement_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_NonSpecificHierarchicalAgreement(FALSE, tvb, 0, pinfo, tree, hf_dop_NonSpecificHierarchicalAgreement_PDU);
}
static void dissect_NHOBSuperiorToSubordinate_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_NHOBSuperiorToSubordinate(FALSE, tvb, 0, pinfo, tree, hf_dop_NHOBSuperiorToSubordinate_PDU);
}
static void dissect_NHOBSubordinateToSuperior_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_NHOBSubordinateToSuperior(FALSE, tvb, 0, pinfo, tree, hf_dop_NHOBSubordinateToSuperior_PDU);
}
static void dissect_ACIItem_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_dop_ACIItem(FALSE, tvb, 0, pinfo, tree, hf_dop_ACIItem_PDU);
}


/*--- End of included file: packet-dop-fn.c ---*/
#line 76 "packet-dop-template.c"

static int
call_dop_oid_callback(char *base_oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *col_info)
{
  char binding_param[MAX_OID_STR_LEN];

  g_snprintf(binding_param, MAX_OID_STR_LEN, "%s.%s", base_oid, binding_type ? binding_type : "");	

  if (col_info && (check_col(pinfo->cinfo, COL_INFO))) 
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", col_info);

  return call_ber_oid_callback(binding_param, tvb, offset, pinfo, tree);
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
	int (*dop_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *dop_op_name;

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
		item = proto_tree_add_item(parent_tree, proto_dop, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_dop);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DOP");
  	if (check_col(pinfo->cinfo, COL_INFO))
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
	  if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_str(pinfo->cinfo, COL_INFO, dop_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dop_dissector)(FALSE, tvb, offset, pinfo , tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DOP PDU");
	      offset = tvb_length(tvb);
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
#line 1 "packet-dop-hfarr.c"
    { &hf_dop_DSEType_PDU,
      { "DSEType", "dop.DSEType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DSEType", HFILL }},
    { &hf_dop_SupplierInformation_PDU,
      { "SupplierInformation", "dop.SupplierInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupplierInformation", HFILL }},
    { &hf_dop_ConsumerInformation_PDU,
      { "ConsumerInformation", "dop.ConsumerInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConsumerInformation", HFILL }},
    { &hf_dop_SupplierAndConsumers_PDU,
      { "SupplierAndConsumers", "dop.SupplierAndConsumers",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupplierAndConsumers", HFILL }},
    { &hf_dop_HierarchicalAgreement_PDU,
      { "HierarchicalAgreement", "dop.HierarchicalAgreement",
        FT_NONE, BASE_NONE, NULL, 0,
        "HierarchicalAgreement", HFILL }},
    { &hf_dop_SuperiorToSubordinate_PDU,
      { "SuperiorToSubordinate", "dop.SuperiorToSubordinate",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuperiorToSubordinate", HFILL }},
    { &hf_dop_SubordinateToSuperior_PDU,
      { "SubordinateToSuperior", "dop.SubordinateToSuperior",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubordinateToSuperior", HFILL }},
    { &hf_dop_SuperiorToSubordinateModification_PDU,
      { "SuperiorToSubordinateModification", "dop.SuperiorToSubordinateModification",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuperiorToSubordinateModification", HFILL }},
    { &hf_dop_NonSpecificHierarchicalAgreement_PDU,
      { "NonSpecificHierarchicalAgreement", "dop.NonSpecificHierarchicalAgreement",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonSpecificHierarchicalAgreement", HFILL }},
    { &hf_dop_NHOBSuperiorToSubordinate_PDU,
      { "NHOBSuperiorToSubordinate", "dop.NHOBSuperiorToSubordinate",
        FT_NONE, BASE_NONE, NULL, 0,
        "NHOBSuperiorToSubordinate", HFILL }},
    { &hf_dop_NHOBSubordinateToSuperior_PDU,
      { "NHOBSubordinateToSuperior", "dop.NHOBSubordinateToSuperior",
        FT_NONE, BASE_NONE, NULL, 0,
        "NHOBSubordinateToSuperior", HFILL }},
    { &hf_dop_ACIItem_PDU,
      { "ACIItem", "dop.ACIItem",
        FT_NONE, BASE_NONE, NULL, 0,
        "ACIItem", HFILL }},
    { &hf_dop_ae_title,
      { "ae-title", "dop.ae_title",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "", HFILL }},
    { &hf_dop_address,
      { "address", "dop.address",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_protocolInformation,
      { "protocolInformation", "dop.protocolInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_protocolInformation_item,
      { "Item", "dop.protocolInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_agreementID,
      { "agreementID", "dop.agreementID",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_supplier_is_master,
      { "supplier-is-master", "dop.supplier_is_master",
        FT_BOOLEAN, 8, NULL, 0,
        "SupplierInformation/supplier-is-master", HFILL }},
    { &hf_dop_non_supplying_master,
      { "non-supplying-master", "dop.non_supplying_master",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupplierInformation/non-supplying-master", HFILL }},
    { &hf_dop_consumers,
      { "consumers", "dop.consumers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SupplierAndConsumers/consumers", HFILL }},
    { &hf_dop_consumers_item,
      { "Item", "dop.consumers_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupplierAndConsumers/consumers/_item", HFILL }},
    { &hf_dop_bindingType,
      { "bindingType", "dop.bindingType",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_bindingID,
      { "bindingID", "dop.bindingID",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_accessPoint,
      { "accessPoint", "dop.accessPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_establishInitiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_EstablishArgumentInitiator_vals), 0,
        "EstablishOperationalBindingArgumentData/initiator", HFILL }},
    { &hf_dop_establishSymmetric,
      { "symmetric", "dop.symmetric",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgumentData/initiator/symmetric", HFILL }},
    { &hf_dop_establishRoleAInitiates,
      { "roleA-initiates", "dop.roleA_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgumentData/initiator/roleA-initiates", HFILL }},
    { &hf_dop_establishRoleBInitiates,
      { "roleB-initiates", "dop.roleB_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgumentData/initiator/roleB-initiates", HFILL }},
    { &hf_dop_agreement,
      { "agreement", "dop.agreement",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgumentData/agreement", HFILL }},
    { &hf_dop_valid,
      { "valid", "dop.valid",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_securityParameters,
      { "securityParameters", "dop.securityParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_unsignedEstablishOperationalBindingArgument,
      { "unsignedEstablishOperationalBindingArgument", "dop.unsignedEstablishOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgument/unsignedEstablishOperationalBindingArgument", HFILL }},
    { &hf_dop_signedEstablishOperationalBindingArgument,
      { "signedEstablishOperationalBindingArgument", "dop.signedEstablishOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgument/signedEstablishOperationalBindingArgument", HFILL }},
    { &hf_dop_establishOperationalBindingArgument,
      { "establishOperationalBindingArgument", "dop.establishOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingArgument/signedEstablishOperationalBindingArgument/establishOperationalBindingArgument", HFILL }},
    { &hf_dop_algorithmIdentifier,
      { "algorithmIdentifier", "dop.algorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_encrypted,
      { "encrypted", "dop.encrypted",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_dop_identifier,
      { "identifier", "dop.identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "OperationalBindingID/identifier", HFILL }},
    { &hf_dop_version,
      { "version", "dop.version",
        FT_INT32, BASE_DEC, NULL, 0,
        "OperationalBindingID/version", HFILL }},
    { &hf_dop_validFrom,
      { "validFrom", "dop.validFrom",
        FT_UINT32, BASE_DEC, VALS(dop_T_validFrom_vals), 0,
        "Validity/validFrom", HFILL }},
    { &hf_dop_now,
      { "now", "dop.now",
        FT_NONE, BASE_NONE, NULL, 0,
        "Validity/validFrom/now", HFILL }},
    { &hf_dop_time,
      { "time", "dop.time",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "", HFILL }},
    { &hf_dop_validUntil,
      { "validUntil", "dop.validUntil",
        FT_UINT32, BASE_DEC, VALS(dop_T_validUntil_vals), 0,
        "Validity/validUntil", HFILL }},
    { &hf_dop_explicitTermination,
      { "explicitTermination", "dop.explicitTermination",
        FT_NONE, BASE_NONE, NULL, 0,
        "Validity/validUntil/explicitTermination", HFILL }},
    { &hf_dop_utcTime,
      { "utcTime", "dop.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time/utcTime", HFILL }},
    { &hf_dop_generalizedTime,
      { "generalizedTime", "dop.generalizedTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time/generalizedTime", HFILL }},
    { &hf_dop_initiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_T_initiator_vals), 0,
        "EstablishOperationalBindingResult/initiator", HFILL }},
    { &hf_dop_symmetric,
      { "symmetric", "dop.symmetric",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingResult/initiator/symmetric", HFILL }},
    { &hf_dop_roleA_replies,
      { "roleA-replies", "dop.roleA_replies",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingResult/initiator/roleA-replies", HFILL }},
    { &hf_dop_roleB_replies,
      { "roleB-replies", "dop.roleB_replies",
        FT_NONE, BASE_NONE, NULL, 0,
        "EstablishOperationalBindingResult/initiator/roleB-replies", HFILL }},
    { &hf_dop_performer,
      { "performer", "dop.performer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_aliasDereferenced,
      { "aliasDereferenced", "dop.aliasDereferenced",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_dop_notification,
      { "notification", "dop.notification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_notification_item,
      { "Item", "dop.notification_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_modifyInitiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_ModifyArgumentInitiator_vals), 0,
        "ModifyOperationalBindingArgumentData/initiator", HFILL }},
    { &hf_dop_modifySymmetric,
      { "symmetric", "dop.symmetric",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgumentData/initiator/symmetric", HFILL }},
    { &hf_dop_modifyRoleAInitiates,
      { "roleA-initiates", "dop.roleA_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgumentData/initiator/roleA-initiates", HFILL }},
    { &hf_dop_modifyRoleBInitiates,
      { "roleB-initiates", "dop.roleB_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgumentData/initiator/roleB-initiates", HFILL }},
    { &hf_dop_newBindingID,
      { "newBindingID", "dop.newBindingID",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_argumentNewAgreement,
      { "newAgreement", "dop.newAgreement",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgumentData/newAgreement", HFILL }},
    { &hf_dop_unsignedModifyOperationalBindingArgument,
      { "unsignedModifyOperationalBindingArgument", "dop.unsignedModifyOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgument/unsignedModifyOperationalBindingArgument", HFILL }},
    { &hf_dop_signedModifyOperationalBindingArgument,
      { "signedModifyOperationalBindingArgument", "dop.signedModifyOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgument/signedModifyOperationalBindingArgument", HFILL }},
    { &hf_dop_modifyOperationalBindingArgument,
      { "modifyOperationalBindingArgument", "dop.modifyOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingArgument/signedModifyOperationalBindingArgument/modifyOperationalBindingArgument", HFILL }},
    { &hf_dop_null,
      { "null", "dop.null",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_protectedModifyResult,
      { "protected", "dop.protected",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingResult/protected", HFILL }},
    { &hf_dop_modifyOperationalBindingResultData,
      { "modifyOperationalBindingResultData", "dop.modifyOperationalBindingResultData",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingResult/protected/modifyOperationalBindingResultData", HFILL }},
    { &hf_dop_resultNewAgreement,
      { "newAgreement", "dop.newAgreement",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModifyOperationalBindingResultData/newAgreement", HFILL }},
    { &hf_dop_terminateInitiator,
      { "initiator", "dop.initiator",
        FT_UINT32, BASE_DEC, VALS(dop_TerminateArgumentInitiator_vals), 0,
        "TerminateOperationalBindingArgumentData/initiator", HFILL }},
    { &hf_dop_terminateSymmetric,
      { "symmetric", "dop.symmetric",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgumentData/initiator/symmetric", HFILL }},
    { &hf_dop_terminateRoleAInitiates,
      { "roleA-initiates", "dop.roleA_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgumentData/initiator/roleA-initiates", HFILL }},
    { &hf_dop_terminateRoleBInitiates,
      { "roleB-initiates", "dop.roleB_initiates",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgumentData/initiator/roleB-initiates", HFILL }},
    { &hf_dop_terminateAtTime,
      { "terminateAt", "dop.terminateAt",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "TerminateOperationalBindingArgumentData/terminateAt", HFILL }},
    { &hf_dop_unsignedTerminateOperationalBindingArgument,
      { "unsignedTerminateOperationalBindingArgument", "dop.unsignedTerminateOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgument/unsignedTerminateOperationalBindingArgument", HFILL }},
    { &hf_dop_signedTerminateOperationalBindingArgument,
      { "signedTerminateOperationalBindingArgument", "dop.signedTerminateOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgument/signedTerminateOperationalBindingArgument", HFILL }},
    { &hf_dop_terminateOperationalBindingArgument,
      { "terminateOperationalBindingArgument", "dop.terminateOperationalBindingArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingArgument/signedTerminateOperationalBindingArgument/terminateOperationalBindingArgument", HFILL }},
    { &hf_dop_protectedTerminateResult,
      { "protected", "dop.protected",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingResult/protected", HFILL }},
    { &hf_dop_terminateOperationalBindingResultData,
      { "terminateOperationalBindingResultData", "dop.terminateOperationalBindingResultData",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingResult/protected/terminateOperationalBindingResultData", HFILL }},
    { &hf_dop_terminateAtGeneralizedTime,
      { "terminateAt", "dop.terminateAt",
        FT_STRING, BASE_NONE, NULL, 0,
        "TerminateOperationalBindingResultData/terminateAt", HFILL }},
    { &hf_dop_problem,
      { "problem", "dop.problem",
        FT_UINT32, BASE_DEC, VALS(dop_T_problem_vals), 0,
        "OpBindingErrorParam/problem", HFILL }},
    { &hf_dop_agreementProposal,
      { "agreementProposal", "dop.agreementProposal",
        FT_NONE, BASE_NONE, NULL, 0,
        "OpBindingErrorParam/agreementProposal", HFILL }},
    { &hf_dop_retryAt,
      { "retryAt", "dop.retryAt",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "OpBindingErrorParam/retryAt", HFILL }},
    { &hf_dop_rdn,
      { "rdn", "dop.rdn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_immediateSuperior,
      { "immediateSuperior", "dop.immediateSuperior",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_contextPrefixInfo,
      { "contextPrefixInfo", "dop.contextPrefixInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_entryInfo,
      { "entryInfo", "dop.entryInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_entryInfo_item,
      { "Item", "dop.entryInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_immediateSuperiorInfo,
      { "immediateSuperiorInfo", "dop.immediateSuperiorInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_immediateSuperiorInfo_item,
      { "Item", "dop.immediateSuperiorInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_DITcontext_item,
      { "Item", "dop.DITcontext_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DITcontext/_item", HFILL }},
    { &hf_dop_admPointInfo,
      { "admPointInfo", "dop.admPointInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Vertex/admPointInfo", HFILL }},
    { &hf_dop_admPointInfo_item,
      { "Item", "dop.admPointInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Vertex/admPointInfo/_item", HFILL }},
    { &hf_dop_subentries,
      { "subentries", "dop.subentries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_subentries_item,
      { "Item", "dop.subentries_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_accessPoints,
      { "accessPoints", "dop.accessPoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_info,
      { "info", "dop.info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SubentryInfo/info", HFILL }},
    { &hf_dop_info_item,
      { "Item", "dop.info_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubentryInfo/info/_item", HFILL }},
    { &hf_dop_alias,
      { "alias", "dop.alias",
        FT_BOOLEAN, 8, NULL, 0,
        "SubordinateToSuperior/alias", HFILL }},
    { &hf_dop_identificationTag,
      { "identificationTag", "dop.identificationTag",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "ACIItem/identificationTag", HFILL }},
    { &hf_dop_precedence,
      { "precedence", "dop.precedence",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_dop_authenticationLevel,
      { "authenticationLevel", "dop.authenticationLevel",
        FT_UINT32, BASE_DEC, VALS(dop_AuthenticationLevel_vals), 0,
        "ACIItem/authenticationLevel", HFILL }},
    { &hf_dop_itemOrUserFirst,
      { "itemOrUserFirst", "dop.itemOrUserFirst",
        FT_UINT32, BASE_DEC, VALS(dop_T_itemOrUserFirst_vals), 0,
        "ACIItem/itemOrUserFirst", HFILL }},
    { &hf_dop_itemFirst,
      { "itemFirst", "dop.itemFirst",
        FT_NONE, BASE_NONE, NULL, 0,
        "ACIItem/itemOrUserFirst/itemFirst", HFILL }},
    { &hf_dop_protectedItems,
      { "protectedItems", "dop.protectedItems",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_itemPermissions,
      { "itemPermissions", "dop.itemPermissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ACIItem/itemOrUserFirst/itemFirst/itemPermissions", HFILL }},
    { &hf_dop_itemPermissions_item,
      { "Item", "dop.itemPermissions_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ACIItem/itemOrUserFirst/itemFirst/itemPermissions/_item", HFILL }},
    { &hf_dop_userFirst,
      { "userFirst", "dop.userFirst",
        FT_NONE, BASE_NONE, NULL, 0,
        "ACIItem/itemOrUserFirst/userFirst", HFILL }},
    { &hf_dop_userClasses,
      { "userClasses", "dop.userClasses",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_userPermissions,
      { "userPermissions", "dop.userPermissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ACIItem/itemOrUserFirst/userFirst/userPermissions", HFILL }},
    { &hf_dop_userPermissions_item,
      { "Item", "dop.userPermissions_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ACIItem/itemOrUserFirst/userFirst/userPermissions/_item", HFILL }},
    { &hf_dop_entry,
      { "entry", "dop.entry",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedItems/entry", HFILL }},
    { &hf_dop_allUserAttributeTypes,
      { "allUserAttributeTypes", "dop.allUserAttributeTypes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedItems/allUserAttributeTypes", HFILL }},
    { &hf_dop_attributeType,
      { "attributeType", "dop.attributeType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtectedItems/attributeType", HFILL }},
    { &hf_dop_attributeType_item,
      { "Item", "dop.attributeType_item",
        FT_OID, BASE_NONE, NULL, 0,
        "ProtectedItems/attributeType/_item", HFILL }},
    { &hf_dop_allAttributeValues,
      { "allAttributeValues", "dop.allAttributeValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtectedItems/allAttributeValues", HFILL }},
    { &hf_dop_allAttributeValues_item,
      { "Item", "dop.allAttributeValues_item",
        FT_OID, BASE_NONE, NULL, 0,
        "ProtectedItems/allAttributeValues/_item", HFILL }},
    { &hf_dop_allUserAttributeTypesAndValues,
      { "allUserAttributeTypesAndValues", "dop.allUserAttributeTypesAndValues",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedItems/allUserAttributeTypesAndValues", HFILL }},
    { &hf_dop_attributeValue,
      { "attributeValue", "dop.attributeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtectedItems/attributeValue", HFILL }},
    { &hf_dop_attributeValue_item,
      { "Item", "dop.attributeValue_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedItems/attributeValue/_item", HFILL }},
    { &hf_dop_selfValue,
      { "selfValue", "dop.selfValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtectedItems/selfValue", HFILL }},
    { &hf_dop_selfValue_item,
      { "Item", "dop.selfValue_item",
        FT_OID, BASE_NONE, NULL, 0,
        "ProtectedItems/selfValue/_item", HFILL }},
    { &hf_dop_rangeOfValues,
      { "rangeOfValues", "dop.rangeOfValues",
        FT_UINT32, BASE_DEC, VALS(dap_Filter_vals), 0,
        "ProtectedItems/rangeOfValues", HFILL }},
    { &hf_dop_maxValueCount,
      { "maxValueCount", "dop.maxValueCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtectedItems/maxValueCount", HFILL }},
    { &hf_dop_maxValueCount_item,
      { "Item", "dop.maxValueCount_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedItems/maxValueCount/_item", HFILL }},
    { &hf_dop_maxImmSub,
      { "maxImmSub", "dop.maxImmSub",
        FT_INT32, BASE_DEC, NULL, 0,
        "ProtectedItems/maxImmSub", HFILL }},
    { &hf_dop_restrictedBy,
      { "restrictedBy", "dop.restrictedBy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtectedItems/restrictedBy", HFILL }},
    { &hf_dop_restrictedBy_item,
      { "Item", "dop.restrictedBy_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedItems/restrictedBy/_item", HFILL }},
    { &hf_dop_contexts,
      { "contexts", "dop.contexts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtectedItems/contexts", HFILL }},
    { &hf_dop_contexts_item,
      { "Item", "dop.contexts_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtectedItems/contexts/_item", HFILL }},
    { &hf_dop_classes,
      { "classes", "dop.classes",
        FT_UINT32, BASE_DEC, VALS(x509if_Refinement_vals), 0,
        "ProtectedItems/classes", HFILL }},
    { &hf_dop_type,
      { "type", "dop.type",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_dop_maxCount,
      { "maxCount", "dop.maxCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "MaxValueCount/maxCount", HFILL }},
    { &hf_dop_valuesIn,
      { "valuesIn", "dop.valuesIn",
        FT_OID, BASE_NONE, NULL, 0,
        "RestrictedValue/valuesIn", HFILL }},
    { &hf_dop_allUsers,
      { "allUsers", "dop.allUsers",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserClasses/allUsers", HFILL }},
    { &hf_dop_thisEntry,
      { "thisEntry", "dop.thisEntry",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserClasses/thisEntry", HFILL }},
    { &hf_dop_name,
      { "name", "dop.name",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserClasses/name", HFILL }},
    { &hf_dop_name_item,
      { "Item", "dop.name_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserClasses/name/_item", HFILL }},
    { &hf_dop_userGroup,
      { "userGroup", "dop.userGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserClasses/userGroup", HFILL }},
    { &hf_dop_userGroup_item,
      { "Item", "dop.userGroup_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserClasses/userGroup/_item", HFILL }},
    { &hf_dop_subtree,
      { "subtree", "dop.subtree",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UserClasses/subtree", HFILL }},
    { &hf_dop_subtree_item,
      { "Item", "dop.subtree_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserClasses/subtree/_item", HFILL }},
    { &hf_dop_grantsAndDenials,
      { "grantsAndDenials", "dop.grantsAndDenials",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_dop_basicLevels,
      { "basicLevels", "dop.basicLevels",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationLevel/basicLevels", HFILL }},
    { &hf_dop_level,
      { "level", "dop.level",
        FT_UINT32, BASE_DEC, VALS(dop_T_level_vals), 0,
        "AuthenticationLevel/basicLevels/level", HFILL }},
    { &hf_dop_localQualifier,
      { "localQualifier", "dop.localQualifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AuthenticationLevel/basicLevels/localQualifier", HFILL }},
    { &hf_dop_signed,
      { "signed", "dop.signed",
        FT_BOOLEAN, 8, NULL, 0,
        "AuthenticationLevel/basicLevels/signed", HFILL }},
    { &hf_dop_other,
      { "other", "dop.other",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationLevel/other", HFILL }},
    { &hf_dop_DSEType_root,
      { "root", "dop.root",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dop_DSEType_glue,
      { "glue", "dop.glue",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dop_DSEType_cp,
      { "cp", "dop.cp",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dop_DSEType_entry,
      { "entry", "dop.entry",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dop_DSEType_alias,
      { "alias", "dop.alias",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_dop_DSEType_subr,
      { "subr", "dop.subr",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_dop_DSEType_nssr,
      { "nssr", "dop.nssr",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_dop_DSEType_supr,
      { "supr", "dop.supr",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_dop_DSEType_xr,
      { "xr", "dop.xr",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dop_DSEType_admPoint,
      { "admPoint", "dop.admPoint",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dop_DSEType_subentry,
      { "subentry", "dop.subentry",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dop_DSEType_shadow,
      { "shadow", "dop.shadow",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dop_DSEType_immSupr,
      { "immSupr", "dop.immSupr",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_dop_DSEType_rhob,
      { "rhob", "dop.rhob",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_dop_DSEType_sa,
      { "sa", "dop.sa",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_dop_DSEType_dsSubentry,
      { "dsSubentry", "dop.dsSubentry",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dop_DSEType_familyMember,
      { "familyMember", "dop.familyMember",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantAdd,
      { "grantAdd", "dop.grantAdd",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyAdd,
      { "denyAdd", "dop.denyAdd",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantDiscloseOnError,
      { "grantDiscloseOnError", "dop.grantDiscloseOnError",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyDiscloseOnError,
      { "denyDiscloseOnError", "dop.denyDiscloseOnError",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantRead,
      { "grantRead", "dop.grantRead",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyRead,
      { "denyRead", "dop.denyRead",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantRemove,
      { "grantRemove", "dop.grantRemove",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyRemove,
      { "denyRemove", "dop.denyRemove",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantBrowse,
      { "grantBrowse", "dop.grantBrowse",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyBrowse,
      { "denyBrowse", "dop.denyBrowse",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantExport,
      { "grantExport", "dop.grantExport",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyExport,
      { "denyExport", "dop.denyExport",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantImport,
      { "grantImport", "dop.grantImport",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyImport,
      { "denyImport", "dop.denyImport",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantModify,
      { "grantModify", "dop.grantModify",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyModify,
      { "denyModify", "dop.denyModify",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantRename,
      { "grantRename", "dop.grantRename",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyRename,
      { "denyRename", "dop.denyRename",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantReturnDN,
      { "grantReturnDN", "dop.grantReturnDN",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyReturnDN,
      { "denyReturnDN", "dop.denyReturnDN",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantCompare,
      { "grantCompare", "dop.grantCompare",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyCompare,
      { "denyCompare", "dop.denyCompare",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantFilterMatch,
      { "grantFilterMatch", "dop.grantFilterMatch",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyFilterMatch,
      { "denyFilterMatch", "dop.denyFilterMatch",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_grantInvoke,
      { "grantInvoke", "dop.grantInvoke",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_dop_GrantsAndDenials_denyInvoke,
      { "denyInvoke", "dop.denyInvoke",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},

/*--- End of included file: packet-dop-hfarr.c ---*/
#line 219 "packet-dop-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_dop,

/*--- Included file: packet-dop-ettarr.c ---*/
#line 1 "packet-dop-ettarr.c"
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
#line 225 "packet-dop-template.c"
  };

  module_t *dop_module;

  /* Register protocol */
  proto_dop = proto_register_protocol(PNAME, PSNAME, PFNAME);

  register_dissector("dop", dissect_dop, proto_dop);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DOP, particularly our port */

#ifdef PREFERENCE_GROUPING
  dop_module = prefs_register_protocol_subtree("OSI/X.500", proto_dop, prefs_register_dop);
#else
  dop_module = prefs_register_protocol(proto_dop, prefs_register_dop);
#endif 

  prefs_register_uint_preference(dop_module, "tcp.port", "DOP TCP Port",
				 "Set the port for DOP operations (if other"
				 " than the default of 102)",
				 10, &global_dop_tcp_port);


}


/*--- proto_reg_handoff_dop --- */
void proto_reg_handoff_dop(void) {
  dissector_handle_t handle = NULL;


/*--- Included file: packet-dop-dis-tab.c ---*/
#line 1 "packet-dop-dis-tab.c"
  register_ber_oid_dissector("2.5.12.0", dissect_DSEType_PDU, proto_dop, "id-doa-dseType");
  register_ber_oid_dissector("2.5.12.5", dissect_SupplierInformation_PDU, proto_dop, "id-doa-supplierKnowledge");
  register_ber_oid_dissector("2.5.12.6", dissect_ConsumerInformation_PDU, proto_dop, "id-doa-consumerKnowledge");
  register_ber_oid_dissector("2.5.12.7", dissect_SupplierAndConsumers_PDU, proto_dop, "id-doa-secondaryShadows");
  register_ber_oid_dissector("dop.agreement.2.5.19.2", dissect_HierarchicalAgreement_PDU, proto_dop, "hierarchical-agreement");
  register_ber_oid_dissector("dop.establish.rolea.2.5.19.2", dissect_SuperiorToSubordinate_PDU, proto_dop, "hierarchical-establish-rolea");
  register_ber_oid_dissector("dop.modify.rolea.2.5.19.2", dissect_SuperiorToSubordinateModification_PDU, proto_dop, "hierarchical-modify-rolea");
  register_ber_oid_dissector("dop.establish.roleb.2.5.19.2", dissect_SubordinateToSuperior_PDU, proto_dop, "hierarchical-establish-roleb");
  register_ber_oid_dissector("dop.modify.roleb.2.5.19.2", dissect_SubordinateToSuperior_PDU, proto_dop, "hierarchical-modify-roleb");
  register_ber_oid_dissector("dop.agreement.2.5.19.3", dissect_NonSpecificHierarchicalAgreement_PDU, proto_dop, "non-specific-hierarchical-agreement");
  register_ber_oid_dissector("dop.establish.rolea.2.5.19.3", dissect_NHOBSuperiorToSubordinate_PDU, proto_dop, "non-specific-hierarchical-establish-rolea");
  register_ber_oid_dissector("dop.modify.rolea.2.5.19.3", dissect_NHOBSuperiorToSubordinate_PDU, proto_dop, "non-specific-hierarchical-modify-rolea");
  register_ber_oid_dissector("dop.establish.roleb.2.5.19.3", dissect_NHOBSubordinateToSuperior_PDU, proto_dop, "non-specific-hierarchical-establish-roleb");
  register_ber_oid_dissector("dop.modify.roleb.2.5.19.3", dissect_NHOBSubordinateToSuperior_PDU, proto_dop, "non-specific-hierarchical-modify-roleb");
  register_ber_oid_dissector("2.5.24.4", dissect_ACIItem_PDU, proto_dop, "id-aca-prescriptiveACI");
  register_ber_oid_dissector("2.5.24.5", dissect_ACIItem_PDU, proto_dop, "id-aca-entryACI");
  register_ber_oid_dissector("2.5.24.6", dissect_ACIItem_PDU, proto_dop, "id-aca-subentryACI");


/*--- End of included file: packet-dop-dis-tab.c ---*/
#line 260 "packet-dop-template.c"
  /* APPLICATION CONTEXT */

  register_ber_oid_name("2.5.3.3", "id-ac-directory-operational-binding-management");

  /* ABSTRACT SYNTAXES */
    
  /* Register DOP with ROS (with no use of RTSE) */
  if((handle = find_dissector("dop"))) {
    register_ros_oid_dissector_handle("2.5.9.4", handle, 0, "id-as-directory-operational-binding-management", FALSE); 
  }

  /* BINDING TYPES */

  register_ber_oid_name("2.5.19.1", "shadow-agreement");
  register_ber_oid_name("2.5.19.2", "hierarchical-agreement");
  register_ber_oid_name("2.5.19.3", "non-specific-hierarchical-agreement");

  /* ACCESS CONTROL SCHEMES */
  register_ber_oid_name("2.5.28.1", "basic-ACS");
  register_ber_oid_name("2.5.28.2", "simplified-ACS");
  register_ber_oid_name("2.5.28.3", "ruleBased-ACS");
  register_ber_oid_name("2.5.28.4", "ruleAndBasic-ACS");
  register_ber_oid_name("2.5.28.5", "ruleAndSimple-ACS");

  /* ADMINISTRATIVE ROLES */
  register_ber_oid_name("2.5.23.1", "id-ar-autonomousArea");
  register_ber_oid_name("2.5.23.2", "id-ar-accessControlSpecificArea");
  register_ber_oid_name("2.5.23.3", "id-ar-accessControlInnerArea");
  register_ber_oid_name("2.5.23.4", "id-ar-subschemaAdminSpecificArea");
  register_ber_oid_name("2.5.23.5", "id-ar-collectiveAttributeSpecificArea");
  register_ber_oid_name("2.5.23.6", "id-ar-collectiveAttributeInnerArea");
  register_ber_oid_name("2.5.23.7", "id-ar-contextDefaultSpecificArea");
  register_ber_oid_name("2.5.23.8", "id-ar-serviceSpecificArea");

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");

}

void prefs_register_dop(void) {

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port != 102) && tpkt_handle)
    dissector_delete("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_dop_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add("tcp.port", global_dop_tcp_port, tpkt_handle);

}
