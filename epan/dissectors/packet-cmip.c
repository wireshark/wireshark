/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-cmip.c                                                            */
/* ../../tools/asn2wrs.py -b -e -p cmip -c cmip.cnf -s packet-cmip-template CMIP.asn */

/* Input file: packet-cmip-template.c */

#line 1 "packet-cmip-template.c"
/* packet-cmip.c
 * Routines for X.711 CMIP packet dissection
 *   Ronnie Sahlberg 2004
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-x509if.h"
#include "packet-cmip.h"

#define PNAME  "X711 CMIP"
#define PSNAME "CMIP"
#define PFNAME "cmip"

/* XXX some stuff we need until we can get rid of it */
#include "packet-ses.h"
#include "packet-pres.h"

/* Initialize the protocol and registered fields */
int proto_cmip = -1;
static int hf_cmip_actionType_OID = -1;
static int hf_cmip_eventType_OID = -1;
static int hf_cmip_attributeId_OID = -1;
static int hf_cmip_errorId_OID = -1;
static int hf_DiscriminatorConstruct = -1;
static int hf_Destination = -1;
static int hf_NameBinding = -1;
static int hf_ObjectClass = -1;
static int hf_OperationalState = -1;

/*--- Included file: packet-cmip-hf.c ---*/
#line 1 "packet-cmip-hf.c"
static int hf_cmip_modifyOperator = -1;           /* ModifyOperator */
static int hf_cmip_attributeId = -1;              /* T_attributeId */
static int hf_cmip_attributeValue = -1;           /* T_attributeValue */
static int hf_cmip_managedObjectClass = -1;       /* ObjectClass */
static int hf_cmip_managedObjectInstance = -1;    /* ObjectInstance */
static int hf_cmip_currentTime = -1;              /* GeneralizedTime */
static int hf_cmip_getInfoList = -1;              /* SET_OF_GetInfoStatus */
static int hf_cmip_getInfoList_item = -1;         /* GetInfoStatus */
static int hf_cmip_attributeIdError = -1;         /* AttributeIdError */
static int hf_cmip_attribute = -1;                /* Attribute */
static int hf_cmip_errorStatus = -1;              /* T_errorStatus */
static int hf_cmip_attributeId1 = -1;             /* AttributeId */
static int hf_cmip_setInfoList = -1;              /* SET_OF_SetInfoStatus */
static int hf_cmip_setInfoList_item = -1;         /* SetInfoStatus */
static int hf_cmip_actionErrorInfo = -1;          /* ActionErrorInfo */
static int hf_cmip_specificErrorInfo = -1;        /* SpecificErrorInfo */
static int hf_cmip_RDNSequence_item = -1;         /* RelativeDistinguishedName */
static int hf_cmip_RelativeDistinguishedName_item = -1;  /* AttributeValueAssertion */
static int hf_cmip_deleteErrorInfo = -1;          /* T_deleteErrorInfo */
static int hf_cmip_attributeError = -1;           /* AttributeError */
static int hf_cmip_errorId = -1;                  /* T_errorId */
static int hf_cmip_errorInfo = -1;                /* T_errorInfo */
static int hf_cmip_actionType = -1;               /* T_actionType */
static int hf_cmip_eventType = -1;                /* T_eventType */
static int hf_cmip_actionId = -1;                 /* NoSuchArgumentAction */
static int hf_cmip_eventId = -1;                  /* NoSuchArgumentEvent */
static int hf_cmip_eventType1 = -1;               /* T_eventType1 */
static int hf_cmip_eventInfo = -1;                /* T_eventInfo */
static int hf_cmip_actionValue = -1;              /* ActionInfo */
static int hf_cmip_eventValue = -1;               /* InvalidArgumentValueEventValue */
static int hf_cmip_actionType1 = -1;              /* T_actionType1 */
static int hf_cmip_actionArgument = -1;           /* NoSuchArgument */
static int hf_cmip_argumentValue = -1;            /* InvalidArgumentValue */
static int hf_cmip_errorStatus1 = -1;             /* T_errorStatus1 */
static int hf_cmip_errorInfo1 = -1;               /* ErrorInfo */
static int hf_cmip_errorStatus2 = -1;             /* T_errorStatus2 */
static int hf_cmip_attributeId2 = -1;             /* T_attributeId1 */
static int hf_cmip_attributeValue1 = -1;          /* T_attributeValue1 */
static int hf_cmip_attributeList = -1;            /* SET_OF_Attribute */
static int hf_cmip_attributeList_item = -1;       /* Attribute */
static int hf_cmip_baseManagedObjectClass = -1;   /* ObjectClass */
static int hf_cmip_baseManagedObjectInstance = -1;  /* ObjectInstance */
static int hf_cmip_accessControl = -1;            /* AccessControl */
static int hf_cmip_synchronization = -1;          /* CMISSync */
static int hf_cmip_scope = -1;                    /* Scope */
static int hf_cmip_filter = -1;                   /* CMISFilter */
static int hf_cmip_modificationList = -1;         /* SET_OF_ModificationItem */
static int hf_cmip_modificationList_item = -1;    /* ModificationItem */
static int hf_cmip_getResult = -1;                /* GetResult */
static int hf_cmip_getListError = -1;             /* GetListError */
static int hf_cmip_setResult = -1;                /* SetResult */
static int hf_cmip_setListError = -1;             /* SetListError */
static int hf_cmip_actionResult = -1;             /* ActionResult */
static int hf_cmip_processingFailure = -1;        /* ProcessingFailure */
static int hf_cmip_deleteResult = -1;             /* DeleteResult */
static int hf_cmip_actionError = -1;              /* ActionError */
static int hf_cmip_deleteError = -1;              /* DeleteError */
static int hf_cmip_eventType2 = -1;               /* T_eventType2 */
static int hf_cmip_eventReplyInfo = -1;           /* T_eventReplyInfo */
static int hf_cmip_eventReply = -1;               /* EventReply */
static int hf_cmip_eventTime = -1;                /* GeneralizedTime */
static int hf_cmip_eventType3 = -1;               /* T_eventType3 */
static int hf_cmip_eventInfo1 = -1;               /* T_eventInfo1 */
static int hf_cmip_managedOrSuperiorObjectInstance = -1;  /* T_managedOrSuperiorObjectInstance */
static int hf_cmip_superiorObjectInstance = -1;   /* ObjectInstance */
static int hf_cmip_referenceObjectInstance = -1;  /* ObjectInstance */
static int hf_cmip_actionType2 = -1;              /* T_actionType2 */
static int hf_cmip_actionReplyInfo = -1;          /* T_actionReplyInfo */
static int hf_cmip_actionReply = -1;              /* ActionReply */
static int hf_cmip_actionInfo = -1;               /* ActionInfo */
static int hf_cmip_actionType3 = -1;              /* T_actionType3 */
static int hf_cmip_actionInfoArg = -1;            /* T_actionInfoArg */
static int hf_cmip_ocglobalForm = -1;             /* T_ocglobalForm */
static int hf_cmip_oclocalForm = -1;              /* T_oclocalForm */
static int hf_cmip_distinguishedName = -1;        /* DistinguishedName */
static int hf_cmip_nonSpecificForm = -1;          /* OCTET_STRING */
static int hf_cmip_localDistinguishedName = -1;   /* RDNSequence */
static int hf_cmip_globalForm = -1;               /* T_globalForm */
static int hf_cmip_localForm = -1;                /* T_localForm */
static int hf_cmip_id = -1;                       /* AttributeId */
static int hf_cmip_value = -1;                    /* T_value */
static int hf_cmip_id1 = -1;                      /* T_id */
static int hf_cmip_value1 = -1;                   /* T_value1 */
static int hf_cmip_equality = -1;                 /* Attribute */
static int hf_cmip_substrings = -1;               /* T_substrings */
static int hf_cmip_substrings_item = -1;          /* T_substrings_item */
static int hf_cmip_initialString = -1;            /* Attribute */
static int hf_cmip_anyString = -1;                /* Attribute */
static int hf_cmip_finalString = -1;              /* Attribute */
static int hf_cmip_greaterOrEqual = -1;           /* Attribute */
static int hf_cmip_lessOrEqual = -1;              /* Attribute */
static int hf_cmip_present = -1;                  /* AttributeId */
static int hf_cmip_subsetOf = -1;                 /* Attribute */
static int hf_cmip_supersetOf = -1;               /* Attribute */
static int hf_cmip_nonNullSetIntersection = -1;   /* Attribute */
static int hf_cmip_single = -1;                   /* AE_title */
static int hf_cmip_multiple = -1;                 /* SET_OF_AE_title */
static int hf_cmip_multiple_item = -1;            /* AE_title */
static int hf_cmip_ae_title_form1 = -1;           /* AE_title_form1 */
static int hf_cmip_ae_title_form2 = -1;           /* AE_title_form2 */
static int hf_cmip_rdnSequence = -1;              /* RDNSequence */
static int hf_cmip_item = -1;                     /* FilterItem */
static int hf_cmip_and = -1;                      /* SET_OF_CMISFilter */
static int hf_cmip_and_item = -1;                 /* CMISFilter */
static int hf_cmip_or = -1;                       /* SET_OF_CMISFilter */
static int hf_cmip_or_item = -1;                  /* CMISFilter */
static int hf_cmip_not = -1;                      /* CMISFilter */
static int hf_cmip_namedNumbers = -1;             /* T_namedNumbers */
static int hf_cmip_individualLevels = -1;         /* INTEGER */
static int hf_cmip_baseToNthLevel = -1;           /* INTEGER */
static int hf_cmip_attributeIdList = -1;          /* SET_OF_AttributeId */
static int hf_cmip_attributeIdList_item = -1;     /* AttributeId */
static int hf_cmip_opcode = -1;                   /* Opcode */
static int hf_cmip_argument = -1;                 /* Argument */
static int hf_cmip_present1 = -1;                 /* InvokeID */
static int hf_cmip_absent = -1;                   /* NULL */
static int hf_cmip_invokeId = -1;                 /* InvokeId */
static int hf_cmip_linkedId = -1;                 /* InvokeLinkedId */
static int hf_cmip_rRBody = -1;                   /* ReturnResultBody */
static int hf_cmip_generalProblem = -1;           /* GeneralProblem */
static int hf_cmip_invokeProblem = -1;            /* InvokeProblem */
static int hf_cmip_returnResultProblem = -1;      /* ReturnResultProblem */
static int hf_cmip_returnErrorProblem = -1;       /* ReturnErrorProblem */
static int hf_cmip_rejectProblem = -1;            /* RejectProb */
static int hf_cmip_invoke = -1;                   /* Invoke */
static int hf_cmip_returnResult = -1;             /* ReturnResult */
static int hf_cmip_returnError = -1;              /* ReturnError */
static int hf_cmip_reject = -1;                   /* Reject */
static int hf_cmip_abortSource = -1;              /* CMIPAbortSource */
static int hf_cmip_userInfo = -1;                 /* EXTERNAL */
static int hf_cmip_protocolVersion = -1;          /* ProtocolVersion */
static int hf_cmip_functionalUnits = -1;          /* FunctionalUnits */
static int hf_cmip_accessControl1 = -1;           /* EXTERNAL */
/* named bits */
static int hf_cmip_FunctionalUnits_multipleObjectSelection = -1;
static int hf_cmip_FunctionalUnits_filter = -1;
static int hf_cmip_FunctionalUnits_multipleReply = -1;
static int hf_cmip_FunctionalUnits_extendedService = -1;
static int hf_cmip_FunctionalUnits_cancelGet = -1;
static int hf_cmip_ProtocolVersion_version1 = -1;
static int hf_cmip_ProtocolVersion_version2 = -1;

/*--- End of included file: packet-cmip-hf.c ---*/
#line 62 "packet-cmip-template.c"

/* Initialize the subtree pointers */
static gint ett_cmip = -1;

/*--- Included file: packet-cmip-ett.c ---*/
#line 1 "packet-cmip-ett.c"
static gint ett_cmip_ModificationItem = -1;
static gint ett_cmip_GetListError = -1;
static gint ett_cmip_SET_OF_GetInfoStatus = -1;
static gint ett_cmip_GetInfoStatus = -1;
static gint ett_cmip_AttributeIdError = -1;
static gint ett_cmip_SetListError = -1;
static gint ett_cmip_SET_OF_SetInfoStatus = -1;
static gint ett_cmip_ActionError = -1;
static gint ett_cmip_ProcessingFailure = -1;
static gint ett_cmip_RDNSequence = -1;
static gint ett_cmip_RelativeDistinguishedName = -1;
static gint ett_cmip_DeleteError = -1;
static gint ett_cmip_SetInfoStatus = -1;
static gint ett_cmip_SpecificErrorInfo = -1;
static gint ett_cmip_NoSuchArgumentAction = -1;
static gint ett_cmip_NoSuchArgumentEvent = -1;
static gint ett_cmip_NoSuchArgument = -1;
static gint ett_cmip_InvalidArgumentValueEventValue = -1;
static gint ett_cmip_InvalidArgumentValue = -1;
static gint ett_cmip_ErrorInfo = -1;
static gint ett_cmip_ActionErrorInfo = -1;
static gint ett_cmip_AttributeError = -1;
static gint ett_cmip_SetResult = -1;
static gint ett_cmip_SET_OF_Attribute = -1;
static gint ett_cmip_SetArgument = -1;
static gint ett_cmip_SET_OF_ModificationItem = -1;
static gint ett_cmip_LinkedReplyArgument = -1;
static gint ett_cmip_EventReply = -1;
static gint ett_cmip_EventReportResult = -1;
static gint ett_cmip_EventReportArgument = -1;
static gint ett_cmip_DeleteArgument = -1;
static gint ett_cmip_DeleteResult = -1;
static gint ett_cmip_CreateArgument = -1;
static gint ett_cmip_T_managedOrSuperiorObjectInstance = -1;
static gint ett_cmip_CreateResult = -1;
static gint ett_cmip_ActionReply = -1;
static gint ett_cmip_ActionResult = -1;
static gint ett_cmip_ActionArgument = -1;
static gint ett_cmip_ActionInfo = -1;
static gint ett_cmip_ObjectClass = -1;
static gint ett_cmip_ObjectInstance = -1;
static gint ett_cmip_BaseManagedObjectId = -1;
static gint ett_cmip_AttributeId = -1;
static gint ett_cmip_Attribute = -1;
static gint ett_cmip_AttributeValueAssertion = -1;
static gint ett_cmip_FilterItem = -1;
static gint ett_cmip_T_substrings = -1;
static gint ett_cmip_T_substrings_item = -1;
static gint ett_cmip_Destination = -1;
static gint ett_cmip_SET_OF_AE_title = -1;
static gint ett_cmip_AE_title = -1;
static gint ett_cmip_Name = -1;
static gint ett_cmip_CMISFilter = -1;
static gint ett_cmip_SET_OF_CMISFilter = -1;
static gint ett_cmip_Scope = -1;
static gint ett_cmip_GetArgument = -1;
static gint ett_cmip_SET_OF_AttributeId = -1;
static gint ett_cmip_GetResult = -1;
static gint ett_cmip_ReturnResultBody = -1;
static gint ett_cmip_InvokeId = -1;
static gint ett_cmip_Invoke = -1;
static gint ett_cmip_ReturnResult = -1;
static gint ett_cmip_ReturnError = -1;
static gint ett_cmip_RejectProb = -1;
static gint ett_cmip_Reject = -1;
static gint ett_cmip_ROS = -1;
static gint ett_cmip_CMIPAbortInfo = -1;
static gint ett_cmip_FunctionalUnits = -1;
static gint ett_cmip_CMIPUserInfo = -1;
static gint ett_cmip_ProtocolVersion = -1;

/*--- End of included file: packet-cmip-ett.c ---*/
#line 66 "packet-cmip-template.c"

static guint32 opcode;

static int opcode_type;
#define OPCODE_INVOKE        1
#define OPCODE_RETURN_RESULT 2
#define OPCODE_RETURN_ERROR  3
#define OPCODE_REJECT        4

static int attributeform;
#define ATTRIBUTE_LOCAL_FORM  0
#define ATTRIBUTE_GLOBAL_FORM 1
static const char *attribute_identifier_id;

static const char *attributevalueassertion_id;

static const char *object_identifier_id;

static int objectclassform;
#define OBJECTCLASS_LOCAL_FORM  0
#define OBJECTCLASS_GLOBAL_FORM 1
static const char *objectclass_identifier_id;


/*--- Included file: packet-cmip-fn.c ---*/
#line 1 "packet-cmip-fn.c"
/*--- Cyclic dependencies ---*/

/* CMISFilter -> CMISFilter/and -> CMISFilter */
/* CMISFilter -> CMISFilter */
static int dissect_cmip_CMISFilter(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_filter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_CMISFilter(FALSE, tvb, offset, pinfo, tree, hf_cmip_filter);
}
static int dissect_and_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_CMISFilter(FALSE, tvb, offset, pinfo, tree, hf_cmip_and_item);
}
static int dissect_or_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_CMISFilter(FALSE, tvb, offset, pinfo, tree, hf_cmip_or_item);
}
static int dissect_not(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_CMISFilter(FALSE, tvb, offset, pinfo, tree, hf_cmip_not);
}


/*--- Fields for imported types ---*/

static int dissect_userInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(FALSE, tvb, offset, pinfo, tree, hf_cmip_userInfo);
}
static int dissect_accessControl1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(FALSE, tvb, offset, pinfo, tree, hf_cmip_accessControl1);
}


static const value_string cmip_ModifyOperator_vals[] = {
  {   0, "replace" },
  {   1, "addValues" },
  {   2, "removeValues" },
  {   3, "setToDefault" },
  { 0, NULL }
};


static int
dissect_cmip_ModifyOperator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_modifyOperator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ModifyOperator(TRUE, tvb, offset, pinfo, tree, hf_cmip_modifyOperator);
}



static int
dissect_cmip_T_attributeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_attributeId_OID, &object_identifier_id);

  return offset;
}
static int dissect_attributeId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_attributeId(FALSE, tvb, offset, pinfo, tree, hf_cmip_attributeId);
}



static int
dissect_cmip_T_attributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 211 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_attributeValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_attributeValue(FALSE, tvb, offset, pinfo, tree, hf_cmip_attributeValue);
}


static const ber_sequence_t ModificationItem_sequence[] = {
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modifyOperator_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attributeId },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_attributeValue },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ModificationItem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModificationItem_sequence, hf_index, ett_cmip_ModificationItem);

  return offset;
}
static int dissect_modificationList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ModificationItem(FALSE, tvb, offset, pinfo, tree, hf_cmip_modificationList_item);
}



static int
dissect_cmip_T_ocglobalForm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 176 "cmip.cnf"
  objectclassform = OBJECTCLASS_GLOBAL_FORM;

  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &objectclass_identifier_id);

  return offset;
}
static int dissect_ocglobalForm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_ocglobalForm(TRUE, tvb, offset, pinfo, tree, hf_cmip_ocglobalForm);
}



static int
dissect_cmip_T_oclocalForm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 181 "cmip.cnf"
  objectclassform = OBJECTCLASS_LOCAL_FORM;


  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_oclocalForm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_oclocalForm(TRUE, tvb, offset, pinfo, tree, hf_cmip_oclocalForm);
}


const value_string cmip_ObjectClass_vals[] = {
  {   0, "ocglobalForm" },
  {   1, "oclocalForm" },
  { 0, NULL }
};

static const ber_choice_t ObjectClass_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ocglobalForm_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_oclocalForm_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_cmip_ObjectClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ObjectClass_choice, hf_index, ett_cmip_ObjectClass,
                                 NULL);

  return offset;
}
static int dissect_managedObjectClass(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectClass(FALSE, tvb, offset, pinfo, tree, hf_cmip_managedObjectClass);
}
static int dissect_baseManagedObjectClass(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectClass(FALSE, tvb, offset, pinfo, tree, hf_cmip_baseManagedObjectClass);
}



static int
dissect_cmip_T_id(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &attributevalueassertion_id);

  return offset;
}
static int dissect_id1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_id(FALSE, tvb, offset, pinfo, tree, hf_cmip_id1);
}



static int
dissect_cmip_T_value1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 99 "cmip.cnf"
    offset=call_ber_oid_callback(attributevalueassertion_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_value1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_value1(FALSE, tvb, offset, pinfo, tree, hf_cmip_value1);
}


static const ber_sequence_t AttributeValueAssertion_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_id1 },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_value1 },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeValueAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeValueAssertion_sequence, hf_index, ett_cmip_AttributeValueAssertion);

  return offset;
}
static int dissect_RelativeDistinguishedName_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_cmip_RelativeDistinguishedName_item);
}


static const ber_sequence_t RelativeDistinguishedName_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RelativeDistinguishedName_item },
};

static int
dissect_cmip_RelativeDistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 RelativeDistinguishedName_set_of, hf_index, ett_cmip_RelativeDistinguishedName);

  return offset;
}
static int dissect_RDNSequence_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_RelativeDistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_cmip_RDNSequence_item);
}


static const ber_sequence_t RDNSequence_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_RDNSequence_item },
};

int
dissect_cmip_RDNSequence(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RDNSequence_sequence_of, hf_index, ett_cmip_RDNSequence);

  return offset;
}
static int dissect_localDistinguishedName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_RDNSequence(TRUE, tvb, offset, pinfo, tree, hf_cmip_localDistinguishedName);
}
static int dissect_rdnSequence(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_RDNSequence(FALSE, tvb, offset, pinfo, tree, hf_cmip_rdnSequence);
}



static int
dissect_cmip_DistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_cmip_RDNSequence(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_distinguishedName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_DistinguishedName(TRUE, tvb, offset, pinfo, tree, hf_cmip_distinguishedName);
}



static int
dissect_cmip_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_nonSpecificForm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_cmip_nonSpecificForm);
}


const value_string cmip_ObjectInstance_vals[] = {
  {   2, "distinguishedName" },
  {   3, "nonSpecificForm" },
  {   4, "localDistinguishedName" },
  { 0, NULL }
};

static const ber_choice_t ObjectInstance_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_distinguishedName_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_nonSpecificForm_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_localDistinguishedName_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_cmip_ObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ObjectInstance_choice, hf_index, ett_cmip_ObjectInstance,
                                 NULL);

  return offset;
}
static int dissect_managedObjectInstance(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_cmip_managedObjectInstance);
}
static int dissect_baseManagedObjectInstance(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_cmip_baseManagedObjectInstance);
}
static int dissect_superiorObjectInstance(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_cmip_superiorObjectInstance);
}
static int dissect_referenceObjectInstance(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_cmip_referenceObjectInstance);
}



static int
dissect_cmip_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_currentTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_GeneralizedTime(TRUE, tvb, offset, pinfo, tree, hf_cmip_currentTime);
}
static int dissect_eventTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_GeneralizedTime(TRUE, tvb, offset, pinfo, tree, hf_cmip_eventTime);
}


static const value_string cmip_T_errorStatus_vals[] = {
  {   2, "accessDenied" },
  {   5, "noSuchAttribute" },
  { 0, NULL }
};


static int
dissect_cmip_T_errorStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_errorStatus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_errorStatus(FALSE, tvb, offset, pinfo, tree, hf_cmip_errorStatus);
}



static int
dissect_cmip_T_globalForm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 83 "cmip.cnf"
  attributeform = ATTRIBUTE_GLOBAL_FORM;
    offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &attribute_identifier_id);




  return offset;
}
static int dissect_globalForm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_globalForm(TRUE, tvb, offset, pinfo, tree, hf_cmip_globalForm);
}



static int
dissect_cmip_T_localForm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 87 "cmip.cnf"
  attributeform = ATTRIBUTE_LOCAL_FORM;
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_localForm, NULL);



  return offset;
}
static int dissect_localForm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_localForm(TRUE, tvb, offset, pinfo, tree, hf_cmip_localForm);
}


static const value_string cmip_AttributeId_vals[] = {
  {   0, "globalForm" },
  {   1, "localForm" },
  { 0, NULL }
};

static const ber_choice_t AttributeId_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_globalForm_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_localForm_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AttributeId_choice, hf_index, ett_cmip_AttributeId,
                                 NULL);

  return offset;
}
static int dissect_attributeId1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_cmip_attributeId1);
}
static int dissect_id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_cmip_id);
}
static int dissect_present(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_cmip_present);
}
static int dissect_attributeIdList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AttributeId(FALSE, tvb, offset, pinfo, tree, hf_cmip_attributeIdList_item);
}


static const ber_sequence_t AttributeIdError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_errorStatus },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_attributeId1 },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeIdError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeIdError_sequence, hf_index, ett_cmip_AttributeIdError);

  return offset;
}
static int dissect_attributeIdError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AttributeIdError(TRUE, tvb, offset, pinfo, tree, hf_cmip_attributeIdError);
}



static int
dissect_cmip_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 91 "cmip.cnf"
  /*XXX handle local form here */
  if(attributeform==ATTRIBUTE_GLOBAL_FORM){
    offset=call_ber_oid_callback(attribute_identifier_id, tvb, offset, pinfo, tree);
  }


  return offset;
}
static int dissect_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_value(FALSE, tvb, offset, pinfo, tree, hf_cmip_value);
}


static const ber_sequence_t Attribute_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_id },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_value },
  { 0, 0, 0, NULL }
};

int
dissect_cmip_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Attribute_sequence, hf_index, ett_cmip_Attribute);

  return offset;
}
static int dissect_attribute_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_attribute);
}
static int dissect_attributeList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(FALSE, tvb, offset, pinfo, tree, hf_cmip_attributeList_item);
}
static int dissect_equality_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_equality);
}
static int dissect_initialString_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_initialString);
}
static int dissect_anyString_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_anyString);
}
static int dissect_finalString_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_finalString);
}
static int dissect_greaterOrEqual_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_greaterOrEqual);
}
static int dissect_lessOrEqual_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_lessOrEqual);
}
static int dissect_subsetOf_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_subsetOf);
}
static int dissect_supersetOf_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_supersetOf);
}
static int dissect_nonNullSetIntersection_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_nonNullSetIntersection);
}


static const value_string cmip_GetInfoStatus_vals[] = {
  {   0, "attributeIdError" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t GetInfoStatus_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_attributeIdError_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_attribute_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_GetInfoStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 GetInfoStatus_choice, hf_index, ett_cmip_GetInfoStatus,
                                 NULL);

  return offset;
}
static int dissect_getInfoList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_GetInfoStatus(FALSE, tvb, offset, pinfo, tree, hf_cmip_getInfoList_item);
}


static const ber_sequence_t SET_OF_GetInfoStatus_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_getInfoList_item },
};

static int
dissect_cmip_SET_OF_GetInfoStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_GetInfoStatus_set_of, hf_index, ett_cmip_SET_OF_GetInfoStatus);

  return offset;
}
static int dissect_getInfoList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SET_OF_GetInfoStatus(TRUE, tvb, offset, pinfo, tree, hf_cmip_getInfoList);
}


static const ber_sequence_t GetListError_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_getInfoList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_GetListError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetListError_sequence, hf_index, ett_cmip_GetListError);

  return offset;
}
static int dissect_getListError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_GetListError(TRUE, tvb, offset, pinfo, tree, hf_cmip_getListError);
}


static const value_string cmip_T_errorStatus2_vals[] = {
  {   2, "accessDenied" },
  {   5, "noSuchAttribute" },
  {   6, "invalidAttributeValue" },
  {  24, "invalidOperation" },
  {  25, "invalidOperator" },
  { 0, NULL }
};


static int
dissect_cmip_T_errorStatus2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_errorStatus2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_errorStatus2(FALSE, tvb, offset, pinfo, tree, hf_cmip_errorStatus2);
}



static int
dissect_cmip_T_attributeId1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_attributeId_OID, &object_identifier_id);

  return offset;
}
static int dissect_attributeId2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_attributeId1(FALSE, tvb, offset, pinfo, tree, hf_cmip_attributeId2);
}



static int
dissect_cmip_T_attributeValue1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 223 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_attributeValue1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_attributeValue1(FALSE, tvb, offset, pinfo, tree, hf_cmip_attributeValue1);
}


static const ber_sequence_t AttributeError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_errorStatus2 },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modifyOperator_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attributeId2 },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_attributeValue1 },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeError_sequence, hf_index, ett_cmip_AttributeError);

  return offset;
}
static int dissect_attributeError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AttributeError(TRUE, tvb, offset, pinfo, tree, hf_cmip_attributeError);
}


static const value_string cmip_SetInfoStatus_vals[] = {
  {   0, "attributeError" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t SetInfoStatus_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_attributeError_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_attribute_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_SetInfoStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SetInfoStatus_choice, hf_index, ett_cmip_SetInfoStatus,
                                 NULL);

  return offset;
}
static int dissect_setInfoList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SetInfoStatus(FALSE, tvb, offset, pinfo, tree, hf_cmip_setInfoList_item);
}


static const ber_sequence_t SET_OF_SetInfoStatus_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_setInfoList_item },
};

static int
dissect_cmip_SET_OF_SetInfoStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_SetInfoStatus_set_of, hf_index, ett_cmip_SET_OF_SetInfoStatus);

  return offset;
}
static int dissect_setInfoList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SET_OF_SetInfoStatus(TRUE, tvb, offset, pinfo, tree, hf_cmip_setInfoList);
}


static const ber_sequence_t SetListError_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_setInfoList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_SetListError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SetListError_sequence, hf_index, ett_cmip_SetListError);

  return offset;
}
static int dissect_setListError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SetListError(TRUE, tvb, offset, pinfo, tree, hf_cmip_setListError);
}


static const value_string cmip_T_errorStatus1_vals[] = {
  {   2, "accessDenied" },
  {   9, "noSuchAction" },
  {  14, "noSuchArgument" },
  {  15, "invalidArgumentValue" },
  { 0, NULL }
};


static int
dissect_cmip_T_errorStatus1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_errorStatus1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_errorStatus1(FALSE, tvb, offset, pinfo, tree, hf_cmip_errorStatus1);
}



static int
dissect_cmip_T_actionType1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_actionType_OID, &object_identifier_id);

  return offset;
}
static int dissect_actionType1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_actionType1(FALSE, tvb, offset, pinfo, tree, hf_cmip_actionType1);
}



static int
dissect_cmip_T_actionType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_actionType_OID, &object_identifier_id);

  return offset;
}
static int dissect_actionType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_actionType(FALSE, tvb, offset, pinfo, tree, hf_cmip_actionType);
}


static const ber_sequence_t NoSuchArgumentAction_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_actionType },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_NoSuchArgumentAction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NoSuchArgumentAction_sequence, hf_index, ett_cmip_NoSuchArgumentAction);

  return offset;
}
static int dissect_actionId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_NoSuchArgumentAction(TRUE, tvb, offset, pinfo, tree, hf_cmip_actionId);
}



static int
dissect_cmip_T_eventType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_eventType_OID, &object_identifier_id);

  return offset;
}
static int dissect_eventType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_eventType(FALSE, tvb, offset, pinfo, tree, hf_cmip_eventType);
}


static const ber_sequence_t NoSuchArgumentEvent_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_eventType },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_NoSuchArgumentEvent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NoSuchArgumentEvent_sequence, hf_index, ett_cmip_NoSuchArgumentEvent);

  return offset;
}
static int dissect_eventId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_NoSuchArgumentEvent(TRUE, tvb, offset, pinfo, tree, hf_cmip_eventId);
}


static const value_string cmip_NoSuchArgument_vals[] = {
  {   0, "actionId" },
  {   1, "eventId" },
  { 0, NULL }
};

static const ber_choice_t NoSuchArgument_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_actionId_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_eventId_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_NoSuchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 NoSuchArgument_choice, hf_index, ett_cmip_NoSuchArgument,
                                 NULL);

  return offset;
}
static int dissect_actionArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_NoSuchArgument(FALSE, tvb, offset, pinfo, tree, hf_cmip_actionArgument);
}



static int
dissect_cmip_T_actionType3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_actionType_OID, &object_identifier_id);

  return offset;
}
static int dissect_actionType3(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_actionType3(FALSE, tvb, offset, pinfo, tree, hf_cmip_actionType3);
}



static int
dissect_cmip_T_actionInfoArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 187 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_actionInfoArg(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_actionInfoArg(FALSE, tvb, offset, pinfo, tree, hf_cmip_actionInfoArg);
}


static const ber_sequence_t ActionInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_actionType3 },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_actionInfoArg },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ActionInfo_sequence, hf_index, ett_cmip_ActionInfo);

  return offset;
}
static int dissect_actionValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ActionInfo(TRUE, tvb, offset, pinfo, tree, hf_cmip_actionValue);
}
static int dissect_actionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ActionInfo(TRUE, tvb, offset, pinfo, tree, hf_cmip_actionInfo);
}



static int
dissect_cmip_T_eventType1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_eventType_OID, &object_identifier_id);

  return offset;
}
static int dissect_eventType1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_eventType1(FALSE, tvb, offset, pinfo, tree, hf_cmip_eventType1);
}



static int
dissect_cmip_T_eventInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 238 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_eventInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_eventInfo(FALSE, tvb, offset, pinfo, tree, hf_cmip_eventInfo);
}


static const ber_sequence_t InvalidArgumentValueEventValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_eventType1 },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_eventInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_InvalidArgumentValueEventValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InvalidArgumentValueEventValue_sequence, hf_index, ett_cmip_InvalidArgumentValueEventValue);

  return offset;
}
static int dissect_eventValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_InvalidArgumentValueEventValue(TRUE, tvb, offset, pinfo, tree, hf_cmip_eventValue);
}


static const value_string cmip_InvalidArgumentValue_vals[] = {
  {   0, "actionValue" },
  {   1, "eventValue" },
  { 0, NULL }
};

static const ber_choice_t InvalidArgumentValue_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_actionValue_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_eventValue_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_InvalidArgumentValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 InvalidArgumentValue_choice, hf_index, ett_cmip_InvalidArgumentValue,
                                 NULL);

  return offset;
}
static int dissect_argumentValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_InvalidArgumentValue(FALSE, tvb, offset, pinfo, tree, hf_cmip_argumentValue);
}


static const value_string cmip_ErrorInfo_vals[] = {
  {   0, "actionType" },
  {   1, "actionArgument" },
  {   2, "argumentValue" },
  { 0, NULL }
};

static const ber_choice_t ErrorInfo_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_actionType1 },
  {   1, BER_CLASS_CON, 0, 0, dissect_actionArgument },
  {   2, BER_CLASS_CON, 1, 0, dissect_argumentValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_ErrorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ErrorInfo_choice, hf_index, ett_cmip_ErrorInfo,
                                 NULL);

  return offset;
}
static int dissect_errorInfo1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ErrorInfo(FALSE, tvb, offset, pinfo, tree, hf_cmip_errorInfo1);
}


static const ber_sequence_t ActionErrorInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_errorStatus1 },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_errorInfo1 },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionErrorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ActionErrorInfo_sequence, hf_index, ett_cmip_ActionErrorInfo);

  return offset;
}
static int dissect_actionErrorInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ActionErrorInfo(FALSE, tvb, offset, pinfo, tree, hf_cmip_actionErrorInfo);
}


static const ber_sequence_t ActionError_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { BER_CLASS_CON, 6, 0, dissect_actionErrorInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ActionError_sequence, hf_index, ett_cmip_ActionError);

  return offset;
}
static int dissect_actionError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ActionError(TRUE, tvb, offset, pinfo, tree, hf_cmip_actionError);
}



static int
dissect_cmip_T_errorId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_errorId_OID, &object_identifier_id);

  return offset;
}
static int dissect_errorId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_errorId(FALSE, tvb, offset, pinfo, tree, hf_cmip_errorId);
}



static int
dissect_cmip_T_errorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 217 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_errorInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_errorInfo(FALSE, tvb, offset, pinfo, tree, hf_cmip_errorInfo);
}


static const ber_sequence_t SpecificErrorInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_errorId },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_errorInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_SpecificErrorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SpecificErrorInfo_sequence, hf_index, ett_cmip_SpecificErrorInfo);

  return offset;
}
static int dissect_specificErrorInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SpecificErrorInfo(FALSE, tvb, offset, pinfo, tree, hf_cmip_specificErrorInfo);
}


static const ber_sequence_t ProcessingFailure_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, 0, dissect_specificErrorInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ProcessingFailure(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ProcessingFailure_sequence, hf_index, ett_cmip_ProcessingFailure);

  return offset;
}
static int dissect_processingFailure_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ProcessingFailure(TRUE, tvb, offset, pinfo, tree, hf_cmip_processingFailure);
}


static const value_string cmip_T_deleteErrorInfo_vals[] = {
  {   2, "accessDenied" },
  { 0, NULL }
};


static int
dissect_cmip_T_deleteErrorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_deleteErrorInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_deleteErrorInfo(FALSE, tvb, offset, pinfo, tree, hf_cmip_deleteErrorInfo);
}


static const ber_sequence_t DeleteError_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { BER_CLASS_CON, 6, 0, dissect_deleteErrorInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_DeleteError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteError_sequence, hf_index, ett_cmip_DeleteError);

  return offset;
}
static int dissect_deleteError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_DeleteError(TRUE, tvb, offset, pinfo, tree, hf_cmip_deleteError);
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_attributeList_item },
};

static int
dissect_cmip_SET_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Attribute_set_of, hf_index, ett_cmip_SET_OF_Attribute);

  return offset;
}
static int dissect_attributeList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SET_OF_Attribute(TRUE, tvb, offset, pinfo, tree, hf_cmip_attributeList);
}


static const ber_sequence_t SetResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attributeList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_SetResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SetResult_sequence, hf_index, ett_cmip_SetResult);

  return offset;
}
static int dissect_setResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SetResult(TRUE, tvb, offset, pinfo, tree, hf_cmip_setResult);
}



static int
dissect_cmip_AccessControl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_acse_EXTERNAL(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_accessControl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AccessControl(FALSE, tvb, offset, pinfo, tree, hf_cmip_accessControl);
}


static const value_string cmip_CMISSync_vals[] = {
  {   0, "bestEffort" },
  {   1, "atomic" },
  { 0, NULL }
};


static int
dissect_cmip_CMISSync(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_synchronization_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_CMISSync(TRUE, tvb, offset, pinfo, tree, hf_cmip_synchronization);
}


static const value_string cmip_T_namedNumbers_vals[] = {
  {   0, "baseObject" },
  {   1, "firstLevelOnly" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_cmip_T_namedNumbers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_namedNumbers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_namedNumbers(FALSE, tvb, offset, pinfo, tree, hf_cmip_namedNumbers);
}



static int
dissect_cmip_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_individualLevels_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_cmip_individualLevels);
}
static int dissect_baseToNthLevel_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_cmip_baseToNthLevel);
}


static const value_string cmip_Scope_vals[] = {
  {   0, "namedNumbers" },
  {   1, "individualLevels" },
  {   2, "baseToNthLevel" },
  { 0, NULL }
};

static const ber_choice_t Scope_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_namedNumbers },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_individualLevels_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_baseToNthLevel_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_Scope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Scope_choice, hf_index, ett_cmip_Scope,
                                 NULL);

  return offset;
}
static int dissect_scope(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Scope(FALSE, tvb, offset, pinfo, tree, hf_cmip_scope);
}


static const value_string cmip_T_substrings_item_vals[] = {
  {   0, "initialString" },
  {   1, "anyString" },
  {   2, "finalString" },
  { 0, NULL }
};

static const ber_choice_t T_substrings_item_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_initialString_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_anyString_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_finalString_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_substrings_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_substrings_item_choice, hf_index, ett_cmip_T_substrings_item,
                                 NULL);

  return offset;
}
static int dissect_substrings_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_substrings_item(FALSE, tvb, offset, pinfo, tree, hf_cmip_substrings_item);
}


static const ber_sequence_t T_substrings_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_substrings_item },
};

static int
dissect_cmip_T_substrings(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_substrings_sequence_of, hf_index, ett_cmip_T_substrings);

  return offset;
}
static int dissect_substrings_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_substrings(TRUE, tvb, offset, pinfo, tree, hf_cmip_substrings);
}


static const value_string cmip_FilterItem_vals[] = {
  {   0, "equality" },
  {   1, "substrings" },
  {   2, "greaterOrEqual" },
  {   3, "lessOrEqual" },
  {   4, "present" },
  {   5, "subsetOf" },
  {   6, "supersetOf" },
  {   7, "nonNullSetIntersection" },
  { 0, NULL }
};

static const ber_choice_t FilterItem_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_equality_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_substrings_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_greaterOrEqual_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_lessOrEqual_impl },
  {   4, BER_CLASS_CON, 4, 0, dissect_present },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_subsetOf_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_supersetOf_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_nonNullSetIntersection_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_FilterItem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 FilterItem_choice, hf_index, ett_cmip_FilterItem,
                                 NULL);

  return offset;
}
static int dissect_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_FilterItem(FALSE, tvb, offset, pinfo, tree, hf_cmip_item);
}


static const ber_sequence_t SET_OF_CMISFilter_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_and_item },
};

static int
dissect_cmip_SET_OF_CMISFilter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_CMISFilter_set_of, hf_index, ett_cmip_SET_OF_CMISFilter);

  return offset;
}
static int dissect_and_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SET_OF_CMISFilter(TRUE, tvb, offset, pinfo, tree, hf_cmip_and);
}
static int dissect_or_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SET_OF_CMISFilter(TRUE, tvb, offset, pinfo, tree, hf_cmip_or);
}


static const value_string cmip_CMISFilter_vals[] = {
  {   8, "item" },
  {   9, "and" },
  {  10, "or" },
  {  11, "not" },
  { 0, NULL }
};

static const ber_choice_t CMISFilter_choice[] = {
  {   8, BER_CLASS_CON, 8, 0, dissect_item },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_and_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_or_impl },
  {  11, BER_CLASS_CON, 11, 0, dissect_not },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_CMISFilter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CMISFilter_choice, hf_index, ett_cmip_CMISFilter,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ModificationItem_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_modificationList_item },
};

static int
dissect_cmip_SET_OF_ModificationItem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ModificationItem_set_of, hf_index, ett_cmip_SET_OF_ModificationItem);

  return offset;
}
static int dissect_modificationList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SET_OF_ModificationItem(TRUE, tvb, offset, pinfo, tree, hf_cmip_modificationList);
}


static const ber_sequence_t SetArgument_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_accessControl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_synchronization_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_scope },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_filter },
  { BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_modificationList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_SetArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SetArgument_sequence, hf_index, ett_cmip_SetArgument);

  return offset;
}


static const ber_sequence_t GetResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attributeList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_GetResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetResult_sequence, hf_index, ett_cmip_GetResult);

  return offset;
}
static int dissect_getResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_GetResult(TRUE, tvb, offset, pinfo, tree, hf_cmip_getResult);
}



static int
dissect_cmip_T_actionType2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_actionType_OID, &object_identifier_id);

  return offset;
}
static int dissect_actionType2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_actionType2(FALSE, tvb, offset, pinfo, tree, hf_cmip_actionType2);
}



static int
dissect_cmip_T_actionReplyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 193 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_actionReplyInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_actionReplyInfo(FALSE, tvb, offset, pinfo, tree, hf_cmip_actionReplyInfo);
}


static const ber_sequence_t ActionReply_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_actionType2 },
  { BER_CLASS_CON, 4, 0, dissect_actionReplyInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionReply(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ActionReply_sequence, hf_index, ett_cmip_ActionReply);

  return offset;
}
static int dissect_actionReply_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ActionReply(TRUE, tvb, offset, pinfo, tree, hf_cmip_actionReply);
}


static const ber_sequence_t ActionResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionReply_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ActionResult_sequence, hf_index, ett_cmip_ActionResult);

  return offset;
}
static int dissect_actionResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ActionResult(TRUE, tvb, offset, pinfo, tree, hf_cmip_actionResult);
}


static const ber_sequence_t DeleteResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_DeleteResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteResult_sequence, hf_index, ett_cmip_DeleteResult);

  return offset;
}
static int dissect_deleteResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_DeleteResult(TRUE, tvb, offset, pinfo, tree, hf_cmip_deleteResult);
}


static const value_string cmip_LinkedReplyArgument_vals[] = {
  {   0, "getResult" },
  {   1, "getListError" },
  {   2, "setResult" },
  {   3, "setListError" },
  {   4, "actionResult" },
  {   5, "processingFailure" },
  {   6, "deleteResult" },
  {   7, "actionError" },
  {   8, "deleteError" },
  { 0, NULL }
};

static const ber_choice_t LinkedReplyArgument_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_getResult_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_getListError_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_setResult_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_setListError_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_actionResult_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_processingFailure_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_deleteResult_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_actionError_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_deleteError_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_LinkedReplyArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 LinkedReplyArgument_choice, hf_index, ett_cmip_LinkedReplyArgument,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_eventType2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_eventType_OID, &object_identifier_id);

  return offset;
}
static int dissect_eventType2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_eventType2(FALSE, tvb, offset, pinfo, tree, hf_cmip_eventType2);
}



static int
dissect_cmip_T_eventReplyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 205 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_eventReplyInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_eventReplyInfo(FALSE, tvb, offset, pinfo, tree, hf_cmip_eventReplyInfo);
}


static const ber_sequence_t EventReply_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_eventType2 },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_eventReplyInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_EventReply(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EventReply_sequence, hf_index, ett_cmip_EventReply);

  return offset;
}
static int dissect_eventReply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_EventReply(FALSE, tvb, offset, pinfo, tree, hf_cmip_eventReply);
}


static const ber_sequence_t EventReportResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_eventReply },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_EventReportResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EventReportResult_sequence, hf_index, ett_cmip_EventReportResult);

  return offset;
}



static int
dissect_cmip_T_eventType3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cmip_eventType_OID, &object_identifier_id);

  return offset;
}
static int dissect_eventType3(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_eventType3(FALSE, tvb, offset, pinfo, tree, hf_cmip_eventType3);
}



static int
dissect_cmip_T_eventInfo1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 199 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_eventInfo1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_eventInfo1(FALSE, tvb, offset, pinfo, tree, hf_cmip_eventInfo1);
}


static const ber_sequence_t EventReportArgument_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_eventTime_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_eventType3 },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_eventInfo1 },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_EventReportArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EventReportArgument_sequence, hf_index, ett_cmip_EventReportArgument);

  return offset;
}


static const ber_sequence_t DeleteArgument_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_accessControl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_synchronization_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_scope },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_filter },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_DeleteArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteArgument_sequence, hf_index, ett_cmip_DeleteArgument);

  return offset;
}


static const value_string cmip_T_managedOrSuperiorObjectInstance_vals[] = {
  {   0, "managedObjectInstance" },
  {   1, "superiorObjectInstance" },
  { 0, NULL }
};

static const ber_choice_t T_managedOrSuperiorObjectInstance_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_managedObjectInstance },
  {   1, BER_CLASS_CON, 8, 0, dissect_superiorObjectInstance },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_managedOrSuperiorObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_managedOrSuperiorObjectInstance_choice, hf_index, ett_cmip_T_managedOrSuperiorObjectInstance,
                                 NULL);

  return offset;
}
static int dissect_managedOrSuperiorObjectInstance(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_T_managedOrSuperiorObjectInstance(FALSE, tvb, offset, pinfo, tree, hf_cmip_managedOrSuperiorObjectInstance);
}


static const ber_sequence_t CreateArgument_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedOrSuperiorObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_accessControl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_referenceObjectInstance },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attributeList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_CreateArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CreateArgument_sequence, hf_index, ett_cmip_CreateArgument);

  return offset;
}


static const ber_sequence_t CreateResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_managedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentTime_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attributeList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_CreateResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CreateResult_sequence, hf_index, ett_cmip_CreateResult);

  return offset;
}


static const ber_sequence_t ActionArgument_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_accessControl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_synchronization_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_scope },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_filter },
  { BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_actionInfo_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ActionArgument_sequence, hf_index, ett_cmip_ActionArgument);

  return offset;
}


static const ber_sequence_t BaseManagedObjectId_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectInstance },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_BaseManagedObjectId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BaseManagedObjectId_sequence, hf_index, ett_cmip_BaseManagedObjectId);

  return offset;
}


static const value_string cmip_AdministrativeState_vals[] = {
  {   0, "locked" },
  {   1, "unlocked" },
  {   2, "shuttingDown" },
  { 0, NULL }
};


static int
dissect_cmip_AdministrativeState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_DiscriminatorConstruct(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_cmip_CMISFilter(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string cmip_Name_vals[] = {
  {   0, "rdnSequence" },
  { 0, NULL }
};

static const ber_choice_t Name_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_rdnSequence },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_Name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Name_choice, hf_index, ett_cmip_Name,
                                 NULL);

  return offset;
}



static int
dissect_cmip_AE_title_form1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_cmip_Name(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_ae_title_form1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AE_title_form1(FALSE, tvb, offset, pinfo, tree, hf_cmip_ae_title_form1);
}



static int
dissect_cmip_AE_title_form2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_ae_title_form2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AE_title_form2(FALSE, tvb, offset, pinfo, tree, hf_cmip_ae_title_form2);
}


static const value_string cmip_AE_title_vals[] = {
  {   0, "ae-title-form1" },
  {   1, "ae-title-form2" },
  { 0, NULL }
};

static const ber_choice_t AE_title_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ae_title_form1 },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ae_title_form2 },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_AE_title(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AE_title_choice, hf_index, ett_cmip_AE_title,
                                 NULL);

  return offset;
}
static int dissect_single(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AE_title(FALSE, tvb, offset, pinfo, tree, hf_cmip_single);
}
static int dissect_multiple_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_AE_title(FALSE, tvb, offset, pinfo, tree, hf_cmip_multiple_item);
}


static const ber_sequence_t SET_OF_AE_title_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_multiple_item },
};

static int
dissect_cmip_SET_OF_AE_title(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AE_title_set_of, hf_index, ett_cmip_SET_OF_AE_title);

  return offset;
}
static int dissect_multiple(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SET_OF_AE_title(FALSE, tvb, offset, pinfo, tree, hf_cmip_multiple);
}


static const value_string cmip_Destination_vals[] = {
  {   0, "single" },
  {   1, "multiple" },
  { 0, NULL }
};

static const ber_choice_t Destination_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_single },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_multiple },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_Destination(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Destination_choice, hf_index, ett_cmip_Destination,
                                 NULL);

  return offset;
}


static const value_string cmip_OperationalState_vals[] = {
  {   0, "disabled" },
  {   1, "enabled" },
  { 0, NULL }
};


static int
dissect_cmip_OperationalState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_NameBinding(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeId_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_attributeIdList_item },
};

static int
dissect_cmip_SET_OF_AttributeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AttributeId_set_of, hf_index, ett_cmip_SET_OF_AttributeId);

  return offset;
}
static int dissect_attributeIdList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_SET_OF_AttributeId(TRUE, tvb, offset, pinfo, tree, hf_cmip_attributeIdList);
}


static const ber_sequence_t GetArgument_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectClass },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_baseManagedObjectInstance },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_accessControl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_synchronization_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_scope },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_filter },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attributeIdList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_GetArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetArgument_sequence, hf_index, ett_cmip_GetArgument);

  return offset;
}



static int
dissect_cmip_Argument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 102 "cmip.cnf"
  switch(opcode_type){
  case OPCODE_INVOKE:
    switch(opcode){
    case 0: /* M-eventreport */
      offset = dissect_cmip_EventReportArgument(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 1: /* M-eventreport-confirmed */
      offset = dissect_cmip_EventReportArgument(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 2: /* M-linkedreply */
      offset = dissect_cmip_LinkedReplyArgument(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 3: /* M-get */
      offset = dissect_cmip_GetArgument(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 4: /* M-set */
      offset = dissect_cmip_SetArgument(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 5: /* M-set-confirmed */
      offset = dissect_cmip_SetArgument(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 6: /* M-action*/
      offset = dissect_cmip_ActionArgument(FALSE, tvb,  offset, pinfo, tree, -1);
      break;
    case 7: /* M-action-confirmed*/
      offset = dissect_cmip_ActionArgument(FALSE, tvb,  offset, pinfo, tree, -1);
      break;
    case 8: /* M-create*/
      offset = dissect_cmip_CreateArgument(FALSE, tvb,  offset, pinfo, tree, -1);
      break;
    case 9: /* M-delete*/
      offset = dissect_cmip_DeleteArgument(FALSE, tvb,  offset, pinfo, tree, -1);
      break;
    case 10: /* M-cancelget */
      offset = dissect_cmip_InvokeIDType(FALSE, tvb,  offset, pinfo, tree, -1);
      break;
    }
    break;
  case OPCODE_RETURN_RESULT:
    switch(opcode){
    case 0: /* M-eventreport*/
      break;  /* No return data */
    case 1: /* M-eventreport-confirmed */
      offset = dissect_cmip_EventReportResult(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 2: /* M-linkedreply*/
      break;  /* No return data */
    case 3: /* M-get */
      offset = dissect_cmip_GetResult(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 4: /* M-set */
      break;  /* No return data */
    case 5: /* M-set-confirmed*/
      offset = dissect_cmip_SetResult(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 6: /* M-action*/
      break;  /* No return data */
    case 7: /* M-action-confirmed*/
      offset = dissect_cmip_ActionResult(FALSE, tvb, offset, pinfo, tree, -1);
      break;
    case 8: /* M-create*/
      offset = dissect_cmip_CreateResult(FALSE, tvb,  offset, pinfo, tree, -1);
      break;
    case 9: /* M-delete*/
      offset = dissect_cmip_DeleteResult(FALSE, tvb,  offset, pinfo, tree, -1);
      break;
    case 10: /* M-cancelget */
      break; /* doe this one return any data? */
    }
    break;
  /*XXX add more types here */
  }



  return offset;
}
static int dissect_argument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Argument(FALSE, tvb, offset, pinfo, tree, hf_cmip_argument);
}


static const value_string cmip_Opcode_vals[] = {
  {   0, "m-EventReport" },
  {   1, "m-EventReport-Confirmed" },
  {   2, "m-Linked-Reply" },
  {   3, "m-Get" },
  {   4, "m-Set" },
  {   5, "m-Set-Confirmed" },
  {   6, "m-Action" },
  {   7, "m-Action-Confirmed" },
  {   8, "m-Create" },
  {   9, "m-Delete" },
  {  10, "m-CancelGet" },
  { 0, NULL }
};


static int
dissect_cmip_Opcode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 48 "cmip.cnf"
    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &opcode);

  if(check_col(pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(opcode, cmip_Opcode_vals, " Unknown Opcode:%d"));
  }


  return offset;
}
static int dissect_opcode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Opcode(FALSE, tvb, offset, pinfo, tree, hf_cmip_opcode);
}


static const ber_sequence_t ReturnResultBody_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_opcode },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_argument },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ReturnResultBody(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnResultBody_sequence, hf_index, ett_cmip_ReturnResultBody);

  return offset;
}
static int dissect_rRBody(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ReturnResultBody(FALSE, tvb, offset, pinfo, tree, hf_cmip_rRBody);
}



static int
dissect_cmip_InvokeID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_present1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_InvokeID(FALSE, tvb, offset, pinfo, tree, hf_cmip_present1);
}



static int
dissect_cmip_InvokeLinkedId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_linkedId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_InvokeLinkedId(TRUE, tvb, offset, pinfo, tree, hf_cmip_linkedId);
}



static int
dissect_cmip_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_absent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_NULL(FALSE, tvb, offset, pinfo, tree, hf_cmip_absent);
}


static const value_string cmip_InvokeId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t InvokeId_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_present1 },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_absent },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_InvokeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 InvokeId_choice, hf_index, ett_cmip_InvokeId,
                                 NULL);

  return offset;
}
static int dissect_invokeId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_InvokeId(FALSE, tvb, offset, pinfo, tree, hf_cmip_invokeId);
}



int
dissect_cmip_InvokeIDType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_cmip_InvokeId(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_linkedId_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_opcode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_argument },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 55 "cmip.cnf"
  opcode_type=OPCODE_INVOKE;
  if(check_col(pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "Invoke ");
  }

  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_cmip_Invoke);

  return offset;
}
static int dissect_invoke_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Invoke(TRUE, tvb, offset, pinfo, tree, hf_cmip_invoke);
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_rRBody },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 62 "cmip.cnf"
  opcode_type=OPCODE_RETURN_RESULT;
  if(check_col(pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "ReturnResult ");
  }

  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_cmip_ReturnResult);

  return offset;
}
static int dissect_returnResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ReturnResult(TRUE, tvb, offset, pinfo, tree, hf_cmip_returnResult);
}


static const ber_sequence_t ReturnError_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 69 "cmip.cnf"
  opcode_type=OPCODE_RETURN_ERROR;
  if(check_col(pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "ReturnError ");
  }

  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_cmip_ReturnError);

  return offset;
}
static int dissect_returnError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ReturnError(TRUE, tvb, offset, pinfo, tree, hf_cmip_returnError);
}


static const value_string cmip_GeneralProblem_vals[] = {
  {   0, "unrecognizedPDU" },
  {   1, "mistypedPDU" },
  {   2, "badlyStructuredPDU" },
  { 0, NULL }
};


static int
dissect_cmip_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_generalProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_GeneralProblem(TRUE, tvb, offset, pinfo, tree, hf_cmip_generalProblem);
}


static const value_string cmip_InvokeProblem_vals[] = {
  {   0, "duplicateInvocation" },
  {   1, "unrecognizedOperation" },
  {   2, "mistypedArgument" },
  {   3, "resourceLimitation" },
  {   4, "releaseInProgress" },
  {   5, "unrecognizedLinkedId" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedLinkedOperation" },
  { 0, NULL }
};


static int
dissect_cmip_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_InvokeProblem(TRUE, tvb, offset, pinfo, tree, hf_cmip_invokeProblem);
}


static const value_string cmip_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "resultResponseUnexpected" },
  {   2, "mistypedResult" },
  { 0, NULL }
};


static int
dissect_cmip_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_returnResultProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ReturnResultProblem(TRUE, tvb, offset, pinfo, tree, hf_cmip_returnResultProblem);
}


static const value_string cmip_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "errorResponseUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_cmip_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_returnErrorProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ReturnErrorProblem(TRUE, tvb, offset, pinfo, tree, hf_cmip_returnErrorProblem);
}


static const value_string cmip_RejectProblem_vals[] = {
  {   0, "general-unrecognizedPDU" },
  {   1, "general-mistypedPDU" },
  {   2, "general-badlyStructuredPDU" },
  {  10, "invoke-duplicateInvocation" },
  {  11, "invoke-unrecognizedOperation" },
  {  12, "invoke-mistypedArgument" },
  {  13, "invoke-resourceLimitation" },
  {  14, "invoke-releaseInProgress" },
  {  15, "invoke-unrecognizedLinkedId" },
  {  16, "invoke-linkedResponseUnexpected" },
  {  17, "invoke-unexpectedLinkedOperation" },
  {  20, "returnResult-unrecognizedInvocation" },
  {  21, "returnResult-resultResponseUnexpected" },
  {  22, "returnResult-mistypedResult" },
  {  30, "returnError-unrecognizedInvocation" },
  {  31, "returnError-errorResponseUnexpected" },
  {  32, "returnError-unrecognizedError" },
  {  33, "returnError-unexpectedError" },
  {  34, "returnError-mistypedParameter" },
  { 0, NULL }
};


static int
dissect_cmip_RejectProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string cmip_RejectProb_vals[] = {
  {   0, "generalProblem" },
  {   1, "invokeProblem" },
  {   2, "returnResultProblem" },
  {   3, "returnErrorProblem" },
  { 0, NULL }
};

static const ber_choice_t RejectProb_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_generalProblem_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invokeProblem_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResultProblem_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnErrorProblem_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cmip_RejectProb(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RejectProb_choice, hf_index, ett_cmip_RejectProb,
                                 NULL);

  return offset;
}
static int dissect_rejectProblem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_RejectProb(FALSE, tvb, offset, pinfo, tree, hf_cmip_rejectProblem);
}


static const ber_sequence_t Reject_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_rejectProblem },
  { 0, 0, 0, NULL }
};

static int
dissect_cmip_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 76 "cmip.cnf"
  opcode_type=OPCODE_REJECT;
  if(check_col(pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "Reject ");
  }

  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_cmip_Reject);

  return offset;
}
static int dissect_reject_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_Reject(TRUE, tvb, offset, pinfo, tree, hf_cmip_reject);
}


const value_string cmip_ROS_vals[] = {
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const ber_choice_t ROS_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invoke_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResult_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnError_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_reject_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_cmip_ROS(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ROS_choice, hf_index, ett_cmip_ROS,
                                 NULL);

  return offset;
}


static const value_string cmip_CMIPAbortSource_vals[] = {
  {   0, "cmiseServiceUser" },
  {   1, "cmiseServiceProvider" },
  { 0, NULL }
};


static int
dissect_cmip_CMIPAbortSource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 39 "cmip.cnf"
  guint32 value;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &value);

  if(check_col(pinfo->cinfo, COL_INFO)){
    col_append_fstr(pinfo->cinfo, COL_INFO, " AbortSource:%s", val_to_str(value, cmip_CMIPAbortSource_vals, " Unknown AbortSource:%d"));
  }


  return offset;
}
static int dissect_abortSource_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_CMIPAbortSource(TRUE, tvb, offset, pinfo, tree, hf_cmip_abortSource);
}


static const ber_sequence_t CMIPAbortInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_abortSource_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_userInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmip_CMIPAbortInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 27 "cmip.cnf"
  if(check_col(pinfo->cinfo, COL_INFO)){
    col_append_fstr(pinfo->cinfo, COL_INFO, "CMIP-A-ABORT");
  }

  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CMIPAbortInfo_sequence, hf_index, ett_cmip_CMIPAbortInfo);

  return offset;
}


static const asn_namedbit FunctionalUnits_bits[] = {
  {  0, &hf_cmip_FunctionalUnits_multipleObjectSelection, -1, -1, "multipleObjectSelection", NULL },
  {  1, &hf_cmip_FunctionalUnits_filter, -1, -1, "filter", NULL },
  {  2, &hf_cmip_FunctionalUnits_multipleReply, -1, -1, "multipleReply", NULL },
  {  3, &hf_cmip_FunctionalUnits_extendedService, -1, -1, "extendedService", NULL },
  {  4, &hf_cmip_FunctionalUnits_cancelGet, -1, -1, "cancelGet", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_cmip_FunctionalUnits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    FunctionalUnits_bits, hf_index, ett_cmip_FunctionalUnits,
                                    NULL);

  return offset;
}
static int dissect_functionalUnits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_FunctionalUnits(TRUE, tvb, offset, pinfo, tree, hf_cmip_functionalUnits);
}


static const asn_namedbit ProtocolVersion_bits[] = {
  {  0, &hf_cmip_ProtocolVersion_version1, -1, -1, "version1", NULL },
  {  1, &hf_cmip_ProtocolVersion_version2, -1, -1, "version2", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_cmip_ProtocolVersion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    ProtocolVersion_bits, hf_index, ett_cmip_ProtocolVersion,
                                    NULL);

  return offset;
}
static int dissect_protocolVersion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cmip_ProtocolVersion(TRUE, tvb, offset, pinfo, tree, hf_cmip_protocolVersion);
}


static const ber_sequence_t CMIPUserInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_protocolVersion_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_functionalUnits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_accessControl1 },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_userInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cmip_CMIPUserInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 33 "cmip.cnf"
  if(check_col(pinfo->cinfo, COL_INFO)){
    col_append_fstr(pinfo->cinfo, COL_INFO, "CMIP-A-ASSOCIATE");
  }

  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CMIPUserInfo_sequence, hf_index, ett_cmip_CMIPUserInfo);

  return offset;
}


/*--- End of included file: packet-cmip-fn.c ---*/
#line 90 "packet-cmip-template.c"


static void
dissect_cmip_attribute_35(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_cmip_OperationalState(FALSE, tvb, 0, pinfo, parent_tree, hf_OperationalState);

}

static void
dissect_cmip_attribute_55(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_cmip_Destination(FALSE, tvb, 0, pinfo, parent_tree,hf_Destination);

}

static void
dissect_cmip_attribute_56(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_cmip_DiscriminatorConstruct(FALSE, tvb, 0, pinfo, parent_tree, hf_DiscriminatorConstruct);

}

static void
dissect_cmip_attribute_63(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_cmip_NameBinding(FALSE, tvb, 0, pinfo, parent_tree, hf_NameBinding);

}

static void
dissect_cmip_attribute_65(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_cmip_ObjectClass(FALSE, tvb, 0, pinfo, parent_tree, hf_ObjectClass);

}


/* XXX this one should be broken out later and moved into the conformance file */
static void
dissect_cmip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	static struct SESSION_DATA_STRUCTURE* session = NULL;
	proto_item *item = NULL;
	proto_tree *tree = NULL;


	/* do we have spdu type from the session dissector?  */
	if( !pinfo->private_data ){
		if(tree){
			proto_tree_add_text(tree, tvb, 0, -1,
				"Internal error:can't get spdu type from session dissector.");
			return;
		}
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );
		if(session->spdu_type == 0 ){
			if(tree){
				proto_tree_add_text(tree, tvb, 0, -1,
					"Internal error:wrong spdu type %x from session dissector.",session->spdu_type);
				return;
			}
		}
	}

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_cmip, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_cmip);
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMIP");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);
	switch(session->spdu_type){
		case SES_CONNECTION_REQUEST:
		case SES_CONNECTION_ACCEPT:
		case SES_DISCONNECT:
		case SES_FINISH:
		case SES_REFUSE:
			dissect_cmip_CMIPUserInfo(FALSE,tvb,0,pinfo,tree,-1);
			break;
		case SES_ABORT:
			dissect_cmip_CMIPAbortInfo(FALSE,tvb,0,pinfo,tree,-1);
			break;
		case SES_DATA_TRANSFER:
			dissect_cmip_ROS(FALSE,tvb,0,pinfo,tree,-1);
			break;
		default:
			;
	}
}

/*--- proto_register_cmip ----------------------------------------------*/
void proto_register_cmip(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cmip_actionType_OID,
      { "actionType", "cmip.actionType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        "actionType", HFILL }},
    { &hf_cmip_eventType_OID,
      { "eventType", "cmip.eventType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        "eventType", HFILL }},
    { &hf_cmip_attributeId_OID,
      { "attributeId", "cmip.attributeId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        "attributeId", HFILL }},
    { &hf_cmip_errorId_OID,
      { "errorId", "cmip.errorId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        "errorId", HFILL }},
   { &hf_DiscriminatorConstruct,
      { "DiscriminatorConstruct", "cmip.DiscriminatorConstruct",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_Destination,
      { "Destination", "cmip.Destination",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_NameBinding,
      { "NameBinding", "cmip.NameBinding",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ObjectClass,
      { "ObjectClass", "cmip.ObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "", HFILL }},
    { &hf_OperationalState,
      { "OperationalState", "cmip.OperationalState",
        FT_UINT32, BASE_DEC, VALS(cmip_OperationalState_vals), 0,
        "", HFILL }},


/*--- Included file: packet-cmip-hfarr.c ---*/
#line 1 "packet-cmip-hfarr.c"
    { &hf_cmip_modifyOperator,
      { "modifyOperator", "cmip.modifyOperator",
        FT_INT32, BASE_DEC, VALS(cmip_ModifyOperator_vals), 0,
        "", HFILL }},
    { &hf_cmip_attributeId,
      { "attributeId", "cmip.attributeId",
        FT_OID, BASE_NONE, NULL, 0,
        "ModificationItem/attributeId", HFILL }},
    { &hf_cmip_attributeValue,
      { "attributeValue", "cmip.attributeValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModificationItem/attributeValue", HFILL }},
    { &hf_cmip_managedObjectClass,
      { "managedObjectClass", "cmip.managedObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "", HFILL }},
    { &hf_cmip_managedObjectInstance,
      { "managedObjectInstance", "cmip.managedObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "", HFILL }},
    { &hf_cmip_currentTime,
      { "currentTime", "cmip.currentTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmip_getInfoList,
      { "getInfoList", "cmip.getInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GetListError/getInfoList", HFILL }},
    { &hf_cmip_getInfoList_item,
      { "Item", "cmip.getInfoList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_GetInfoStatus_vals), 0,
        "GetListError/getInfoList/_item", HFILL }},
    { &hf_cmip_attributeIdError,
      { "attributeIdError", "cmip.attributeIdError",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetInfoStatus/attributeIdError", HFILL }},
    { &hf_cmip_attribute,
      { "attribute", "cmip.attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmip_errorStatus,
      { "errorStatus", "cmip.errorStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_T_errorStatus_vals), 0,
        "AttributeIdError/errorStatus", HFILL }},
    { &hf_cmip_attributeId1,
      { "attributeId", "cmip.attributeId",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "AttributeIdError/attributeId", HFILL }},
    { &hf_cmip_setInfoList,
      { "setInfoList", "cmip.setInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SetListError/setInfoList", HFILL }},
    { &hf_cmip_setInfoList_item,
      { "Item", "cmip.setInfoList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_SetInfoStatus_vals), 0,
        "SetListError/setInfoList/_item", HFILL }},
    { &hf_cmip_actionErrorInfo,
      { "actionErrorInfo", "cmip.actionErrorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActionError/actionErrorInfo", HFILL }},
    { &hf_cmip_specificErrorInfo,
      { "specificErrorInfo", "cmip.specificErrorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcessingFailure/specificErrorInfo", HFILL }},
    { &hf_cmip_RDNSequence_item,
      { "Item", "cmip.RDNSequence_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RDNSequence/_item", HFILL }},
    { &hf_cmip_RelativeDistinguishedName_item,
      { "Item", "cmip.RelativeDistinguishedName_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelativeDistinguishedName/_item", HFILL }},
    { &hf_cmip_deleteErrorInfo,
      { "deleteErrorInfo", "cmip.deleteErrorInfo",
        FT_UINT32, BASE_DEC, VALS(cmip_T_deleteErrorInfo_vals), 0,
        "DeleteError/deleteErrorInfo", HFILL }},
    { &hf_cmip_attributeError,
      { "attributeError", "cmip.attributeError",
        FT_NONE, BASE_NONE, NULL, 0,
        "SetInfoStatus/attributeError", HFILL }},
    { &hf_cmip_errorId,
      { "errorId", "cmip.errorId",
        FT_OID, BASE_NONE, NULL, 0,
        "SpecificErrorInfo/errorId", HFILL }},
    { &hf_cmip_errorInfo,
      { "errorInfo", "cmip.errorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SpecificErrorInfo/errorInfo", HFILL }},
    { &hf_cmip_actionType,
      { "actionType", "cmip.actionType",
        FT_OID, BASE_NONE, NULL, 0,
        "NoSuchArgumentAction/actionType", HFILL }},
    { &hf_cmip_eventType,
      { "eventType", "cmip.eventType",
        FT_OID, BASE_NONE, NULL, 0,
        "NoSuchArgumentEvent/eventType", HFILL }},
    { &hf_cmip_actionId,
      { "actionId", "cmip.actionId",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSuchArgument/actionId", HFILL }},
    { &hf_cmip_eventId,
      { "eventId", "cmip.eventId",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoSuchArgument/eventId", HFILL }},
    { &hf_cmip_eventType1,
      { "eventType", "cmip.eventType",
        FT_OID, BASE_NONE, NULL, 0,
        "InvalidArgumentValueEventValue/eventType", HFILL }},
    { &hf_cmip_eventInfo,
      { "eventInfo", "cmip.eventInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "InvalidArgumentValueEventValue/eventInfo", HFILL }},
    { &hf_cmip_actionValue,
      { "actionValue", "cmip.actionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "InvalidArgumentValue/actionValue", HFILL }},
    { &hf_cmip_eventValue,
      { "eventValue", "cmip.eventValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "InvalidArgumentValue/eventValue", HFILL }},
    { &hf_cmip_actionType1,
      { "actionType", "cmip.actionType",
        FT_OID, BASE_NONE, NULL, 0,
        "ErrorInfo/actionType", HFILL }},
    { &hf_cmip_actionArgument,
      { "actionArgument", "cmip.actionArgument",
        FT_UINT32, BASE_DEC, VALS(cmip_NoSuchArgument_vals), 0,
        "ErrorInfo/actionArgument", HFILL }},
    { &hf_cmip_argumentValue,
      { "argumentValue", "cmip.argumentValue",
        FT_UINT32, BASE_DEC, VALS(cmip_InvalidArgumentValue_vals), 0,
        "ErrorInfo/argumentValue", HFILL }},
    { &hf_cmip_errorStatus1,
      { "errorStatus", "cmip.errorStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_T_errorStatus1_vals), 0,
        "ActionErrorInfo/errorStatus", HFILL }},
    { &hf_cmip_errorInfo1,
      { "errorInfo", "cmip.errorInfo",
        FT_UINT32, BASE_DEC, VALS(cmip_ErrorInfo_vals), 0,
        "ActionErrorInfo/errorInfo", HFILL }},
    { &hf_cmip_errorStatus2,
      { "errorStatus", "cmip.errorStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_T_errorStatus2_vals), 0,
        "AttributeError/errorStatus", HFILL }},
    { &hf_cmip_attributeId2,
      { "attributeId", "cmip.attributeId",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeError/attributeId", HFILL }},
    { &hf_cmip_attributeValue1,
      { "attributeValue", "cmip.attributeValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeError/attributeValue", HFILL }},
    { &hf_cmip_attributeList,
      { "attributeList", "cmip.attributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_cmip_attributeList_item,
      { "Item", "cmip.attributeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmip_baseManagedObjectClass,
      { "baseManagedObjectClass", "cmip.baseManagedObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "", HFILL }},
    { &hf_cmip_baseManagedObjectInstance,
      { "baseManagedObjectInstance", "cmip.baseManagedObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "", HFILL }},
    { &hf_cmip_accessControl,
      { "accessControl", "cmip.accessControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmip_synchronization,
      { "synchronization", "cmip.synchronization",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISSync_vals), 0,
        "", HFILL }},
    { &hf_cmip_scope,
      { "scope", "cmip.scope",
        FT_UINT32, BASE_DEC, VALS(cmip_Scope_vals), 0,
        "", HFILL }},
    { &hf_cmip_filter,
      { "filter", "cmip.filter",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "", HFILL }},
    { &hf_cmip_modificationList,
      { "modificationList", "cmip.modificationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SetArgument/modificationList", HFILL }},
    { &hf_cmip_modificationList_item,
      { "Item", "cmip.modificationList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SetArgument/modificationList/_item", HFILL }},
    { &hf_cmip_getResult,
      { "getResult", "cmip.getResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "LinkedReplyArgument/getResult", HFILL }},
    { &hf_cmip_getListError,
      { "getListError", "cmip.getListError",
        FT_NONE, BASE_NONE, NULL, 0,
        "LinkedReplyArgument/getListError", HFILL }},
    { &hf_cmip_setResult,
      { "setResult", "cmip.setResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "LinkedReplyArgument/setResult", HFILL }},
    { &hf_cmip_setListError,
      { "setListError", "cmip.setListError",
        FT_NONE, BASE_NONE, NULL, 0,
        "LinkedReplyArgument/setListError", HFILL }},
    { &hf_cmip_actionResult,
      { "actionResult", "cmip.actionResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "LinkedReplyArgument/actionResult", HFILL }},
    { &hf_cmip_processingFailure,
      { "processingFailure", "cmip.processingFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "LinkedReplyArgument/processingFailure", HFILL }},
    { &hf_cmip_deleteResult,
      { "deleteResult", "cmip.deleteResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "LinkedReplyArgument/deleteResult", HFILL }},
    { &hf_cmip_actionError,
      { "actionError", "cmip.actionError",
        FT_NONE, BASE_NONE, NULL, 0,
        "LinkedReplyArgument/actionError", HFILL }},
    { &hf_cmip_deleteError,
      { "deleteError", "cmip.deleteError",
        FT_NONE, BASE_NONE, NULL, 0,
        "LinkedReplyArgument/deleteError", HFILL }},
    { &hf_cmip_eventType2,
      { "eventType", "cmip.eventType",
        FT_OID, BASE_NONE, NULL, 0,
        "EventReply/eventType", HFILL }},
    { &hf_cmip_eventReplyInfo,
      { "eventReplyInfo", "cmip.eventReplyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReply/eventReplyInfo", HFILL }},
    { &hf_cmip_eventReply,
      { "eventReply", "cmip.eventReply",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportResult/eventReply", HFILL }},
    { &hf_cmip_eventTime,
      { "eventTime", "cmip.eventTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "EventReportArgument/eventTime", HFILL }},
    { &hf_cmip_eventType3,
      { "eventType", "cmip.eventType",
        FT_OID, BASE_NONE, NULL, 0,
        "EventReportArgument/eventType", HFILL }},
    { &hf_cmip_eventInfo1,
      { "eventInfo", "cmip.eventInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportArgument/eventInfo", HFILL }},
    { &hf_cmip_managedOrSuperiorObjectInstance,
      { "managedOrSuperiorObjectInstance", "cmip.managedOrSuperiorObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_T_managedOrSuperiorObjectInstance_vals), 0,
        "CreateArgument/managedOrSuperiorObjectInstance", HFILL }},
    { &hf_cmip_superiorObjectInstance,
      { "superiorObjectInstance", "cmip.superiorObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "CreateArgument/managedOrSuperiorObjectInstance/superiorObjectInstance", HFILL }},
    { &hf_cmip_referenceObjectInstance,
      { "referenceObjectInstance", "cmip.referenceObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "CreateArgument/referenceObjectInstance", HFILL }},
    { &hf_cmip_actionType2,
      { "actionType", "cmip.actionType",
        FT_OID, BASE_NONE, NULL, 0,
        "ActionReply/actionType", HFILL }},
    { &hf_cmip_actionReplyInfo,
      { "actionReplyInfo", "cmip.actionReplyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActionReply/actionReplyInfo", HFILL }},
    { &hf_cmip_actionReply,
      { "actionReply", "cmip.actionReply",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActionResult/actionReply", HFILL }},
    { &hf_cmip_actionInfo,
      { "actionInfo", "cmip.actionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActionArgument/actionInfo", HFILL }},
    { &hf_cmip_actionType3,
      { "actionType", "cmip.actionType",
        FT_OID, BASE_NONE, NULL, 0,
        "ActionInfo/actionType", HFILL }},
    { &hf_cmip_actionInfoArg,
      { "actionInfoArg", "cmip.actionInfoArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActionInfo/actionInfoArg", HFILL }},
    { &hf_cmip_ocglobalForm,
      { "ocglobalForm", "cmip.ocglobalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "ObjectClass/ocglobalForm", HFILL }},
    { &hf_cmip_oclocalForm,
      { "oclocalForm", "cmip.oclocalForm",
        FT_INT32, BASE_DEC, NULL, 0,
        "ObjectClass/oclocalForm", HFILL }},
    { &hf_cmip_distinguishedName,
      { "distinguishedName", "cmip.distinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ObjectInstance/distinguishedName", HFILL }},
    { &hf_cmip_nonSpecificForm,
      { "nonSpecificForm", "cmip.nonSpecificForm",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ObjectInstance/nonSpecificForm", HFILL }},
    { &hf_cmip_localDistinguishedName,
      { "localDistinguishedName", "cmip.localDistinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ObjectInstance/localDistinguishedName", HFILL }},
    { &hf_cmip_globalForm,
      { "globalForm", "cmip.globalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeId/globalForm", HFILL }},
    { &hf_cmip_localForm,
      { "localForm", "cmip.localForm",
        FT_INT32, BASE_DEC, NULL, 0,
        "AttributeId/localForm", HFILL }},
    { &hf_cmip_id,
      { "id", "cmip.id",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "Attribute/id", HFILL }},
    { &hf_cmip_value,
      { "value", "cmip.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute/value", HFILL }},
    { &hf_cmip_id1,
      { "id", "cmip.id",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeValueAssertion/id", HFILL }},
    { &hf_cmip_value1,
      { "value", "cmip.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValueAssertion/value", HFILL }},
    { &hf_cmip_equality,
      { "equality", "cmip.equality",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/equality", HFILL }},
    { &hf_cmip_substrings,
      { "substrings", "cmip.substrings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FilterItem/substrings", HFILL }},
    { &hf_cmip_substrings_item,
      { "Item", "cmip.substrings_item",
        FT_UINT32, BASE_DEC, VALS(cmip_T_substrings_item_vals), 0,
        "FilterItem/substrings/_item", HFILL }},
    { &hf_cmip_initialString,
      { "initialString", "cmip.initialString",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/substrings/_item/initialString", HFILL }},
    { &hf_cmip_anyString,
      { "anyString", "cmip.anyString",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/substrings/_item/anyString", HFILL }},
    { &hf_cmip_finalString,
      { "finalString", "cmip.finalString",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/substrings/_item/finalString", HFILL }},
    { &hf_cmip_greaterOrEqual,
      { "greaterOrEqual", "cmip.greaterOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/greaterOrEqual", HFILL }},
    { &hf_cmip_lessOrEqual,
      { "lessOrEqual", "cmip.lessOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/lessOrEqual", HFILL }},
    { &hf_cmip_present,
      { "present", "cmip.present",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "FilterItem/present", HFILL }},
    { &hf_cmip_subsetOf,
      { "subsetOf", "cmip.subsetOf",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/subsetOf", HFILL }},
    { &hf_cmip_supersetOf,
      { "supersetOf", "cmip.supersetOf",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/supersetOf", HFILL }},
    { &hf_cmip_nonNullSetIntersection,
      { "nonNullSetIntersection", "cmip.nonNullSetIntersection",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterItem/nonNullSetIntersection", HFILL }},
    { &hf_cmip_single,
      { "single", "cmip.single",
        FT_UINT32, BASE_DEC, VALS(cmip_AE_title_vals), 0,
        "Destination/single", HFILL }},
    { &hf_cmip_multiple,
      { "multiple", "cmip.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Destination/multiple", HFILL }},
    { &hf_cmip_multiple_item,
      { "Item", "cmip.multiple_item",
        FT_UINT32, BASE_DEC, VALS(cmip_AE_title_vals), 0,
        "Destination/multiple/_item", HFILL }},
    { &hf_cmip_ae_title_form1,
      { "ae-title-form1", "cmip.ae_title_form1",
        FT_UINT32, BASE_DEC, VALS(cmip_Name_vals), 0,
        "AE-title/ae-title-form1", HFILL }},
    { &hf_cmip_ae_title_form2,
      { "ae-title-form2", "cmip.ae_title_form2",
        FT_OID, BASE_NONE, NULL, 0,
        "AE-title/ae-title-form2", HFILL }},
    { &hf_cmip_rdnSequence,
      { "rdnSequence", "cmip.rdnSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name/rdnSequence", HFILL }},
    { &hf_cmip_item,
      { "item", "cmip.item",
        FT_UINT32, BASE_DEC, VALS(cmip_FilterItem_vals), 0,
        "CMISFilter/item", HFILL }},
    { &hf_cmip_and,
      { "and", "cmip.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CMISFilter/and", HFILL }},
    { &hf_cmip_and_item,
      { "Item", "cmip.and_item",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "CMISFilter/and/_item", HFILL }},
    { &hf_cmip_or,
      { "or", "cmip.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CMISFilter/or", HFILL }},
    { &hf_cmip_or_item,
      { "Item", "cmip.or_item",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "CMISFilter/or/_item", HFILL }},
    { &hf_cmip_not,
      { "not", "cmip.not",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "CMISFilter/not", HFILL }},
    { &hf_cmip_namedNumbers,
      { "namedNumbers", "cmip.namedNumbers",
        FT_INT32, BASE_DEC, VALS(cmip_T_namedNumbers_vals), 0,
        "Scope/namedNumbers", HFILL }},
    { &hf_cmip_individualLevels,
      { "individualLevels", "cmip.individualLevels",
        FT_INT32, BASE_DEC, NULL, 0,
        "Scope/individualLevels", HFILL }},
    { &hf_cmip_baseToNthLevel,
      { "baseToNthLevel", "cmip.baseToNthLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "Scope/baseToNthLevel", HFILL }},
    { &hf_cmip_attributeIdList,
      { "attributeIdList", "cmip.attributeIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GetArgument/attributeIdList", HFILL }},
    { &hf_cmip_attributeIdList_item,
      { "Item", "cmip.attributeIdList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "GetArgument/attributeIdList/_item", HFILL }},
    { &hf_cmip_opcode,
      { "opcode", "cmip.opcode",
        FT_INT32, BASE_DEC, VALS(cmip_Opcode_vals), 0,
        "", HFILL }},
    { &hf_cmip_argument,
      { "argument", "cmip.argument",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmip_present1,
      { "present", "cmip.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId/present", HFILL }},
    { &hf_cmip_absent,
      { "absent", "cmip.absent",
        FT_NONE, BASE_NONE, NULL, 0,
        "InvokeId/absent", HFILL }},
    { &hf_cmip_invokeId,
      { "invokeId", "cmip.invokeId",
        FT_UINT32, BASE_DEC, VALS(cmip_InvokeId_vals), 0,
        "", HFILL }},
    { &hf_cmip_linkedId,
      { "linkedId", "cmip.linkedId",
        FT_INT32, BASE_DEC, NULL, 0,
        "Invoke/linkedId", HFILL }},
    { &hf_cmip_rRBody,
      { "rRBody", "cmip.rRBody",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult/rRBody", HFILL }},
    { &hf_cmip_generalProblem,
      { "generalProblem", "cmip.generalProblem",
        FT_INT32, BASE_DEC, VALS(cmip_GeneralProblem_vals), 0,
        "RejectProb/generalProblem", HFILL }},
    { &hf_cmip_invokeProblem,
      { "invokeProblem", "cmip.invokeProblem",
        FT_INT32, BASE_DEC, VALS(cmip_InvokeProblem_vals), 0,
        "RejectProb/invokeProblem", HFILL }},
    { &hf_cmip_returnResultProblem,
      { "returnResultProblem", "cmip.returnResultProblem",
        FT_INT32, BASE_DEC, VALS(cmip_ReturnResultProblem_vals), 0,
        "RejectProb/returnResultProblem", HFILL }},
    { &hf_cmip_returnErrorProblem,
      { "returnErrorProblem", "cmip.returnErrorProblem",
        FT_INT32, BASE_DEC, VALS(cmip_ReturnErrorProblem_vals), 0,
        "RejectProb/returnErrorProblem", HFILL }},
    { &hf_cmip_rejectProblem,
      { "rejectProblem", "cmip.rejectProblem",
        FT_UINT32, BASE_DEC, VALS(cmip_RejectProb_vals), 0,
        "Reject/rejectProblem", HFILL }},
    { &hf_cmip_invoke,
      { "invoke", "cmip.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/invoke", HFILL }},
    { &hf_cmip_returnResult,
      { "returnResult", "cmip.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/returnResult", HFILL }},
    { &hf_cmip_returnError,
      { "returnError", "cmip.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/returnError", HFILL }},
    { &hf_cmip_reject,
      { "reject", "cmip.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        "ROS/reject", HFILL }},
    { &hf_cmip_abortSource,
      { "abortSource", "cmip.abortSource",
        FT_UINT32, BASE_DEC, VALS(cmip_CMIPAbortSource_vals), 0,
        "CMIPAbortInfo/abortSource", HFILL }},
    { &hf_cmip_userInfo,
      { "userInfo", "cmip.userInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cmip_protocolVersion,
      { "protocolVersion", "cmip.protocolVersion",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CMIPUserInfo/protocolVersion", HFILL }},
    { &hf_cmip_functionalUnits,
      { "functionalUnits", "cmip.functionalUnits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CMIPUserInfo/functionalUnits", HFILL }},
    { &hf_cmip_accessControl1,
      { "accessControl", "cmip.accessControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "CMIPUserInfo/accessControl", HFILL }},
    { &hf_cmip_FunctionalUnits_multipleObjectSelection,
      { "multipleObjectSelection", "cmip.multipleObjectSelection",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_cmip_FunctionalUnits_filter,
      { "filter", "cmip.filter",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_cmip_FunctionalUnits_multipleReply,
      { "multipleReply", "cmip.multipleReply",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_cmip_FunctionalUnits_extendedService,
      { "extendedService", "cmip.extendedService",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_cmip_FunctionalUnits_cancelGet,
      { "cancelGet", "cmip.cancelGet",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_cmip_ProtocolVersion_version1,
      { "version1", "cmip.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_cmip_ProtocolVersion_version2,
      { "version2", "cmip.version2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},

/*--- End of included file: packet-cmip-hfarr.c ---*/
#line 231 "packet-cmip-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_cmip,

/*--- Included file: packet-cmip-ettarr.c ---*/
#line 1 "packet-cmip-ettarr.c"
    &ett_cmip_ModificationItem,
    &ett_cmip_GetListError,
    &ett_cmip_SET_OF_GetInfoStatus,
    &ett_cmip_GetInfoStatus,
    &ett_cmip_AttributeIdError,
    &ett_cmip_SetListError,
    &ett_cmip_SET_OF_SetInfoStatus,
    &ett_cmip_ActionError,
    &ett_cmip_ProcessingFailure,
    &ett_cmip_RDNSequence,
    &ett_cmip_RelativeDistinguishedName,
    &ett_cmip_DeleteError,
    &ett_cmip_SetInfoStatus,
    &ett_cmip_SpecificErrorInfo,
    &ett_cmip_NoSuchArgumentAction,
    &ett_cmip_NoSuchArgumentEvent,
    &ett_cmip_NoSuchArgument,
    &ett_cmip_InvalidArgumentValueEventValue,
    &ett_cmip_InvalidArgumentValue,
    &ett_cmip_ErrorInfo,
    &ett_cmip_ActionErrorInfo,
    &ett_cmip_AttributeError,
    &ett_cmip_SetResult,
    &ett_cmip_SET_OF_Attribute,
    &ett_cmip_SetArgument,
    &ett_cmip_SET_OF_ModificationItem,
    &ett_cmip_LinkedReplyArgument,
    &ett_cmip_EventReply,
    &ett_cmip_EventReportResult,
    &ett_cmip_EventReportArgument,
    &ett_cmip_DeleteArgument,
    &ett_cmip_DeleteResult,
    &ett_cmip_CreateArgument,
    &ett_cmip_T_managedOrSuperiorObjectInstance,
    &ett_cmip_CreateResult,
    &ett_cmip_ActionReply,
    &ett_cmip_ActionResult,
    &ett_cmip_ActionArgument,
    &ett_cmip_ActionInfo,
    &ett_cmip_ObjectClass,
    &ett_cmip_ObjectInstance,
    &ett_cmip_BaseManagedObjectId,
    &ett_cmip_AttributeId,
    &ett_cmip_Attribute,
    &ett_cmip_AttributeValueAssertion,
    &ett_cmip_FilterItem,
    &ett_cmip_T_substrings,
    &ett_cmip_T_substrings_item,
    &ett_cmip_Destination,
    &ett_cmip_SET_OF_AE_title,
    &ett_cmip_AE_title,
    &ett_cmip_Name,
    &ett_cmip_CMISFilter,
    &ett_cmip_SET_OF_CMISFilter,
    &ett_cmip_Scope,
    &ett_cmip_GetArgument,
    &ett_cmip_SET_OF_AttributeId,
    &ett_cmip_GetResult,
    &ett_cmip_ReturnResultBody,
    &ett_cmip_InvokeId,
    &ett_cmip_Invoke,
    &ett_cmip_ReturnResult,
    &ett_cmip_ReturnError,
    &ett_cmip_RejectProb,
    &ett_cmip_Reject,
    &ett_cmip_ROS,
    &ett_cmip_CMIPAbortInfo,
    &ett_cmip_FunctionalUnits,
    &ett_cmip_CMIPUserInfo,
    &ett_cmip_ProtocolVersion,

/*--- End of included file: packet-cmip-ettarr.c ---*/
#line 237 "packet-cmip-template.c"
  };

  /* Register protocol */
  proto_cmip = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cmip, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_cmip -------------------------------------------*/
void proto_reg_handoff_cmip(void) {
	register_ber_oid_dissector("2.9.0.0.2", dissect_cmip, proto_cmip, "cmip");
	register_ber_oid_dissector("2.9.1.1.4", dissect_cmip, proto_cmip, "joint-iso-itu-t(2) ms(9) cmip(1) cmip-pci(1) abstractSyntax(4)");
	register_ber_oid_dissector("2.9.3.2.7.35", dissect_cmip_attribute_35, proto_cmip, "smi2AttributeID (7) operationalState(35)");
	register_ber_oid_dissector("2.9.3.2.7.55", dissect_cmip_attribute_55, proto_cmip, "smi2AttributeID (7) destination(55)");
	register_ber_oid_dissector("2.9.3.2.7.56", dissect_cmip_attribute_56, proto_cmip, "smi2AttributeID (7) discriminatorConstruct(56)");
	register_ber_oid_dissector("2.9.3.2.7.63", dissect_cmip_attribute_63, proto_cmip, "smi2AttributeID (7) nameBinding(63)");
	register_ber_oid_dissector("2.9.3.2.7.65", dissect_cmip_attribute_65, proto_cmip, "smi2AttributeID (7) objectClass(65)");

	register_ber_oid_name("2.9.3.2.3.4","eventForwardingDiscriminator(4)");
	register_ber_oid_name("2.9.1.1.4","joint-iso-itu-t(2) ms(9) cmip(1) cmip-pci(1) abstractSyntax(4)");

}

