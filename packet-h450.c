/* packet-h450.c
 * Routines for H.450 packet dissection
 * 2003  Graeme Reid (graeme.reid@norwoodsystems.com)
 *
 * Copied from packet-h225.c and packet-h245.c
 *
 * $Id: packet-h450.c,v 1.4 2003/10/09 20:52:57 guy Exp $
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

#include "prefs.h"
#include "packet-per.h"
#include "packet-h225.h"
#include "packet-h245.h"

/* H.450.2 Call Transfer constants */
#define CallTransferIdentify        7
#define CallTransferAbandon         8
#define CallTransferInitiate        9
#define CallTransferSetup           10
#define CallTransferUpdate          13
#define SubaddressTransfer          14
#define CallTransferComplete        12
#define CallTransferActive          11

/* H.450.3 Call Diversion constants */
#define ActivateDiversionQ          15
#define DeactivateDiversionQ        16
#define InterrogateDiversionQ       17
#define CheckRestriction            18
#define CallRerouting               19
#define DivertingLegInformation1    20
#define DivertingLegInformation2    21
#define DivertingLegInformation3    22
#define DivertingLegInformation4    100
#define CfnrDivertedLegFailed       23

/* H.450.4 Call Hold constants */
#define HoldNotific                 101
#define RetrieveNotific             102
#define RemoteHold                  103
#define RemoteRetrieve              104

/* H.450.5 Call Park and Pickup constants */
#define CpRequest                   106
#define CpSetup                     107
#define GroupIndicationOn           108
#define GroupIndicationOff          109
#define Pickrequ                    110
#define Pickup                      111
#define PickExe                     112
#define CpNotify                    113
#define CpickupNotify               114

/* H.450.6 Call Waiting constants */
#define CallWaiting                 105

/* TODO - define other H.450.x constants here */

static dissector_handle_t h4501_handle;

static int proto_h4501 = -1;

static int hf_h4501 = -1;
static int hf_h4501_EntityType = -1;
static int hf_h4501_NetworkFacilityExtension = -1;
static int hf_h4501_InterpretationApdu = -1;
static int hf_h4501_constrained_invokeId = -1;
static int hf_h4501_invokeId = -1;
static int hf_h4501_localOpcode = -1;
static int hf_h4501_globalCode = -1;
static int hf_h4501_opcode = -1;
static int hf_h4501_destinationAddress = -1;
static int hf_h4501_EndpointAddress = -1;
static int hf_h4501_H225InformationElement = -1;
static int hf_h4501_SubaddressInformation = -1;
static int hf_h4501_oddCountIndicator = -1;
static int hf_h4501_UserSpecifiedSubaddress = -1;
static int hf_h4501_NSAPAddress = -1;
static int hf_h4501_PartySubaddress = -1;
static int hf_h4501_argumentExtension = -1;
static int hf_h4501_argument = -1;
static int hf_h4501_Invoke = -1;
static int hf_h4501_resultExtension = -1;
static int hf_h4501_ReturnResult_result = -1;
static int hf_h4501_result = -1;
static int hf_h4501_ReturnResult = -1;
static int hf_h4501_localErrorCode = -1;
static int hf_h4501_errorCode = -1;
static int hf_h4501_parameter = -1;
static int hf_h4501_ReturnError = -1;
static int hf_h4501_GeneralProblem = -1;
static int hf_h4501_InvokeProblem = -1;
static int hf_h4501_ReturnResultProblem = -1;
static int hf_h4501_ReturnErrorProblem = -1;
static int hf_h4501_problem = -1;
static int hf_h4501_Reject = -1;
static int hf_h4501_ROS = -1;
static int hf_h4501_rosApdus = -1;
static int hf_h4501_ServiceApdus = -1;

static int hf_h4502_nonStandardData = -1;
static int hf_h4502_DummyArg = -1;
static int hf_h4502_CallIdentity = -1;
static int hf_h4502_CTInitiateArg = -1;
static int hf_h4502_CTSetupArg = -1;
static int hf_h4502_redirectionInfo = -1;
static int hf_h4502_CTUpdateArg = -1;
static int hf_h4502_SubaddressTransferArg = -1;
static int hf_h4502_EndDesignation = -1;
static int hf_h4502_CallStatus = -1;
static int hf_h4502_CTCompleteArg = -1;
static int hf_h4502_connectedInfo = -1;
static int hf_h4502_CTActiveArg = -1;
static int hf_h4502_CTIdentifyRes = -1;
static int hf_h4502_DummyRes = -1;

static gint ett_h4501 = -1;
static gint ett_h4501_EntityType = -1;
static gint ett_h4501_NetworkFacilityExtension = -1;
static gint ett_h4501_InterpretationApdu = -1;
static gint ett_h4501_opcode = -1;
static gint ett_h4501_destinationAddress = -1;
static gint ett_h4501_EndpointAddress = -1;
static gint ett_h4501_UserSpecifiedSubaddress = -1;
static gint ett_h4501_PartySubaddress = -1;
static gint ett_h4501_argumentExtension = -1;
static gint ett_h4501_Invoke = -1;
static gint ett_h4501_resultExtension = -1;
static gint ett_h4501_result = -1;
static gint ett_h4501_ReturnResult = -1;
static gint ett_h4501_errorCode = -1;
static gint ett_h4501_ReturnError = -1;
static gint ett_h4501_problem = -1;
static gint ett_h4501_Reject = -1;
static gint ett_h4501_ROS = -1;
static gint ett_h4501_rosApdus = -1;
static gint ett_h4501_ServiceApdus = -1;

static gint ett_h4502_DummyArg = -1;
static gint ett_h4502_CTInitiateArg = -1;
static gint ett_h4502_CTSetupArg = -1;
static gint ett_h4502_CTUpdateArg = -1;
static gint ett_h4502_SubaddressTransferArg = -1;
static gint ett_h4502_CTCompleteArg = -1;
static gint ett_h4502_CTActiveArg = -1;
static gint ett_h4502_CTIdentifyRes = -1;
static gint ett_h4502_DummyRes = -1;

static guint32 localOpcode;
static guint32 localErrorCode;

static int
dissect_h4501_NULL(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return offset;
}


static const value_string EntityType_vals[] = {
	{ 0, "endpoint" },
	{ 1, "anyEntity" },
	{ 0, NULL}
};
static per_choice_t EntityType_choice[] = {
	{ 0, "endpoint", EXTENSION_ROOT, 
		dissect_h4501_NULL },
	{ 1, "anyEntity", EXTENSION_ROOT, 
		dissect_h4501_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_EntityType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_EntityType, ett_h4501_EntityType, EntityType_choice, "EntityType", NULL);
   return offset;
}


static per_sequence_t NetworkFacilityExtension_sequence[] = {
	{ "sourceEntity", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_EntityType },
	{ "sourceEntityAddress", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h225_AliasAddress },
	{ "destinationEntity", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_EntityType },
	{ "destinationEntityAddress", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h225_AliasAddress },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_NetworkFacilityExtension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_NetworkFacilityExtension, ett_h4501_NetworkFacilityExtension, NetworkFacilityExtension_sequence);
   return offset;
}


static const value_string InterpretationApdu_vals[] = {
	{ 0, "discardAnyUnrecognizedInvokePdu" },
	{ 1, "clearCallIfAnyInvokePduNotRecognized" },
	{ 2, "rejectAnyUnrecognizedInvokePdu" },
	{ 0, NULL}
};
static per_choice_t InterpretationApdu_choice[] = {
	{ 0, "discardAnyUnrecognizedInvokePdu", EXTENSION_ROOT, 
		dissect_h4501_NULL },
	{ 1, "clearCallIfAnyInvokePduNotRecognized", EXTENSION_ROOT, 
		dissect_h4501_NULL },
	{ 2, "rejectAnyUnrecognizedInvokePdu", EXTENSION_ROOT, 
		dissect_h4501_NULL },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_InterpretationApdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_InterpretationApdu, ett_h4501_InterpretationApdu, InterpretationApdu_choice, "InterpretationApdu", NULL);
   return offset;
}


static int
dissect_h4501_constrained_invokeId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_constrained_invokeId, 0, 65535, NULL, NULL, FALSE);
	return offset;
}


static int
dissect_h4501_invokeId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_integer(tvb, offset, pinfo, tree, hf_h4501_invokeId, NULL, NULL);
	return offset;
}


static const value_string localOpcode_vals[] = {
   /* H.450.2 Call Transfer opcodes */
   { CallTransferIdentify,    "callTransferIdentify"},
   { CallTransferAbandon,     "callTransferAbandon"},
   { CallTransferInitiate,    "callTransferInitiate"},
   { CallTransferSetup,       "callTransferSetup"},
   { CallTransferUpdate,      "callTransferUpdate"},
   { SubaddressTransfer,      "subaddressTransfer"},
   { CallTransferComplete,    "callTransferComplete"},
   { CallTransferActive,      "callTransferActive"},

   /* H.450.3 Call Diversion opcodes */
   { ActivateDiversionQ,      "activateDiversionQ"},
   { DeactivateDiversionQ,    "deactivateDiversionQ"},
   { InterrogateDiversionQ,   "interrogateDiversionQ"},
   { CheckRestriction,        "checkRestriction"},
   { CallRerouting,           "callRerouting"},
   { DivertingLegInformation1,"divertingLegInformation1"},
   { DivertingLegInformation2,"divertingLegInformation2"},
   { DivertingLegInformation3,"divertingLegInformation3"},
   { DivertingLegInformation4,"divertingLegInformation4"},
   { CfnrDivertedLegFailed,   "cfnrDivertedLegFailed"},

   /* H.450.4 Call Hold opcodes */
   { HoldNotific,             "holdNotific"},
   { RetrieveNotific,         "retrieveNotific"},
   { RemoteHold,              "remoteHold"},
   { RemoteRetrieve,          "remoteRetrieve"},

   /* H.450.5 Call Park and Pickup opcodes */
   { CpRequest,               "cpRequest"},
   { CpSetup,                 "cpSetup"},
   { GroupIndicationOn,       "groupIndicationOn"},
   { GroupIndicationOff,      "groupIndicationOff"},
   { Pickrequ,                "pickrequ"},
   { Pickup,                  "pickup"},
   { PickExe,                 "pickExe"},
   { CpNotify,                "cpNotify"},
   { CpickupNotify,           "cpickupNotify"},

   /* H.450.6 Call Waiting opcodes */
   { CallWaiting,             "callWaiting"},

   /* TODO - add other H.450.x invoke opcodes here */

	{  0, NULL }
};
static int
dissect_h4501_localOpcode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_integer(tvb, offset, pinfo, tree, hf_h4501_localOpcode, &localOpcode, NULL);
	return offset;
}


static int
dissect_h4501_globalCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h4501_globalCode, NULL);
   return offset;
}


static const value_string opcode_vals[] = {
	{ 0, "local" },
	{ 1, "global" },
	{ 0, NULL}
};
static per_choice_t opcode_choice[] = {
	{ 0, "local", NO_EXTENSIONS,
		dissect_h4501_localOpcode },
	{ 1, "global", NO_EXTENSIONS,
		dissect_h4501_globalCode },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_opcode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_opcode, ett_h4501_opcode, opcode_choice, "Opcode", NULL);
   return offset;
}


static int
dissect_h4501_ExtensionSeq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
NOT_DECODED_YET("H.450.1 ExtensionSeq");
   return offset;
}


static int
dissect_h4502_nonStandardData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_h225_NonStandardParameter(tvb, offset, pinfo, tree, 
				hf_h4502_nonStandardData);
	return offset;
}

static const value_string Extension_vals[] = {
	{ 0, "extensionSeq" },
	{ 1, "nonStandardData" },
	{ 0, NULL}
};
static per_choice_t Extension_choice[] = {
	{ 0, "extensionSeq", NO_EXTENSIONS, 
		dissect_h4501_ExtensionSeq },
	{ 1, "nonStandardData", NO_EXTENSIONS, 
		dissect_h4502_nonStandardData },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4502_DummyArg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4502_DummyArg, ett_h4502_DummyArg, Extension_choice, "DummyArg", NULL);
   return offset;
}


static int
dissect_h4502_CallIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_NumericString(tvb, offset, pinfo, tree, hf_h4502_CallIdentity, 0, 4);
   return offset;
}


static int
dissect_h4501_destinationAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h4501_destinationAddress, ett_h4501_destinationAddress, dissect_h225_AliasAddress);
   return offset;
}


static per_sequence_t EndpointAddress_sequence[] = {
	{ "destinationAddress", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_destinationAddress },
	{ "remoteExtensionAddress", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h225_AliasAddress },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_EndpointAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_EndpointAddress, ett_h4501_EndpointAddress, EndpointAddress_sequence);
   return offset;
}


static int
dissect_h4501_argumentExtension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_argumentExtension, ett_h4501_argumentExtension, Extension_choice, "argumentExtension", NULL);
   return offset;
}


static per_sequence_t CTInitiateArg_sequence[] = {
	{ "callIdentity", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4502_CallIdentity },
	{ "reroutingNumber", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_EndpointAddress },
	{ "argumentExtension", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_argumentExtension },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4502_CTInitiateArg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4502_CTInitiateArg, ett_h4502_CTInitiateArg, CTInitiateArg_sequence);
   return offset;
}


static per_sequence_t CTSetupArg_sequence[] = {
	{ "callIdentity", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4502_CallIdentity },
	{ "transferringNumber", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_EndpointAddress },
	{ "argumentExtension", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_argumentExtension },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4502_CTSetupArg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4502_CTSetupArg, ett_h4502_CTSetupArg, CTSetupArg_sequence);
   return offset;
}


static int
dissect_h4502_redirectionInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_BMPString(tvb, offset, pinfo, tree, hf_h4502_redirectionInfo, 1, 128);
   return offset;
}


static int
dissect_h4501_H225InformationElement(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h4501_H225InformationElement, -1, -1, NULL, NULL);
   return offset;
}


static per_sequence_t CTUpdateArg_sequence[] = {
	{ "redirectionNumber", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_EndpointAddress },
	{ "redirectionInfo", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4502_redirectionInfo },
	{ "basicCallInfoElements", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_H225InformationElement },
	{ "argumentExtension", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_argumentExtension },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4502_CTUpdateArg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4502_CTUpdateArg, ett_h4502_CTUpdateArg, CTUpdateArg_sequence);
   return offset;
}


static int
dissect_h4501_SubaddressInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h4501_SubaddressInformation, 1, 20, NULL, NULL);
   return offset;
}


static const true_false_string tfs_oddCountIndicator_bit = {
	"oddCountIndicator bit is SET",
	"oddCountIndicator bit is CLEAR"
};
static int
dissect_h4501_oddCountIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_boolean(tvb, offset, pinfo, tree, hf_h4501_oddCountIndicator, NULL, NULL);
   return offset;
}


static per_sequence_t UserSpecifiedSubaddress_sequence[] = {
	{ "subaddressInformation", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_SubaddressInformation },
	{ "oddCountIndicator", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_oddCountIndicator },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_UserSpecifiedSubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_UserSpecifiedSubaddress, ett_h4501_UserSpecifiedSubaddress, UserSpecifiedSubaddress_sequence);
   return offset;
}


static int
dissect_h4501_NSAPSubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h4501_NSAPAddress, 1, 20, NULL, NULL);
   return offset;
}


static const value_string PartySubaddress_vals[] = {
	{ 0, "userSpecifiedSubaddress" },
	{ 1, "nsapSubaddress" },
	{ 0, NULL}
};
static per_choice_t PartySubaddress_choice[] = {
	{ 0, "userSpecifiedSubaddress", EXTENSION_ROOT, 
		dissect_h4501_UserSpecifiedSubaddress },
	{ 1, "nsapSubaddress", EXTENSION_ROOT, 
		dissect_h4501_NSAPSubaddress },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_PartySubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_PartySubaddress, ett_h4501_PartySubaddress, PartySubaddress_choice, "PartySubaddress", NULL);
   return offset;
}


static per_sequence_t SubaddressTransferArg_sequence[] = {
	{ "redirectionSubaddress", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_PartySubaddress },
	{ "argumentExtension", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_argumentExtension },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4502_SubaddressTransferArg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4502_SubaddressTransferArg, ett_h4502_SubaddressTransferArg, SubaddressTransferArg_sequence);
   return offset;
}


static const value_string EndDesignation_vals[] = {
   {  0, "primaryEnd"},
   {  1, "secondaryEnd"},
   {  0, NULL }
};
static int
dissect_h4502_EndDesignation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4502_EndDesignation, 0, 1, NULL, NULL, TRUE);
   return offset;
}


static const value_string CallStatus_vals[] = {
   {  0, "answered"},
   {  1, "alerting"},
   {  0, NULL }
};
static int
dissect_h4502_CallStatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4502_CallStatus, 0, 1, NULL, NULL, TRUE);
   return offset;
}


static per_sequence_t CTCompleteArg_sequence[] = {
	{ "endDesignation", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4502_EndDesignation },
	{ "redirectionNumber", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_EndpointAddress },
	{ "basicCallInfoElements", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_H225InformationElement },
	{ "redirectionInfo", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4502_redirectionInfo },
	{ "callStatus", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4502_CallStatus },
	{ "argumentExtension", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_argumentExtension },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4502_CTCompleteArg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4502_CTCompleteArg, ett_h4502_CTCompleteArg, CTCompleteArg_sequence);
   return offset;
}


static int
dissect_h4502_connectedInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_BMPString(tvb, offset, pinfo, tree, hf_h4502_connectedInfo, 1, 128);
   return offset;
}


static per_sequence_t CTActiveArg_sequence[] = {
	{ "connectedAddress", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_EndpointAddress },
	{ "basicCallInfoElements", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_H225InformationElement },
	{ "connectedInfo", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4502_connectedInfo },
	{ "argumentExtension", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_argumentExtension },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4502_CTActiveArg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4502_CTActiveArg, ett_h4502_CTActiveArg, CTActiveArg_sequence);
   return offset;
}


static int
dissect_h4501_argument(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   tvbuff_t *argument_tvb;
   guint32 argument_offset=0;
   guint32 argument_len=0;

   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, -1, -1, -1, &argument_offset, &argument_len);

   if(argument_len){
      argument_tvb = tvb_new_subset(tvb, argument_offset, argument_len, argument_len);

      switch (localOpcode) {
      case CallTransferIdentify:
      case CallTransferAbandon:
         offset = dissect_h4502_DummyArg(argument_tvb, 0, pinfo, tree);
         break;

      case CallTransferInitiate:
         offset = dissect_h4502_CTInitiateArg(argument_tvb, 0, pinfo, tree);
         break;

      case CallTransferSetup:
         offset = dissect_h4502_CTSetupArg(argument_tvb, 0, pinfo, tree);
         break;

      case CallTransferUpdate:
         offset = dissect_h4502_CTUpdateArg(argument_tvb, 0, pinfo, tree);
         break;

      case SubaddressTransfer:
         offset = dissect_h4502_SubaddressTransferArg(argument_tvb, 0, pinfo, tree);
         break;

      case CallTransferComplete:
         offset = dissect_h4502_CTCompleteArg(argument_tvb, 0, pinfo, tree);
         break;

      case CallTransferActive:
         offset = dissect_h4502_CTActiveArg(argument_tvb, 0, pinfo, tree);
         break;

      /* TODO - decode other H.450.x invoke arguments here */

      default:
NOT_DECODED_YET("Unrecognized H.450.x operation");
         break;
      }
   }
	return offset;
}


static per_sequence_t Invoke_sequence[] = {
	{ "invokeID", NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_constrained_invokeId },
	{ "linkedId", NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h4501_invokeId },
	{ "opcode", NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_opcode },
	{ "argument", NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h4501_argument },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_Invoke(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_Invoke, ett_h4501_Invoke, Invoke_sequence);
   return offset;
}


static int
dissect_h4501_resultExtension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_resultExtension, ett_h4501_resultExtension, Extension_choice, "resultExtension", NULL);
   return offset;
}


static per_sequence_t CTIdentifyRes_sequence[] = {
	{ "callIdentity", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4502_CallIdentity },
	{ "reroutingNumber", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_EndpointAddress },
	{ "resultExtension", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_resultExtension },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4502_CTIdentifyRes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4502_CTIdentifyRes, ett_h4502_CTIdentifyRes, CTIdentifyRes_sequence);
   return offset;
}


static int
dissect_h4502_DummyRes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4502_DummyRes, ett_h4502_DummyRes, Extension_choice, "DummyRes", NULL);
   return offset;
}


static int
dissect_h4501_ReturnResult_result(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   tvbuff_t *result_tvb;
   guint32 result_offset=0;
   guint32 result_len=0;

   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, -1, -1, -1, &result_offset, &result_len);

   if(result_len){
      result_tvb = tvb_new_subset(tvb, result_offset, result_len, result_len);

      switch (localOpcode) {
      case CallTransferIdentify:
         offset = dissect_h4502_CTIdentifyRes(result_tvb, 0, pinfo, tree);
         break;

      case CallTransferInitiate:
      case CallTransferSetup:
         offset = dissect_h4502_DummyRes(result_tvb, 0, pinfo, tree);
         break;

      default:
NOT_DECODED_YET("Unrecognized H.450.x return result");
         break;
      }
   }

   return offset;
}


static per_sequence_t result_sequence[] = {
	{ "opcode", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_opcode },
	{ "result", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_ReturnResult_result },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_result(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_result, ett_h4501_result, result_sequence);
   return offset;
}


static per_sequence_t ReturnResult_sequence[] = {
	{ "invokeID", NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_invokeId },
	{ "result", NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h4501_result },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_ReturnResult(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_ReturnResult, ett_h4501_ReturnResult, ReturnResult_sequence);
   return offset;
}


static const value_string localErrorCode_vals[] = {
   /* H.450.1 general error list */
   {    0, "userNotSubscribed"},
   {    1, "RejectedByNetwork"},
   {    2, "RejectedByUser"},
   {    3, "NotAvailable"},
   {    5, "InsufficientInformation"},
   {    6, "InvalidServedUserNumber"},
   {    7, "InvalidCallState"},
   {    8, "BasicServiceNotProvided"},
   {    9, "NotIncomingCall"},
   {   10, "SupplementaryServiceInteractionNotAllowed"},
   {   11, "ResourceUnavailable"},
   {   25, "CallFailure"},
   {   43, "ProceduralError"},

   /* H.450.2 Call Transfer return errors */
   { 1004, "invalidReroutingNumber"},
   { 1005, "unrecognizedCallIdentity"},
   { 1006, "establishmentFailure"},
   { 1008, "unspecified"},

   /* H.450.4 Call Hold return errors */
   { 2002, "undefined"},

   /* H.450.5 Call Park and Pickup return errors */
   { 2000, "callPickupIdInvalid"},
   { 2001, "callAlreadyPickedUp"},

   /* TODO - add other H.450.x error codes here */

   {  0, NULL }
};
static int
dissect_h4501_localErrorCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_integer(tvb, offset, pinfo, tree, hf_h4501_localErrorCode, &localErrorCode, NULL);
	return offset;
}


static const value_string errorCode_vals[] = {
	{ 0, "local" },
	{ 1, "global" },
	{ 0, NULL}
};
static per_choice_t errorCode_choice[] = {
	{ 0, "local", NO_EXTENSIONS,
		dissect_h4501_localErrorCode },
	{ 1, "global", NO_EXTENSIONS,
		dissect_h4501_globalCode },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_errorCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_errorCode, ett_h4501_errorCode, errorCode_choice, "errorCode", NULL);
   return offset;
}


static int
dissect_h4501_parameter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   /* TODO - decode return error parameter based on localErrorCode */
   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h4501_parameter, -1, -1, NULL, NULL);
   return offset;
}


static per_sequence_t ReturnError_sequence[] = {
	{ "invokeID", NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_invokeId },
	{ "errorCode", NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_errorCode },
	{ "parameter", NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h4501_parameter },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_ReturnError(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_ReturnError, ett_h4501_ReturnError, ReturnError_sequence);
   return offset;
}


static const value_string GeneralProblem_vals[] = {
   {  0, "unrecognizedCompenent"},
   {  1, "mistypedCompenent"},
   {  2, "badlyStructuredCompenent"},
   {  0, NULL }
};
static int
dissect_h4501_GeneralProblem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_GeneralProblem, 0, 2, NULL, NULL, FALSE);
   return offset;
}


static const value_string InvokeProblem_vals[] = {
   {  0, "duplicateInvocation"},
   {  1, "unrecognizedOperation"},
   {  2, "mistypedArgument"},
   {  3, "resourceLimitation"},
   {  4, "releaseInProgress"},
   {  5, "unrecognizedLinkedId"},
   {  6, "linkedResponseUnexpected"},
   {  7, "unexpectedLinkedOperation"},
   {  0, NULL }
};
static int
dissect_h4501_InvokeProblem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_InvokeProblem, 0, 7, NULL, NULL, FALSE);
   return offset;
}


static const value_string ReturnResultProblem_vals[] = {
   {  0, "unrecognizedInvocation"},
   {  1, "resultResponseUnexpected"},
   {  2, "mistypedResult"},
   {  0, NULL }
};
static int
dissect_h4501_ReturnResultProblem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_ReturnResultProblem, 0, 2, NULL, NULL, FALSE);
   return offset;
}


static const value_string ReturnErrorProblem_vals[] = {
   {  0, "unrecognizedInvocation"},
   {  1, "errorResponseUnexpected"},
   {  2, "unrecognizedError"},
   {  3, "unexpectedError"},
   {  4, "mistypedParameter"},
   {  0, NULL }
};
static int
dissect_h4501_ReturnErrorProblem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_ReturnErrorProblem, 0, 4, NULL, NULL, FALSE);
   return offset;
}


static const value_string problem_vals[] = {
	{ 0, "general" },
	{ 1, "invoke" },
	{ 2, "returnResult" },
	{ 3, "returnError" },
	{ 0, NULL}
};
static per_choice_t problem_choice[] = {
	{ 0, "general", NO_EXTENSIONS,
		dissect_h4501_GeneralProblem },
	{ 1, "invoke", NO_EXTENSIONS,
		dissect_h4501_InvokeProblem },
	{ 2, "returnResult", NO_EXTENSIONS,
		dissect_h4501_ReturnResultProblem },
	{ 3, "returnError", NO_EXTENSIONS,
		dissect_h4501_ReturnErrorProblem },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_problem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_problem, ett_h4501_problem, problem_choice, "problem", NULL);
   return offset;
}


static per_sequence_t Reject_sequence[] = {
	{ "invokeID", NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_invokeId },
	{ "problem", NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_problem },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_Reject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_Reject, ett_h4501_Reject, Reject_sequence);
   return offset;
}


static const value_string ROS_vals[] = {
	{ 1, "invoke" },
	{ 2, "returnResult" },
	{ 3, "returnError" },
	{ 4, "reject" },
	{ 0, NULL}
};
static per_choice_t ROS_choice[] = {
	{ 1, "invoke", NO_EXTENSIONS,
		dissect_h4501_Invoke },
	{ 2, "returnResult", NO_EXTENSIONS,
		dissect_h4501_ReturnResult },
	{ 3, "returnError", NO_EXTENSIONS,
		dissect_h4501_ReturnError },
	{ 4, "reject", NO_EXTENSIONS,
		dissect_h4501_Reject },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_ROS(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_ROS, ett_h4501_ROS, ROS_choice, "ROS", NULL);
   return offset;
}


static int
dissect_h4501_rosApdus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_h4501_rosApdus, ett_h4501_rosApdus, dissect_h4501_ROS);
	return offset;
}


static const value_string ServiceApdus_vals[] = {
	{ 0, "rosApdus" },
	{ 0, NULL}
};
static per_choice_t ServiceApdus_choice[] = {
	{ 0, "rosApdus", EXTENSION_ROOT, 
		dissect_h4501_rosApdus },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_ServiceApdus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_ServiceApdus, ett_h4501_ServiceApdus, ServiceApdus_choice, "ServiceApdus", NULL);
   return offset;
}


static per_sequence_t H4501_SupplementaryService_sequence[] = {
	{ "networkFacilityExtension", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_NetworkFacilityExtension },
	{ "interpretationApdu", EXTENSION_ROOT, ASN1_OPTIONAL,
		dissect_h4501_InterpretationApdu },
	{ "serviceApdu", EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_ServiceApdus },
	{ NULL, 0, 0, NULL }
};
static void
dissect_h4501(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree)
{
   proto_item *it;
   proto_tree *tr;
   guint32 offset=0;

   it=proto_tree_add_protocol_format(tree, proto_h4501, tvb, 0, tvb_length(tvb), "H.450.1");
   tr=proto_item_add_subtree(it, ett_h4501);

   offset=dissect_per_sequence(tvb, offset, pinfo, tr, hf_h4501, ett_h4501, H4501_SupplementaryService_sequence);
}


void
proto_register_h4501(void)
{
	static hf_register_info hf[] =
	{
   { &hf_h4501,
      { "SupplementaryService", "h4501.SupplementaryService", FT_NONE, BASE_NONE,
      NULL, 0, "SupplementaryService sequence", HFILL }},
   { &hf_h4501_EntityType,
      { "EntityType", "h4501.EntityType", FT_UINT32, BASE_DEC,
      VALS(EntityType_vals), 0, "EntityType choice", HFILL }},
   { &hf_h4501_NetworkFacilityExtension,
      { "NetworkFacilityExtension", "h4501.NetworkFacilityExtension", FT_NONE, BASE_NONE,
      NULL, 0, "NetworkFacilityExtension sequence", HFILL }},
   { &hf_h4501_InterpretationApdu,
      { "InterpretationApdu", "h4501.InterpretationApdu", FT_UINT32, BASE_DEC,
      VALS(InterpretationApdu_vals), 0, "InterpretationApdu choice", HFILL }},
   { &hf_h4501_constrained_invokeId,
      { "invokeId", "h4501.invokeId", FT_UINT32, BASE_DEC,
      NULL, 0, "invokeId", HFILL }},
   { &hf_h4501_invokeId,
      { "invokeId", "h4501.invokeId", FT_INT32, BASE_DEC,
      NULL, 0, "invokeId", HFILL }},
   { &hf_h4501_localOpcode,
      { "opcode", "h4501.opcode", FT_INT32, BASE_DEC,
      VALS(localOpcode_vals), 0, "local", HFILL }},
   { &hf_h4501_globalCode,
      { "global", "h4501.global", FT_BYTES, BASE_HEX,
      NULL, 0, "global", HFILL }},
   { &hf_h4501_opcode,
      { "opcode", "h4501.opcode", FT_UINT32, BASE_DEC,
      VALS(opcode_vals), 0, "opcode choice", HFILL }},
   { &hf_h4502_CallIdentity,
      { "CallIdentity", "h4502.CallIdentity", FT_STRING, BASE_NONE,
      NULL, 0, "CallIdentity", HFILL }},
   { &hf_h4501_destinationAddress,
      { "destinationAddress", "h4501.destinationAddress", FT_NONE, BASE_NONE,
      NULL, 0, "destinationAddress sequence of", HFILL }},
   { &hf_h4501_EndpointAddress,
      { "EndpointAddress", "h4501.EndpointAddress", FT_NONE, BASE_NONE,
      NULL, 0, "EndpointAddress sequence of", HFILL }},
   { &hf_h4501_H225InformationElement,
      { "H225InformationElement", "h4501.H225InformationElement", FT_BYTES, BASE_HEX,
      NULL, 0, "H225InformationElement", HFILL }},
   { &hf_h4502_nonStandardData,
      { "nonStandardData", "h4502.nonStandardData", FT_NONE, BASE_NONE,
	  NULL, 0, "NonStandardParameter SEQUENCE", HFILL }},
   { &hf_h4502_DummyArg,
      { "DummyArg", "h4502.DummyArg", FT_NONE, BASE_NONE,
      NULL, 0, "DummyArg sequence of", HFILL }},
   { &hf_h4502_CTInitiateArg,
      { "CTInitiateArg", "h4502.CTInitiateArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTInitiateArg sequence of", HFILL }},
   { &hf_h4502_CTSetupArg,
      { "CTSetupArg", "h4502.CTSetupArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTSetupArg sequence of", HFILL }},
	{ &hf_h4502_redirectionInfo,
		{ "redirectionInfo", "h4502.redirectionInfo", FT_STRING, BASE_HEX,
		NULL, 0, "redirectionInfo BMPString", HFILL }},
   { &hf_h4502_CTUpdateArg,
      { "CTUpdateArg", "h4502.CTUpdateArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTUpdateArg sequence of", HFILL }},
   { &hf_h4501_SubaddressInformation,
		{ "SubaddressInformation", "h4501.SubaddressInformation", FT_BYTES, BASE_HEX,
		NULL, 0, "SubaddressInformation octet string", HFILL }},
	{ &hf_h4501_oddCountIndicator,
		{ "oddCountIndicator", "h4501.oddCountIndicator", FT_BOOLEAN, 8,
		TFS(&tfs_oddCountIndicator_bit), 0x01, "The oddCountIndicator bit", HFILL }},
   { &hf_h4501_UserSpecifiedSubaddress,
      { "UserSpecifiedSubaddress", "h4501.UserSpecifiedSubaddress", FT_NONE, BASE_NONE,
      NULL, 0, "UserSpecifiedSubaddress sequence of", HFILL }},
   { &hf_h4501_NSAPAddress,
		{ "NSAPAddress", "h4501.NSAPAddress", FT_BYTES, BASE_HEX,
		NULL, 0, "NSAPAddress octet string", HFILL }},
   { &hf_h4501_PartySubaddress,
      { "PartySubaddress", "h4501.PartySubaddress", FT_UINT32, BASE_DEC,
      VALS(PartySubaddress_vals), 0, "PartySubaddress choice", HFILL }},
   { &hf_h4502_SubaddressTransferArg,
      { "SubaddressTransferArg", "h4502.SubaddressTransferArg", FT_NONE, BASE_NONE,
      NULL, 0, "SubaddressTransferArg sequence of", HFILL }},
   { &hf_h4502_EndDesignation,
      { "EndDesignation", "h4502.EndDesignation", FT_UINT32, BASE_DEC,
      VALS(EndDesignation_vals), 0, "EndDesignation", HFILL }},
   { &hf_h4502_CallStatus,
      { "CallStatus", "h4502.CallStatus", FT_UINT32, BASE_DEC,
      VALS(CallStatus_vals), 0, "CallStatus", HFILL }},
   { &hf_h4502_CTCompleteArg,
      { "CTCompleteArg", "h4502.CTCompleteArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTCompleteArg sequence of", HFILL }},
	{ &hf_h4502_connectedInfo,
		{ "connectedInfo", "h4502.connectedInfo", FT_STRING, BASE_HEX,
		NULL, 0, "connectedInfo BMPString", HFILL }},
   { &hf_h4502_CTActiveArg,
      { "CTActiveArg", "h4502.CTActiveArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTActiveArg sequence of", HFILL }},
   { &hf_h4501_argumentExtension,
      { "argumentExtension", "h4501.argumentExtension", FT_BYTES, BASE_HEX,
      NULL, 0, "argumentExtension", HFILL }},
   { &hf_h4501_argument,
      { "argument", "h4501.argument", FT_BYTES, BASE_HEX,
      NULL, 0, "argument", HFILL }},
   { &hf_h4501_Invoke,
      { "Invoke", "h4501.Invoke", FT_NONE, BASE_NONE,
      NULL, 0, "Invoke sequence of", HFILL }},
   { &hf_h4502_CTIdentifyRes,
      { "CTIdentifyRes", "h4502.CTIdentifyRes", FT_NONE, BASE_NONE,
      NULL, 0, "CTIdentifyRes sequence of", HFILL }},
   { &hf_h4502_DummyRes,
      { "DummyRes", "h4502.DummyRes", FT_NONE, BASE_NONE,
      NULL, 0, "DummyRes sequence of", HFILL }},
   { &hf_h4501_resultExtension,
      { "resultExtension", "h4501.resultExtension", FT_BYTES, BASE_HEX,
      NULL, 0, "resultExtension", HFILL }},
   { &hf_h4501_ReturnResult_result,
      { "result", "h4501.ReturnResult.result", FT_BYTES, BASE_HEX,
      NULL, 0, "result", HFILL }},
   { &hf_h4501_result,
      { "result", "h4501.result", FT_NONE, BASE_NONE,
      NULL, 0, "result sequence of", HFILL }},
   { &hf_h4501_ReturnResult,
      { "ReturnResult", "h4501.ReturnResult", FT_NONE, BASE_NONE,
      NULL, 0, "ReturnResult sequence of", HFILL }},
   { &hf_h4501_localErrorCode,
      { "errorCode", "h4501.errorCode", FT_INT32, BASE_DEC,
      VALS(localErrorCode_vals), 0, "local", HFILL }},
   { &hf_h4501_errorCode,
      { "errorCode", "h4501.errorCode", FT_UINT32, BASE_DEC,
      VALS(errorCode_vals), 0, "errorCode", HFILL }},
   { &hf_h4501_parameter,
      { "parameter", "h4501.parameter", FT_BYTES, BASE_HEX,
      NULL, 0, "parameter", HFILL }},
   { &hf_h4501_ReturnError,
      { "ReturnError", "h4501.ReturnError", FT_NONE, BASE_NONE,
      NULL, 0, "ReturnError sequence of", HFILL }},
   { &hf_h4501_GeneralProblem,
      { "GeneralProblem", "h4501.GeneralProblem", FT_UINT32, BASE_DEC,
      VALS(GeneralProblem_vals), 0, "GeneralProblem", HFILL }},
   { &hf_h4501_InvokeProblem,
      { "InvokeProblem", "h4501.InvokeProblem", FT_UINT32, BASE_DEC,
      VALS(InvokeProblem_vals), 0, "InvokeProblem", HFILL }},
   { &hf_h4501_ReturnResultProblem,
      { "ReturnResultProblem", "h4501.ReturnResultProblem", FT_UINT32, BASE_DEC,
      VALS(ReturnResultProblem_vals), 0, "ReturnResultProblem", HFILL }},
   { &hf_h4501_ReturnErrorProblem,
      { "ReturnErrorProblem", "h4501.ReturnErrorProblem", FT_UINT32, BASE_DEC,
      VALS(ReturnErrorProblem_vals), 0, "ReturnErrorProblem", HFILL }},
   { &hf_h4501_problem,
      { "problem", "h4501.problem", FT_UINT32, BASE_DEC,
      VALS(problem_vals), 0, "problem choice", HFILL }},
   { &hf_h4501_Reject,
      { "Reject", "h4501.Reject", FT_NONE, BASE_NONE,
      NULL, 0, "Reject sequence of", HFILL }},
   { &hf_h4501_ROS,
      { "ROS", "h4501.ROS", FT_UINT32, BASE_DEC,
      VALS(ROS_vals), 0, "ROS choice", HFILL }},
   { &hf_h4501_rosApdus,
      { "rosApdus", "h4501.rosApdus", FT_NONE, BASE_NONE,
      NULL, 0, "rosApdus sequence of", HFILL }},
   { &hf_h4501_ServiceApdus,
      { "ServiceApdus", "h4501.ServiceApdus", FT_UINT32, BASE_DEC,
      VALS(ServiceApdus_vals), 0, "ServiceApdus choice", HFILL }}
   };

	static gint *ett[] =
	{
      &ett_h4501,
      &ett_h4501_EntityType,
      &ett_h4501_NetworkFacilityExtension,
      &ett_h4501_InterpretationApdu,
      &ett_h4501_opcode,
      &ett_h4501_destinationAddress,
      &ett_h4501_EndpointAddress,
      &ett_h4501_PartySubaddress,
      &ett_h4501_argumentExtension,
      &ett_h4501_Invoke,
      &ett_h4501_resultExtension,
      &ett_h4501_result,
      &ett_h4501_ReturnResult,
      &ett_h4501_errorCode,
      &ett_h4501_ReturnError,
      &ett_h4501_problem,
      &ett_h4501_Reject,
      &ett_h4501_ROS,
      &ett_h4501_rosApdus,
      &ett_h4501_ServiceApdus,

      &ett_h4502_DummyArg,
      &ett_h4502_CTInitiateArg,
      &ett_h4502_CTSetupArg,
      &ett_h4502_CTUpdateArg,
      &ett_h4502_SubaddressTransferArg,
      &ett_h4502_CTCompleteArg,
      &ett_h4502_CTActiveArg,
      &ett_h4502_CTIdentifyRes,
      &ett_h4502_DummyRes
   };

   proto_h4501 = proto_register_protocol("H4501", "H4501", "h4501");
   proto_register_field_array(proto_h4501, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
   register_dissector("h4501", dissect_h4501, proto_h4501);
}

void
proto_reg_handoff_h4501(void)
{
   h4501_handle=create_dissector_handle(dissect_h4501, proto_h4501);
}
