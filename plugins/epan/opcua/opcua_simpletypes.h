/******************************************************************************
** Copyright (C) 2006-2007 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** SPDX-License-Identifier: GPL-2.0-or-later
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** Project: OpcUa Wireshark Plugin
**
** Description: Implementation of OpcUa built-in type parsers.
**              This contains all the simple types and some complex types.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/
#include "opcua_identifiers.h"

/* simple header fields */
extern int hf_opcua_returnDiag;
extern int hf_opcua_returnDiag_mask_sl_symbolicId;
extern int hf_opcua_returnDiag_mask_sl_localizedText;
extern int hf_opcua_returnDiag_mask_sl_additionalinfo;
extern int hf_opcua_returnDiag_mask_sl_innerstatuscode;
extern int hf_opcua_returnDiag_mask_sl_innerdiagnostics;
extern int hf_opcua_returnDiag_mask_ol_symbolicId;
extern int hf_opcua_returnDiag_mask_ol_localizedText;
extern int hf_opcua_returnDiag_mask_ol_additionalinfo;
extern int hf_opcua_returnDiag_mask_ol_innerstatuscode;
extern int hf_opcua_returnDiag_mask_ol_innerdiagnostics;
extern int hf_opcua_nodeClassMask;
extern int hf_opcua_nodeClassMask_object;
extern int hf_opcua_nodeClassMask_variable;
extern int hf_opcua_nodeClassMask_method;
extern int hf_opcua_nodeClassMask_objecttype;
extern int hf_opcua_nodeClassMask_variabletype;
extern int hf_opcua_nodeClassMask_referencetype;
extern int hf_opcua_nodeClassMask_datatype;
extern int hf_opcua_nodeClassMask_view;

/* simple types trees */
extern int ett_opcua_array_Boolean;
extern int ett_opcua_array_SByte;
extern int ett_opcua_array_Byte;
extern int ett_opcua_array_Int16;
extern int ett_opcua_array_UInt16;
extern int ett_opcua_array_Int32;
extern int ett_opcua_array_UInt32;
extern int ett_opcua_array_Int64;
extern int ett_opcua_array_UInt64;
extern int ett_opcua_array_Float;
extern int ett_opcua_array_Double;
extern int ett_opcua_array_String;
extern int ett_opcua_array_DateTime;
extern int ett_opcua_array_Guid;
extern int ett_opcua_array_ByteString;
extern int ett_opcua_array_XmlElement;
extern int ett_opcua_array_NodeId;
extern int ett_opcua_array_ExpandedNodeId;
extern int ett_opcua_array_StatusCode;
extern int ett_opcua_array_DiagnosticInfo;
extern int ett_opcua_array_QualifiedName;
extern int ett_opcua_array_LocalizedText;
extern int ett_opcua_array_ExtensionObject;
extern int ett_opcua_array_DataValue;
extern int ett_opcua_array_Variant;
extern int ett_opcua_returnDiagnostics;

enum ua_message_mode {
    UA_MessageMode_Unknown = 0,
    UA_MessageMode_None,
    UA_MessageMode_Sign,
    UA_MessageMode_SignAndEncrypt,
    UA_MessageMode_MaybeEncrypted
};

/* simple types */
proto_item* parseBoolean(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseByte(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseSByte(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseUInt16(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseInt16(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseUInt32(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseInt32(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseUInt64(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseInt64(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseString(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseString_ret_string_and_length(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex, const uint8_t **retval, int *lenretval);
proto_item* parseGuid(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseByteString(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseXmlElement(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseFloat(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseDouble(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseDateTime(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
proto_item* parseStatusCode(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
/* complex types */
void parseLocalizedText(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);
void parseNodeId(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);
void parseDiagnosticInfo(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);
void parseExtensionObject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);
void parseQualifiedName(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);
void parseCertificate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
void parseDataValue(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);
void parseVariant(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);
void parseExpandedNodeId(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);
void parseArraySimple(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName, const char *szTypeName, int hfIndex, fctSimpleTypeParser pParserFunction, const int idx);
void parseArrayEnum(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName, const char *szTypeName, fctEnumParser pParserFunction, const int idx);
void parseArrayComplex(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName, const char *szTypeName, fctComplexTypeParser pParserFunction, const int idx);
void registerSimpleTypes(int proto);
uint32_t getExtensionObjectType(tvbuff_t *tvb, int *pOffset);
void parseNodeClassMask(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset);
void parseResultMask(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset);

void dispatchExtensionObjectType(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int TypeId);

