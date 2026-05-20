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
#ifndef OPCUA_IDENTIFIERS_H
#define OPCUA_IDENTIFIERS_H

#include "opcua_identifiers.h"

/* simple header fields */
/** @brief Wireshark header field index for the ReturnDiagnostics bitmask field. */
extern int hf_opcua_returnDiag;

/** @brief Wireshark header field index for the service-level SymbolicId diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_sl_symbolicId;

/** @brief Wireshark header field index for the service-level LocalizedText diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_sl_localizedText;

/** @brief Wireshark header field index for the service-level AdditionalInfo diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_sl_additionalinfo;

/** @brief Wireshark header field index for the service-level InnerStatusCode diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_sl_innerstatuscode;

/** @brief Wireshark header field index for the service-level InnerDiagnostics diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_sl_innerdiagnostics;

/** @brief Wireshark header field index for the operation-level SymbolicId diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_ol_symbolicId;

/** @brief Wireshark header field index for the operation-level LocalizedText diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_ol_localizedText;

/** @brief Wireshark header field index for the operation-level AdditionalInfo diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_ol_additionalinfo;

/** @brief Wireshark header field index for the operation-level InnerStatusCode diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_ol_innerstatuscode;

/** @brief Wireshark header field index for the operation-level InnerDiagnostics diagnostics mask bit. */
extern int hf_opcua_returnDiag_mask_ol_innerdiagnostics;

/** @brief Wireshark header field index for the NodeClassMask bitmask field. */
extern int hf_opcua_nodeClassMask;

/** @brief Wireshark header field index for the NodeClassMask "all node classes" bit. */
extern int hf_opcua_nodeClassMask_all;

/** @brief Wireshark header field index for the NodeClassMask Object bit. */
extern int hf_opcua_nodeClassMask_object;

/** @brief Wireshark header field index for the NodeClassMask Variable bit. */
extern int hf_opcua_nodeClassMask_variable;

/** @brief Wireshark header field index for the NodeClassMask Method bit. */
extern int hf_opcua_nodeClassMask_method;

/** @brief Wireshark header field index for the NodeClassMask ObjectType bit. */
extern int hf_opcua_nodeClassMask_objecttype;

/** @brief Wireshark header field index for the NodeClassMask VariableType bit. */
extern int hf_opcua_nodeClassMask_variabletype;

/** @brief Wireshark header field index for the NodeClassMask ReferenceType bit. */
extern int hf_opcua_nodeClassMask_referencetype;

/** @brief Wireshark header field index for the NodeClassMask DataType bit. */
extern int hf_opcua_nodeClassMask_datatype;

/** @brief Wireshark header field index for the NodeClassMask View bit. */
extern int hf_opcua_nodeClassMask_view;

/** @brief Wireshark header field index for the ResultMask bitmask field. */
extern int hf_opcua_resultMask;

/** @brief Wireshark header field index for the ResultMask "all results" bit. */
extern int hf_opcua_resultMask_all;

/** @brief Wireshark header field index for the ResultMask ReferenceType bit. */
extern int hf_opcua_resultMask_referencetype;

/** @brief Wireshark header field index for the ResultMask IsForward bit. */
extern int hf_opcua_resultMask_isforward;

/** @brief Wireshark header field index for the ResultMask NodeClass bit. */
extern int hf_opcua_resultMask_nodeclass;

/** @brief Wireshark header field index for the ResultMask BrowseName bit. */
extern int hf_opcua_resultMask_browsename;

/** @brief Wireshark header field index for the ResultMask DisplayName bit. */
extern int hf_opcua_resultMask_displayname;

/** @brief Wireshark header field index for the ResultMask TypeDefinition bit. */
extern int hf_opcua_resultMask_typedefinition;

/* simple types trees */
/** @brief Subtree index for the NodeId subtree in the Wireshark protocol tree. */
extern int ett_opcua_nodeid;

/** @brief Subtree index for the ExtensionObject subtree. */
extern int ett_opcua_extensionobject;

/** @brief Subtree index for an array of Boolean values. */
extern int ett_opcua_array_Boolean;

/** @brief Subtree index for an array of SByte values. */
extern int ett_opcua_array_SByte;

/** @brief Subtree index for an array of Byte values. */
extern int ett_opcua_array_Byte;

/** @brief Subtree index for an array of Int16 values. */
extern int ett_opcua_array_Int16;

/** @brief Subtree index for an array of UInt16 values. */
extern int ett_opcua_array_UInt16;

/** @brief Subtree index for an array of Int32 values. */
extern int ett_opcua_array_Int32;

/** @brief Subtree index for an array of UInt32 values. */
extern int ett_opcua_array_UInt32;

/** @brief Subtree index for an array of Int64 values. */
extern int ett_opcua_array_Int64;

/** @brief Subtree index for an array of UInt64 values. */
extern int ett_opcua_array_UInt64;

/** @brief Subtree index for an array of Float values. */
extern int ett_opcua_array_Float;

/** @brief Subtree index for an array of Double values. */
extern int ett_opcua_array_Double;

/** @brief Subtree index for an array of String values. */
extern int ett_opcua_array_String;

/** @brief Subtree index for an array of DateTime values. */
extern int ett_opcua_array_DateTime;

/** @brief Subtree index for an array of Guid values. */
extern int ett_opcua_array_Guid;

/** @brief Subtree index for an array of ByteString values. */
extern int ett_opcua_array_ByteString;

/** @brief Subtree index for an array of XmlElement values. */
extern int ett_opcua_array_XmlElement;

/** @brief Subtree index for an array of NodeId values. */
extern int ett_opcua_array_NodeId;

/** @brief Subtree index for an array of ExpandedNodeId values. */
extern int ett_opcua_array_ExpandedNodeId;

/** @brief Subtree index for an array of StatusCode values. */
extern int ett_opcua_array_StatusCode;

/** @brief Subtree index for an array of DiagnosticInfo values. */
extern int ett_opcua_array_DiagnosticInfo;

/** @brief Subtree index for an array of QualifiedName values. */
extern int ett_opcua_array_QualifiedName;

/** @brief Subtree index for an array of LocalizedText values. */
extern int ett_opcua_array_LocalizedText;

/** @brief Subtree index for an array of ExtensionObject values. */
extern int ett_opcua_array_ExtensionObject;

/** @brief Subtree index for an array of DataValue values. */
extern int ett_opcua_array_DataValue;

/** @brief Subtree index for an array of Variant values. */
extern int ett_opcua_array_Variant;

/** @brief Subtree index for the ReturnDiagnostics bitmask subtree. */
extern int ett_opcua_returnDiagnostics;

/** @brief Subtree index for the NodeClassMask bitmask subtree. */
extern int ett_opcua_nodeClassMask;

/** @brief Subtree index for the ResultMask bitmask subtree. */
extern int ett_opcua_resultMask;


/**
 * @brief OPC UA message security mode, indicating whether a message channel is unsecured, signed, or encrypted.
 */
enum ua_message_mode {
    UA_MessageMode_Unknown        = 0, /**< Security mode has not been determined. */
    UA_MessageMode_None,               /**< No security applied; messages are neither signed nor encrypted. */
    UA_MessageMode_Sign,               /**< Messages are signed but not encrypted. */
    UA_MessageMode_SignAndEncrypt,     /**< Messages are both signed and encrypted. */
    UA_MessageMode_MaybeEncrypted     /**< Encryption state is indeterminate (e.g., during initial decoding). */
};

/* simple types */

/**
 * @brief Parses a boolean value from the buffer.
 *
 * @param tree The protocol tree to add the item to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return A pointer to the newly created proto_item or NULL on failure.
 */
proto_item* parseBoolean(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a byte from the buffer.
 *
 * @param tree The protocol tree to add the item to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the header field to use.
 * @return proto_item* Pointer to the created protocol item or NULL on failure.
 */
proto_item* parseByte(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses an OPC UA SByte from the buffer.
 *
 * @param tree The protocol tree to add items to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return A pointer to the newly created proto_item or NULL on failure.
 */
proto_item* parseSByte(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a 16-bit unsigned integer from the buffer.
 *
 * @param tree The protocol tree to add the item to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return proto_item* Pointer to the newly created protocol item.
 */
proto_item* parseUInt16(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses an OPC UA Int16 value from the buffer.
 *
 * @param tree Pointer to the protocol tree.
 * @param tvb Pointer to the TVB buffer containing the data.
 * @param pinfo Pointer to the packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return Pointer to the newly created proto_item.
 */
proto_item* parseInt16(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a 32-bit unsigned integer from the given buffer.
 *
 * @param tree The protocol tree to add items to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the header field to use for displaying the parsed value.
 * @return A pointer to the protocol item representing the parsed 32-bit unsigned integer.
 */
proto_item* parseUInt32(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a 32-bit integer from the given TVB buffer.
 *
 * @param tree The protocol tree to add items to.
 * @param tvb The TVB buffer containing the data.
 * @param pinfo The packet information structure.
 * @param pOffset A pointer to the current offset in the TVB buffer.
 * @param hfIndex The field ID for the parsed integer.
 * @return A pointer to the protocol item representing the parsed integer.
 */
proto_item* parseInt32(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a UInt64 value from the given tvbuff_t and adds it to the protocol tree.
 *
 * @param tree The protocol tree to which the parsed value will be added.
 * @param tvb The tvbuff_t containing the data to parse.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset within the tvbuff_t.
 * @param hfIndex Index of the field in the protocol hierarchy.
 * @return A pointer to the newly created proto_item representing the parsed UInt64 value.
 */
proto_item* parseUInt64(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a 64-bit integer from the given buffer.
 *
 * @param tree The protocol tree to add the parsed item to.
 * @param tvb The input buffer containing the data to parse.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return A pointer to the newly created proto_item, or NULL if parsing fails.
 */
proto_item* parseInt64(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a string from the given buffer and adds it to the protocol tree.
 *
 * @param tree The protocol tree to which the parsed string will be added.
 * @param tvb The input buffer containing the data to parse.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset within the buffer.
 * @param hfIndex The field ID for the parsed string.
 * @return A pointer to the protocol item representing the parsed string, or NULL if parsing fails.
 */
proto_item* parseString(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a string from the buffer and returns it along with its length.
 *
 * @param tree The protocol tree to add the item to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information (not used).
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex The field index for the string item.
 * @param retval Pointer to store the parsed string value.
 * @param lenretval Pointer to store the length of the parsed string.
 * @return proto_item* The protocol tree item representing the string.
 */
proto_item* parseString_ret_string_and_length(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex, const uint8_t **retval, int *lenretval);

/**
 * @brief Parses a GUID from the buffer.
 *
 * @param tree The protocol tree to add the item to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return A pointer to the newly created proto_item or NULL on failure.
 */
proto_item* parseGuid(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a byte string from the buffer.
 *
 * @param tree The protocol tree to add items to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return A pointer to the newly created proto_item or NULL on failure.
 */
proto_item* parseByteString(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses an XML element from a buffer.
 *
 * @param tree The protocol tree to add items to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return A pointer to the newly created protocol item or NULL on failure.
 */
proto_item* parseXmlElement(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a floating-point number from the buffer.
 *
 * @param tree The protocol tree to add the item to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return proto_item* Pointer to the newly created protocol item or NULL on failure.
 */
proto_item* parseFloat(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a 32-bit unsigned integer from the given buffer.
 *
 * @param tree The protocol tree to add items to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the field to be added to the protocol tree.
 * @return Pointer to the newly created proto_item.
 */
proto_item* parseDouble(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a DateTime value from the given buffer.
 *
 * @param tree The protocol tree to add items to.
 * @param tvb The input buffer containing the data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset in the buffer.
 * @param hfIndex Index of the header field to use for displaying the parsed value.
 * @return A pointer to the protocol item representing the parsed DateTime value.
 */
proto_item* parseDateTime(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parses a StatusCode from the given TVB buffer.
 *
 * @param tree The protocol tree to add items to.
 * @param tvb The TVB buffer containing the data.
 * @param pinfo The packet information structure.
 * @param pOffset A pointer to the current offset in the TVB buffer.
 * @param hfIndex The field ID for the parsed StatusCode.
 * @return A pointer to the protocol item representing the parsed StatusCode.
 */
proto_item* parseStatusCode(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);
/* complex types */

/**
 * @brief Parses a LocalizedText structure from the given TVB and adds it to the protocol tree.
 *
 * @param tree The protocol tree to add the subtree to.
 * @param tvb The TVB containing the data to parse.
 * @param pinfo Packet information.
 * @param pOffset Pointer to the current offset in the TVB, which will be updated after parsing.
 * @param szFieldName Name of the field being parsed.
 */
void parseLocalizedText(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);
/**
 * @brief Parse a NodeId field into the protocol tree.
 *
 * @param tree        The protocol tree to add items to.
 * @param tvb         The packet buffer.
 * @param pinfo       The packet info.
 * @param pOffset     The current offset into @p tvb; updated on return.
 * @param szFieldName The name of the field being parsed.
 */
void parseNodeId(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);

/**
 * @brief Parse a DiagnosticInfo field into the protocol tree.
 *
 * @param tree        The protocol tree to add items to.
 * @param tvb         The packet buffer.
 * @param pinfo       The packet info.
 * @param pOffset     The current offset into @p tvb; updated on return.
 * @param szFieldName The name of the field being parsed.
 */
void parseDiagnosticInfo(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);

/**
 * @brief Parse an ExtensionObject field into the protocol tree.
 *
 * @param tree        The protocol tree to add items to.
 * @param tvb         The packet buffer.
 * @param pinfo       The packet info.
 * @param pOffset     The current offset into @p tvb; updated on return.
 * @param szFieldName The name of the field being parsed.
 */
void parseExtensionObject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);

/**
 * @brief Parse a QualifiedName field into the protocol tree.
 *
 * @param tree        The protocol tree to add items to.
 * @param tvb         The packet buffer.
 * @param pinfo       The packet info.
 * @param pOffset     The current offset into @p tvb; updated on return.
 * @param szFieldName The name of the field being parsed.
 */
void parseQualifiedName(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);

/**
 * @brief Parse a certificate field into the protocol tree.
 *
 * @param tree    The protocol tree to add items to.
 * @param tvb     The packet buffer.
 * @param pinfo   The packet info.
 * @param pOffset The current offset into @p tvb; updated on return.
 * @param hfIndex The header field index to use when adding the certificate item.
 */
void parseCertificate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex);

/**
 * @brief Parse a DataValue field into the protocol tree.
 *
 * @param tree        The protocol tree to add items to.
 * @param tvb         The packet buffer.
 * @param pinfo       The packet info.
 * @param pOffset     The current offset into @p tvb; updated on return.
 * @param szFieldName The name of the field being parsed.
 */
void parseDataValue(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);

/**
 * @brief Parse a Variant field into the protocol tree.
 *
 * @param tree        The protocol tree to add items to.
 * @param tvb         The packet buffer.
 * @param pinfo       The packet info.
 * @param pOffset     The current offset into @p tvb; updated on return.
 * @param szFieldName The name of the field being parsed.
 */
void parseVariant(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);

/**
 * @brief Parse an ExpandedNodeId field into the protocol tree.
 *
 * @param tree        The protocol tree to add items to.
 * @param tvb         The packet buffer.
 * @param pinfo       The packet info.
 * @param pOffset     The current offset into @p tvb; updated on return.
 * @param szFieldName The name of the field being parsed.
 */
void parseExpandedNodeId(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName);

/**
 * @brief Parse an array of simple-typed elements into the protocol tree.
 *
 * @param tree            The protocol tree to add items to.
 * @param tvb             The packet buffer.
 * @param pinfo           The packet info.
 * @param pOffset         The current offset into @p tvb; updated on return.
 * @param szFieldName     The name of the array field.
 * @param szTypeName      The name of the element type.
 * @param hfIndex         The header field index for each element.
 * @param pParserFunction The parser function to call for each element.
 * @param idx             The ett index for the array subtree.
 */
void parseArraySimple(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName, const char *szTypeName, int hfIndex, fctSimpleTypeParser pParserFunction, const int idx);

/**
 * @brief Parse an array of enumerated elements into the protocol tree.
 *
 * @param tree            The protocol tree to add items to.
 * @param tvb             The packet buffer.
 * @param pinfo           The packet info.
 * @param pOffset         The current offset into @p tvb; updated on return.
 * @param szFieldName     The name of the array field.
 * @param szTypeName      The name of the element type.
 * @param pParserFunction The parser function to call for each element.
 * @param idx             The ett index for the array subtree.
 */
void parseArrayEnum(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName, const char *szTypeName, fctEnumParser pParserFunction, const int idx);

/**
 * @brief Parse an array of complex-typed elements into the protocol tree.
 *
 * @param tree            The protocol tree to add items to.
 * @param tvb             The packet buffer.
 * @param pinfo           The packet info.
 * @param pOffset         The current offset into @p tvb; updated on return.
 * @param szFieldName     The name of the array field.
 * @param szTypeName      The name of the element type.
 * @param pParserFunction The parser function to call for each element.
 * @param idx             The ett index for the array subtree.
 */
void parseArrayComplex(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName, const char *szTypeName, fctComplexTypeParser pParserFunction, const int idx);

/**
 * @brief Register the OPC UA simple types with the dissector.
 *
 * @param proto The protocol handle to register types for.
 */
void registerSimpleTypes(int proto);

/**
 * @brief Read the type ID of an ExtensionObject without advancing the offset.
 *
 * @param tvb     The packet buffer.
 * @param pOffset The current offset into @p tvb.
 * @return The ExtensionObject type ID.
 */
uint32_t getExtensionObjectType(tvbuff_t *tvb, int *pOffset);

/**
 * @brief Parse a NodeClassMask field into the protocol tree.
 *
 * @param tree    The protocol tree to add items to.
 * @param tvb     The packet buffer.
 * @param pinfo   The packet info.
 * @param pOffset The current offset into @p tvb; updated on return.
 */
void parseNodeClassMask(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset);

/**
 * @brief Parse a ResultMask field into the protocol tree.
 *
 * @param tree    The protocol tree to add items to.
 * @param tvb     The packet buffer.
 * @param pinfo   The packet info.
 * @param pOffset The current offset into @p tvb; updated on return.
 */
void parseResultMask(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset);

/**
 * @brief Dispatch parsing of an ExtensionObject body to the appropriate
 * type-specific parser.
 *
 * @param tree    The protocol tree to add items to.
 * @param tvb     The packet buffer.
 * @param pinfo   The packet info.
 * @param pOffset The current offset into @p tvb; updated on return.
 * @param TypeId  The ExtensionObject type ID used to select the parser.
 */
void dispatchExtensionObjectType(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int TypeId);

#endif /* OPCUA_IDENTIFIERS_H */
