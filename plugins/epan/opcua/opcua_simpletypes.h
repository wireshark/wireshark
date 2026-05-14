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
