/* wimax_tlv.h
 * WiMax TLV handling function header file
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _WIMAX_TLV_H_
#define _WIMAX_TLV_H_

#include <epan/packet.h>

#define	WIMAX_TLV_EXTENDED_LENGTH_MASK 0x80
#define	WIMAX_TLV_LENGTH_MASK          0x7F

#define MAX_TLV_LEN 64000

/**
 * @brief Describes the parsed layout of a single TLV (Type-Length-Value) field.
 */
typedef struct
{
    uint8_t  valid;          /**< Validity flag for this TLV entry: 0 = invalid, 1 = valid. */
    uint8_t  type;           /**< TLV type identifier. */
    uint8_t  length_type;    /**< Encoding of the length field: 0 = single byte, 1 = multi-byte. */
    uint8_t  size_of_length; /**< Number of bytes used to encode the TLV length field. */
    unsigned value_offset;   /**< Byte offset to the start of the TLV value field within the enclosing buffer. */
    int32_t  length;         /**< Length in bytes of the TLV value field. */
} tlv_info_t;

/**
 * @brief Initialize TLV information.
 *
 * @param info Pointer to tlv_info_t structure to be initialized.
 * @param tvb Pointer to tvbuff_t containing the data.
 * @param offset Offset within the tvbuff_t where the TLV starts.
 * @return 0 on success, -1 on failure.
 */
int    init_tlv_info(tlv_info_t *info, tvbuff_t *tvb, int offset);

/**
 * @brief Check if the TLV information is valid.
 *
 * @param info Pointer to tlv_info_t structure to be checked.
 * @return 0 if valid, -1 otherwise.
 */
int    valid_tlv_info(tlv_info_t *info);

/**
 * @brief Get the type of a WiMax TLV.
 *
 * @param info Pointer to the tlv_info_t structure containing TLV information.
 * @return int The type of the TLV if valid, otherwise -1.
 */
int    get_tlv_type(tlv_info_t *info);

/**
* @brief Get the length type of a WiMax TLV.
*
* @param info Pointer to the tlv_info_t structure containing TLV information.
* @return int The length type if valid, otherwise -1.
*/
int    get_tlv_length_type(tlv_info_t *info);

/**
 * @brief Get the size of the length field for a TLV.
 *
 * @param info Pointer to the tlv_info_t structure containing TLV information.
 * @return int The size of the length field if valid, otherwise -1.
 */
int    get_tlv_size_of_length(tlv_info_t *info);

/**
 * @brief Get the offset of the TLV value field.
 *
 * @param info Pointer to the tlv_info_t structure containing TLV information.
 * @return int The offset of the TLV value field if valid, otherwise -1.
 */
int    get_tlv_value_offset(tlv_info_t *info);

/**
 * @brief Get the length of the TLV value field.
 *
 * @param info Pointer to the tlv_info_t structure containing TLV information.
 * @return int The length of the TLV value field if valid, otherwise -1.
 */
int32_t get_tlv_length(tlv_info_t *info);

/**
 * @brief Adds a protocol subtree for a WiMax TLV and returns the associated proto_item.
 *
 * @param info Pointer to the tlv_info_t structure containing TLV information.
 * @param tree Parent protocol tree.
 * @param hfindex Field ID for the TLV value field.
 * @param tvb TV buffer containing the packet data.
 * @param start Start offset of the TLV in the TV buffer.
 * @param encoding Encoding type for displaying the TLV value.
 * @return Pointer to the created proto_item for the TLV subtree, or NULL on failure.
 */
proto_item *add_tlv_subtree(tlv_info_t *info, proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, const unsigned encoding);

/**
 * @brief Adds a protocol subtree for a WiMax TLV without creating a proto_item for the subtree.
 *
 * @param info Pointer to the tlv_info_t structure containing TLV information.
 * @param tree Parent protocol tree.
 * @param hfindex Field ID for the TLV value field.
 * @param tvb TV buffer containing the packet data.
 * @param start Start offset of the TLV in the TV buffer.
 * @return Pointer to the created protocol subtree, or NULL on failure.
 */
proto_tree *add_tlv_subtree_no_item(tlv_info_t *info, proto_tree *tree, int hfindex, tvbuff_t *tvb, int start);

/**
 * @brief Adds a protocol subtree for a WiMax TLV.
 *
 * @param info Pointer to the tlv_info_t structure containing TLV information.
 * @param idx Index of the TLV within the packet.
 * @param tree Parent protocol tree.
 * @param hfindex Field ID for the TLV value field.
 * @param tvb TV buffer containing the packet data.
 * @param start Start offset of the TLV in the TV buffer.
 * @param length Length of the TLV in the TV buffer.
 * @param label Label for the subtree.
 * @return Pointer to the newly created protocol subtree.
 */
proto_tree *add_protocol_subtree(tlv_info_t *info, int idx, proto_tree *tree, int hfindex, tvbuff_t *tvb, int start, int length, const char *label);

#endif /* WIMAX_TLV_H */
