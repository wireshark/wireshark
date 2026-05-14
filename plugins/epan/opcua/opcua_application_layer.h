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
** Description: OpcUa Application Layer Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/

/**
 * @brief Registers the types for the OPC UA application layer.
 *
 * @param proto The protocol identifier.
 */
void registerApplicationLayerTypes(int proto);

/* Ua type parsers */
/**
 * @brief Decodes the service nodeid without modifying the tree or offset.
 * Service NodeIds are always numeric
 * @param tvb The tvb containing the data.
 * @param offset offset of data in the buffer.
 * @return The numeric value of the NodeId, or 0 on failure.
 */
int getServiceNodeId(tvbuff_t *tvb, int offset);

/**
 * @brief Parses a NodeId from the buffer and adds it to the protocol tree.
 *
 * Parses an OpcUa Service NodeId and returns the service type.
 * In this cases the NodeId is always from type numeric and NSId = 0.
 *
 * @param tree The protocol tree to add the parsed items to.
 * @param tvb The input buffer containing the data.
 * @param pOffset Pointer to the current offset in the buffer; this will be updated to point to the next position after parsing.
 * @return The numeric value of the NodeId, or 0 on failure.
 */
int parseServiceNodeId(proto_tree *tree, tvbuff_t *tvb, int *pOffset);
