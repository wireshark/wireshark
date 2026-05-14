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
** Description: OpcUa Security Layer Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/

struct ua_metadata;

/**
 * @brief Register security layer types.
 *
 * @param proto Protocol identifier
 */
void registerSecurityLayerTypes(int proto);
/**
 * @brief Register the OPC UA sequence layer types with the dissector.
 *
 * @param proto The protocol handle to register types for.
 */
void registerSequenceLayerTypes(int proto);

/**
 * @brief Parse the security header into the protocol tree.
 *
 * @param tree    The protocol tree to add items to.
 * @param tvb     The packet buffer.
 * @param pOffset The current offset into @p tvb; updated on return.
 * @param data    The UA metadata for the current message.
 */
void parseSecurityHeader(proto_tree *tree, tvbuff_t *tvb, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse the sequence header into the protocol tree.
 *
 * @param tree    The protocol tree to add items to.
 * @param tvb     The packet buffer.
 * @param pOffset The current offset into @p tvb; updated on return.
 * @param data    The UA metadata for the current message.
 */
void parseSequenceHeader(proto_tree *tree, tvbuff_t *tvb, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse the security footer of a SignOnly message into the protocol tree.
 *
 * @param tree    The protocol tree to add items to.
 * @param tvb     The packet buffer.
 * @param offset  The offset of the security footer within @p tvb.
 * @param sig_len The length of the signature in bytes.
 */
void parseSecurityFooterSO(proto_tree *tree, tvbuff_t *tvb, int offset, unsigned sig_len);

/**
 * @brief Parse the security footer of a SignAndEncrypt message into the
 * protocol tree.
 *
 * @param tree    The protocol tree to add items to.
 * @param tvb     The packet buffer.
 * @param offset  The offset of the security footer within @p tvb.
 * @param pad_len The length of the padding in bytes.
 * @param sig_len The length of the signature in bytes.
 */
void parseSecurityFooterSAE(proto_tree *tree, tvbuff_t *tvb, int offset, unsigned pad_len, unsigned sig_len);
