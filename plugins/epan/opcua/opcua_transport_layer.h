/******************************************************************************
** Copyright (C) 2006-2009 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** SPDX-License-Identifier: GPL-2.0-or-later
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** Project: OpcUa Wireshark Plugin
**
** Description: OpcUa Transport Layer Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/

/* This struct is used to pass meta data down to decoding functions. */
struct ua_metadata {
    bool encrypted; /* true if payload is encrypted, false if no encryption was used or it was successfully decrypted. */
};

extern int g_opcua_default_sig_len;

/* Transport Layer: message parsers */

/**
 * @brief Parse the OPC UA Hello message.
 *
 * @param tree    Pointer to the protocol tree where the parsed data will be added.
 * @param tvb     Pointer to the TVB containing the packet data.
 * @param pinfo   Pointer to the packet info structure.
 * @param pOffset Pointer to the current offset within the TVB.
 * @param data    Pointer to the metadata structure containing additional
 *                information about the message.
 * @return 0 on success, -1 on failure.
 */
int parseHello(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse the OPC UA Acknowledge message.
 *
 * @param tree    Pointer to the protocol tree where the parsed data will be added.
 * @param tvb     Pointer to the TVB containing the packet data.
 * @param pinfo   Pointer to the packet info structure.
 * @param pOffset Pointer to the current offset within the TVB.
 * @param data    Pointer to the metadata structure containing additional
 *                information about the message.
 * @return 0 on success, -1 on failure.
 */
int parseAcknowledge(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse the OPC UA Error message.
 *
 * @param tree    Pointer to the protocol tree where the parsed data will be added.
 * @param tvb     Pointer to the TVB containing the packet data.
 * @param pinfo   Pointer to the packet info structure.
 * @param pOffset Pointer to the current offset within the TVB.
 * @param data    Pointer to the metadata structure containing additional
 *                information about the message.
 * @return 0 on success, -1 on failure.
 */
int parseError(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse the OPC UA ReverseHello message.
 *
 * @param tree    Pointer to the protocol tree where the parsed data will be added.
 * @param tvb     Pointer to the TVB containing the packet data.
 * @param pinfo   Pointer to the packet info structure.
 * @param pOffset Pointer to the current offset within the TVB.
 * @param data    Pointer to the metadata structure containing additional
 *                information about the message.
 * @return 0 on success, -1 on failure.
 */
int parseReverseHello(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse an OPC UA Message.
 *
 * @param tree    Pointer to the protocol tree where the parsed data will be added.
 * @param tvb     Pointer to the TVB containing the packet data.
 * @param pinfo   Pointer to the packet info structure.
 * @param pOffset Pointer to the current offset within the TVB.
 * @param data    Pointer to the metadata structure containing additional
 *                information about the message.
 * @return 0 on success, -1 on failure.
 */
int parseMessage(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse the OPC UA Abort message.
 *
 * @param tree    Pointer to the protocol tree where the parsed data will be added.
 * @param tvb     Pointer to the TVB containing the packet data.
 * @param pinfo   Pointer to the packet info structure.
 * @param pOffset Pointer to the current offset within the TVB.
 * @param data    Pointer to the metadata structure containing additional
 *                information about the message.
 * @return 0 on success, -1 on failure.
 */
int parseAbort(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse an OPC UA service payload.
 *
 * @param tree    Pointer to the protocol tree where the parsed data will be added.
 * @param tvb     Pointer to the TVB containing the packet data.
 * @param pinfo   Pointer to the packet info structure.
 * @param pOffset Pointer to the current offset within the TVB.
 * @param data    Pointer to the metadata structure containing additional
 *                information about the message.
 * @return 0 on success, -1 on failure.
 */
int parseService(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse the OPC UA OpenSecureChannel message.
 *
 * @param tree    Pointer to the protocol tree where the parsed data will be added.
 * @param tvb     Pointer to the TVB containing the packet data.
 * @param pinfo   Pointer to the packet info structure.
 * @param pOffset Pointer to the current offset within the TVB.
 * @param data    Pointer to the metadata structure containing additional
 *                information about the message.
 * @return 0 on success, -1 on failure.
 */
int parseOpenSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

/**
 * @brief Parse the OPC UA CloseSecureChannel message.
 *
 * @param tree    Pointer to the protocol tree where the parsed data will be added.
 * @param tvb     Pointer to the TVB containing the packet data.
 * @param pinfo   Pointer to the packet info structure.
 * @param pOffset Pointer to the current offset within the TVB.
 * @param data    Pointer to the metadata structure containing additional
 *                information about the message.
 * @return 0 on success, -1 on failure.
 */
int parseCloseSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);

/**
 * @brief Register the OPC UA transport layer types with the dissector.
 *
 * @param proto The protocol handle to register types for.
 */
void registerTransportLayerTypes(int proto);


/*
 * The per-conversation encryption information is stored in a pointer
 * value; here are functions to construct the pointer value, as a
 * uintptr_t and extract values from the pointer value.
 */
#include "opcua_simpletypes.h"

/**
 * @brief Pack a message mode and signature length into an opaque pointer value.
 *
 * @param mode    The OPC UA message mode.
 * @param sig_len The signature length in bytes.
 * @return The packed pointer value encoding both fields.
 */
static inline uintptr_t
construct_encryption_info(enum ua_message_mode mode, uint8_t sig_len)
{
    return ((uintptr_t)sig_len << 8) | (uintptr_t)mode;
}

/**
 * @brief Extract the message mode from a packed encryption info value.
 *
 * @param data The packed pointer value from @c construct_encryption_info.
 * @return The OPC UA message mode.
 */
static inline enum ua_message_mode
extract_message_mode(uintptr_t data)
{
    return (enum ua_message_mode)(data & 0xff);
}

/**
 * @brief Extract the signature length from a packed encryption info value.
 *
 * @param data The packed pointer value from @c construct_encryption_info.
 * @return The signature length in bytes.
 */
static inline uint8_t
extract_signature_length(uintptr_t data)
{
    return (uint8_t)(data >> 8);
}

/**
 * @brief Store encryption information for the current TCP conversation.
 *
 * @param pinfo   Pointer to the packet info structure.
 * @param mode    The OPC UA message mode.
 * @param sig_len The signature length in bytes.
 */
void store_encryption_info(packet_info *pinfo, enum ua_message_mode mode, uint8_t sig_len);

/**
 * @brief Retrieve encryption information for the current TCP conversation.
 *
 * @param pinfo   Pointer to the packet info structure.
 * @param mode    Output pointer for the OPC UA message mode.
 * @param sig_len Output pointer for the signature length in bytes.
 */
void get_encryption_info(packet_info *pinfo, enum ua_message_mode *mode, uint8_t *sig_len);