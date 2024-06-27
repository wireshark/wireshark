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
int parseHello(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);
int parseAcknowledge(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);
int parseError(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);
int parseReverseHello(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);
int parseMessage(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);
int parseAbort(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);
int parseService(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);
int parseOpenSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);
int parseCloseSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, struct ua_metadata *data);
void registerTransportLayerTypes(int proto);

enum ua_message_mode;
void store_encryption_info(packet_info *pinfo, enum ua_message_mode mode, uint8_t sig_len);
void get_encryption_info(packet_info *pinfo, enum ua_message_mode *mode, uint8_t *sig_len);
