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

/* Transport Layer: message parsers */
int parseHello(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);
int parseAcknowledge(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);
int parseError(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);
int parseReverseHello(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);
int parseMessage(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);
int parseAbort(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);
int parseService(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);
int parseOpenSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);
int parseCloseSecureChannel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset);
void registerTransportLayerTypes(int proto);
