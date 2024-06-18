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

void registerSecurityLayerTypes(int proto);
void registerSequenceLayerTypes(int proto);
void parseSecurityHeader(proto_tree *tree, tvbuff_t *tvb, int *pOffset, struct ua_metadata *data);
void parseSequenceHeader(proto_tree *tree, tvbuff_t *tvb, int *pOffset, struct ua_metadata *data);
void parseSecurityFooterSO(proto_tree *tree, tvbuff_t *tvb, int offset, unsigned sig_len);
void parseSecurityFooterSAE(proto_tree *tree, tvbuff_t *tvb, int offset, unsigned pad_len, unsigned sig_len);
