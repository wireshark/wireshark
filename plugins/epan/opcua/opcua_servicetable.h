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
** Description: Service table and service dispatcher.
**
******************************************************************************/

void dispatchService(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint *pOffset, int ServiceId);

