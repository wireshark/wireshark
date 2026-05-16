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

extern const value_string g_requesttypes[];

/**
 * @brief Dispatches an OPC UA service based on the ServiceId.
 *
 * @param tree Protocol tree to which the dissection results will be added.
 * @param tvb The TVB buffer containing the packet data.
 * @param pinfo Packet information structure.
 * @param pOffset Pointer to the current offset within the TVB buffer.
 * @param ServiceId ID of the service to dispatch.
 */
void dispatchService(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int ServiceId);

