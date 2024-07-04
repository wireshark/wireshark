/* packet-cell_broadcast.h
 *
 * Copyright 2011, Mike Morrin <mike.morrin [AT] ipaccess.com>,
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CELL_BROADCAST_H
#define PACKET_CELL_BROADCAST_H


/**
 * Dissects the GSM/UMTS/SABP Message Identifier
 *
 * @param tvb the tv buffer of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 *
 * @return the offset after the Message Identifier
 */
unsigned dissect_cbs_message_identifier(tvbuff_t *tvb, proto_tree *tree, unsigned offset);


/**
 * Decodes the GSM/UMTS/SABP message Serial Number
 *
 * @param tvb the tv buffer of the current data
 * @param tree the tree to append this item to
 * @param offset the offset in the tvb
 *
 * @return the offset after the Serial Number
 */
unsigned dissect_cbs_serial_number(tvbuff_t *tvb, proto_tree *tree, unsigned offset);


/**
 * Dissects UMTS/SABP Cell Broadcast Message
 *
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param data parameter to pass to subdissector
 */
int dissect_umts_cell_broadcast_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

/**
 * Dissects CB Data
 */
tvbuff_t * dissect_cbs_data(uint8_t sms_encoding, tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, unsigned offset);

#endif /* PACKET_CELL_BROADCAST_H */
