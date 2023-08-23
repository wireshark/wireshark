/* packet-zbee-direct.h
 * Dissector routines for the ZigBee Direct
 * Copyright 2021 DSR Corporation, http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ZB_DIRECT_H
#define PACKET_ZB_DIRECT_H

#define ZB_DIRECT_JOINED_STATUS_NO_NWK            0
#define ZB_DIRECT_JOINED_STATUS_JOINING           1
#define ZB_DIRECT_JOINED_STATUS_JOINED            2
#define ZB_DIRECT_JOINED_STATUS_JOINED_NO_PARENT  3
#define ZB_DIRECT_JOINED_STATUS_LEAVING           4

/* ZB Direct local Message IDs */
enum
{
    ZB_DIRECT_MSG_ID_FORMATION,
    ZB_DIRECT_MSG_ID_LEAVE,
    ZB_DIRECT_MSG_ID_JOIN,
    ZB_DIRECT_MSG_ID_PERMIT_JOIN,
    ZB_DIRECT_MSG_ID_STATUS,
    ZB_DIRECT_MSG_ID_MANAGE_JOINERS,
    ZB_DIRECT_MSG_ID_IDENTIFY,
    ZB_DIRECT_MSG_ID_FINDING_BINDING,
    ZB_DIRECT_MSG_ID_TUNNELING,
    ZB_DIRECT_MSG_ID_SECUR_C25519_AESMMO,
    ZB_DIRECT_MSG_ID_SECUR_C25519_SHA256,
    ZB_DIRECT_MSG_ID_SECUR_P256
};

#endif
