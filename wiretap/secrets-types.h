/** @file
 *
 * Identifiers used by Decryption Secrets Blocks (DSB).
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SECRETS_TYPES_H__
#define __SECRETS_TYPES_H__

/*
 * Type describing the format of the opaque secrets value in a pcapng DSB.
 */
#define SECRETS_TYPE_TLS            0x544c534b /* TLS Key Log */
#define SECRETS_TYPE_WIREGUARD      0x57474b4c /* WireGuard Key Log */
#define SECRETS_TYPE_ZIGBEE_NWK_KEY 0x5a4e574b /* Zigbee NWK Key */
#define SECRETS_TYPE_ZIGBEE_APS_KEY 0x5a415053 /* Zigbee APS Key */

#endif /* __SECRETS_TYPES_H__ */
