/* secrets-types.h
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
#define SECRETS_TYPE_TLS        0x544c534b /* TLS Key Log */
#define SECRETS_TYPE_WIREGUARD  0x57474b4c /* WireGuard Key Log */

#endif /* __SECRETS_TYPES_H__ */
