/******************************************************************************
** Copyright (C) 2006-2023 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** SPDX-License-Identifier: GPL-2.0-or-later
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** Project: OpcUa Wireshark Plugin
**
** Description: OpcUa Protocol Decoder.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
******************************************************************************/

#ifndef __OPCUA_KEYSET_H__
#define __OPCUA_KEYSET_H__

#include <stdint.h>

/** symmetric encryption keyset */
struct ua_keyset {
    uint64_t id; /** keyset identifier: combination of securechannel_id and token_id */
    unsigned char client_iv[16]; /**< Client side IV. Always 128 bit. */
    unsigned char server_iv[16]; /**< Server side IV. Always 128 bit. */
    unsigned char client_key[32]; /**< client encryption key */
    unsigned char server_key[32]; /**< server encryption key */
    unsigned int client_key_len; /**< AES key length: 16 (AES-128) or 32 (AES-256) */
    unsigned int server_key_len; /**< AES key length: 16 (AES-128) or 32 (AES-256) */
    unsigned int client_sig_len; /**< Client side symmetric signature length. */
    unsigned int server_sig_len; /**< Server side symmetric signature length. */
};

int ua_keysets_init(void);
int ua_keysets_clear(void);

/**
 * Creates a unique keyset id from securechannel_id and token_id.
 *
 * @param securechannel_id Identifies the secure channel to be able to distinguish
 *   different connections. This is a randomly generated id.
 * @param token_id Identifies the keyset of a channel. This number normally starts with
 *   1 and gets incremented with every secure channel renew.
 *
 * @return 64bit Id.
 */
static inline uint64_t ua_keyset_id(uint32_t securechannel_id, uint32_t token_id)
{
    return ((uint64_t)securechannel_id << 32) | token_id;
}

struct ua_keyset *ua_keysets_add(void);
void ua_keysets_sort(void);
struct ua_keyset *ua_keysets_lookup(uint64_t id);
void ua_keysets_dump(void);

#endif /* __OPCUA_KEYSET_H__ */

