/* dot1905mic.c
 *
 * Ieee1905 MIC derivation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define DOT1905MIC_KEY_LEN  32
#define DOT1905MIC_HASH_LEN 32

int Dot1905MICDerive(const uint8_t *key, size_t keylen, const uint8_t *data, size_t data_len, uint8_t *hash);

#ifdef  __cplusplus
}
#endif
