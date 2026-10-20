/* dot1905decrypt.c
 *
 * AES SIV (RFC 5297)
 * Copyright (c) 2013 Cozybit, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Code originates from hostap project and is modified to use gcrypt
 */

#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define DOT1905DECRYPT_KEY_LEN 32

int Dot1905DecryptGetDecryptLength(size_t data_len, size_t *out_len);

int Dot1905DecryptDecrypt(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                          size_t num_params, const uint8_t *params[], const size_t *params_lens, uint8_t *out);

#ifdef  __cplusplus
}
#endif
