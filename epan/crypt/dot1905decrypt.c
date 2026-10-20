/* dot1905decrypt.c
 *
 * AES SIV (RFC 5297)
 * Copyright (c) 2013 Cozybit, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Code originates from hostap project and is modified to use gcrypt
 */

#include <stdbool.h>

#include <glib.h>
#include <gcrypt.h>

#include "dot1905decrypt.h"

#define AES_BLOCK_SIZE 16
#define MAX_PARAMS 8

static const uint8_t zero[AES_BLOCK_SIZE];

static void dbl(uint8_t *pad)
{
    int i, carry;

    carry = pad[0] & 0x80;
    for (i = 0; i < AES_BLOCK_SIZE - 1; i++) {
        pad[i] = (pad[i] << 1) | (pad[i + 1] >> 7);
    }

    pad[AES_BLOCK_SIZE - 1] <<= 1;

    if (carry) {
        pad[AES_BLOCK_SIZE - 1] ^= 0x87;
    }
}

static void xor(uint8_t *a, const uint8_t *b)
{
    int i;

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        *a++ ^= *b++;
    }
}

static void xorend(uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    size_t i;

    if (alen < blen) {
        return;
    }

    for (i = 0; i < blen; i++) {
        a[alen - blen + i] ^= b[i];
    }
}

static void pad_block(uint8_t *pad, const uint8_t *addr, size_t len)
{
    memset(pad, 0, AES_BLOCK_SIZE);
    memcpy(pad, addr, len);

    if (len < AES_BLOCK_SIZE) {
        pad[len] = 0x80;
    }
}

static void bin_clear_free(void *bin, size_t len)
{
    if (bin) {
        memset(bin, 0, len);
        g_free(bin);
    }
}

static bool gcrypt_init(void)
{
    return gcry_check_version(GCRYPT_VERSION) != NULL;
}

static int omac1_aes_vector(const uint8_t *key, size_t key_len, size_t num_elem,
                            const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
    int ret = -1;
    gcry_mac_hd_t hd = NULL;
    size_t outlen = AES_BLOCK_SIZE, i;

    if ((key_len != 16 && key_len != 32) || !gcrypt_init()) {
        return -1;
    }

    if (gcry_mac_open(&hd, GCRY_MAC_CMAC_AES, 0, NULL)) {
        return -1;
    }

    if (gcry_mac_setkey(hd, key, key_len)) {
        goto fail;
    }
    for (i = 0; i < num_elem; i++) {
        if (gcry_mac_write(hd, addr[i], len[i])) {
            goto fail;
        }
    }
    if (gcry_mac_read(hd, mac, &outlen) || outlen != AES_BLOCK_SIZE) {
        goto fail;
    }

    ret = 0;
fail:
    gcry_mac_close(hd);
    return ret;
}

static void *memdup(const void *src, size_t len)
{
    void *r = g_malloc0(len);

    if (r && src) {
        memcpy(r, src, len);
    }
    return r;
}

static int aes_s2v(const uint8_t *key, size_t key_len, size_t num_elem, const uint8_t *addr[], size_t *len, uint8_t *mac)
{
    int ret;
    size_t i;
    uint8_t tmp[AES_BLOCK_SIZE]  = {0};
    uint8_t tmp2[AES_BLOCK_SIZE] = {0};
    uint8_t *buf                 = NULL;
    const uint8_t *data[1]       = {0};
    size_t data_len[1]           = {0};

    if (!num_elem) {
        memcpy(tmp, zero, sizeof(zero));
        tmp[AES_BLOCK_SIZE - 1] = 1;
        data[0] = tmp;
        data_len[0] = sizeof(tmp);
        return omac1_aes_vector(key, key_len, 1, data, data_len, mac);
    }

    data[0] = zero;
    data_len[0] = sizeof(zero);
    ret = omac1_aes_vector(key, key_len, 1, data, data_len, tmp);
    if (ret) {
        return ret;
    }

    for (i = 0; i < num_elem - 1; i++) {
        ret = omac1_aes_vector(key, key_len, 1, &addr[i], &len[i], tmp2);
        if (ret) {
            return ret;
        }

        dbl(tmp);
        xor(tmp, tmp2);
    }
    if (len[i] >= AES_BLOCK_SIZE) {
        buf = memdup(addr[i], len[i]);
        if (!buf) {
            return -ENOMEM;
        }

        xorend(buf, len[i], tmp, AES_BLOCK_SIZE);
        data[0] = buf;
        ret = omac1_aes_vector(key, key_len, 1, data, &len[i], mac);
        bin_clear_free(buf, len[i]);
        return ret;
    }

    dbl(tmp);
    pad_block(tmp2, addr[i], len[i]);
    xor(tmp, tmp2);

    data[0] = tmp;
    data_len[0] = sizeof(tmp);
    return omac1_aes_vector(key, key_len, 1, data, data_len, mac);
}

static int aes_ctr_encrypt(const uint8_t *key, size_t key_len, const uint8_t *nonce, uint8_t *data, size_t data_len)
{
    gcry_cipher_hd_t hd = NULL;
    int algo, ret = -1;

    switch (key_len) {
        case 16: algo = GCRY_CIPHER_AES128; break;
        case 24: algo = GCRY_CIPHER_AES192; break;
        case 32: algo = GCRY_CIPHER_AES256; break;
        default: return -1;
    }

    if (!gcrypt_init() || gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CTR, 0)) {
        return -1;
    }

    if (!gcry_cipher_setkey(hd, key, key_len) &&
        !gcry_cipher_setctr(hd, nonce, AES_BLOCK_SIZE) &&
        !gcry_cipher_encrypt(hd, data, data_len, NULL, 0)) {
        ret = 0;
    }

    gcry_cipher_close(hd);
    return ret;
}

int Dot1905DecryptGetDecryptLength(size_t data_len, size_t *out_len)
{
    if (data_len < AES_BLOCK_SIZE) {
        return -1;
    }

    *out_len = data_len - AES_BLOCK_SIZE;

    return 0;
}

int Dot1905DecryptDecrypt(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                          size_t num_params, const uint8_t *params[], const size_t *params_lens, uint8_t *out)
{
    const uint8_t *_params[MAX_PARAMS + 1] = {0};
    uint8_t iv[AES_BLOCK_SIZE]             = {0};
    uint8_t check[AES_BLOCK_SIZE]          = {0};
    size_t _params_lens[MAX_PARAMS + 1]    = {0};
    const uint8_t *k1                      = NULL;
    const uint8_t *k2                      = NULL;
    size_t i = 0, crypt_len = 0;

    if (data_len < AES_BLOCK_SIZE ||
        num_params > MAX_PARAMS ||
        key_len != DOT1905DECRYPT_KEY_LEN) {
        return -1;
    }

    crypt_len = data_len - AES_BLOCK_SIZE;
    key_len /= 2;
    k1 = key;
    k2 = key + key_len;

    for (i = 0; i < num_params; i++) {
        _params[i] = params[i];
        _params_lens[i] = params_lens[i];
    }
    _params[num_params] = out;
    _params_lens[num_params] = crypt_len;

    memcpy(iv, data, AES_BLOCK_SIZE);
    memcpy(out, data + AES_BLOCK_SIZE, crypt_len);

    iv[8] &= 0x7f;
    iv[12] &= 0x7f;

    if (aes_ctr_encrypt(k2, key_len, iv, out, crypt_len)) {
        return -1;
    }

    if (aes_s2v(k1, key_len, num_params + 1, _params, _params_lens, check)) {
        return -1;
    }

    if (memcmp(check, data, AES_BLOCK_SIZE) != 0) {
        return -1;
    }

    return 0;
}
