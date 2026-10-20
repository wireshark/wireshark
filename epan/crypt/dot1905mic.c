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

#include <gcrypt.h>

#include "dot1905mic.h"

int Dot1905MICDerive(const uint8_t *key, size_t keylen, const uint8_t *data, size_t data_len, uint8_t *hash)
{
    gcry_md_hd_t  hd;
    uint8_t      *digest;

    if (!gcry_check_version(GCRYPT_VERSION)) {
        return -1;
    }

    if (gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC) != 0) {
        return -1;
    }

    if (gcry_md_setkey(hd, key, keylen) != 0) {
        gcry_md_close(hd);
        return -1;
    }

    gcry_md_write(hd, data, data_len);

    digest = gcry_md_read(hd, GCRY_MD_SHA256);
    if (!digest) {
        gcry_md_close(hd);
        return -1;
    }

    memcpy(hash, digest, DOT1905MIC_HASH_LEN);
    gcry_md_close(hd);

    return 0;
}
