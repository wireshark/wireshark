/* xtea.c
 * Implementation of XTEA cipher
 * By Ahmad Fatoum <ahmad[AT]a3f.at>
 * Copyright 2017 Ahmad Fatoum
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <string.h>

#include "pint.h"
#include "xtea.h"

void decrypt_xtea_ecb(guint8 plaintext[8], const guint8 ciphertext[8], const guint32 key[4], guint num_rounds)
{
    guint i;
    guint32 v[2], delta = 0x9E3779B9, sum = delta * num_rounds;

    v[0] = pntoh32(&ciphertext[0]);
    v[1] = pntoh32(&ciphertext[4]);

    for (i = 0; i < num_rounds; i++) {
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3]);
    }

    v[0] = GUINT32_TO_BE(v[0]);
    v[1] = GUINT32_TO_BE(v[1]);

    memcpy(plaintext, v, sizeof v);
}

void decrypt_xtea_le_ecb(guint8 plaintext[8], const guint8 ciphertext[8], const guint32 key[4], guint num_rounds)
{
    guint i;
    guint32 v[2], delta = 0x9E3779B9, sum = delta * num_rounds;

    v[0] = pletoh32(&ciphertext[0]);
    v[1] = pletoh32(&ciphertext[4]);

    for (i = 0; i < num_rounds; i++) {
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3]);
    }

    v[0] = GUINT32_TO_LE(v[0]);
    v[1] = GUINT32_TO_LE(v[1]);

    memcpy(plaintext, v, sizeof v);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
