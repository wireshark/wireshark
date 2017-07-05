/* xtea.c
 * Implementation of XTEA cipher
 * By Ahmad Fatoum <ahmad[AT]a3f.at>
 * Copyright 2017 Ahmad Fatoum
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <glib.h>
#include <string.h>

#include "pint.h"
#include "xtea.h"

void decrypt_xtea_ecb(guint8 output[8], const guint8 v_in[8], const guint32 key[4], guint num_rounds)
{
    guint i;
    guint32 v[2], delta = 0x9E3779B9, sum = delta * num_rounds;

    v[0] = pntoh32(&v_in[0]);
    v[1] = pntoh32(&v_in[4]);

    for (i = 0; i < num_rounds; i++) {
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3]);
    }

    v[0] = GUINT32_TO_BE(v[0]);
    v[1] = GUINT32_TO_BE(v[1]);

    memcpy(output, v, sizeof v);
}

void decrypt_xtea_le_ecb(guint8 output[8], const guint8 v_in[8], const guint32 key[4], guint num_rounds)
{
    guint i;
    guint32 v[2], delta = 0x9E3779B9, sum = delta * num_rounds;

    v[0] = pletoh32(&v_in[0]);
    v[1] = pletoh32(&v_in[4]);

    for (i = 0; i < num_rounds; i++) {
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3]);
    }

    v[0] = GUINT32_TO_LE(v[0]);
    v[1] = GUINT32_TO_LE(v[1]);

    memcpy(output, v, sizeof v);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
