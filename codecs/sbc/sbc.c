/* sbc.c
 * Support for external Bluetooth SBC codec
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
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
 */

#include "config.h"

#ifdef HAVE_SBC

#include <glib.h>
#include <sbc/sbc.h>

#include "sbc_private.h"

#define SBC_BUFFER 8192

void *
codec_sbc_init(void)
{
    sbc_t *sbc;

    sbc = (sbc_t *) g_malloc(sizeof(sbc_t));
    sbc_init(sbc, 0L);

    return sbc;
}

void
codec_sbc_release(void *ctx)
{
    sbc_t *sbc = (sbc_t *) ctx;

    sbc_finish(sbc);
    g_free(sbc);
}

unsigned
codec_sbc_get_channels(void *ctx)
{
    sbc_t *sbc = (sbc_t *) ctx;
    if (sbc->mode == SBC_MODE_MONO)
        return 1;

    return 2;
}

unsigned
codec_sbc_get_frequency(void *ctx)
{
    sbc_t *sbc = (sbc_t *) ctx;
    int frequency;

    switch (sbc->frequency) {
    case SBC_FREQ_16000:
        frequency = 16000;
        break;

    case SBC_FREQ_32000:
        frequency = 32000;
        break;

    case SBC_FREQ_44100:
        frequency = 44100;
        break;

    case SBC_FREQ_48000:
        frequency = 48000;
        break;
    default:
        frequency = 0;
    }

    return frequency;
}

size_t
codec_sbc_decode(void *ctx, const void *input, size_t inputSizeBytes, void *output,
        size_t *outputSizeBytes)
{
    size_t         size_in = (size_t) inputSizeBytes;
    size_t         size_out = SBC_BUFFER;
    size_t         len;
    size_t         framelen;
    size_t         xframe_pos = 0;
    const guint8  *data_in  = (const guint8 *) input;
    guint8        *data_out = (guint8 *) output;
    sbc_t         *sbc = (sbc_t *) ctx;
    guint8        *i_data;
    guint8         tmp;

    if (!output || !outputSizeBytes) {
        return size_out;
    }

    sbc->endian = SBC_BE;

    *outputSizeBytes = 0;
    while (xframe_pos < inputSizeBytes) {
        framelen = sbc_decode(sbc, data_in, size_in, data_out, size_out, &len);
        xframe_pos += framelen;
        data_in += framelen;
        *outputSizeBytes += len;

        for (i_data = data_out; i_data < data_out + len; i_data += 2) {
                tmp = i_data[0];
                i_data[0] = i_data[1];
                i_data[1] = tmp;
        }

        data_out += len;
    }

    return *outputSizeBytes;
}

#endif

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
