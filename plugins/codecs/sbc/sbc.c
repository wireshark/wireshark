/* sbc.c
 * Support for external Bluetooth SBC codec
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wireshark.h>
#include <sbc/sbc.h>

#include "wsutil/codecs.h"

#define SBC_BUFFER 8192

void codec_register_sbc(void);

static void *
codec_sbc_init(codec_context_t *ctx _U_)
{
    sbc_t *sbc;

    sbc = g_new(sbc_t, 1);
    sbc_init(sbc, 0L);

    return sbc;
}

static void
codec_sbc_release(codec_context_t *ctx)
{
    sbc_t *sbc = (sbc_t *) ctx->priv;

    sbc_finish(sbc);
    g_free(sbc);
}

static unsigned
codec_sbc_get_channels(codec_context_t *ctx)
{
    sbc_t *sbc = (sbc_t *) ctx->priv;
    if (sbc->mode == SBC_MODE_MONO)
        return 1;

    return 2;
}

static unsigned
codec_sbc_get_frequency(codec_context_t *ctx)
{
    sbc_t *sbc = (sbc_t *) ctx->priv;
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

static size_t
codec_sbc_decode(codec_context_t *ctx,
        const void *input, size_t inputSizeBytes,
        void *output, size_t *outputSizeBytes)
{
    size_t         size_in = (size_t) inputSizeBytes;
    size_t         size_out = SBC_BUFFER;
    size_t         len;
    size_t         framelen;
    size_t         xframe_pos = 0;
    const uint8_t *data_in  = (const uint8_t *) input;
    uint8_t       *data_out = (uint8_t *) output;
    sbc_t         *sbc = (sbc_t *) ctx->priv;
    uint8_t       *i_data;
    uint8_t        tmp;

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

void
codec_register_sbc(void)
{
    register_codec("SBC", codec_sbc_init, codec_sbc_release,
            codec_sbc_get_channels, codec_sbc_get_frequency, codec_sbc_decode);
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
