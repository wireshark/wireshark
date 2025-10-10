/* l24decode.c
 * 24-bit audio, mono codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include <string.h>

#include "wsutil/codecs.h"
#include "ws_attributes.h"

#pragma pack(push, 1)
typedef struct {
    int16_t sample16;
    uint8_t extra;
} sample24_t;
#pragma pack(pop)

void codec_register_l24(void);

static void *
codec_l24_init(codec_context_t *ctx _U_)
{
    return NULL;
}

static void *
codec_l24_mono_init(codec_context_t *ctx)
{
    ctx->sample_rate = 44100;
    ctx->channels = 1;
    return NULL;
}

static void *
codec_l24_stereo_init(codec_context_t *ctx)
{
    ctx->sample_rate = 44100;
    /* In practice, we will downmix to mono. */
    ctx->channels = 2;
    return NULL;
}

static void
codec_l24_release(codec_context_t *ctx _U_)
{

}

static unsigned
codec_l24_get_channels(codec_context_t *ctx _U_)
{
    /* XXX: Downmix to mono regardless of the actual number of channels
     * because RTP Player expects mono, and doesn't actually do anything
     * with this.
     */
    return 1;
}

static unsigned
codec_l24_get_frequency(codec_context_t *ctx)
{
    return ctx->sample_rate ? ctx->sample_rate : 44100;
}

static size_t
codec_l24_decode(codec_context_t *ctx _U_,
                 const void *inputBytes, size_t inputBytesSize,
                 void *outputSamples, size_t *outputSamplesSize)
{
    const sample24_t    *dataIn  = (const sample24_t *)inputBytes;
    uint16_t            *dataOut = (int16_t *)outputSamples;
    size_t              i;
    unsigned            channels = ctx->channels ? ctx->channels : 1;
    if (!outputSamples || !outputSamplesSize)
    {
        return inputBytesSize/channels;
    }
    /* Downmix to mono. */
    for (i=0; i<inputBytesSize/(3 * channels); i++)
    {
        int32_t tmp = 0;
        for (unsigned j=0; j < channels; j++) {
            tmp += (int16_t)g_ntohs(dataIn[channels*i + j].sample16);
        }
        dataOut[i] = (int16_t)(tmp / channels);
    }
    *outputSamplesSize = inputBytesSize * 2 / 3 / channels;
    return *outputSamplesSize;
}

void
codec_register_l24(void)
{
    register_codec("24-bit audio, monaural", codec_l24_mono_init,
        codec_l24_release, codec_l24_get_channels, codec_l24_get_frequency,
        codec_l24_decode);

    register_codec("24-bit audio, stereo", codec_l24_stereo_init,
        codec_l24_release, codec_l24_get_channels, codec_l24_get_frequency,
        codec_l24_decode);

    register_codec("L24", codec_l24_init, codec_l24_release,
        codec_l24_get_channels, codec_l24_get_frequency, codec_l24_decode);
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
