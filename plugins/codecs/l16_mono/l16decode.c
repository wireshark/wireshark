/* l16decode.c
 * 16-bit audio, mono codec
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

void codec_register_l16(void);

static void *
codec_l16_init(codec_context_t *ctx _U_)
{
    return NULL;
}

static void *
codec_l16_mono_init(codec_context_t *ctx)
{
    /* L16 mono as registered as PT 11 */
    ctx->sample_rate = 44100;
    ctx->channels = 1;
    return NULL;
}

static void *
codec_l16_stereo_init(codec_context_t *ctx)
{
    /* L16 stereo as registered as PT 10 */
    ctx->sample_rate = 44100;
    /* In practice, we will downmix to mono. */
    ctx->channels = 2;
    return NULL;
}

static void
codec_l16_release(codec_context_t *ctx _U_)
{

}

static unsigned
codec_l16_get_channels(codec_context_t *ctx _U_)
{
    /* XXX: Downmix to mono regardless of the actual number of channels
     * because RTP Player expects mono, and doesn't actually do anything
     * with this.
     */
    return 1;
}

static unsigned
codec_l16_get_frequency(codec_context_t *ctx)
{
    return ctx->sample_rate ? ctx->sample_rate : 44100;
}

static size_t
codec_l16_decode(codec_context_t *ctx _U_,
                 const void *inputBytes, size_t inputBytesSize,
                 void *outputSamples, size_t *outputSamplesSize)
{
    const uint16_t *dataIn  = (const uint16_t *)inputBytes;
    uint16_t      *dataOut = (int16_t *)outputSamples;
    size_t         i;
    unsigned       channels = ctx->channels ? ctx->channels : 1;
    if (!outputSamples || !outputSamplesSize)
    {
        return inputBytesSize/channels;
    }

    /* Downmix to mono. No worries about overflow because tmp is 32 bit. */
    for (i=0; i<inputBytesSize/(2 * channels); i++)
    {
        int32_t tmp = 0;
        for (unsigned j=0; j < channels; j++) {
            tmp += (int16_t)g_ntohs(dataIn[channels*i + j]);
        }
        dataOut[i] = (int16_t)(tmp / channels);
    }

    *outputSamplesSize = inputBytesSize/channels;
    return *outputSamplesSize;
}

void
codec_register_l16(void)
{
    register_codec("16-bit audio, monaural", codec_l16_mono_init,
        codec_l16_release, codec_l16_get_channels, codec_l16_get_frequency,
        codec_l16_decode);

    register_codec("16-bit audio, stereo", codec_l16_stereo_init,
        codec_l16_release, codec_l16_get_channels, codec_l16_get_frequency,
        codec_l16_decode);

    register_codec("L16", codec_l16_init, codec_l16_release,
        codec_l16_get_channels, codec_l16_get_frequency, codec_l16_decode);
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
