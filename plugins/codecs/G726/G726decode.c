/* G726decode.c
 * G.726 codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "spandsp.h"
#include "wsutil/codecs.h"
#include "ws_attributes.h"

typedef struct _g726_codec_ctx {
    g726_state_t *state;
    int bit_rate;
} g726_codec_ctx;

static void *
codec_g726_init(int bit_rate, int packing)
{
    g726_state_t *decoder = g726_init(NULL, bit_rate, G726_ENCODING_LINEAR, packing);

    if (!decoder) {
        return NULL;  /* out-of-memory; */
    }

    g726_codec_ctx *state = g_new(g726_codec_ctx, 1);
    state->state = decoder;
    state->bit_rate = bit_rate;

    return state;
}

static void *codec_g726_16_init(void) { return codec_g726_init(16000, G726_PACKING_RIGHT); }
static void *codec_g726_24_init(void) { return codec_g726_init(24000, G726_PACKING_RIGHT); }
static void *codec_g726_32_init(void) { return codec_g726_init(32000, G726_PACKING_RIGHT); }
static void *codec_g726_40_init(void) { return codec_g726_init(40000, G726_PACKING_RIGHT); }
static void *codec_aal2_g726_16_init(void) { return codec_g726_init(16000, G726_PACKING_LEFT); }
static void *codec_aal2_g726_24_init(void) { return codec_g726_init(24000, G726_PACKING_LEFT); }
static void *codec_aal2_g726_32_init(void) { return codec_g726_init(32000, G726_PACKING_LEFT); }
static void *codec_aal2_g726_40_init(void) { return codec_g726_init(40000, G726_PACKING_LEFT); }

static void
codec_g726_release(void *ctx)
{
    g726_codec_ctx *state = (g726_codec_ctx *)ctx;

    if (!state) {
        return;  /* out-of-memory; */
    }

    /* Note: replaces g726_release since SpanDSP 20090211 */
    g726_free(state->state);
    g_free(state);
}

static unsigned
codec_g726_get_channels(void *ctx _U_)
{
    return 1;
}

static unsigned
codec_g726_get_frequency(void *ctx _U_)
{
    return 8000;
}

static size_t
codec_g726_decode(void *ctx, const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize)
{
    g726_codec_ctx *state = (g726_codec_ctx *)ctx;

    if (!state) {
        return 0;  /* out-of-memory; */
    }

    if (!outputSamples || !outputSamplesSize) {
        /*
         * sample rate 8kHz, for bitrate 16kHz we have 16/8 = 2 bits/sample, so
         * 1 input byte (8 bits) will expand to four 16-bit samples. Likewise,
         * for bitrate 40kHz we have 40/8 = 5 bits/sample.  Alternatively:
         * bitsPerSample = bitRate / sampleRate (8kHz).
         * outputBytes = (inputBits / bitsPerSample) * sizeof(sample)
         */
        return inputBytesSize * 8 / (state->bit_rate / 8000) * 2;
    }

    /* g726_decode returns the number of 16-bit samples. */
    *outputSamplesSize = 2 * g726_decode(state->state, (int16_t *)outputSamples, (const uint8_t *) inputBytes, (int)inputBytesSize);
    return *outputSamplesSize;
}

void
codec_register_g726(void)
{
    register_codec("G726-16", codec_g726_16_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("G726-24", codec_g726_24_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("G726-32", codec_g726_32_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("G726-40", codec_g726_40_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("AAL2-G726-16", codec_aal2_g726_16_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("AAL2-G726-24", codec_aal2_g726_24_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("AAL2-G726-32", codec_aal2_g726_32_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
    register_codec("AAL2-G726-40", codec_aal2_g726_40_init, codec_g726_release,
            codec_g726_get_channels, codec_g726_get_frequency, codec_g726_decode);
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
