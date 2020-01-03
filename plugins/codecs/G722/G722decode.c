/* G722decode.c
 * G.722 codec
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

static void *
codec_g722_init(void)
{
    g722_decode_state_t *state;

    /* Valid values for bit_rate for G.722 are 48000, 56000, 64000, but RTP/AVP
     * profile requires 64kbps, aligned at octets. */
    state = g722_decode_init(NULL, 64000, 0);

    return state;
}

static void
codec_g722_release(void *ctx)
{
    g722_decode_state_t *state = (g722_decode_state_t *)ctx;

    if (!state) {
        return;  /* out-of-memory; */
    }

    /* Note: replaces g722_decode_release since SpanDSP 20090211 */
    g722_decode_free(state);
}

static unsigned
codec_g722_get_channels(void *ctx _U_)
{
    /* G.722 has only one channel. */
    return 1;
}

static unsigned
codec_g722_get_frequency(void *ctx _U_)
{
    /* Note: RTP Clock rate is 8kHz due to a historic error, but actual sampling
     * rate is 16kHz (RFC 3551, section 4.5.2). */
    return 16000;
}

static size_t
codec_g722_decode(void *ctx, const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize)
{
    g722_decode_state_t *state = (g722_decode_state_t *)ctx;

    if (!state) {
        return 0;  /* out-of-memory; */
    }

    if (!outputSamples || !outputSamplesSize) {
        return 4 * inputBytesSize;
    }

    /* g722_decode returns the number of 16-bit samples. */
    *outputSamplesSize = 2 * g722_decode(state, (int16_t *)outputSamples,
        (const uint8_t *)inputBytes, (int)inputBytesSize);
    return *outputSamplesSize;
}

void
codec_register_g722(void)
{
    register_codec("g722", codec_g722_init, codec_g722_release,
            codec_g722_get_channels, codec_g722_get_frequency, codec_g722_decode);
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
