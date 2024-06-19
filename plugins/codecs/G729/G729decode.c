/* G729decode.c
 * G.729 codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "bcg729/decoder.h"
#include "wsutil/codecs.h"
#include "ws_attributes.h"

void codec_register_g729(void);

static void *
codec_g729_init(codec_context_t *ctx _U_)
{
    return initBcg729DecoderChannel();
}

static void
codec_g729_release(codec_context_t *ctx)
{
    closeBcg729DecoderChannel((bcg729DecoderChannelContextStruct *)ctx->priv);
}

static unsigned
codec_g729_get_channels(codec_context_t *ctx _U_)
{
    return 1;
}

static unsigned
codec_g729_get_frequency(codec_context_t *ctx _U_)
{
    return 8000;
}

static size_t
codec_g729_decode(codec_context_t *ctx,
        const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize)
{
    bcg729DecoderChannelContextStruct *state = (bcg729DecoderChannelContextStruct *)ctx->priv;
    const uint8_t *dataIn = (const uint8_t *) inputBytes;
    int16_t *dataOut = (int16_t *) outputSamples;
    size_t i;

    if (!ctx) {
        return 0;
    }

    size_t full_frames = inputBytesSize / 10;
    /* Almost surely only one SID frame. SID frames come at the end of
       the payload, and 10 ms packets can be used when transitioning to
       avoid ambiguity. (RFC 3551 4.5.6 "G729")
     */
    size_t sid_frames = (inputBytesSize % 10) / 2;

    if (!outputSamples || !outputSamplesSize) {
        return 80*2*(full_frames + sid_frames);
    }

    /* The G729 algorithm encodes 10ms of voice into 80bit (10 bytes).
       Based on the RTP packetization period (usually 20ms), we need to
       pass to the bcg729 decoder chunks of 10ms (10 bytes)
    */
    for (i = 0; i < full_frames; i++) {
        /* As of version 1.1.0, the bcg729 decoder library declares the second
           argument to bcg729Decoder() to be a const pointer, but prior to
           that it did not (though it didn't modify the input and could be
           fixed to accept a const pointer.) Cast away the problem for now;
           in the future we could check the version of the library.
        */
        bcg729Decoder(state, (uint8_t *)dataIn + i*10, 10, 0, 0, 0, dataOut + i*80);
    }

    for (; i < full_frames + sid_frames; i++) {
        bcg729Decoder(state, (uint8_t *)dataIn + full_frames*10 + (i - full_frames)*2, 2, 0, 1, 0, dataOut + i*80);
    }
    *outputSamplesSize = 80*2*(full_frames + sid_frames);
    return *outputSamplesSize;
}

void
codec_register_g729(void)
{
    register_codec("g729", codec_g729_init, codec_g729_release,
            codec_g729_get_channels, codec_g729_get_frequency, codec_g729_decode);
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
