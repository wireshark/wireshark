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

static void *
codec_g729_init(void)
{
    return initBcg729DecoderChannel();
}

static void
codec_g729_release(void *ctx)
{
    closeBcg729DecoderChannel((bcg729DecoderChannelContextStruct *)ctx);
}

static unsigned
codec_g729_get_channels(void *ctx _U_)
{
    return 1;
}

static unsigned
codec_g729_get_frequency(void *ctx _U_)
{
    return 8000;
}

static size_t
codec_g729_decode(void *ctx, const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize)
{
    bcg729DecoderChannelContextStruct *state = (bcg729DecoderChannelContextStruct *)ctx;
    const guint8 *dataIn = (const guint8 *) inputBytes;
    gint16 *dataOut = (gint16 *) outputSamples;
    size_t i;

    if (!ctx) {
        return 0;
    }

    if (!outputSamples || !outputSamplesSize) {
        return 80*2*(inputBytesSize/10);
    }

    /* The G729 algorithm encodes 10ms of voice into 80bit (10 bytes).
       Based on the RTP packetization period (usually 20ms), we need to
       pass to the bcg729 decoder chunks of 10ms (10 bytes)
    */
    for (i = 0; i < (inputBytesSize/10); i++) {
        /* The bcg729 decoder library fails to declare the second
           argument to bcg729Decoder() to be a const pointer.  If you
           fix it, and some other functions, to use const, the library
           compiles, so presumably it doesn't modify its input and
           therefore can safely be passed a const pointer.  Cast away
           the problem for now; a patch will be sent to the maintainers
           of the library.
        */
        bcg729Decoder(state, (guint8 *)dataIn + i*10, 10, 0, 0, 0, dataOut + i*80);
    }
    *outputSamplesSize = 80*2*(inputBytesSize/10);
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
