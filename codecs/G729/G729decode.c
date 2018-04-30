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
#ifdef HAVE_BCG729
#include "bcg729/decoder.h"
#include "G729decode.h"

#include "ws_attributes.h"

void *
codec_g729_init(void)
{
    return initBcg729DecoderChannel();
}

void
codec_g729_release(void *ctx)
{
    closeBcg729DecoderChannel((bcg729DecoderChannelContextStruct *)ctx);
}

unsigned
codec_g729_get_channels(void *ctx _U_)
{
    return 1;
}

unsigned
codec_g729_get_frequency(void *ctx _U_)
{
    return 8000;
}

size_t
codec_g729_decode(void *ctx, const void *input, size_t inputSizeBytes, void *output,
        size_t *outputSizeBytes)
{
    bcg729DecoderChannelContextStruct *state = (bcg729DecoderChannelContextStruct *)ctx;
    guint8 *dataIn = (guint8 *) input;
    gint16 *dataOut = (gint16 *) output;
    size_t i;

    if (!ctx) {
        return 0;
    }

    if (!output || !outputSizeBytes) {
        return 80*2*(inputSizeBytes/10);
    }

    /* The G729 algorithm encodes 10ms of voice into 80bit (10 bytes).
       Based on the RTP packetization period (usually 20ms), we need to
       pass to the bcg729 decoder chunks of 10ms (10 bytes)
    */
    for (i = 0; i < (inputSizeBytes/10); i++) {
        bcg729Decoder(state, dataIn + i*10, 10, 0, 0, 0, dataOut + i*80);
    }
    *outputSizeBytes = 80*2*(inputSizeBytes/10);
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
