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

#include "codecs/codecs.h"
#include "ws_attributes.h"

void codec_register_l16(void);

static void *
codec_l16_init(void)
{
    return NULL;
}

static void
codec_l16_release(void *ctx _U_)
{

}

static unsigned
codec_l16_get_channels(void *ctx _U_)
{
    return 1;
}

static unsigned
codec_l16_get_frequency(void *ctx _U_)
{
    return 44100;
}

static size_t
codec_l16_decode(void *ctx _U_, const void *input, size_t inputSizeBytes,
                 void *output, size_t *outputSizeBytes)
{
    const guint16 *dataIn  = (const guint16 *)input;
    guint16       *dataOut = (guint16 *)output;
    size_t         i;

    if (!output || !outputSizeBytes)
    {
        return inputSizeBytes;
    }

    for (i=0; i<inputSizeBytes/2; i++)
    {
        dataOut[i] = g_ntohs(dataIn[i]);
    }

    *outputSizeBytes = inputSizeBytes;
    return *outputSizeBytes;
}

void
codec_register_l16(void)
{
    register_codec("16-bit audio, monaural", codec_l16_init, codec_l16_release,
        codec_l16_get_channels, codec_l16_get_frequency, codec_l16_decode);
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
