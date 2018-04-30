/* G711udecode.c
 * mu-law G.711 codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "G711udecode.h"
#include "G711utable.h"

#include "ws_attributes.h"

void *
codec_g711u_init(void)
{
    return NULL;
}

void
codec_g711u_release(void *ctx _U_)
{

}

unsigned
codec_g711u_get_channels(void *ctx _U_)
{
    return 1;
}

unsigned
codec_g711u_get_frequency(void *ctx _U_)
{
    return 8000;
}

size_t
codec_g711u_decode(void *ctx _U_, const void *input, size_t inputSizeBytes, void *output,
        size_t *outputSizeBytes)
{
    const guint8 *dataIn = (const guint8 *) input;
    gint16       *dataOut = (gint16 *) output;
    size_t       i;

    if (!output || !outputSizeBytes) {
        return inputSizeBytes * 2;
    }

    for (i = 0; i < inputSizeBytes; i++)
    {
        dataOut[i] = ulaw_exp_table[dataIn[i]];
    }

    *outputSizeBytes = inputSizeBytes * 2;
    return inputSizeBytes * 2;
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

