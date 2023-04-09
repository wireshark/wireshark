/* amrdecode.c
 * AMR codec
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

#include <opencore-amrnb/interf_dec.h>

void codec_register_amr(void);

static void *
codec_amr_init(void)
{
    void *state;
    state = Decoder_Interface_init();

    return state;
}

static void
codec_amr_release(void *state)
{
    Decoder_Interface_exit(state);
}

static unsigned
codec_amr_get_channels(void *ctx _U_)
{
    return 1;
}

static unsigned
codec_amr_get_frequency(void *ctx _U_)
{
    return 8000;
}

static size_t
codec_amr_decode(void *state, const void *input, size_t inputSizeBytes, void *output,
        size_t *outputSizeBytes)
{
    int mode;
    unsigned packet_size;
    static const guint8 block_size[16] = {12, 13, 15, 17, 19, 20, 26, 31, 5, 0, 0, 0, 0, 0, 0, 0};

    /* First byte is CMR, second is the Payload TOC */
    mode = (((guint8 *)input)[1] >> 3) & 0x0F;
    packet_size = block_size[mode] + 2;

    if (!output || !outputSizeBytes)
	    return 160*2;

    *outputSizeBytes = 160 * 2; /* 160 frames, two byte per frame, 20ms */

    /* If the size is screwed up, insert silence */
    if (packet_size > inputSizeBytes) {
	    memset(output, 0, *outputSizeBytes);
	    return *outputSizeBytes;
    }

    Decoder_Interface_Decode(state, (const unsigned char *)input+1, (short *)output, 0);
    return *outputSizeBytes;
}

void
codec_register_amr(void)
{
    register_codec("AMR", codec_amr_init, codec_amr_release,
            codec_amr_get_channels, codec_amr_get_frequency, codec_amr_decode);
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
