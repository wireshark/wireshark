/* opusdecode.c
 * opus codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <stdlib.h>
#include "opus/opus.h"

#include "wsutil/codecs.h"
#include "ws_attributes.h"

void codec_register_opus(void);

static void *
codec_opus_init(void)
{
    OpusDecoder *state;
    int err = OPUS_INTERNAL_ERROR;
    /* always use maximum 48000 to cover all 8k/12k/16k/24k/48k */
    state = opus_decoder_create(48000, 1, &err);
    return state;
}

static void
codec_opus_release(void *ctx)
{
    OpusDecoder* state = (OpusDecoder*)ctx;
    if (!state) {
      return; /* out-of-memory; */
    }
    opus_decoder_destroy(state);
}

static unsigned
codec_opus_get_channels(void *ctx _U_)
{
    return 1;
}

static unsigned
codec_opus_get_frequency(void *ctx _U_)
{
    /* although can set kinds of fs, but we set 48K now */
    return 48000;
}

static size_t
codec_opus_decode(void *ctx , const void *input, size_t inputSizeBytes,
                  void *output, size_t *outputSizeBytes  )
{
    OpusDecoder *state = (OpusDecoder *)ctx;

    if (!ctx) {
        return 0;  /* out-of-memory */
    }
    // reserve space for the first time
    if (!output || !outputSizeBytes) {
        return 1920;
    }
    const unsigned char *data = (const unsigned char *)input;
    opus_int32 len= (opus_int32)inputSizeBytes;
    opus_int16 *pcm = (opus_int16*)(output);
    int frame_size = 960;
    int ret = opus_decode(state, data, len, pcm, frame_size, 0);

    if (ret < 0) {
        return 0;
    }
    *outputSizeBytes = ret * 2;
    return *outputSizeBytes;
}

void
codec_register_opus(void)
{
    register_codec("opus", codec_opus_init, codec_opus_release,
                   codec_opus_get_channels, codec_opus_get_frequency, codec_opus_decode);
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
