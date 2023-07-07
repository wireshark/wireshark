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
codec_opus_init(codec_context_t *ctx _U_)
{
    OpusDecoder *state;
    int err = OPUS_INTERNAL_ERROR;
    /* Opus has in-band signaling and can convert what is sent to our
     * desired output.
     * always use maximum 48000 to cover all 8k/12k/16k/24k/48k
     * always downmix to mono because RTP Player only supports mono now
     */
    state = opus_decoder_create(48000, 1, &err);
    return state;
}

static void
codec_opus_release(codec_context_t *ctx)
{
    OpusDecoder* state = (OpusDecoder*)ctx->priv;
    if (!state) {
      return; /* out-of-memory; */
    }
    opus_decoder_destroy(state);
}

static unsigned
codec_opus_get_channels(codec_context_t *ctx _U_)
{
    return 1;
}

static unsigned
codec_opus_get_frequency(codec_context_t *ctx _U_)
{
    /* although can set kinds of fs, but we set 48K now */
    return 48000;
}

static size_t
codec_opus_decode(codec_context_t *ctx,
                  const void *input, size_t inputSizeBytes,
                  void *output, size_t *outputSizeBytes)
{
    OpusDecoder *state = (OpusDecoder *)ctx->priv;

    if (!state) {
        return 0;  /* out-of-memory */
    }

    const unsigned char *data = (const unsigned char *)input;
    opus_int32 len = (opus_int32)inputSizeBytes;
    int frame_samples = opus_decoder_get_nb_samples(state, data, len);
    if (frame_samples < 0) { // OPUS_INVALID_PACKET
        return 0;
    }

    // reserve space for the first time
    if (!output || !outputSizeBytes) {
        return frame_samples*2;
    }
    opus_int16 *pcm = (opus_int16*)(output);
    int ret = opus_decode(state, data, len, pcm, frame_samples, 0);

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
