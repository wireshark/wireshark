/* G726decode.c
 * G.726 codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#ifdef HAVE_SPANDSP
#include "spandsp.h"
#include "G726decode.h"

typedef struct _g726_codec_ctx {
    g726_state_t *state;
    int bit_rate;
} g726_codec_ctx;

static inline void *
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

void *codec_g726_16_init(void) { return codec_g726_init(16000, G726_PACKING_RIGHT); }
void *codec_g726_24_init(void) { return codec_g726_init(24000, G726_PACKING_RIGHT); }
void *codec_g726_32_init(void) { return codec_g726_init(32000, G726_PACKING_RIGHT); }
void *codec_g726_40_init(void) { return codec_g726_init(40000, G726_PACKING_RIGHT); }
void *codec_aal2_g726_16_init(void) { return codec_g726_init(16000, G726_PACKING_LEFT); }
void *codec_aal2_g726_24_init(void) { return codec_g726_init(24000, G726_PACKING_LEFT); }
void *codec_aal2_g726_32_init(void) { return codec_g726_init(32000, G726_PACKING_LEFT); }
void *codec_aal2_g726_40_init(void) { return codec_g726_init(40000, G726_PACKING_LEFT); }

void
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

unsigned
codec_g726_get_channels(void *ctx _U_)
{
    return 1;
}

unsigned
codec_g726_get_frequency(void *ctx _U_)
{
    return 8000;
}

size_t
codec_g726_decode(void *ctx, const void *input, size_t inputSizeBytes, void *output,
        size_t *outputSizeBytes)
{
    g726_codec_ctx *state = (g726_codec_ctx *)ctx;

    if (!state) {
        return 0;  /* out-of-memory; */
    }

    if (!output || !outputSizeBytes) {
        /*
         * sample rate 8kHz, for bitrate 16kHz we have 16/8 = 2 bits/sample, so
         * 1 input byte (8 bits) will expand to four 16-bit samples. Likewise,
         * for bitrate 40kHz we have 40/8 = 5 bits/sample.  Alternatively:
         * bitsPerSample = bitRate / sampleRate (8kHz).
         * outputBytes = (inputBits / bitsPerSample) * sizeof(sample)
         */
        return inputSizeBytes * 8 / (state->bit_rate / 8000) * 2;
    }

    /* g726_decode returns the number of 16-bit samples. */
    *outputSizeBytes = 2 * g726_decode(state->state, (int16_t *)output, (const uint8_t *) input, (int)inputSizeBytes);
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

