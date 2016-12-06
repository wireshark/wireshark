/* G722decode.c
 * G.722 codec
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
#include "G722decode.h"

void *
codec_g722_init(void)
{
    g722_decode_state_t *state;

    /* Valid values for bit_rate for G.722 are 48000, 56000, 64000, but RTP/AVP
     * profile requires 64kbps, aligned at octets. */
    state = g722_decode_init(NULL, 64000, 0);

    return state;
}

void
codec_g722_release(void *ctx)
{
    g722_decode_state_t *state = (g722_decode_state_t *)ctx;

    if (!state) {
        return;  /* out-of-memory; */
    }

    /* Note: replaces g722_decode_release since SpanDSP 20090211 */
    g722_decode_free(state);
}

unsigned
codec_g722_get_channels(void *ctx _U_)
{
    /* G.722 has only one channel. */
    return 1;
}

unsigned
codec_g722_get_frequency(void *ctx _U_)
{
    /* Note: RTP Clock rate is 8kHz due to a historic error, but actual sampling
     * rate is 16kHz (RFC 3551, section 4.5.2). */
    return 16000;
}

size_t
codec_g722_decode(void *ctx, const void *input, size_t inputSizeBytes, void *output,
        size_t *outputSizeBytes)
{
    g722_decode_state_t *state = (g722_decode_state_t *)ctx;

    if (!state) {
        return 0;  /* out-of-memory; */
    }

    if (!output || !outputSizeBytes) {
        return 4 * inputSizeBytes;
    }

    /* g722_decode returns the number of 16-bit samples. */
    *outputSizeBytes = 2 * g722_decode(state, (int16_t *)output, (const uint8_t *)input, (int)inputSizeBytes);
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

