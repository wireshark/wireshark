/* amrwbdecode.c
 * AMR WB codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wireshark.h>

#include "wsutil/codecs.h"
#include "ws_attributes.h"

#include <opencore-amrwb/dec_if.h>

void codec_register_amrwb(void);

static void *
codec_amrwb_init(codec_context_t *ctx _U_)
{
    void *state;
    state = D_IF_init();

    return state;
}

static void
codec_amrwb_release(codec_context_t *state)
{
    D_IF_exit(state->priv);
}

static unsigned
codec_amrwb_get_channels(codec_context_t *ctx _U_)
{
    return 1;
}

static unsigned
codec_amrwb_get_frequency(codec_context_t *ctx _U_)
{
    return 16000;
}

/* RTP doesn't allow the other SID types */
/* modes: 7k,9k,12k,14k,16k,18k,20k,23k,24k, MRDTX/SID */
static const uint16_t speech_bits[16] = {132, 177, 253, 285, 317, 365, 397, 461, 477, 35, 0, 0, 0, 0, 0, 0};
/* The number of speech bits rounded up to bytes */
static const uint8_t block_size[16]   = { 17,  23,  32,  36,  40,  46,  50,  58,  60,  5, 0, 0, 0, 0, 0, 0};

static const uint8_t bit_mask8[] = { 0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF };

/* 320 samples per frame, two bytes per frame, 20ms */
static const size_t out_frame_bytes = 320U * 2U;
/* Retrieve no_of_bits (<= 8) from in, starting at bit_offset.
 * Does not do bounds checking.
 */
static uint8_t
get_bits8(uint8_t *in, unsigned bit_offset, const unsigned no_of_bits)
{
    uint8_t ret;
    unsigned octet_offset = bit_offset >> 3;
    unsigned bits_in_first_octet = 8 - (bit_offset % 8);
    if (bits_in_first_octet >= no_of_bits) {
        ret = in[octet_offset] >> (bits_in_first_octet - no_of_bits) & bit_mask8[no_of_bits];
    } else {
        unsigned left_shift = no_of_bits - bits_in_first_octet;
        ret = (in[octet_offset] << left_shift) & bit_mask8[no_of_bits];
        ret |= (in[octet_offset + 1] >> (8 - left_shift));
    }
    return ret;
}

static size_t
codec_amrwb_decode_one(void *state, const void *input, size_t inputSizeBytes,
    void *output, size_t *outputSizeBytes)
{
    uint8_t *in;
    int mode;
    unsigned packet_size;
    packet_size = 2; /* CMR + TOC */

    /* 320 samples per frame, two bytes per frame, 20ms defined at top */
    *outputSizeBytes = out_frame_bytes;

    /* If no room for CMR + TOC, insert silence */
    if (packet_size > inputSizeBytes) {
        memset(output, 0, out_frame_bytes);
        return *outputSizeBytes;
    }

    in = (uint8_t*)input + 1;
    mode = (in[0] >> 3) & 0x0F;
    packet_size += block_size[mode];

    /* If the size is screwed up, insert silence */
    if (packet_size > inputSizeBytes) {
        memset(output, 0, out_frame_bytes);
        return *outputSizeBytes;
    }

    /* XXX: The last parameter is the BFI - we could invert the
     * Q-bit and pass it in, which might be better?
     */
    D_IF_decode(state, in, (short *)output, 0);
    return *outputSizeBytes;
}

static size_t
codec_amrwb_decode_many(void *state, const void *input, size_t inputSizeBytes,
        void *output, size_t *outputSizeBytes, unsigned frames)
{
    int mode;
    unsigned packet_size = 1; /* CMR */

    *outputSizeBytes = out_frame_bytes * frames;

    uint8_t *toc = (uint8_t *)input + 1;
    uint8_t *speech = toc + frames;
    uint8_t in[64];

    for (unsigned i = 0; i < frames; i++) {
        mode = (toc[i] >> 3) & 0x0F;
        packet_size += block_size[mode] + 1; /* include the TOC */

        /* If the size is screwed up, insert silence */
        if (packet_size > inputSizeBytes) {
            memset(output, 0, out_frame_bytes * (frames - i));
            return *outputSizeBytes;
        }

        /* OpenCORE-AMR ignores the F-bit (which is why we're doing
         * this memcpy) but might as well clear it.
         */
        in[0] = toc[i] & 0x7F;
        memcpy(&in[1], speech, block_size[mode]);
        /* XXX: The last parameter is the BFI - we could invert the
         * Q-bit and pass it in, which might be better?
         */
        D_IF_decode(state, in, (short *)output, 0);
        speech += block_size[mode];
        output = (uint8_t *)output + out_frame_bytes;
    }

    return *outputSizeBytes;
}

static size_t
codec_amrwb_decode_oa(codec_context_t *ctx, const void *input,
        size_t inputSizeBytes, void *output, size_t *outputSizeBytes)
{
    bool f_bit;
    unsigned frames = 0;
    void *state = ctx->priv;

    /* First byte is CMR, second is the Payload TOC */
    if (inputSizeBytes < 2) {
        frames = 1;
    } else {
        uint8_t *in = (uint8_t *)input;
        do {
            f_bit = (in[++frames] >> 7) & 0x01;
        } while (f_bit && inputSizeBytes > frames + 1);
    }

    if (!output || !outputSizeBytes)
        return out_frame_bytes * frames;

    if (frames == 1) {
        return codec_amrwb_decode_one(state, input, inputSizeBytes, output, outputSizeBytes);
    } else {
        return codec_amrwb_decode_many(state, input, inputSizeBytes, output, outputSizeBytes, frames);
    }
}

static size_t
codec_amrwb_decode(codec_context_t *ctx, const void *input,
        size_t inputSizeBytes, void *output, size_t *outputSizeBytes)
{
    bool f_bit;
    unsigned frames = 0;
    void *state = ctx->priv;

    if (ctx->fmtp_map) {
        const char* octet_align = (const char *)wmem_map_lookup(ctx->fmtp_map, "octet-align");
        /* There's a few other lesser used options like "crc", "interleaving",
         * and "robust-sorting" that can change how it should be decoded.
         * (All of them imply octet-aligned.) Ideally we'd handle them too.
         */
        if (g_strcmp0(octet_align, "1") == 0) {
            return codec_amrwb_decode_oa(ctx, input, inputSizeBytes, output, outputSizeBytes);
        }
    }

    unsigned bit_offset = 4;
    uint8_t *in = (uint8_t *)input;
    /* Per RFC 4867, if the format parameters don't indicate octet-align,
     * bandwidth-efficient mode is used. (For Decode As, we'll pass in
     * the value of the dissector's prefs.)
     * OpenCORE-AMR's interface only supports octet-aligned mode, so we
     * have to align the data. (From the source, the decode also supports
     * IF2, except that there's no way to access that from the interface.)
     */
    /* First byte is CMR, second is the Payload TOC */
    if (inputSizeBytes < 2) {
        frames = 1;
    } else {
        do {
            f_bit = get_bits8(in, bit_offset, 1);
            bit_offset += 6;
            frames++;
        } while (f_bit && inputSizeBytes > (bit_offset / 8));
    }

    /* 320 samples per frame, two byte per frame, 20ms */
    size_t total_out_bytes = out_frame_bytes * (size_t)frames;
    if (!output || !outputSizeBytes) {
        return total_out_bytes;
    }
    *outputSizeBytes = total_out_bytes;

    /* bit_offset is now where the speech bits begin */
    unsigned toc_offset = 5; /* Mode start */
    /* Make room for mode byte + largest WB frame bytes + 1 */
    uint8_t aligned[64];
    int mode;
    for (unsigned i = 0; i < frames; ++i) {
        mode = get_bits8(in, toc_offset, 4);

        /* If the size is screwed up, insert silence */
        if ((bit_offset + speech_bits[mode] + 7) / 8 > inputSizeBytes) {
            memset(output, 0, out_frame_bytes * (frames - i));
            return *outputSizeBytes;
        }

        memset(aligned, 0, sizeof(aligned));
        aligned[0] = mode << 3;
        for (unsigned j = 0; j < speech_bits[mode] / 8U; ++j) {
            aligned[1 + j] = get_bits8(in, bit_offset, 8);
            bit_offset += 8;
        }
        if (speech_bits[mode] % 8) {
            aligned[1 + block_size[mode]] = get_bits8(in, bit_offset, speech_bits[mode] % 8);
        }
        /* Padding might be different. */

        /* XXX: The last parameter is the BFI - we could invert the
         * Q-bit and pass it in, which might be better?
         */
        D_IF_decode(state, aligned, (short *)output, 0);
        output = (uint8_t *)output + out_frame_bytes;
    }

    return *outputSizeBytes;
}

void
codec_register_amrwb(void)
{
    register_codec("AMR-WB", codec_amrwb_init, codec_amrwb_release,
            codec_amrwb_get_channels, codec_amrwb_get_frequency, codec_amrwb_decode);
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
