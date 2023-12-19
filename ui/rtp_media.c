/* rtp_media.c
 *
 * RTP decoding routines for Wireshark.
 * Copied from ui/gtk/rtp_player.c
 *
 * Copyright 2006, Alejandro Vaquero <alejandrovaquero@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wsutil/codecs.h>

#include <epan/rtp_pt.h>
#include <epan/dissectors/packet-rtp.h>

#include <ui/rtp_media.h>

/****************************************************************************/
/* DECODING */
/****************************************************************************/

typedef struct _rtp_decoder_t {
    codec_handle_t handle;
    codec_context_t *context;
} rtp_decoder_t;

/****************************************************************************/
/*
 * Return the number of decoded bytes
 */

size_t
decode_rtp_packet_payload(uint8_t payload_type, const char *payload_type_str, int payload_rate, int payload_channels, wmem_map_t *payload_fmtp_map, uint8_t *payload_data, size_t payload_len, SAMPLE **out_buff, GHashTable *decoders_hash, unsigned *channels_ptr, unsigned *sample_rate_ptr)
{
    const char *p;
    rtp_decoder_t *decoder;
    SAMPLE *tmp_buff = NULL;
    size_t tmp_buff_len;
    size_t decoded_bytes = 0;

    /* Look for registered codecs */
    decoder = (rtp_decoder_t *)g_hash_table_lookup(decoders_hash, GUINT_TO_POINTER(payload_type));
    if (!decoder) {  /* Put either valid or empty decoder into the hash table */
        decoder = g_new(rtp_decoder_t,1);
        decoder->handle = NULL;
        decoder->context = g_new(codec_context_t, 1);
        decoder->context->sample_rate = payload_rate;
        decoder->context->channels = payload_channels;
        decoder->context->fmtp_map = payload_fmtp_map;
        decoder->context->priv = NULL;

        if (payload_type_str && find_codec(payload_type_str)) {
            p = payload_type_str;
        } else {
            p = try_val_to_str_ext(payload_type, &rtp_payload_type_short_vals_ext);
        }

        if (p) {
            decoder->handle = find_codec(p);
            if (decoder->handle)
                decoder->context->priv = codec_init(decoder->handle, decoder->context);
        }
        g_hash_table_insert(decoders_hash, GUINT_TO_POINTER(payload_type), decoder);
    }
    if (decoder->handle) {  /* Decode with registered codec */
        /* if output == NULL and outputSizeBytes == NULL => ask for expected size of the buffer */
        tmp_buff_len = codec_decode(decoder->handle, decoder->context, payload_data, payload_len, NULL, NULL);
        tmp_buff = (SAMPLE *)g_malloc(tmp_buff_len);
        decoded_bytes = codec_decode(decoder->handle, decoder->context, payload_data, payload_len, tmp_buff, &tmp_buff_len);
        *out_buff = tmp_buff;

        if (channels_ptr) {
            *channels_ptr = codec_get_channels(decoder->handle, decoder->context);
        }

        if (sample_rate_ptr) {
            *sample_rate_ptr = codec_get_frequency(decoder->handle, decoder->context);
        }

        return decoded_bytes;
    }

    *out_buff = NULL;
    return 0;
}

/****************************************************************************/
/*
 * @return Number of decoded bytes
 */

size_t
decode_rtp_packet(rtp_packet_t *rp, SAMPLE **out_buff, GHashTable *decoders_hash, unsigned *channels_ptr, unsigned *sample_rate_ptr)
{
    uint8_t payload_type;

    if ((rp->payload_data == NULL) || (rp->info->info_payload_len == 0) ) {
        return 0;
    }

    payload_type = rp->info->info_payload_type;

    return decode_rtp_packet_payload(payload_type, rp->info->info_payload_type_str, rp->info->info_payload_rate, rp->info->info_payload_channels, rp->info->info_payload_fmtp_map, rp->payload_data, rp->info->info_payload_len, out_buff, decoders_hash, channels_ptr, sample_rate_ptr);
}

/****************************************************************************/
static void
rtp_decoder_value_destroy(void *dec_arg)
{
    rtp_decoder_t *dec = (rtp_decoder_t *)dec_arg;

    if (dec->handle) {
        codec_release(dec->handle, dec->context);
        g_free(dec->context);
    }
    g_free(dec_arg);
}

GHashTable *rtp_decoder_hash_table_new(void)
{
    return g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, rtp_decoder_value_destroy);
}
