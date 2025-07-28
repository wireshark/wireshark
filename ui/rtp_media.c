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
#include <wsutil/wslog.h>

#include <epan/dissectors/packet-rtp.h>
#include <epan/dissectors/packet-iuup.h>
#include <epan/dissectors/packet-amr.h>

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
 * Return rtp_decoder_t for packet
 */

static inline rtp_decoder_t *
decode_rtp_find_decoder(uint8_t payload_type, GHashTable *decoders_hash)
{
    /* Look for registered codecs */
    return (rtp_decoder_t *)g_hash_table_lookup(decoders_hash, GUINT_TO_POINTER(payload_type));
}

static rtp_decoder_t *
decode_rtp_create_decoder(uint8_t payload_type, const char *payload_type_str, int payload_rate,
                          int payload_channels, wmem_map_t *payload_fmtp_map, GHashTable *decoders_hash)
{
    rtp_decoder_t *decoder;
    /* Put either valid or empty decoder into the hash table */
    decoder = g_new(rtp_decoder_t, 1);
    decoder->handle = NULL;
    decoder->context = g_new(codec_context_t, 1);
    decoder->context->sample_rate = payload_rate;
    decoder->context->channels = payload_channels;
    decoder->context->fmtp_map = payload_fmtp_map;
    decoder->context->priv = NULL;

    if (payload_type_str)
         decoder->handle = find_codec(payload_type_str);
    if (!decoder->handle) {
        const char *p = try_val_to_str_ext(payload_type, get_external_value_string_ext("rtp_payload_type_short_vals_ext"));
        if (p)
            decoder->handle = find_codec(p);
    }

    if (decoder->handle)
        decoder->context->priv = codec_init(decoder->handle, decoder->context);

    g_hash_table_insert(decoders_hash, GUINT_TO_POINTER(payload_type), decoder);
    return decoder;
}

static rtp_decoder_t *
decode_rtp_find_or_create_decoder(uint8_t payload_type, const char *payload_type_str, int payload_rate,
                                  int payload_channels, wmem_map_t *payload_fmtp_map, GHashTable *decoders_hash)
{
    rtp_decoder_t *decoder;

    /* Look for registered codecs */
    decoder = decode_rtp_find_decoder(payload_type, decoders_hash);
    if (!decoder)
        decoder = decode_rtp_create_decoder(payload_type, payload_type_str, payload_rate,
                                            payload_channels, payload_fmtp_map, decoders_hash);
    ws_assert(decoder);
    return decoder;
}

/****************************************************************************/
/** Decode payload from an RTP packet
 * For RTP packets with dynamic payload types, the payload name, clock rate,
 * and number of audio channels (e.g., from the SDP) can be provided.
 * Note that the output sample rate and number of channels might not be the
 * same as that of the input.
 *
 * @param decoder RTP decoder used to decode the audio in the RTP payload.
 * @param payload_data Payload
 * @param payload_len Length of payload
 * @param out_buff Output audio samples.
 * @param channels_ptr If non-NULL, receives the number of channels in the sample.
 * @param sample_rate_ptr If non-NULL, receives the sample rate.
 * @return The number of decoded bytes on success, 0 on failure.
 */

static size_t
decode_rtp_packet_payload(rtp_decoder_t *decoder, uint8_t *payload_data, size_t payload_len,
                          SAMPLE **out_buff, unsigned *channels_ptr, unsigned *sample_rate_ptr)
{
    SAMPLE *tmp_buff = NULL;
    size_t tmp_buff_len;
    size_t decoded_bytes = 0;

    if (!decoder->handle) {
        *out_buff = NULL;
        return 0;
    }

    /* Decode with registered codec */
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

/****************************************************************************/
/** Prepend an AMR NB Octet-Aligned header (2 bytes) to the AMR payload.
 * A new buffer is allocated, filled and returned. The caller is responsible of freeing it.
 *
 * @return The callee-allocated buffer containing the AMR OA header + payload
 */
static uint8_t *
prepend_amr_oa_hdr(uint8_t amr_ft, uint8_t amr_q, const uint8_t *amr_payload, uint8_t amr_payload_len)
{
    uint8_t *amr_hdr;

    amr_hdr = (uint8_t *)g_malloc(AMR_NB_OA_HDR_LEN + amr_payload_len);
    amr_hdr[0] = 0xf0; /* CMR = 15 = "no change" */
    amr_hdr[1] = (0 << 7) | /* F=0 */
                 ((amr_ft & 0x0f) << 3) |
                 (amr_q && 0x01) << 2;
    memcpy(amr_hdr + AMR_NB_OA_HDR_LEN, amr_payload, amr_payload_len);
    return amr_hdr;
}

/****************************************************************************/
/** Parse IuUP header to obtain the AMR payload, generate a octet-aligned AMR
 * buffer which the AMR decoder can digest and decode it.
 *
 * @return Number of decoded bytes
 */

size_t
decode_iuup_packet(rtp_packet_t *rp, SAMPLE **out_buff, GHashTable *decoders_hash, unsigned *channels_ptr,
                  unsigned *sample_rate_ptr)
{
    uint8_t iuup_pdu_type;
    uint8_t iuup_frame_nr;
    uint8_t iuup_fqc;
    uint8_t iuup_hdr_len;
    uint8_t *iuup_payload;
    uint8_t iuup_payload_len;
    int amr_ft;
    uint8_t *amr_hdr;
    rtp_decoder_t *decoder;
    size_t decoded_bytes;

    if (rp->info->info_payload_len < 1)
        goto ret_err;

    /* Parse the IuUP header into struct iuup_decoded dt: */
    iuup_pdu_type = rp->payload_data[0] >> 4;
    switch (iuup_pdu_type) {
    case PDUTYPE_DATA_WITH_CRC:
        iuup_hdr_len = PDUTYPE_DATA_WITH_CRC_HDR_LEN;
        break;
    case PDUTYPE_DATA_NO_CRC:
        iuup_hdr_len = PDUTYPE_DATA_NO_CRC_HDR_LEN;
        break;
    default:
        goto ret_err;
    }

    if (rp->info->info_payload_len < iuup_hdr_len)
        goto ret_err;

    iuup_frame_nr = rp->payload_data[0] & 0x0f;
    iuup_fqc = rp->payload_data[1] >> 6;
    iuup_payload = rp->payload_data + iuup_hdr_len;
    iuup_payload_len = rp->info->info_payload_len - iuup_hdr_len;
    ws_assert(rp->info->info_payload_len - iuup_hdr_len < sizeof(uint8_t));

    /* Figure out AMR FT from size: */
    amr_ft = amr_nb_bytes_to_ft(iuup_payload_len);
    if (amr_ft < 0) {
        ws_log(LOG_DOMAIN_QTUI, LOG_LEVEL_MESSAGE,
               "#%u: IuUP with unknown AMR payload format: frame_nr=%u bytes=%u\n",
               rp->frame_num, iuup_frame_nr, iuup_payload_len);
		goto ret_err;
	}

    /* Prepend an octet-aligned header to the AMR payload, so that the decoder can digest it: */
    amr_hdr = prepend_amr_oa_hdr(amr_ft, !iuup_fqc, iuup_payload, iuup_payload_len);

    /* Look for registered codecs */
    decoder = decode_rtp_find_decoder(rp->info->info_payload_type, decoders_hash);
    if (!decoder) {
            wmem_map_t *iuup_decode_amr_fmtp = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
            wmem_map_insert(iuup_decode_amr_fmtp, "octet-align", "1");
            decoder = decode_rtp_create_decoder(rp->info->info_payload_type,
                                                "amr",
                                                rp->info->info_payload_rate,
                                                rp->info->info_payload_channels,
                                                iuup_decode_amr_fmtp,
                                                decoders_hash);
            ws_assert(decoder);
    }
    decoded_bytes = decode_rtp_packet_payload(decoder, amr_hdr, AMR_NB_OA_HDR_LEN + iuup_payload_len,
                                              out_buff, channels_ptr, sample_rate_ptr);
    g_free(amr_hdr);
    return decoded_bytes;

ret_err:
    *out_buff = NULL;
    return 0;
}

/****************************************************************************/
/*
 * @return Number of decoded bytes
 */

size_t
decode_rtp_packet(rtp_packet_t *rp, SAMPLE **out_buff, GHashTable *decoders_hash, unsigned *channels_ptr,
                  unsigned *sample_rate_ptr)
{
    rtp_decoder_t *decoder;

    if ((rp->payload_data == NULL) || (rp->info->info_payload_len == 0) ) {
        return 0;
    }

    if (rp->info->info_is_iuup)
        return decode_iuup_packet(rp, out_buff, decoders_hash, channels_ptr, sample_rate_ptr);

    /* Look for registered codecs */
    decoder = decode_rtp_find_or_create_decoder(rp->info->info_payload_type,
                                                rp->info->info_payload_type_str,
                                                rp->info->info_payload_rate,
                                                rp->info->info_payload_channels,
                                                rp->info->info_payload_fmtp_map,
                                                decoders_hash);
    return decode_rtp_packet_payload(decoder,
                                     rp->payload_data, rp->info->info_payload_len,
                                     out_buff, channels_ptr, sample_rate_ptr);
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
