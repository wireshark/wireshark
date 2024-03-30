/** @file
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

#ifndef __RTP_MEDIA_H__
#define __RTP_MEDIA_H__

#include <glib.h>
#include <wsutil/wmem/wmem_map.h>

/** @file
 *  "RTP Player" dialog box common routines.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************************************************************/
/* INTERFACE */
/****************************************************************************/

typedef int16_t SAMPLE;
#define SAMPLE_MAX INT16_MAX
#define SAMPLE_MIN INT16_MIN
#define SAMPLE_NaN SAMPLE_MIN
#define SAMPLE_BYTES (sizeof(SAMPLE) / sizeof(char))

/* Defines an RTP packet */
typedef struct _rtp_packet {
    uint32_t frame_num;      /* Qt only */
    struct _rtp_info *info;	/* the RTP dissected info */
    double arrive_offset;	/* arrive offset time since the beginning of the stream as ms in GTK UI and s in Qt UI */
    uint8_t* payload_data;
} rtp_packet_t;

/** Create a new hash table.
 *
 * @return A new hash table suitable for passing to decode_rtp_packet.
 */
GHashTable *rtp_decoder_hash_table_new(void);

/** Decode payload from an RTP packet
 * For RTP packets with dynamic payload types, the payload name, clock rate,
 * and number of audio channels (e.g., from the SDP) can be provided.
 * Note that the output sample rate and number of channels might not be the
 * same as that of the input.
 *
 * @param payload_type Payload number
 * @param payload_type_str Payload name, can be NULL
 * @param payload_rate Sample rate, can be 0 for codec default
 * @param payload_channels Audio channels, can be 0 for codec default
 * @param payload_fmtp_map Map of format parameters for the media type
 * @param payload_data Payload
 * @param payload_len Length of payload
 * @param out_buff Output audio samples.
 * @param decoders_hash Hash table created with rtp_decoder_hash_table_new.
 * @param channels_ptr If non-NULL, receives the number of channels in the sample.
 * @param sample_rate_ptr If non-NULL, receives the sample rate.
 * @return The number of decoded bytes on success, 0 on failure.
 */
size_t decode_rtp_packet_payload(uint8_t payload_type, const char *payload_type_str, int payload_rate, int payload_channels, wmem_map_t *payload_fmtp_map, uint8_t *payload_data, size_t payload_len, SAMPLE **out_buff, GHashTable *decoders_hash, unsigned *channels_ptr, unsigned *sample_rate_ptr);

/** Decode an RTP packet
 *
 * @param rp Wrapper for per-packet RTP tap data.
 * @param out_buff Output audio samples.
 * @param decoders_hash Hash table created with rtp_decoder_hash_table_new.
 * @param channels_ptr If non-NULL, receives the number of channels in the sample.
 * @param sample_rate_ptr If non-NULL, receives the sample rate.
 * @return The number of decoded bytes on success, 0 on failure.
 */
size_t decode_rtp_packet(rtp_packet_t *rp, SAMPLE **out_buff, GHashTable *decoders_hash, unsigned *channels_ptr, unsigned *sample_rate_ptr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RTP_MEDIA_H__ */
