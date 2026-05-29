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

/**
 * @brief Represents a single dissected RTP packet captured within an RTP stream.
 */
typedef struct _rtp_packet {
    uint32_t         frame_num;     /**< Frame number of this packet in the capture file; used by the Qt UI only. */
    struct _rtp_info *info;         /**< Pointer to the dissected RTP header and payload metadata for this packet. */
    double           arrive_offset; /**< Arrival time offset from the start of the stream; expressed in milliseconds in the GTK UI and seconds in the Qt UI. */
    uint8_t         *payload_data;  /**< Pointer to the raw RTP payload bytes for this packet. */
} rtp_packet_t;

/** Create a new hash table.
 *
 * @return A new hash table suitable for passing to decode_rtp_packet.
 */
GHashTable *rtp_decoder_hash_table_new(void);

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
