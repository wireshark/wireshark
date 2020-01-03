/* rtp_media.h
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

/** @file
 *  "RTP Player" dialog box common routines.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>

/****************************************************************************/
/* INTERFACE */
/****************************************************************************/

typedef gint16 SAMPLE;
#define SAMPLE_MAX G_MAXINT16
#define SAMPLE_MIN G_MININT16

/* Defines an RTP packet */
typedef struct _rtp_packet {
    guint32 frame_num;      /* Qt only */
    struct _rtp_info *info;	/* the RTP dissected info */
    double arrive_offset;	/* arrive offset time since the beginning of the stream as ms in GTK UI and s in Qt UI */
    guint8* payload_data;
} rtp_packet_t;

/** Create a new hash table.
 *
 * @return A new hash table suitable for passing to decode_rtp_packet.
 */
GHashTable *rtp_decoder_hash_table_new(void);

/** Decode payload from an RTP packet
 *
 * @param payload_type Payload number
 * @param payload_type_str Payload name, can be NULL
 * @param payload_data Payload
 * @param payload_len Length of payload
 * @param out_buff Output audio samples.
 * @param decoders_hash Hash table created with rtp_decoder_hash_table_new.
 * @param channels_ptr If non-NULL, receives the number of channels in the sample.
 * @param sample_rate_ptr If non-NULL, receives the sample rate.
 * @return The number of decoded bytes on success, 0 on failure.
 */
size_t decode_rtp_packet_payload(guint8 payload_type, const gchar *payload_type_str, guint8 *payload_data, size_t payload_len, SAMPLE **out_buff, GHashTable *decoders_hash, guint *channels_ptr, guint *sample_rate_ptr);

/** Decode an RTP packet
 *
 * @param rp Wrapper for per-packet RTP tap data.
 * @param out_buff Output audio samples.
 * @param decoders_hash Hash table created with rtp_decoder_hash_table_new.
 * @param channels_ptr If non-NULL, receives the number of channels in the sample.
 * @param sample_rate_ptr If non-NULL, receives the sample rate.
 * @return The number of decoded bytes on success, 0 on failure.
 */
size_t decode_rtp_packet(rtp_packet_t *rp, SAMPLE **out_buff, GHashTable *decoders_hash, guint *channels_ptr, guint *sample_rate_ptr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RTP_MEDIA_H__ */

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
