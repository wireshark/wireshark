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
