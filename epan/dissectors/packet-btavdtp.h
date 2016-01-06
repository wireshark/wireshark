/* packet-btavdtp.h
 * Headers for AVDTP
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
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

#ifndef __PACKET_BTAVDTP_H__
#define __PACKET_BTAVDTP_H__

#define BTAVDTP_CONTENT_PROTECTION_TYPE_SCMS_T  0x02

typedef struct _media_packet_info_t {
    nstime_t  abs_ts;
    nstime_t  first_abs_ts;
    gdouble   cumulative_frame_duration;
    gdouble   avrcp_song_position;
    guint32   stream_number;
} media_packet_info_t;

typedef struct _bta2dp_codec_info_t {
    dissector_handle_t    codec_dissector;
    guint8                configuration_length;
    guint8               *configuration;
    gint                  content_protection_type;
    media_packet_info_t  *previous_media_packet_info;
    media_packet_info_t  *current_media_packet_info;
} bta2dp_codec_info_t;

typedef struct _btvdp_codec_info_t {
    dissector_handle_t   codec_dissector;
    gint                 content_protection_type;
} btvdp_codec_info_t;

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
