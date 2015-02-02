/* tap-rtp-common.h
 * RTP streams handler functions used by tshark and wireshark
 *
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
 *
 * most functions are copied from ui/gtk/rtp_stream.c and ui/gtk/rtp_analisys.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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
 * Foundation,  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __TAP_RTP_COMMON_H__
#define __TAP_RTP_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* type of error when saving voice in a file didn't succeed */
typedef enum {
    TAP_RTP_WRONG_CODEC,
    TAP_RTP_WRONG_LENGTH,
    TAP_RTP_PADDING_ERROR,
    TAP_RTP_SHORT_FRAME,
    TAP_RTP_FILE_OPEN_ERROR,
    TAP_RTP_FILE_WRITE_ERROR,
    TAP_RTP_NO_DATA
} error_type_t;

typedef struct _tap_rtp_save_info_t {
    FILE *fp;
    guint32 count;
    error_type_t error_type;
    gboolean saved;
} tap_rtp_save_info_t;

struct _rtp_stream_info;

void rtpstream_reset_cb(void*);
void rtp_write_header(struct _rtp_stream_info*, FILE*);
int rtpstream_packet(void*, packet_info*, epan_dissect_t *, const void *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_RTP_COMMON_H__ */

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
