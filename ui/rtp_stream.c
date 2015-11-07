/* rtp_stream.c
 * RTP streams summary addition for Wireshark
 *
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

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "file.h"

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/addr_resolv.h>

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "ui/rtp_stream.h"
#include "ui/tap-rtp-common.h"
#include <wsutil/file_util.h>


/****************************************************************************/
/* redraw the output */
static void rtpstream_draw(void *ti_ptr)
{
    rtpstream_tapinfo_t *tapinfo = (rtpstream_tapinfo_t *)ti_ptr;
/* XXX: see rtpstream_on_update in rtp_streams_dlg.c for comments
    g_signal_emit_by_name(top_level, "signal_rtpstream_update");
*/
    if (tapinfo && tapinfo->tap_draw) {
        /* RTP_STREAM_DEBUG("streams: %d packets: %d", tapinfo->nstreams, tapinfo->npackets); */
        tapinfo->tap_draw(tapinfo);
    }
    return;
}


/****************************************************************************/
/* scan for RTP streams */
void rtpstream_scan(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, const char *fstring)
{
    gboolean was_registered;

    if (!tapinfo || !cap_file) {
        return;
    }

    was_registered = tapinfo->is_registered;
    if (!tapinfo->is_registered)
        register_tap_listener_rtp_stream(tapinfo, fstring);

    /* RTP_STREAM_DEBUG("scanning %s, filter: %s", cap_file->filename, fstring); */
    tapinfo->mode = TAP_ANALYSE;
    cf_retap_packets(cap_file);

    if (!was_registered)
        remove_tap_listener_rtp_stream(tapinfo);
}


/****************************************************************************/
/* save rtp dump of stream_fwd */
gboolean rtpstream_save(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtp_stream_info_t* stream, const gchar *filename)
{
    gboolean was_registered;

    if (!tapinfo) {
        return FALSE;
    }

    was_registered = tapinfo->is_registered;

    /* open file for saving */
    tapinfo->save_file = ws_fopen(filename, "wb");
    if (tapinfo->save_file==NULL) {
        open_failure_alert_box(filename, errno, TRUE);
        return FALSE;
    }

    rtp_write_header(stream, tapinfo->save_file);
    if (ferror(tapinfo->save_file)) {
        write_failure_alert_box(filename, errno);
        fclose(tapinfo->save_file);
        return FALSE;
    }

    if (!tapinfo->is_registered)
        register_tap_listener_rtp_stream(tapinfo, NULL);

    tapinfo->mode = TAP_SAVE;
    tapinfo->filter_stream_fwd = stream;
    cf_retap_packets(cap_file);
    tapinfo->mode = TAP_ANALYSE;

    if (!was_registered)
        remove_tap_listener_rtp_stream(tapinfo);

    if (ferror(tapinfo->save_file)) {
        write_failure_alert_box(filename, errno);
        fclose(tapinfo->save_file);
        return FALSE;
    }

    if (fclose(tapinfo->save_file) == EOF) {
        write_failure_alert_box(filename, errno);
        return FALSE;
    }
    return TRUE;
}

/****************************************************************************/
/* compare the endpoints of two RTP streams */
gboolean rtp_stream_info_is_reverse(const rtp_stream_info_t *stream_a, rtp_stream_info_t *stream_b)
{
    if (stream_a == NULL || stream_b == NULL)
        return FALSE;

    if ((addresses_equal(&(stream_a->src_addr), &(stream_b->dest_addr)))
        && (stream_a->src_port == stream_b->dest_port)
        && (addresses_equal(&(stream_a->dest_addr), &(stream_b->src_addr)))
        && (stream_a->dest_port == stream_b->src_port))
        return TRUE;
    else
        return FALSE;
}

/****************************************************************************/
/* mark packets in stream_fwd or stream_rev */
void rtpstream_mark(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtp_stream_info_t* stream_fwd, rtp_stream_info_t* stream_rev)
{
    gboolean was_registered;

    if (!tapinfo) {
        return;
    }

    was_registered = tapinfo->is_registered;

    if (!tapinfo->is_registered)
        register_tap_listener_rtp_stream(tapinfo, NULL);

    tapinfo->mode = TAP_MARK;
    tapinfo->filter_stream_fwd = stream_fwd;
    tapinfo->filter_stream_rev = stream_rev;
    cf_retap_packets(cap_file);
    tapinfo->mode = TAP_ANALYSE;

    if (!was_registered)
        remove_tap_listener_rtp_stream(tapinfo);
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/

/****************************************************************************/
void
remove_tap_listener_rtp_stream(rtpstream_tapinfo_t *tapinfo)
{
    if (tapinfo && tapinfo->is_registered) {
        remove_tap_listener(tapinfo);
        tapinfo->is_registered = FALSE;
    }
}


/****************************************************************************/
void
register_tap_listener_rtp_stream(rtpstream_tapinfo_t *tapinfo, const char *fstring)
{
    GString *error_string;

    if (!tapinfo) {
        return;
    }

    if (!tapinfo->is_registered) {
        error_string = register_tap_listener("rtp", tapinfo,
            fstring, 0, rtpstream_reset_cb, rtpstream_packet,
            rtpstream_draw);

        if (error_string != NULL) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                          "%s", error_string->str);
            g_string_free(error_string, TRUE);
            exit(1);
        }

        tapinfo->is_registered = TRUE;
    }
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
