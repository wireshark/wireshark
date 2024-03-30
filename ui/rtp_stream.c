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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>
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
/* scan for RTP streams */
void
show_tap_registration_error(GString *error_string)
{
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "%s", error_string->str);
}

/****************************************************************************/
/* scan for RTP streams */
void rtpstream_scan(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, const char *fstring)
{
    bool was_registered;

    if (!tapinfo || !cap_file) {
        return;
    }

    was_registered = tapinfo->is_registered;
    if (!tapinfo->is_registered)
        register_tap_listener_rtpstream(tapinfo, fstring, show_tap_registration_error);

    /* RTP_STREAM_DEBUG("scanning %s, filter: %s", cap_file->filename, fstring); */
    tapinfo->mode = TAP_ANALYSE;
    cf_retap_packets(cap_file);

    if (!was_registered)
        remove_tap_listener_rtpstream(tapinfo);
}


/****************************************************************************/
/* save rtp dump of stream_fwd */
bool rtpstream_save(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtpstream_info_t* stream, const char *filename)
{
    bool was_registered;

    if (!tapinfo) {
        return false;
    }

    was_registered = tapinfo->is_registered;

    /* open file for saving */
    tapinfo->save_file = ws_fopen(filename, "wb");
    if (tapinfo->save_file==NULL) {
        open_failure_alert_box(filename, errno, true);
        return false;
    }

    rtp_write_header(stream, tapinfo->save_file);
    if (ferror(tapinfo->save_file)) {
        write_failure_alert_box(filename, errno);
        fclose(tapinfo->save_file);
        return false;
    }

    if (!tapinfo->is_registered)
        register_tap_listener_rtpstream(tapinfo, NULL, show_tap_registration_error);

    tapinfo->mode = TAP_SAVE;
    tapinfo->filter_stream_fwd = stream;
    cf_retap_packets(cap_file);
    tapinfo->mode = TAP_ANALYSE;

    if (!was_registered)
        remove_tap_listener_rtpstream(tapinfo);

    if (ferror(tapinfo->save_file)) {
        write_failure_alert_box(filename, errno);
        fclose(tapinfo->save_file);
        return false;
    }

    if (fclose(tapinfo->save_file) == EOF) {
        write_failure_alert_box(filename, errno);
        return false;
    }
    return true;
}

/****************************************************************************/
/* mark packets in stream_fwd or stream_rev */
void rtpstream_mark(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtpstream_info_t* stream_fwd, rtpstream_info_t* stream_rev)
{
    bool was_registered;

    if (!tapinfo) {
        return;
    }

    was_registered = tapinfo->is_registered;

    if (!tapinfo->is_registered)
        register_tap_listener_rtpstream(tapinfo, NULL, show_tap_registration_error);

    tapinfo->mode = TAP_MARK;
    tapinfo->filter_stream_fwd = stream_fwd;
    tapinfo->filter_stream_rev = stream_rev;
    cf_retap_packets(cap_file);
    tapinfo->mode = TAP_ANALYSE;

    if (!was_registered)
        remove_tap_listener_rtpstream(tapinfo);
}
