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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/addr_resolv.h>

#include "../globals.h"
#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "ui/rtp_stream.h"
#include "ui/tap-rtp-common.h"
#include <wsutil/file_util.h>

#include "ui/rtp_stream.h"
#include "ui/gtk/rtp_stream_dlg.h"
#include "ui/gtk/main.h"

/* The one and only global rtpstream_tapinfo_t structure for tshark and wireshark.
 */
static rtpstream_tapinfo_t the_tapinfo_struct =
        {0, NULL, 0, TAP_ANALYSE, NULL, NULL, NULL, 0, FALSE};


/****************************************************************************/
/* redraw the output */
static void rtpstream_draw(void *arg _U_)
{
/* XXX: see rtpstream_on_update in rtp_streams_dlg.c for comments
	g_signal_emit_by_name(top_level, "signal_rtpstream_update");
*/
	rtpstream_dlg_update(the_tapinfo_struct.strinfo_list);
	return;
}


/****************************************************************************/
/* scan for RTP streams */
void rtpstream_scan(void)
{
	gboolean was_registered = the_tapinfo_struct.is_registered;
	if (!the_tapinfo_struct.is_registered)
		register_tap_listener_rtp_stream();

	the_tapinfo_struct.mode = TAP_ANALYSE;
	cf_retap_packets(&cfile);

	if (!was_registered)
		remove_tap_listener_rtp_stream();
}


/****************************************************************************/
/* save rtp dump of stream_fwd */
gboolean rtpstream_save(rtp_stream_info_t* stream, const gchar *filename)
{
	gboolean was_registered = the_tapinfo_struct.is_registered;
	/* open file for saving */
	the_tapinfo_struct.save_file = ws_fopen(filename, "wb");
	if (the_tapinfo_struct.save_file==NULL) {
		open_failure_alert_box(filename, errno, TRUE);
		return FALSE;
	}

	rtp_write_header(stream, the_tapinfo_struct.save_file);
	if (ferror(the_tapinfo_struct.save_file)) {
		write_failure_alert_box(filename, errno);
		fclose(the_tapinfo_struct.save_file);
		return FALSE;
	}

	if (!the_tapinfo_struct.is_registered)
		register_tap_listener_rtp_stream();

	the_tapinfo_struct.mode = TAP_SAVE;
	the_tapinfo_struct.filter_stream_fwd = stream;
	cf_retap_packets(&cfile);
	the_tapinfo_struct.mode = TAP_ANALYSE;

	if (!was_registered)
		remove_tap_listener_rtp_stream();

	if (ferror(the_tapinfo_struct.save_file)) {
		write_failure_alert_box(filename, errno);
		fclose(the_tapinfo_struct.save_file);
		return FALSE;
	}

	if (fclose(the_tapinfo_struct.save_file) == EOF) {
		write_failure_alert_box(filename, errno);
		return FALSE;
	}
	return TRUE;
}


/****************************************************************************/
/* mark packets in stream_fwd or stream_rev */
void rtpstream_mark(rtp_stream_info_t* stream_fwd, rtp_stream_info_t* stream_rev)
{
	gboolean was_registered = the_tapinfo_struct.is_registered;
	if (!the_tapinfo_struct.is_registered)
		register_tap_listener_rtp_stream();

	the_tapinfo_struct.mode = TAP_MARK;
	the_tapinfo_struct.filter_stream_fwd = stream_fwd;
	the_tapinfo_struct.filter_stream_rev = stream_rev;
	cf_retap_packets(&cfile);
	the_tapinfo_struct.mode = TAP_ANALYSE;

	if (!was_registered)
		remove_tap_listener_rtp_stream();
}


/****************************************************************************/
const rtpstream_tapinfo_t* rtpstream_get_info(void)
{
	return &the_tapinfo_struct;
}


/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/

/****************************************************************************/
void
remove_tap_listener_rtp_stream(void)
{
	if (the_tapinfo_struct.is_registered) {
		remove_tap_listener(&the_tapinfo_struct);

		the_tapinfo_struct.is_registered = FALSE;
	}
}


/****************************************************************************/
void
register_tap_listener_rtp_stream(void)
{
	GString *error_string;

	if (!the_tapinfo_struct.is_registered) {
		error_string = register_tap_listener("rtp", &the_tapinfo_struct,
			NULL, 0, rtpstream_reset_cb, rtpstream_packet,
			rtpstream_draw);

		if (error_string != NULL) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "%s", error_string->str);
			g_string_free(error_string, TRUE);
			exit(1);
		}

		the_tapinfo_struct.is_registered = TRUE;
	}
}
