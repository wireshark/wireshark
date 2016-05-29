/*
* export_pdu_ui_utils.c
* Routines for exported_pdu dissection
* Copyright 2013, Anders Broman <anders-broman@ericsson.com>
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "config.h"

#include "globals.h"
#include "wiretap/pcap-encap.h"
#include "wsutil/os_version_info.h"
#include "wsutil/tempfile.h"
#include "ws_version_info.h"

#include <epan/tap.h>
#include <epan/exported_pdu.h>
#include <epan/epan_dissect.h>
#include <wiretap/wtap.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "tap_export_pdu.h"
#include "export_pdu_ui_utils.h"

static void
exp_pdu_file_open(exp_pdu_t *exp_pdu_tap_data)
{
    int   import_file_fd;
    char *tmpname, *capfile_name;
    int   err;

    /* Choose a random name for the temporary import buffer */
    import_file_fd = create_tempfile(&tmpname, "Wireshark_PDU_", NULL);
    capfile_name = g_strdup(tmpname);

    err = exp_pdu_open(exp_pdu_tap_data, import_file_fd,
        g_strdup_printf("Dump of PDUs from %s", cfile.filename));
    if (err != 0) {
        open_failure_alert_box(capfile_name ? capfile_name : "temporary file", err, TRUE);
        goto end;
    }

    /* Run the tap */
    cf_retap_packets(&cfile);

    err = exp_pdu_close(exp_pdu_tap_data);
    if (err!= 0) {
        write_failure_alert_box(capfile_name, err);
    }

    /* XXX: should this use the open_routine type in the cfile instead of WTAP_TYPE_AUTO? */
    if (cf_open(&cfile, capfile_name, WTAP_TYPE_AUTO, TRUE /* temporary file */, &err) != CF_OK) {
        open_failure_alert_box(capfile_name, err, FALSE);
        goto end;
    }

    switch (cf_read(&cfile, FALSE)) {
    case CF_READ_OK:
    case CF_READ_ERROR:
        /* Just because we got an error, that doesn't mean we were unable
        to read any of the file; we handle what we could get from the
        file. */
        break;

    case CF_READ_ABORTED:
        /* The user bailed out of re-reading the capture file; the
        capture file has been closed - just free the capture file name
        string and return (without changing the last containing
        directory). */
        break;
    }

end:
    g_free(capfile_name);
}

gboolean
do_export_pdu(const char *filter, gchar *tap_name, exp_pdu_t *exp_pdu_tap_data)
{
    char *error;
    error = exp_pdu_pre_open(tap_name, filter, exp_pdu_tap_data);
    if (error) {
        /* Error.  We failed to attach to the tap. Clean up */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error);
        g_free(error);
        return FALSE;
    }

    exp_pdu_file_open(exp_pdu_tap_data);

    return TRUE;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
