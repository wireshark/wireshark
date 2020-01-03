/*
 * export_pdu_ui_utils.c
 * Routines for exported_pdu dissection
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "globals.h"
#include "wiretap/pcap-encap.h"
#include "wsutil/os_version_info.h"
#include "wsutil/tempfile.h"
#include "version_info.h"

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
    char *capfile_name, *comment;
    int   err;

    /* Choose a random name for the temporary import buffer */
    GError *err_tempfile = NULL;
    import_file_fd = create_tempfile(&capfile_name, "Wireshark_PDU_", NULL, &err_tempfile);
    if (import_file_fd < 0) {
        failure_alert_box("Temporary file could not be created: %s", err_tempfile->message);
        g_error_free(err_tempfile);
        goto end;
    }

    comment = g_strdup_printf("Dump of PDUs from %s", cfile.filename);
    err = exp_pdu_open(exp_pdu_tap_data, import_file_fd, comment);
    g_free(comment);
    if (err != 0) {
        cfile_dump_open_failure_alert_box(capfile_name ? capfile_name : "temporary file",
                                          err, WTAP_FILE_TYPE_SUBTYPE_PCAPNG);
        goto end;
    }

    /* Run the tap */
    cf_retap_packets(&cfile);

    err = exp_pdu_close(exp_pdu_tap_data);
    if (err!= 0) {
        cfile_close_failure_alert_box(capfile_name, err);
    }

    /* XXX: should this use the open_routine type in the cfile instead of WTAP_TYPE_AUTO? */
    if (cf_open(&cfile, capfile_name, WTAP_TYPE_AUTO, TRUE /* temporary file */, &err) != CF_OK) {
        /* cf_open() has put up a dialog box for the error */
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
do_export_pdu(const char *filter, const gchar *tap_name, exp_pdu_t *exp_pdu_tap_data)
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
