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
#include "wsutil/os_version_info.h"
#include "wsutil/tempfile.h"
#include "wsutil/version_info.h"

#include <epan/tap.h>
#include <epan/prefs.h>
#include <epan/exported_pdu.h>
#include <epan/epan_dissect.h>
#include <wiretap/wtap.h>
#include <wiretap/wtap_opttypes.h>

#include "ui/alert_box.h"
#include "ui/simple_dialog.h"
#include "tap_export_pdu.h"
#include "export_pdu_ui_utils.h"

void
do_export_pdu(const char *filter, const char *temp_dir, const char *tap_name)
{
    exp_pdu_t exp_pdu_tap_data;
    char *error;
    int   import_file_fd;
    int   file_type_subtype;
    char *capfile_name = NULL, *comment;
    bool status;
    int   err;
    char *err_info;

    error = exp_pdu_pre_open(tap_name, filter, &exp_pdu_tap_data);
    if (error) {
        /* Error.  We failed to attach to the tap. Clean up */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error);
        g_free(error);
        return;
    }

    /* Choose a random name for the temporary import buffer */
    GError *err_tempfile = NULL;
    import_file_fd = create_tempfile(temp_dir, &capfile_name, "Wireshark_PDU_", NULL, &err_tempfile);
    if (import_file_fd < 0) {
        failure_alert_box("Temporary file could not be created: %s", err_tempfile->message);
        g_error_free(err_tempfile);
        g_free(capfile_name);
        return;
    }

    /* Write a pcapng file... */
    file_type_subtype = wtap_pcapng_file_type_subtype();
    /* ...with this comment */
    comment = ws_strdup_printf("Dump of PDUs from %s", cfile.filename);
    status = exp_pdu_open(&exp_pdu_tap_data, capfile_name, file_type_subtype,
                          import_file_fd, comment, &err, &err_info);
    g_free(comment);
    if (!status) {
        cfile_dump_open_failure_alert_box(capfile_name ? capfile_name : "temporary file",
                                          err, err_info, file_type_subtype);
        g_free(capfile_name);
        return;
    }

    /* Run the tap */
    cf_retap_packets(&cfile);

    if (!exp_pdu_close(&exp_pdu_tap_data, &err, &err_info)) {
        cfile_close_failure_alert_box(capfile_name, err, err_info);
        /*
         * XXX - remove the temporary file and don't open it as
         * the current capture?
         */
    }

    /* XXX: should this use the open_routine type in the cfile instead of WTAP_TYPE_AUTO? */
    if (cf_open(&cfile, capfile_name, WTAP_TYPE_AUTO, true /* temporary file */, &err) != CF_OK) {
        /* cf_open() has put up a dialog box for the error */
        g_free(capfile_name);
        return;
    }

    switch (cf_read(&cfile, /*reloading=*/false)) {
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

    g_free(capfile_name);
}
