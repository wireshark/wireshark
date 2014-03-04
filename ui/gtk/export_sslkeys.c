/* export_sslkeys.c
 *
 * Export SSL Session Keys dialog
 * by Sake Blok <sake@euronet.nl> (20110526)
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

#include "config.h"

#include <ctype.h>
#include <string.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <wsutil/file_util.h>

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

#include <wsutil/filesystem.h>
#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include <epan/charsets.h>
#include <epan/prefs.h>

#include "ui/alert_box.h"
#include "ui/last_open_dir.h"
#include "ui/progress_dlg.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/ssl_key_export.h"
#include "ui/ui_util.h"

#include "ui/gtk/keys.h"
#include "ui/gtk/color_utils.h"
#include "ui/gtk/packet_win.h"
#include "ui/gtk/file_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/font_utils.h"
#include "ui/gtk/webbrowser.h"
#include "ui/gtk/main.h"
#include "ui/gtk/export_sslkeys.h"

#ifdef _WIN32
#include <gdk/gdkwin32.h>
#include <windows.h>
#include "ui/win32/file_dlg_win32.h"
#endif

/* save the SSL Session Keys */
static gboolean
savesslkeys_save_clicked_cb(char *file, gchar *keylist)
{
    int fd;

    fd = ws_open(file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0666);
    if (fd == -1) {
        open_failure_alert_box(file, errno, TRUE);
        return FALSE;
    }
    /*
     * Thanks, Microsoft, for not using size_t for the third argument to
     * _write().  Presumably this string will be <= 4GiB long....
     */
    if (ws_write(fd, keylist, (unsigned int)strlen(keylist)) < 0) {
        write_failure_alert_box(file, errno);
        ws_close(fd);
        return FALSE;
    }
    if (ws_close(fd) < 0) {
        write_failure_alert_box(file, errno);
        return FALSE;
    }

    g_free(keylist);
    return TRUE;
}


/* Launch the dialog box to put up the file selection box etc */
#ifdef _WIN32
void
savesslkeys_cb(GtkWidget * w _U_, gpointer data _U_)
{
    win32_export_sslkeys_file(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)));
    return;
}
#else
static char *
gtk_export_sslkeys_file(guint keylist_len)
{
    GtkWidget *savesslkeys_dlg;
    gchar *label;
    GtkWidget *dlg_lb;
    char *pathname;

    /*
     * Build the dialog box we need.
     */
    savesslkeys_dlg = file_selection_new("Wireshark: Export SSL Session Keys",
                                         GTK_WINDOW(top_level),
                                         FILE_SELECTION_SAVE);

    /* label */
    label = g_strdup_printf("Will save %u SSL Session %s to specified file.",
                            keylist_len, plurality(keylist_len, "key", "keys"));
    dlg_lb = gtk_label_new(label);
    g_free(label);
    file_selection_set_extra_widget(savesslkeys_dlg, dlg_lb);
    gtk_widget_show(dlg_lb);

    pathname = file_selection_run(savesslkeys_dlg);
    if (pathname == NULL) {
        /* User cancelled or closed the dialog. */
        return NULL;
    }

    /* We've crosed the Rubicon; get rid of the dialog box. */
    window_destroy(savesslkeys_dlg);

    return pathname;
}

void
savesslkeys_cb(GtkWidget * w _U_, gpointer data _U_)
{
    char *pathname;
    guint keylist_len;
    gchar *keylist;

    keylist_len = ssl_session_key_count();
    /* don't show up the dialog, if no data has to be saved */
    if (keylist_len==0) {
        /* shouldn't happen as the menu item should have been greyed out */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "There are no SSL Session Keys to save.");
        return;
    }

    /*
     * Retrieve the info we need
     */
    keylist = ssl_export_sessions();

    /*
     * Loop until the user either selects a file or gives up.
     */
    for (;;) {
        pathname = gtk_export_sslkeys_file(keylist_len);
        if (pathname == NULL) {
            /* User gave up. */
            break;
        }
        if (savesslkeys_save_clicked_cb(pathname, keylist)) {
            /* We succeeded. */
            g_free(pathname);
            break;
        }
        /* Dump failed; let the user select another file or give up. */
        g_free(pathname);
    }
}
#endif
