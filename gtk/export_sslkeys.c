/* export_sslkeys.c
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * 
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <ctype.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif
#include <wsutil/file_util.h>

#include <string.h>


#include <epan/filesystem.h>
#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include <epan/charsets.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-ssl.h>
#include <epan/dissectors/packet-ssl-utils.h>

#include "../simple_dialog.h"
#include "../isprint.h"
#include "../alert_box.h"
#include "../progress_dlg.h"
#include "../ui_util.h"

#include "gtk/keys.h"
#include "gtk/color_utils.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/packet_win.h"
#include "gtk/file_dlg.h"
#include "gtk/gui_utils.h"
#include "gtk/gtkglobals.h"
#include "gtk/font_utils.h"
#include "gtk/webbrowser.h"
#include "gtk/main.h"
#include "gtk/menus.h"
#include "gtk/recent.h"
#include "gtk/export_sslkeys.h"

#ifdef _WIN32
#include <gdk/gdkwin32.h>
#include <windows.h>
#include "win32/file_dlg_win32.h"
#endif

static void
ssl_export_sessions_func(gpointer key, gpointer value, gpointer user_data)
{
    guint i;
    size_t offset;
    StringInfo* sslid = (StringInfo*)key;
    StringInfo* mastersecret = (StringInfo*)value;
    StringInfo* keylist = (StringInfo*)user_data;

    offset = strlen(keylist->data);
    
    /*
     * XXX - should this be a string that grows as necessary to hold
     * everything in it?
     */
    g_snprintf(keylist->data+offset,(gulong)(keylist->data_len-offset),"RSA Session-ID:");
    offset += 15;

    for( i=0; i<sslid->data_len; i++) {
        g_snprintf(keylist->data+offset,(gulong)(keylist->data_len-offset),"%.2x",sslid->data[i]&255);
        offset += 2;
    }

    g_snprintf(keylist->data+offset,(gulong)(keylist->data_len-offset)," Master-Key:");
    offset += 12;

    for( i=0; i<mastersecret->data_len; i++) {
        g_snprintf(keylist->data+offset,(gulong)(keylist->data_len-offset),"%.2x",mastersecret->data[i]&255);
        offset += 2;
    }

    g_snprintf(keylist->data+offset,(gulong)(keylist->data_len-offset),"\n");
}

StringInfo*
ssl_export_sessions(GHashTable *session_hash)
{
    StringInfo* keylist;

    /* Output format is:
     * "RSA Session-ID:xxxx Master-Key:yyyy\n"
     * Where xxxx is the session ID in hex (max 64 chars)
     * Where yyyy is the Master Key in hex (always 96 chars)
     * So in total max 3+1+11+64+1+11+96+2 = 189 chars
     */
    keylist = g_malloc0(sizeof(StringInfo)+189*g_hash_table_size (session_hash));
    keylist->data = ((guchar*)keylist+sizeof(StringInfo));
    keylist->data_len = sizeof(StringInfo)+189*g_hash_table_size (session_hash);

    g_hash_table_foreach(session_hash, ssl_export_sessions_func, (gpointer)keylist);

    return keylist;
}
static GtkWidget *savesslkeys_dlg=NULL;

static void
savesslkeys_dlg_destroy_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
    savesslkeys_dlg = NULL;
}

/* save the SSL Session Keys */
static gboolean
savesslkeys_save_clicked_cb(GtkWidget * w _U_, gpointer data _U_)
{
    int fd;
    char *file;
    StringInfo *keylist;

    file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(savesslkeys_dlg));

    if (test_for_directory(file) == EISDIR) {
        /* It's a directory - set the file selection box to display that
           directory, and leave the selection box displayed. */
        set_last_open_dir(file);
        g_free(file);
        file_selection_set_current_folder(savesslkeys_dlg, get_last_open_dir());
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(savesslkeys_dlg), "");
        return FALSE; /* do gtk_dialog_run again */
    }

    /* XXX: Must check if file name exists first */

    /*
     * Retrieve the info we need
     */
    keylist = ssl_export_sessions(ssl_session_hash);

    if (keylist->data_len == 0 ) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "No SSL Session Keys to export!");
        g_free(keylist);
        g_free(file);
        return TRUE;
    }

    fd = ws_open(file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0666);
    if (fd == -1) {
        open_failure_alert_box(file, errno, TRUE);
        g_free(keylist);
        g_free(file);
        return TRUE;
    }
    /*
     * Thanks, Microsoft, for not using size_t for the third argument to
     * _write().  Presumably this string will be <= 4GiB long....
     */
    if (ws_write(fd, keylist->data, (unsigned int)strlen(keylist->data)) < 0) {
        write_failure_alert_box(file, errno);
        ws_close(fd);
        g_free(keylist);
        g_free(file);
        return TRUE;
    }
    if (ws_close(fd) < 0) {
        write_failure_alert_box(file, errno);
        g_free(keylist);
        g_free(file);
        return TRUE;
    }

    /* Get rid of the dialog box */
    g_free(keylist);
    g_free(file);
    return TRUE;
}


/* Launch the dialog box to put up the file selection box etc */
#ifdef _WIN32
void
savesslkeys_cb(GtkWidget * w _U_, gpointer data _U_)
{
    win32_export_sslkeys_file(GDK_WINDOW_HWND(top_level->window));
    return;
}
#else
void
savesslkeys_cb(GtkWidget * w _U_, gpointer data _U_)
{
    gchar *label;
    GtkWidget   *dlg_lb;
    guint keylist_len;

    keylist_len = g_hash_table_size(ssl_session_hash);
    /* don't show up the dialog, if no data has to be saved */
    if (keylist_len==0) {
        /* shouldn't happen as the menu item should have been greyed out */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "There are no SSL Session Keys to save!");
        return;
    }


    /*
     * Build the dialog box we need.
     */
    savesslkeys_dlg = file_selection_new("Wireshark: Export SSL Session Keys", FILE_SELECTION_SAVE);
#if GTK_CHECK_VERSION(2,8,0)
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(savesslkeys_dlg), TRUE);
#endif

    /* label */
    label = g_strdup_printf("Will save %u SSL Session %s to specified file.",
                            keylist_len, plurality(keylist_len, "key", "keys"));
    dlg_lb = gtk_label_new(label);
    g_free(label);
    file_selection_set_extra_widget(savesslkeys_dlg, dlg_lb);
    gtk_widget_show(dlg_lb);

    g_signal_connect(savesslkeys_dlg, "destroy", G_CALLBACK(savesslkeys_dlg_destroy_cb), NULL);

    /* "Run" the GtkFileChooserDialog.                                              */
    /* Upon exit: If "Accept" run the OK callback.                                  */
    /*            If the OK callback returns with a FALSE status, re-run the dialog.*/
    /*            If not accept (ie: cancel) destroy the window.                    */
    /* XXX: If the OK callback pops up an alert box (eg: for an error) it *must*    */
    /*      return with a TRUE status so that the dialog window will be destroyed.  */
    /*      Trying to re-run the dialog after popping up an alert box will not work */
    /*       since the user will not be able to dismiss the alert box.              */
    /*      The (somewhat unfriendly) effect: the user must re-invoke the           */
    /*      GtkFileChooserDialog whenever the OK callback pops up an alert box.     */
    /*                                                                              */
    /*      ToDo: use GtkFileChooserWidget in a dialog window instead of            */
    /*            GtkFileChooserDialog.                                             */
    while (gtk_dialog_run(GTK_DIALOG(savesslkeys_dlg)) == GTK_RESPONSE_ACCEPT) {
        if (savesslkeys_save_clicked_cb(NULL, savesslkeys_dlg)) {
            break; /* we're done */
        }
    }
    window_destroy(savesslkeys_dlg);
}
#endif
