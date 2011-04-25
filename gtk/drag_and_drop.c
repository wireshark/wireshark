/* drag_and_drop.c
 * Drag and Drop
 *
 * $Id$
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <string.h>
#include <stdio.h>

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "../util.h"
#include "../file.h"
#include "../simple_dialog.h"
#ifdef HAVE_LIBPCAP
#include "../capture.h"
#endif

#include "gtk/gtkglobals.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/drag_and_drop.h"
#include "gtk/main.h"
#include "gtk/menus.h"
#ifdef HAVE_LIBPCAP
#include "gtk/capture_globals.h"
#endif

#ifdef HAVE_GTKOSXAPPLICATION
#include <igemacintegration/gtkosxapplication.h>
#endif

enum { DND_TARGET_STRING, DND_TARGET_ROOTWIN, DND_TARGET_URL };

/* convert drag and drop URI to a local filename */
static gchar *
dnd_uri2filename(gchar *cf_name)
{
    gchar     *src, *dest;
    gint      ret;
    guint     i;
    gchar     esc[3];


    /* Remove URI header.
     * we have to remove the prefix to get a valid filename. */
#ifdef _WIN32
    /*
     * On win32 (at least WinXP), this prefix looks like (UNC):
     * file:////servername/sharename/dir1/dir2/capture-file.cap
     * or (local filename):
     * file:///d:/dir1/dir2/capture-file.cap
     */
    if (strncmp("file:////", cf_name, 9) == 0) {
        /* win32 UNC: now becoming: //servername/sharename/dir1/dir2/capture-file.cap */
        cf_name += 7;
    } else if (strncmp("file:///", cf_name, 8) == 0) {
        /* win32 local: now becoming: d:/dir1/dir2/capture-file.cap */
        cf_name += 8;
    }
#else
    /*
     * On UNIX (at least KDE 3.0 Konqueror), this prefix looks like:
     * file:/dir1/dir2/capture-file.cap
     *
     * On UNIX (at least GNOME Nautilus 2.8.2), this prefix looks like:
     * file:///dir1/dir2/capture-file.cap
     */
    if (strncmp("file:", cf_name, 5) == 0) {
        /* now becoming: /dir1/dir2/capture-file.cap or ///dir1/dir2/capture-file.cap */
        cf_name += 5;
        /* shorten //////thing to /thing */
        for(; cf_name[1] == '/'; ++cf_name);
    }
#endif

    /*
     * unescape the escaped URI characters (spaces, ...)
     *
     * we have to replace escaped chars to their equivalents,
     * e.g. %20 (always a two digit hexstring) -> ' '
     * the percent character '%' is escaped be a double one "%%"
     *
     * we do this conversation "in place" as the result is always
     * equal or smaller in size.
     */
    src = cf_name;
    dest = cf_name;
    while (*src) {
        if (*src == '%') {
            src++;
            if (*src == '%') {
                /* this is an escaped '%' char (was: "%%") */
                *dest = *src;
                src++;
                dest++;
            } else {
                /* convert escaped hexnumber to unscaped character */
                esc[0] = src[0];
                esc[1] = src[1];
                esc[2] = '\0';
                ret = sscanf(esc, "%x", &i);
                if (ret == 1) {
                    src+=2;
                    *dest = (gchar) i;
                    dest++;
                } else {
                    /* somethings wrong, just jump over that char
                     * this will result in a wrong string, but we might get
                     * user feedback and can fix it later ;-) */
                    src++;
                }
            }
        } else {
            *dest = *src;
            src++;
            dest++;
        }
    }
    *dest = '\0';

    return cf_name;
}

static void
dnd_merge_files(int in_file_count, char **in_filenames)
{
    char *tmpname;
    cf_status_t merge_status;
    int err;

    /* merge the files in chonological order */
    tmpname = NULL;
    merge_status = cf_merge_files(&tmpname, in_file_count, in_filenames,
                              WTAP_FILE_PCAP, FALSE);

    if (merge_status != CF_OK) {
        /* merge failed */
        g_free(tmpname);
	return;
    }

    cf_close(&cfile);

    /* Try to open the merged capture file. */
    if (cf_open(&cfile, tmpname, TRUE /* temporary file */, &err) != CF_OK) {
	/* We couldn't open it; don't dismiss the open dialog box,
	   just leave it around so that the user can, after they
	   dismiss the alert box popped up for the open error,
	   try again. */
	g_free(tmpname);
	return;
    }
    g_free(tmpname);

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
	return;
    }
}

/* open/merge the dnd file */
void
dnd_open_file_cmd(gchar *cf_names_freeme)
{
    int       err;
    gchar     *cf_name;
    int       in_files;
    GString   *dialog_text;
    int       files_work;
    char      **in_filenames;


    /* DND_TARGET_URL on Win32:
     * The cf_name_freeme is a single string, containing one or more URI's,
     * seperated by CR/NL chars. The length of the whole field can be found
     * in the selection_data->length field. If it contains one file, simply open it,
     * If it contains more than one file, ask to merge these files. */

    /* count the number of input files */
    cf_name = cf_names_freeme;
    for(in_files = 0; (cf_name = strstr(cf_name, "\r\n")) != NULL; ) {
        cf_name += 2;
        in_files++;
    }

    in_filenames = g_malloc(sizeof(char*) * in_files);

    /* store the starts of the file entries in a gchar array */
    cf_name = cf_names_freeme;
    in_filenames[0] = cf_name;
    for(files_work = 1; (cf_name = strstr(cf_name, "\r\n")) != NULL && files_work < in_files; ) {
        cf_name += 2;
        in_filenames[files_work] = cf_name;
        files_work++;
    }

    /* replace trailing CR NL simply with zeroes (in place), so we get valid terminated strings */
    cf_name = cf_names_freeme;
    g_strdelimit(cf_name, "\r\n", '\0');

    /* convert all filenames from URI to local filename (in place) */
    for(files_work = 0; files_work < in_files; files_work++) {
        in_filenames[files_work] = dnd_uri2filename(in_filenames[files_work]);
    }

    switch(in_files) {
    case(0):
        /* shouldn't happen */
        break;
    case(1):
        /* open and read the capture file (this will close an existing file) */
        if (cf_open(&cfile, in_filenames[0], FALSE, &err) == CF_OK) {
          /* XXX - add this to the menu if the read fails? */
          cf_read(&cfile, FALSE);
          add_menu_recent_capture_file(in_filenames[0]);
	} else {
          /* the capture file couldn't be read (doesn't exist, file format unknown, ...) */
	}
        break;
    default:
        /* build and show the info dialog */
        dialog_text = g_string_sized_new(200);
        g_string_printf(dialog_text,
            "%sMerging the following files:%s\n\n",
            simple_dialog_primary_start(), simple_dialog_primary_end());
        for(files_work = 0; files_work < in_files; files_work++) {
            g_string_append(dialog_text, in_filenames[files_work]);
            g_string_append(dialog_text, "\n");
        }
        g_string_append(dialog_text, "\nThe packets in these files will be merged chronologically into a new temporary file.");
        simple_dialog(ESD_TYPE_CONFIRMATION,
                    ESD_BTN_OK, "%s",
                    dialog_text->str);
        g_string_free(dialog_text, TRUE);

        /* actually merge the files now */
        dnd_merge_files(in_files, in_filenames);
    }

    g_free(in_filenames);
    g_free(cf_names_freeme);
}

/* ask the user to save current unsaved file, before opening the dnd file */
static void
dnd_save_file_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
    switch(btn) {
    case(ESD_BTN_SAVE):
        /* save file first */
        file_save_as_cmd(after_save_open_dnd_file, data);
        break;
    case(ESD_BTN_DONT_SAVE):
        cf_close(&cfile);
        dnd_open_file_cmd(data);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}


/* we have received some drag and drop data */
/* (as we only registered to "text/uri-list", we will only get a file list here) */
static void
dnd_data_received(GtkWidget *widget _U_, GdkDragContext *dc _U_, gint x _U_, gint y _U_,
                  GtkSelectionData *selection_data, guint info, guint t _U_, gpointer data _U_)
{
    gpointer  dialog;
    gchar *cf_names_freeme;
    const guchar *sel_data_data;
    gint sel_data_len;

    if (info == DND_TARGET_URL) {
        /* Usually we block incoming events by disabling the corresponding menu/toolbar items.
         * This is the only place where an incoming event won't be blocked in such a way,
         * so we have to take care of NOT loading a new file while a different process
         * (e.g. capture/load/...) is still in progress. */

#ifdef HAVE_LIBPCAP
        /* if a capture is running, do nothing but warn the user */
        if((global_capture_opts.state != CAPTURE_STOPPED)) {
            simple_dialog(ESD_TYPE_CONFIRMATION,
                        ESD_BTN_OK,
                        "%sDrag and Drop currently not possible!%s\n\n"
                        "Dropping a file isn't possible while a capture is in progress.",
                        simple_dialog_primary_start(), simple_dialog_primary_end());
            return;
        }
#endif

        /* if another file read is still in progress, do nothing but warn the user */
        if(cfile.state == FILE_READ_IN_PROGRESS) {
            simple_dialog(ESD_TYPE_CONFIRMATION,
                        ESD_BTN_OK,
                        "%sDrag and Drop currently not possible!%s\n\n"
                        "Dropping a file isn't possible while loading another capture file.",
                        simple_dialog_primary_start(), simple_dialog_primary_end());
            return;
        }

	/* the selection_data will soon be gone, make a copy first */
	/* the data string is not zero terminated -> make a zero terminated "copy" of it */
#if GTK_CHECK_VERSION(2,14,0)
	sel_data_len = gtk_selection_data_get_length(selection_data);
	sel_data_data = gtk_selection_data_get_data(selection_data);
#else
	sel_data_len = selection_data->length;
	sel_data_data = selection_data->data;
#endif
	cf_names_freeme = g_malloc(sel_data_len + 1);
	memcpy(cf_names_freeme, sel_data_data, sel_data_len);
	cf_names_freeme[sel_data_len] = '\0';

        /* ask the user to save it's current capture file first */
        if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
            /* user didn't saved his current file, ask him */
            dialog = simple_dialog(ESD_TYPE_CONFIRMATION,
                        ESD_BTNS_SAVE_DONTSAVE_CANCEL,
                        "%sSave capture file before opening a new one?%s\n\n"
                        "If you open a new capture file without saving, your current capture data will be discarded.",
                        simple_dialog_primary_start(), simple_dialog_primary_end());
            simple_dialog_set_cb(dialog, dnd_save_file_answered_cb, cf_names_freeme );
        } else {
            /* unchanged file */
            dnd_open_file_cmd( cf_names_freeme );
        }
    }
}

#ifdef HAVE_GTKOSXAPPLICATION
gboolean
gtk_osx_openFile (GtkOSXApplication *app _U_, gchar *path, gpointer user_data _U_)
{
    GtkSelectionData selection_data;
    int length = strlen(path);
	
    selection_data.length = length + 3;
    selection_data.data = g_malloc(length + 3);
    memcpy(selection_data.data, path, length);
	
    selection_data.data[length] = '\r';
    selection_data.data[length + 1] = '\n';
    selection_data.data[length + 2] = '\0';
	
    dnd_data_received(NULL, NULL, 0, 0, &selection_data, DND_TARGET_URL, 0, 0);
	
    g_free(selection_data.data);
	
    return TRUE;
}
#endif

/* init the drag and drop functionality */
void
dnd_init(GtkWidget *w)
{
    /* we are only interested in the URI list containing filenames */
    static GtkTargetEntry target_entry[] = {
         /*{"STRING", 0, DND_TARGET_STRING},*/
         /*{"text/plain", 0, DND_TARGET_STRING},*/
         {"text/uri-list", 0, DND_TARGET_URL}
    };

    /* set this window as a dnd destination */
    gtk_drag_dest_set(
         w, GTK_DEST_DEFAULT_ALL, target_entry,
         sizeof(target_entry) / sizeof(GtkTargetEntry),
         (GdkDragAction)(GDK_ACTION_MOVE | GDK_ACTION_COPY) );

    /* get notified, if some dnd coming in */
    g_signal_connect(w, "drag_data_received", G_CALLBACK(dnd_data_received), NULL);
#ifdef HAVE_GTKOSXAPPLICATION	
    g_signal_connect(g_object_new(GTK_TYPE_OSX_APPLICATION, NULL), "NSApplicationOpenFile", G_CALLBACK(gtk_osx_openFile), NULL);
#endif
}


