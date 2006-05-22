/* file_dlg.c
 * Utilities to use when constructing file selection dialogs
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

#include <gtk/gtk.h>
#if 0
#include <gdk/gdkkeysyms.h>
#endif

#include <epan/filesystem.h>

#if 0
#include "globals.h"
#endif

#include "gtkglobals.h"
#include "gui_utils.h"
#if 0
#include "dlg_utils.h"
#endif
#include "file_dlg.h"
#include "keys.h"
#include "compat_macros.h"
#if 0
#include "main.h"
#endif

#include <string.h>
#if 0
#include <stdio.h>
#endif
#include <errno.h>

static gchar *last_open_dir = NULL;
static gboolean updated_last_open_dir = FALSE;

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION < 4) || GTK_MAJOR_VERSION < 2
static void file_selection_browse_ok_cb(GtkWidget *w, gpointer data);
#endif
static void file_selection_browse_destroy_cb(GtkWidget *win, GtkWidget* file_te);

/* Keys ... */
#define E_FS_CALLER_PTR_KEY       "fs_caller_ptr"

/* Create a file selection dialog box window that belongs to Wireshark's
   main window. */
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
GtkWidget *
file_selection_new(const gchar *title, file_selection_action_t action)
{
  GtkWidget *win;
  GtkFileChooserAction gtk_action;
  const gchar *ok_button_text;

  switch (action) {

  case FILE_SELECTION_OPEN:
    gtk_action = GTK_FILE_CHOOSER_ACTION_OPEN;
    ok_button_text = GTK_STOCK_OPEN;
    break;

  case FILE_SELECTION_READ_BROWSE:
    gtk_action = GTK_FILE_CHOOSER_ACTION_OPEN;
    ok_button_text = GTK_STOCK_OK;
    break;

  case FILE_SELECTION_SAVE:
    gtk_action = GTK_FILE_CHOOSER_ACTION_SAVE;
    ok_button_text = GTK_STOCK_SAVE;
    break;

  case FILE_SELECTION_WRITE_BROWSE:
    gtk_action = GTK_FILE_CHOOSER_ACTION_SAVE;
    ok_button_text = GTK_STOCK_OK;
    break;

  default:
    g_assert_not_reached();
    gtk_action = -1;
    ok_button_text = NULL;
    break;
  }
  win = gtk_file_chooser_dialog_new(title, GTK_WINDOW(top_level), gtk_action,
#ifndef _WIN32
                                    GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                    ok_button_text, GTK_RESPONSE_ACCEPT,
#else
                                    ok_button_text, GTK_RESPONSE_ACCEPT,
                                    GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
#endif
                                    NULL);

  /* If we've opened a file before, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    file_selection_set_current_folder(win, last_open_dir);

  return win;
}
#else
GtkWidget *
file_selection_new(const gchar *title, file_selection_action_t action _U_)
{
  GtkWidget *win;

  win = gtk_file_selection_new(title);
#if GTK_MAJOR_VERSION >= 2
  gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER_ON_PARENT);
#endif
  gtk_window_set_transient_for(GTK_WINDOW(win), GTK_WINDOW(top_level));

  /* XXX - why are we doing this?  We don't do it with the GtkFileChooser,
     as it complains that the file name isn't being set to an absolute
     path; does this provoke a similar complaint? */
  gtk_file_selection_set_filename(GTK_FILE_SELECTION(win), "");

  /* If we've opened a file before, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    file_selection_set_current_folder(win, last_open_dir);

  return win;
}
#endif

/* Set the current folder for a file selection dialog. */
gboolean
file_selection_set_current_folder(GtkWidget *fs, const gchar *filename)
{
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    gboolean ret;
    int filename_len = strlen(filename);
    gchar *new_filename;

    /* trim filename, so gtk_file_chooser_set_current_folder() likes it, see below */
    if (filename[filename_len -1] == G_DIR_SEPARATOR 
#ifdef _WIN32
        && filename_len > 3)    /* e.g. "D:\" */
#else
        && filename_len > 1)    /* e.g. "/" */
#endif
    {
        new_filename = g_strdup(filename);
        new_filename[filename_len-1] = '\0';
    } else {
        new_filename = g_strdup(filename);
    }

    /* this function is very pedantic about it's filename parameter */
    /* no trailing '\' allowed, unless a win32 root dir "D:\" */
    ret = gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(fs), new_filename);
    g_free(new_filename);
    return ret;
#else
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(fs), filename);
    return TRUE;
#endif
}

/* Set the "extra" widget for a file selection dialog, with user-supplied
   options. */
void
file_selection_set_extra_widget(GtkWidget *fs, GtkWidget *extra)
{
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  gtk_file_chooser_set_extra_widget(GTK_FILE_CHOOSER(fs), extra);
#else
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(fs)->action_area), extra,
                     FALSE, FALSE, 0);
#endif
}


/*
 * A generic select_file routine that is intended to be connected to
 * a Browse button on other dialog boxes. This allows the user to browse
 * for a file and select it. We fill in the text_entry that is given to us. 
 *
 * We display the window label specified in our args.
 */
void
file_selection_browse(GtkWidget *file_bt, GtkWidget *file_te, const char *label, file_selection_action_t action)
{
  GtkWidget *caller = gtk_widget_get_toplevel(file_bt);
  GtkWidget *fs;
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  gchar     *f_name;
#endif

  /* Has a file selection dialog box already been opened for that top-level
     widget? */
  fs = OBJECT_GET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY);
  if (fs != NULL) {
    /* Yes.  Just re-activate that dialog box. */
    reactivate_window(fs);
    return;
  }

  fs = file_selection_new(label, action);

  OBJECT_SET_DATA(fs, PRINT_FILE_TE_KEY, file_te);

  /* Set the E_FS_CALLER_PTR_KEY for the new dialog to point to our caller. */
  OBJECT_SET_DATA(fs, E_FS_CALLER_PTR_KEY, caller);

  /* Set the E_FILE_SEL_DIALOG_PTR_KEY for the caller to point to us */
  OBJECT_SET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY, fs);

  /* Call a handler when the file selection box is destroyed, so we can inform
     our caller, if any, that it's been destroyed. */
  SIGNAL_CONNECT(fs, "destroy", GTK_SIGNAL_FUNC(file_selection_browse_destroy_cb), 
		 file_te);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  if (gtk_dialog_run(GTK_DIALOG(fs)) == GTK_RESPONSE_ACCEPT)
  {
      f_name = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs)));
      gtk_entry_set_text(GTK_ENTRY(file_te), f_name);
      g_free(f_name);
  }
  window_destroy(fs);
#else
  SIGNAL_CONNECT(GTK_FILE_SELECTION(fs)->ok_button, "clicked", 
		 file_selection_browse_ok_cb, fs);

  window_set_cancel_button(fs, GTK_FILE_SELECTION(fs)->cancel_button,
                           window_cancel_button_cb);

  SIGNAL_CONNECT(fs, "delete_event", window_delete_event_cb, fs);

  gtk_widget_show(fs);
  window_present(fs);
#endif
}


#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION < 4) || GTK_MAJOR_VERSION < 2
static void
file_selection_browse_ok_cb(GtkWidget *w _U_, gpointer data)
{
  gchar     *f_name;
  GtkWidget *win = data;

  f_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (data)));

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(f_name) == EISDIR) {
        /* It's a directory - set the file selection box to display it. */
        set_last_open_dir(f_name);
        g_free(f_name);
        file_selection_set_current_folder(data, last_open_dir);
        return;
  }

  gtk_entry_set_text(GTK_ENTRY(OBJECT_GET_DATA(win, PRINT_FILE_TE_KEY)),
                     f_name);
  window_destroy(GTK_WIDGET(win));

  g_free(f_name);
}
#endif

static void
file_selection_browse_destroy_cb(GtkWidget *win, GtkWidget* parent_te)
{
  GtkWidget *caller;

  /* Get the widget that requested that we be popped up.
     (It should arrange to destroy us if it's destroyed, so
     that we don't get a pointer to a non-existent window here.) */
  caller = OBJECT_GET_DATA(win, E_FS_CALLER_PTR_KEY);

  /* Tell it we no longer exist. */
  OBJECT_SET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY, NULL);

  /* Give the focus to the file text entry widget so the user can just press
     Return to print to the file. */
  gtk_widget_grab_focus(parent_te);
}


void
set_last_open_dir(char *dirname)
{
	int len;
	gchar *new_last_open_dir;

	if (dirname) {
		len = strlen(dirname);
		if (dirname[len-1] == G_DIR_SEPARATOR) {
			new_last_open_dir = g_strconcat(dirname, NULL);
		}
		else {
			new_last_open_dir = g_strconcat(dirname,
				G_DIR_SEPARATOR_S, NULL);
		}

		if (last_open_dir == NULL ||
		    strcmp(last_open_dir, new_last_open_dir) != 0)
			updated_last_open_dir = TRUE;
	}
	else {
		new_last_open_dir = NULL;
		if (last_open_dir != NULL)
			updated_last_open_dir = TRUE;
	}

	if (last_open_dir) {
		g_free(last_open_dir);
	}
	last_open_dir = new_last_open_dir;
}

char *
get_last_open_dir(void)
{
    return last_open_dir;
}
