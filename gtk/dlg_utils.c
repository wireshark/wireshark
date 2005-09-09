/* dlg_utils.c
 * Utilities to use when constructing dialogs
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <gdk/gdkkeysyms.h>

#include <epan/filesystem.h>

#include "globals.h"

#include "gtkglobals.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "keys.h"
#include "compat_macros.h"
#include "main.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>


/* Keys ... */
#define E_FS_CALLER_PTR_KEY       "fs_caller_ptr"

static gchar *last_open_dir = NULL;
static gboolean updated_last_open_dir = FALSE;


static void
dlg_activate (GtkWidget *widget, gpointer ok_button);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION < 4) || GTK_MAJOR_VERSION < 2
static void file_selection_browse_ok_cb(GtkWidget *w, gpointer data);
#endif
static void file_selection_browse_destroy_cb(GtkWidget *win, GtkWidget* file_te);


/* create a button for the button row (helper for dlg_button_row_new) */
static GtkWidget *
dlg_button_new(GtkWidget *hbox, GtkWidget *button_hbox, const gchar *stock_id)
{
    GtkWidget *button;

    button = BUTTON_NEW_FROM_STOCK(stock_id);
    GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
    OBJECT_SET_DATA(hbox, stock_id, button);
    gtk_box_pack_end(GTK_BOX(button_hbox), button, FALSE, FALSE, 0);
    gtk_widget_show(button);
    return button;
}


/* create a button row for a dialog */

/* The purpose of this is, to have one place available, where all button rows 
 * from all dialogs are laid out. This will:
 *
 * a.) keep the button layout more consistent over the different dialogs
 * b.) being able to switch between different button layouts, e.g.:
 *     GTK1 (e.g. win32) "OK" "Apply" "Cancel"
 *     GTK2 (e.g. GNOME) "Apply" "Cancel" "OK"
 */
GtkWidget *
dlg_button_row_new(const gchar *stock_id_first, ...)
{
    gint        buttons = 0;
    va_list     stock_id_list;
    const gchar *stock_id = stock_id_first;
    GtkWidget   *hbox;
    GtkWidget   *button_hbox;
    GtkWidget   *help_hbox;
    GtkWidget   *button;

    const gchar *ok           = NULL;
    const gchar *apply        = NULL;
    const gchar *save         = NULL;
    const gchar *dont_save    = NULL;
    const gchar *cancel       = NULL;
    const gchar *close        = NULL;
    const gchar *clear        = NULL;
    const gchar *start        = NULL;
    const gchar *stop         = NULL;
    const gchar *create_stat  = NULL;
    const gchar *help         = NULL;
    const gchar *print        = NULL;
    const gchar *find         = NULL;
    const gchar *jump         = NULL;
    const gchar *yes          = NULL;
    const gchar *no           = NULL;


    va_start(stock_id_list, stock_id_first);

    /* get all buttons needed */
    while(stock_id != NULL) {
        if (strcmp(stock_id, GTK_STOCK_OK) == 0) {
            ok = stock_id;
        } else if (strcmp(stock_id, ETHEREAL_STOCK_CREATE_STAT) == 0) {
            create_stat = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_APPLY) == 0) {
            apply = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_SAVE) == 0) {
            save = stock_id;
        } else if (strcmp(stock_id, ETHEREAL_STOCK_DONT_SAVE) == 0) {
        	dont_save = stock_id;  
        } else if (strcmp(stock_id, GTK_STOCK_CANCEL) == 0) {
            cancel = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_CLOSE) == 0) {
            close = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_CLEAR) == 0) {
            clear = stock_id;
#ifdef HAVE_LIBPCAP
        } else if (strcmp(stock_id, ETHEREAL_STOCK_CAPTURE_START) == 0) {
            start = stock_id;
#endif /* HAVE_LIBPCAP */
        } else if (strcmp(stock_id, GTK_STOCK_STOP) == 0) {
            stop = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_HELP) == 0) {
            help = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_PRINT) == 0) {
            print = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_FIND) == 0) {
            find = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_JUMP_TO) == 0) {
            jump = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_YES) == 0) {
            yes = stock_id;
        } else if (strcmp(stock_id, GTK_STOCK_NO) == 0) {
            no = stock_id;
        } else {
            /* we don't know that button! */
            g_assert_not_reached();
        }
        buttons++;
        stock_id = va_arg(stock_id_list, gchar *);
    }
    va_end(stock_id_list);

    /* we should have at least one button */
    g_assert(buttons);


    hbox = gtk_hbox_new(FALSE, 0);
    gtk_widget_show(hbox);

    button_hbox = gtk_hbutton_box_new();
    gtk_box_pack_end(GTK_BOX(hbox), button_hbox, TRUE, TRUE, 0);
    gtk_widget_show(button_hbox);

    help_hbox = gtk_hbutton_box_new();
    gtk_box_pack_end(GTK_BOX(hbox), help_hbox, FALSE, FALSE, 0);
    gtk_widget_show(help_hbox);

    if (buttons == 1) {
        /* if only one button, simply put it in the middle (default) */
        dlg_button_new(hbox, button_hbox, stock_id_first);
        return hbox;
    }

    /* do we have a help button? -> special handling for it */
    if (help) {
        button = BUTTON_NEW_FROM_STOCK(help);
        GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
        OBJECT_SET_DATA(hbox, help, button);
        gtk_box_pack_start(GTK_BOX(help_hbox), button, FALSE, FALSE, 0);
        gtk_widget_show(button);
        buttons--;
    }

    /* if more than one button, sort buttons from left to right */
    /* (the whole button cluster will then be right aligned) */
    gtk_button_box_set_layout (GTK_BUTTON_BOX(button_hbox), GTK_BUTTONBOX_END);
    gtk_button_box_set_spacing(GTK_BUTTON_BOX(button_hbox), 5);

/* GTK+ 1.3 and later - on Win32, we use 1.3[.x] or 2.x, not 1.2[.x] */
#if !defined(_WIN32) && GTK_MAJOR_VERSION >= 2
    /* beware: sequence of buttons are important! */

    /* XXX: this can be implemented more elegant of course, but it works as it should */
    if (buttons == 2) {
        if (ok && cancel) {
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, ok);
            return hbox;
        }
        if (print && cancel) {
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, print);
            return hbox;
        }
        if (find && cancel) {
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, find);
            return hbox;
        }
        if (jump && cancel) {
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, jump);
            return hbox;
        }
        if (save && cancel) {
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, save);
            return hbox;
        }
        if (ok && clear) {
            dlg_button_new(hbox, button_hbox, clear);
            dlg_button_new(hbox, button_hbox, ok);
            return hbox;
        }
        if (save && close) {
            dlg_button_new(hbox, button_hbox, close);
            dlg_button_new(hbox, button_hbox, save);
            return hbox;
        }
        if (create_stat && cancel) {
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, create_stat);
            return hbox;
        }
        if (start && cancel) {
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, start);
            return hbox;
        }
    }
    if (buttons == 3) {
        if (ok && save && close) {
            dlg_button_new(hbox, button_hbox, save);
            dlg_button_new(hbox, button_hbox, close);
            dlg_button_new(hbox, button_hbox, ok);
            return hbox;
        }
        if (ok && apply && cancel) {
            dlg_button_new(hbox, button_hbox, apply);
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, ok);
            return hbox;
        }
        if (apply && save && close) {
            dlg_button_new(hbox, button_hbox, save);
            dlg_button_new(hbox, button_hbox, close);
            dlg_button_new(hbox, button_hbox, apply);
            return hbox;
        }
        if (yes && no && cancel) {
            dlg_button_new(hbox, button_hbox, no);
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, yes);
            return hbox;
        }
        if (save && dont_save && cancel) {
        	dlg_button_new(hbox, button_hbox, dont_save);
        	dlg_button_new(hbox, button_hbox, cancel);
        	dlg_button_new(hbox, button_hbox, save);
        	return hbox;
        }
    }
    if (buttons == 4) {
        if (ok && apply && save && cancel) {
            dlg_button_new(hbox, button_hbox, save);
            dlg_button_new(hbox, button_hbox, apply);
            dlg_button_new(hbox, button_hbox, cancel);
            dlg_button_new(hbox, button_hbox, ok);
            return hbox;
        }
        if (ok && apply && save && close) {
            dlg_button_new(hbox, button_hbox, save);
            dlg_button_new(hbox, button_hbox, apply);
            dlg_button_new(hbox, button_hbox, close);
            dlg_button_new(hbox, button_hbox, ok);
            return hbox;
        }
    }
#endif

    /* beware: sequence of buttons is important! */
    if (ok      != NULL) dlg_button_new(hbox, button_hbox, ok);
    if (jump    != NULL) dlg_button_new(hbox, button_hbox, jump);
    if (find    != NULL) dlg_button_new(hbox, button_hbox, find);
    if (print   != NULL) dlg_button_new(hbox, button_hbox, print);
    if (create_stat != NULL) dlg_button_new(hbox, button_hbox, create_stat);
    if (apply   != NULL) dlg_button_new(hbox, button_hbox, apply);
    if (yes     != NULL) dlg_button_new(hbox, button_hbox, yes);
    if (no      != NULL) dlg_button_new(hbox, button_hbox, no);
    if (save    != NULL) dlg_button_new(hbox, button_hbox, save);
    if (dont_save != NULL) dlg_button_new(hbox, button_hbox, dont_save);
    if (start   != NULL) dlg_button_new(hbox, button_hbox, start);
    if (stop    != NULL) dlg_button_new(hbox, button_hbox, stop);
    if (close   != NULL) dlg_button_new(hbox, button_hbox, close);
    if (clear   != NULL) dlg_button_new(hbox, button_hbox, clear);
    if (cancel  != NULL) dlg_button_new(hbox, button_hbox, cancel);

    /* GTK2: we don't know that button combination, add it to the above list! */
    /* g_assert_not_reached(); */
    return hbox;
}


/* this is called, when a dialog was closed */
static void dlg_destroy_cb(GtkWidget *dialog _U_, gpointer data	_U_)
{
#if GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION < 4
    if(top_level) {
        /* bring main window back to front (workaround for a bug in win32 GTK2.x)
           XXX - do this only on Windows? */
        gtk_window_present(GTK_WINDOW(top_level));
    }
#endif
}


/* Create a dialog box window that belongs to Ethereal's main window. */
GtkWidget *
dlg_window_new(const gchar *title)
{
  GtkWidget *win;

#if GTK_MAJOR_VERSION < 2
  win = window_new(GTK_WINDOW_DIALOG, title);
#else
  win = window_new(GTK_WINDOW_TOPLEVEL, title);
#endif

  /*
   * XXX - if we're running in the capture child process, we can't easily
   * make this window transient for the main process's window.  We just
   * punt here.
   *
   * Perhaps the child process should only capture packets, write them to
   * a file, and somehow notify the parent process and let *it* do all
   * the GUI work.  If we can do that efficiently (so that we don't drop
   * more packets), perhaps we can also do so even when we're *not* doing
   * an "Update list of packets in real time" capture.  That'd let the
   * child process run set-UID on platforms where you need that in order
   * to capture, and might also simplify the job of having the GUI main
   * loop wait both for user input and packet arrival.
   */
  if (top_level) {
    gtk_window_set_transient_for(GTK_WINDOW(win), GTK_WINDOW(top_level));
  }

  SIGNAL_CONNECT(win, "destroy", dlg_destroy_cb, NULL);

  return win;
}


/* Create a file selection dialog box window that belongs to Ethereal's
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

/* Set the "activate" signal for a widget to call a routine to
   activate the "OK" button for a dialog box.

   XXX - there should be a way to specify that a GtkEntry widget
   shouldn't itself handle the Return key, but should let it be
   passed on to the parent, so that you don't have to do this
   by hand for every GtkEntry widget in a dialog box, but, alas,
   there isn't.  (Does this problem exist for other widgets?
   I.e., are there any others that seize the Return key? */
void
dlg_set_activate(GtkWidget *widget, GtkWidget *ok_button)
{
  SIGNAL_CONNECT(widget, "activate", dlg_activate, ok_button);
}

static void
dlg_activate (GtkWidget *widget _U_, gpointer ok_button)
{
  gtk_widget_activate(GTK_WIDGET(ok_button));
}

#if GTK_MAJOR_VERSION < 2
/* Sigh.  GTK+ appears not to acknowledge that it should be possible
   to attach mnemonics to anything other than menu items; provide
   routines to create radio and check buttons with labels that
   include mnemonics.  */
typedef struct {
	GtkWidget *button;
	GtkAccelGroup *accel_group;
} fix_label_args_t;

static void
dlg_fix_label_callback(GtkWidget *label_widget, gpointer data)
{
  fix_label_args_t *args = data;
  gchar *label;
  guint accel_key;

  gtk_label_get(GTK_LABEL(label_widget), &label);
  accel_key = gtk_label_parse_uline(GTK_LABEL(label_widget), label);
  if (accel_key != GDK_VoidSymbol) {
    /* Yes, we have a mnemonic. */
    gtk_widget_add_accelerator(args->button, "clicked", args->accel_group,
				accel_key, 0, GTK_ACCEL_LOCKED);
    gtk_widget_add_accelerator(args->button, "clicked", args->accel_group,
				accel_key, GDK_MOD1_MASK, GTK_ACCEL_LOCKED);
  }
}

static void
dlg_fix_button_label(GtkWidget *button, GtkAccelGroup *accel_group)
{
  fix_label_args_t args;

  args.button = button;
  args.accel_group = accel_group;
  gtk_container_foreach(GTK_CONTAINER(button), dlg_fix_label_callback, &args);
}

GtkWidget *
dlg_radio_button_new_with_label_with_mnemonic(GSList *group,
		const gchar *label, GtkAccelGroup *accel_group)
{
  GtkWidget *radio_button;

  radio_button = gtk_radio_button_new_with_label (group, label);
  dlg_fix_button_label(radio_button, accel_group);
  return radio_button;
}

GtkWidget *
dlg_check_button_new_with_label_with_mnemonic(const gchar *label,
			GtkAccelGroup *accel_group)
{
  GtkWidget *check_button;

  check_button = gtk_check_button_new_with_label (label);
  dlg_fix_button_label(check_button, accel_group);
  return check_button;
}

GtkWidget *
dlg_toggle_button_new_with_label_with_mnemonic(const gchar *label,
			GtkAccelGroup *accel_group)
{
  GtkWidget *toggle_button;

  toggle_button = gtk_toggle_button_new_with_label (label);
  dlg_fix_button_label(toggle_button, accel_group);
  return toggle_button;
}
#endif
