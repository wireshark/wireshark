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
#if 0
#include <gdk/gdkkeysyms.h>
#endif

#if 0
#include <epan/filesystem.h>
#endif

#if 0
#include "globals.h"
#endif

#include "gtkglobals.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "compat_macros.h"
#if 0
#include "main.h"
#endif

#include <string.h>
#if 0
#include <stdio.h>
#endif
#include <stdarg.h>

static void
dlg_activate (GtkWidget *widget, gpointer ok_button);

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
        } else if (strcmp(stock_id, ETHEREAL_STOCK_FILTER_OUT_STREAM) == 0) {
            start = stock_id;
        } else {
            /* we don't know that button! */
            g_assert_not_reached();
        }
        buttons++;
        stock_id = va_arg(stock_id_list, gchar *);
    }
    va_end(stock_id_list);

    hbox = gtk_hbox_new(FALSE, 0);
    gtk_widget_show(hbox);

    button_hbox = gtk_hbutton_box_new();
    gtk_box_pack_end(GTK_BOX(hbox), button_hbox, TRUE, TRUE, 0);
    gtk_widget_show(button_hbox);

    help_hbox = gtk_hbutton_box_new();
    gtk_box_pack_end(GTK_BOX(hbox), help_hbox, FALSE, FALSE, 0);
    gtk_widget_show(help_hbox);

    if (buttons == 0) {
        /* if no buttons wanted, simply do nothing */
        return hbox;
    }

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
