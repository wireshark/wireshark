/* dlg_utils.c
 * Utilities to use when constructing dialogs
 *
 * $Id: dlg_utils.c,v 1.7 2002/03/05 11:55:58 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#include "gtkglobals.h"
#include "ui_util.h"

static void
dlg_activate (GtkWidget *widget, gpointer ok_button);

static gint
dlg_key_press (GtkWidget *widget, GdkEventKey *event, gpointer cancel_button);

/* Create a dialog box window that belongs to Ethereal's main window. */
GtkWidget *
dlg_window_new(const gchar *title)
{
	GtkWidget *win;

	win = gtk_window_new(GTK_WINDOW_DIALOG);
	gtk_window_set_transient_for(GTK_WINDOW(win), GTK_WINDOW(top_level));
	gtk_window_set_title(GTK_WINDOW(win), title);
	gtk_signal_connect (GTK_OBJECT (win), "realize",
		GTK_SIGNAL_FUNC (window_icon_realize_cb), NULL);
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
  gtk_signal_connect(GTK_OBJECT(widget), "activate",
    GTK_SIGNAL_FUNC(dlg_activate), ok_button);
}

static void
dlg_activate (GtkWidget *widget _U_, gpointer ok_button)
{
  gtk_widget_activate(GTK_WIDGET(ok_button));
}

/* Set the "key_press_event" signal for a top-level dialog window to
   call a routine to activate the "Cancel" button for a dialog box if
   the key being pressed is the <Esc> key.

   XXX - there should be a GTK+ widget that'll do that for you, and
   let you specify a "Cancel" button.  It should also not impose
   a requirement that there be a separator in the dialog box, as
   the GtkDialog widget does; the visual convention that there's
   such a separator between the rest of the dialog boxes and buttons
   such as "OK" and "Cancel" is, for better or worse, not universal
   (not even in GTK+ - look at the GtkFileSelection dialog!). */
void
dlg_set_cancel(GtkWidget *widget, GtkWidget *cancel_button)
{
  gtk_signal_connect(GTK_OBJECT(widget), "key_press_event",
    GTK_SIGNAL_FUNC(dlg_key_press), cancel_button);
}

static gint
dlg_key_press (GtkWidget *widget, GdkEventKey *event, gpointer cancel_button)
{
  g_return_val_if_fail (widget != NULL, FALSE);
  g_return_val_if_fail (event != NULL, FALSE);

  if (event->keyval == GDK_Escape) {
    gtk_widget_activate(GTK_WIDGET(cancel_button));
    return TRUE;
  }

  return FALSE;
}

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
