/* dlg_utils.c
 * Utilities to use when constructing dialogs
 *
 * $Id: dlg_utils.c,v 1.1 2000/05/02 08:04:28 guy Exp $
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

static void
dlg_activate (GtkWidget *widget, gpointer ok_button);

static gint
dlg_key_press (GtkWidget *widget, GdkEventKey *event, gpointer cancel_button);

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
dlg_activate (GtkWidget *widget, gpointer ok_button)
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
