/* util.c
 * Utility routines
 *
 * $Id: util.c,v 1.2 1998/09/16 03:22:19 gerald Exp $
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

#include <glib.h>

#include <gtk/gtk.h>

#include <strings.h>

#include "util.h"

const gchar *bm_key = "button mask";

/* Simple dialog function - Displays a dialog box with the supplied message
 * text.
 * 
 * Args:
 * type     : One of ESD_TYPE_*.  Currently ignored.
 * btn_mask : The address of a gint.  The value passed in determines if
 *            the 'Cancel' button is displayed.  The button pressed by the 
 *            user is passed back.
 * message  : The text displayed in the dialog.
 *
 * To do:
 * - Switch to variable args
 */
void
simple_dialog(gint type, gint *btn_mask, gchar *message) {
  GtkWidget   *win, *main_vb, *top_hb, *type_pm, *msg_label,
              *bbox, *ok_btn, *cancel_btn;
  GdkPixmap   *pixmap;
  GdkBitmap   *mask;
  GtkStyle    *style;
  GdkColormap *cmap;
  
  /* Main window */
  win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_container_border_width(GTK_CONTAINER(win), 7);
  gtk_window_set_title(GTK_WINDOW(win), "Ethereal: Warning");
  gtk_object_set_data(GTK_OBJECT(win), bm_key, btn_mask);

  /* Container for our rows */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(win), main_vb);
  gtk_widget_show(main_vb);

  /* Top row: Icon and message text */
  top_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);
  
  style = gtk_widget_get_style(win);
  cmap  = gdk_colormap_get_system();
  pixmap = gdk_pixmap_colormap_create_from_xpm_d(NULL, cmap,  &mask,
    &style->bg[GTK_STATE_NORMAL], icon_excl_xpm);
  type_pm = gtk_pixmap_new(pixmap, mask);
  gtk_container_add(GTK_CONTAINER(top_hb), type_pm);
  gtk_widget_show(type_pm);

  msg_label = gtk_label_new(message);
  gtk_label_set_justify(GTK_LABEL(msg_label), GTK_JUSTIFY_FILL);
  gtk_container_add(GTK_CONTAINER(top_hb), msg_label);
  gtk_widget_show(msg_label);
  
  /* Button row */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_btn = gtk_button_new_with_label ("OK");
  gtk_signal_connect_object(GTK_OBJECT(ok_btn), "clicked",
    GTK_SIGNAL_FUNC(gtk_widget_destroy), GTK_OBJECT (win)); 
  gtk_container_add(GTK_CONTAINER(bbox), ok_btn);
  GTK_WIDGET_SET_FLAGS(ok_btn, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(ok_btn);
  gtk_widget_show(ok_btn);

  if (btn_mask && *btn_mask == ESD_BTN_CANCEL) {
    cancel_btn = gtk_button_new_with_label("Cancel");
    gtk_signal_connect(GTK_OBJECT(cancel_btn), "clicked",
      GTK_SIGNAL_FUNC(simple_dialog_cancel_cb), (gpointer) win);
    gtk_container_add(GTK_CONTAINER(bbox), cancel_btn);
    gtk_widget_show(cancel_btn);
  }

  if (btn_mask)
    *btn_mask = ESD_BTN_OK;

  gtk_widget_show(win);
}

void
simple_dialog_cancel_cb(GtkWidget *w, gpointer win) {
  gint *btn_mask = (gint *) gtk_object_get_data(win, bm_key);
  
  if (btn_mask)
    *btn_mask = ESD_BTN_CANCEL;
  gtk_widget_destroy(GTK_WIDGET(win));
}
