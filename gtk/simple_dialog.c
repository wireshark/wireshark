/* simple_dialog.c
 * Simple message dialog box routines.
 *
 * $Id: simple_dialog.c,v 1.18 2004/01/31 01:28:10 ulfl Exp $
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

#include <stdio.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "gtkglobals.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "compat_macros.h"

#include "image/stock_dialog_error_48.xpm"
#include "image/stock_dialog_info_48.xpm"
#include "image/stock_dialog_question_48.xpm"
#include "image/stock_dialog_warning_48.xpm"

static void simple_dialog_cancel_cb(GtkWidget *, gpointer);

#define CALLBACK_FCT_KEY    "ESD_Callback_Fct"
#define CALLBACK_BTN_KEY    "ESD_Callback_Btn"
#define CALLBACK_DATA_KEY   "ESD_Callback_Data"

/* Simple dialog function - Displays a dialog box with the supplied message
 * text.
 *
 * Args:
 * type       : One of ESD_TYPE_*.
 * btn_mask   : The value passed in determines which buttons are displayed.
 * msg_format : Sprintf-style format of the text displayed in the dialog.
 * ...        : Argument list for msg_format
 *
 */

#define ESD_MAX_MSG_LEN 2048
gpointer
simple_dialog(gint type, gint btn_mask, gchar *msg_format, ...) {
  GtkWidget   *win, *main_vb, *top_hb, *type_pm, *msg_label,
              *bbox, *bt;
  GdkPixmap   *pixmap;
  GdkBitmap   *mask;
  GtkStyle    *style;
  GdkColormap *cmap;
  va_list      ap;
  gchar        message[ESD_MAX_MSG_LEN];
  gchar      **icon;

  /* Main window */
  switch (type & ~ESD_TYPE_MODAL) {
  case ESD_TYPE_WARN :
    icon = stock_dialog_warning_48_xpm;
    win = dlg_window_new("Ethereal: Warning");
    break;
  case ESD_TYPE_CRIT :
    icon = stock_dialog_error_48_xpm;
    win = dlg_window_new("Ethereal: Error");
    break;
  case ESD_TYPE_QUEST:
    icon = stock_dialog_question_48_xpm;
    win = dlg_window_new("Ethereal: Question");
    break;
  case ESD_TYPE_INFO :
  default :
    icon = stock_dialog_info_48_xpm;
    win = dlg_window_new("Ethereal: Information");
    break;
  }

  if (type & ESD_TYPE_MODAL)
    gtk_window_set_modal(GTK_WINDOW(win), TRUE);

  gtk_container_border_width(GTK_CONTAINER(win), 7);

  /* Container for our rows */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(win), main_vb);
  gtk_widget_show(main_vb);

  /* Top row: Icon and message text */
  top_hb = gtk_hbox_new(FALSE, 10);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);

  style = gtk_widget_get_style(win);
  cmap  = gdk_colormap_get_system();
  pixmap = gdk_pixmap_colormap_create_from_xpm_d(NULL, cmap,  &mask,
    &style->bg[GTK_STATE_NORMAL], icon);
  type_pm = gtk_pixmap_new(pixmap, mask);
  gtk_misc_set_alignment (GTK_MISC (type_pm), 0.5, 0.0);
  gtk_container_add(GTK_CONTAINER(top_hb), type_pm);
  gtk_widget_show(type_pm);

  /* Load our vararg list into the message string */
  va_start(ap, msg_format);
  vsnprintf(message, ESD_MAX_MSG_LEN, msg_format, ap);
  va_end(ap);

  msg_label = gtk_label_new(message);
  gtk_label_set_justify(GTK_LABEL(msg_label), GTK_JUSTIFY_FILL);
  gtk_container_add(GTK_CONTAINER(top_hb), msg_label);
  gtk_widget_show(msg_label);

  /* Button row */
  switch(btn_mask) {
  case(0):
  case(ESD_BTN_OK):
    bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
    break;
  case(ESD_BTN_OK | ESD_BTN_CANCEL):
    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, NULL);
    break;
  case(ESD_BTN_YES | ESD_BTN_NO | ESD_BTN_CANCEL):
    bbox = dlg_button_row_new(GTK_STOCK_YES, GTK_STOCK_NO, GTK_STOCK_CANCEL, NULL);
    break;
  default:
    g_assert_not_reached();
  }
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
  if(bt) {
      OBJECT_SET_DATA(bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_OK));
      SIGNAL_CONNECT(bt, "clicked", simple_dialog_cancel_cb, win);
      gtk_widget_grab_default(bt);
    /* Catch the "key_press_event" signal in the window, so that we can catch
       the ESC key being pressed and act as if the "OK" button had
       been selected. */
    dlg_set_cancel(win, bt);
  }

  bt = OBJECT_GET_DATA(bbox, GTK_STOCK_YES);
  if(bt) {
      OBJECT_SET_DATA(bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_YES));
      SIGNAL_CONNECT(bt, "clicked", simple_dialog_cancel_cb, win);
  }

  bt = OBJECT_GET_DATA(bbox, GTK_STOCK_NO);
  if(bt) {
      OBJECT_SET_DATA(bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_NO));
      SIGNAL_CONNECT(bt, "clicked", simple_dialog_cancel_cb, win);
  }

  bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
  if(bt) {
      OBJECT_SET_DATA(bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_CANCEL));
      SIGNAL_CONNECT(bt, "clicked", simple_dialog_cancel_cb, win);
    /* Catch the "key_press_event" signal in the window, so that we can catch
       the ESC key being pressed and act as if the "OK" button had
       been selected. */
      dlg_set_cancel(win, bt);
      gtk_widget_grab_default(bt);
  }

  gtk_widget_show(win);

  return win;
}

static void
simple_dialog_cancel_cb(GtkWidget *w, gpointer win) {
  gint button       = GPOINTER_TO_INT(    OBJECT_GET_DATA(w,   CALLBACK_BTN_KEY));
  simple_dialog_cb_t    callback_fct    = OBJECT_GET_DATA(win, CALLBACK_FCT_KEY);
  gpointer              data            = OBJECT_GET_DATA(win, CALLBACK_DATA_KEY);

  gtk_widget_destroy(GTK_WIDGET(win));

  if (callback_fct)
    (callback_fct) (win, button, data);
}

void simple_dialog_set_cb(gpointer dialog, simple_dialog_cb_t callback_fct, gpointer data)
{

    OBJECT_SET_DATA(GTK_WIDGET(dialog), CALLBACK_FCT_KEY, callback_fct);
    OBJECT_SET_DATA(GTK_WIDGET(dialog), CALLBACK_DATA_KEY, data);
}
