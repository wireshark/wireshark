/* simple_dialog.c
 * Simple message dialog box routines.
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

#include <stdio.h>

#include "gtkglobals.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"

#include <epan/strutil.h>

#include "image/stock_dialog_error_48.xpm"
#include "image/stock_dialog_info_48.xpm"
#include "image/stock_dialog_warning_48.xpm"
#include "image/stock_dialog_stop_48.xpm"

static void simple_dialog_cancel_cb(GtkWidget *, gpointer);

#define CALLBACK_FCT_KEY    "ESD_Callback_Fct"
#define CALLBACK_BTN_KEY    "ESD_Callback_Btn"
#define CALLBACK_DATA_KEY   "ESD_Callback_Data"
#define CHECK_BUTTON        "ESD_Check_Button"

/*
 * Queue for messages requested before we have a main window.
 */
typedef struct {
	gint	type;
	gint	btn_mask;
	char	*message;
} queued_message_t;
	
static GSList *message_queue;

static GtkWidget *
display_simple_dialog(gint type, gint btn_mask, char *message)
{
  GtkWidget   *win, *main_vb, *top_hb, *msg_vb, *type_pm, *msg_label, *ask_cb,
              *bbox, *ok_bt, *yes_bt, *bt, *save_bt, *dont_save_bt;
  GdkPixmap   *pixmap;
  GdkBitmap   *mask;
  GtkStyle    *style;
  GdkColormap *cmap;
  const gchar **icon;

  /* Main window */
  switch (type) {
  case ESD_TYPE_WARN :
    icon = stock_dialog_warning_48_xpm;
    break;
  case ESD_TYPE_CONFIRMATION:
    icon = stock_dialog_warning_48_xpm;
    break;
  case ESD_TYPE_ERROR:
    icon = stock_dialog_error_48_xpm;
    break;
  case ESD_TYPE_STOP :
    icon = stock_dialog_stop_48_xpm;
    break;
  case ESD_TYPE_INFO :
  default :
    icon = stock_dialog_info_48_xpm;
    break;
  }

  /*
   * The GNOME HIG:
   *
   *	http://developer.gnome.org/projects/gup/hig/1.0/windows.html#alert-windows
   *
   * says that the title should be empty for alert boxes, so there's "less
   * visual noise and confounding text."
   *
   * The Windows HIG:
   *
   *	http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dnwue/html/ch09f.asp
   *
   * says it should
   *
   *	...appropriately identify the source of the message -- usually
   *	the name of the object.  For example, if the message results
   *	from editing a document, the title text is the name of the
   *	document, optionally followed by the application name.  If the
   *	message results from a non-document object, then use the
   *	application name."
   *
   * and notes that the title is important "because message boxes might
   * not always the the result of current user interaction" (e.g., some
   * app might randomly pop something up, e.g. some browser letting you
   * know that it couldn't fetch something because of a timeout).
   *
   * It also says not to use "warning" or "caution", as there's already
   * an icon that tells you what type of alert it is, and that you
   * shouldn't say "error", as that provides no useful information.
   *
   * So we give it a title on Win32, and don't give it one on UN*X.
   * For now, we give it a Win32 title of just "Ethereal"; we should
   * arguably take an argument for the title.
   */
  if(btn_mask == ESD_BTN_NONE) {
	win = splash_window_new();
  } else {
#ifdef _WIN32
	win = dlg_window_new("Ethereal");
#else
    win = dlg_window_new("");
#endif
  }

  gtk_window_set_modal(GTK_WINDOW(win), TRUE);
  gtk_container_border_width(GTK_CONTAINER(win), 6);

  /* Container for our rows */
  main_vb = gtk_vbox_new(FALSE, 12);
  gtk_container_add(GTK_CONTAINER(win), main_vb);
  gtk_widget_show(main_vb);

  /* Top row: Icon and message text */
  top_hb = gtk_hbox_new(FALSE, 12);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 6);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);

  /* icon */
  style = gtk_widget_get_style(win);
  cmap  = gdk_colormap_get_system();
  pixmap = gdk_pixmap_colormap_create_from_xpm_d(NULL, cmap,  &mask,
    &style->bg[GTK_STATE_NORMAL], (gchar **) icon);
  type_pm = gtk_pixmap_new(pixmap, mask);
  gtk_misc_set_alignment (GTK_MISC (type_pm), 0.5, 0.0);
  gtk_container_add(GTK_CONTAINER(top_hb), type_pm);
  gtk_widget_show(type_pm);

  /* column for message and optional check button */
  msg_vb = gtk_vbox_new(FALSE, 6);
  gtk_box_set_spacing(GTK_BOX(msg_vb), 24);
  gtk_container_add(GTK_CONTAINER(top_hb), msg_vb);
  gtk_widget_show(msg_vb);

  /* message */
  msg_label = gtk_label_new(message);

#if GTK_MAJOR_VERSION >= 2
  gtk_label_set_markup(GTK_LABEL(msg_label), message);
  gtk_label_set_selectable(GTK_LABEL(msg_label), TRUE);
#endif

  gtk_label_set_justify(GTK_LABEL(msg_label), GTK_JUSTIFY_FILL);
  gtk_misc_set_alignment (GTK_MISC (type_pm), 0.5, 0.0);
  gtk_container_add(GTK_CONTAINER(msg_vb), msg_label);
  gtk_widget_show(msg_label);

  if(btn_mask == ESD_BTN_NONE) {
	gtk_widget_show(win);
	return win;
  }

  /* optional check button */
  ask_cb = gtk_check_button_new_with_label("replace with text...");
  gtk_container_add(GTK_CONTAINER(msg_vb), ask_cb);
  OBJECT_SET_DATA(win, CHECK_BUTTON, ask_cb);

  /* Button row */
  switch(btn_mask) {
  case(ESD_BTN_OK):
    bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
    break;
  case(ESD_BTN_OK | ESD_BTN_CANCEL):
    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, NULL);
    break;
  case(ESD_BTN_CLEAR | ESD_BTN_CANCEL):
    bbox = dlg_button_row_new(GTK_STOCK_CLEAR, GTK_STOCK_CANCEL, NULL);
    break;
  case(ESD_BTNS_YES_NO_CANCEL):
    bbox = dlg_button_row_new(GTK_STOCK_YES, GTK_STOCK_NO, GTK_STOCK_CANCEL, NULL);
    break;
  case(ESD_BTNS_SAVE_DONTSAVE_CANCEL):
    bbox = dlg_button_row_new(GTK_STOCK_SAVE, ETHEREAL_STOCK_DONT_SAVE, GTK_STOCK_CANCEL, NULL);
    break;
  case(ESD_BTNS_YES_NO):
    bbox = dlg_button_row_new(GTK_STOCK_YES, GTK_STOCK_NO, NULL);
    break;
  default:
    g_assert_not_reached();
    bbox = NULL;
    break;
  }
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
  if(ok_bt) {
      OBJECT_SET_DATA(ok_bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_OK));
      SIGNAL_CONNECT(ok_bt, "clicked", simple_dialog_cancel_cb, win);
  }

  save_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_SAVE);
  if (save_bt) {
      OBJECT_SET_DATA(save_bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_SAVE));
      SIGNAL_CONNECT(save_bt, "clicked", simple_dialog_cancel_cb, win);
  }
  
  dont_save_bt = OBJECT_GET_DATA(bbox, ETHEREAL_STOCK_DONT_SAVE);
  if (dont_save_bt) {
      OBJECT_SET_DATA(dont_save_bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_DONT_SAVE));
      SIGNAL_CONNECT(dont_save_bt, "clicked", simple_dialog_cancel_cb, win);  	
  }      
  bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLEAR);
  if(bt) {
      OBJECT_SET_DATA(bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_CLEAR));
      SIGNAL_CONNECT(bt, "clicked", simple_dialog_cancel_cb, win);
  }

  yes_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_YES);
  if(yes_bt) {
      OBJECT_SET_DATA(yes_bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_YES));
      SIGNAL_CONNECT(yes_bt, "clicked", simple_dialog_cancel_cb, win);
  }

  bt = OBJECT_GET_DATA(bbox, GTK_STOCK_NO);
  if(bt) {
      OBJECT_SET_DATA(bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_NO));
      SIGNAL_CONNECT(bt, "clicked", simple_dialog_cancel_cb, win);
  }

  bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
  if(bt) {
      OBJECT_SET_DATA(bt, CALLBACK_BTN_KEY, GINT_TO_POINTER(ESD_BTN_CANCEL));
      window_set_cancel_button(win, bt, simple_dialog_cancel_cb);
  }

  if(!bt) {
      if(yes_bt) {
          window_set_cancel_button(win, yes_bt, simple_dialog_cancel_cb);
      } else {
          window_set_cancel_button(win, ok_bt, simple_dialog_cancel_cb);
      }
  }

  gtk_widget_show(win);

  return win;
}

void
display_queued_messages(void)
{
  queued_message_t *queued_message;

  while (message_queue != NULL) {
    queued_message = message_queue->data;
    message_queue = g_slist_remove(message_queue, queued_message);

    display_simple_dialog(queued_message->type, queued_message->btn_mask,
                          queued_message->message);

    g_free(queued_message->message);
    g_free(queued_message);
  }
}

/* Simple dialog function - Displays a dialog box with the supplied message
 * text.
 *
 * Args:
 * type       : One of ESD_TYPE_*.
 * btn_mask   : The value passed in determines which buttons are displayed.
 * msg_format : Sprintf-style format of the text displayed in the dialog.
 * ...        : Argument list for msg_format
 */

gpointer
vsimple_dialog(ESD_TYPE_E type, gint btn_mask, const gchar *msg_format, va_list ap)
{
  gchar             *vmessage;
  gchar             *message;
  queued_message_t *queued_message;
  GtkWidget        *win;
#if GTK_MAJOR_VERSION >= 2
  GdkWindowState state = 0;
#endif

  /* Format the message. */
  vmessage = g_strdup_vprintf(msg_format, ap);

#if GTK_MAJOR_VERSION >= 2
  /* convert character encoding from locale to UTF8 (using iconv) */
  message = g_locale_to_utf8(vmessage, -1, NULL, NULL, NULL);
  g_free(vmessage);
#else
  message = vmessage;
#endif

#if GTK_MAJOR_VERSION >= 2
  if (top_level != NULL) {
    state = gdk_window_get_state(top_level->window);
  }

  /* If we don't yet have a main window or it's iconified, don't show the 
     dialog. If showing up a dialog, while main window is iconified, program 
     will become unresponsive! */     
  if (top_level == NULL || state & GDK_WINDOW_STATE_ICONIFIED) {
#else

  /* If we don't yet have a main window, queue up the message for later
     display. */
  if (top_level == NULL) {
#endif
    queued_message = g_malloc(sizeof (queued_message_t));
    queued_message->type = type;
    queued_message->btn_mask = btn_mask;
    queued_message->message = message;
    message_queue = g_slist_append(message_queue, queued_message);
    return NULL;
  }

  /*
   * Do we have any queued up messages?  If so, pop them up.
   */
  display_queued_messages();

  win = display_simple_dialog(type, btn_mask, message);

  g_free(message);

  return win;
}

gpointer
simple_dialog(ESD_TYPE_E type, gint btn_mask, const gchar *msg_format, ...)
{
  va_list ap;
  gpointer ret;

  va_start(ap, msg_format);
  ret = vsimple_dialog(type, btn_mask, msg_format, ap);
  va_end(ap);
  return ret;
}

static void
simple_dialog_cancel_cb(GtkWidget *w, gpointer win) {
  gint button = GPOINTER_TO_INT(    OBJECT_GET_DATA(w, CALLBACK_BTN_KEY));
  simple_dialog_cb_t    callback_fct    = OBJECT_GET_DATA(win, CALLBACK_FCT_KEY);
  gpointer              data            = OBJECT_GET_DATA(win, CALLBACK_DATA_KEY);

  window_destroy(GTK_WIDGET(win));

  if (callback_fct)
    (callback_fct) (win, button, data);
}

void
simple_dialog_close(gpointer dialog)
{
	window_destroy(GTK_WIDGET(dialog));
}

void simple_dialog_set_cb(gpointer dialog, simple_dialog_cb_t callback_fct, gpointer data)
{

    OBJECT_SET_DATA(GTK_WIDGET(dialog), CALLBACK_FCT_KEY, callback_fct);
    OBJECT_SET_DATA(GTK_WIDGET(dialog), CALLBACK_DATA_KEY, data);
}

void simple_dialog_check_set(gpointer dialog, gchar *text) {
    GtkWidget *ask_cb = OBJECT_GET_DATA(dialog, CHECK_BUTTON);

#if GTK_MAJOR_VERSION >= 2
    /* XXX - find a way to set the GtkButton label in GTK 1.x */
    gtk_button_set_label(GTK_BUTTON(ask_cb), text);
#endif
    gtk_widget_show(ask_cb);
}

gboolean simple_dialog_check_get(gpointer dialog) {
    GtkWidget *ask_cb = OBJECT_GET_DATA(dialog, CHECK_BUTTON);

    return gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ask_cb));
}

char *
simple_dialog_primary_start(void) {
    return PRIMARY_TEXT_START;
}

char *
simple_dialog_primary_end(void) {
    return PRIMARY_TEXT_END;
}

char *
simple_dialog_format_message(const char *msg)
{
    char *str;

    if (msg) {
#if GTK_MAJOR_VERSION < 2
	str = g_strdup(msg);
#else
	str = xml_escape(msg);
#endif
    } else {
	str = NULL;
    }
    return str;
}
