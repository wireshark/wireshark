/* simple_dialog_qt.cpp
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

#include <stdio.h>

#include <glib.h>

#include <epan/strutil.h>

#include "simple_dialog_qt.h"
#include "simple_dialog.h"

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
    SimpleDialog      *dlg = NULL;
//    queued_message_t *queued_message;
//    GtkWidget        *win;
//    GdkWindowState state = 0;

    /* Format the message. */
    vmessage = g_strdup_vprintf(msg_format, ap);

    /* convert character encoding from locale to UTF8 (using iconv) */
    message = g_locale_to_utf8(vmessage, -1, NULL, NULL, NULL);
    g_free(vmessage);

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: vsimple_dialog t: %d bm: %d m: %s", type, btn_mask, message);


//    if (top_level != NULL) {
//        state = gdk_window_get_state(top_level->window);
//    }

//    /* If we don't yet have a main window or it's iconified, don't show the
//     dialog. If showing up a dialog, while main window is iconified, program
//     will become unresponsive! */
//    if (top_level == NULL || state & GDK_WINDOW_STATE_ICONIFIED) {

//        queued_message = g_malloc(sizeof (queued_message_t));
//        queued_message->type = type;
//        queued_message->btn_mask = btn_mask;
//        queued_message->message = message;
//        message_queue = g_slist_append(message_queue, queued_message);
//        return NULL;
//    }

//    /*
//   * Do we have any queued up messages?  If so, pop them up.
//   */
//    display_queued_messages();

//    win = display_simple_dialog(type, btn_mask, message);

    g_free(message);

    return dlg;
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

char *
simple_dialog_primary_start(void) {
    return "<span weight=\"bold\" size=\"larger\">";
}

char *
simple_dialog_primary_end(void) {
    return "</span>";
}

char *
simple_dialog_format_message(const char *msg)
{
    char *str;

    if (msg) {
        str = xml_escape(msg);
    } else {
        str = NULL;
    }
    return str;
}

void simple_dialog_set_cb(gpointer dialog, simple_dialog_cb_t callback_fct, gpointer data)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: simple_dialog_set_cb d: %p cf: %p d: %p", dialog, callback_fct, data);

//    g_object_set_data(G_OBJECT(GTK_WIDGET(dialog)), CALLBACK_FCT_KEY, callback_fct);
//    g_object_set_data(G_OBJECT(GTK_WIDGET(dialog)), CALLBACK_DATA_KEY, data);
}


SimpleDialog::SimpleDialog(QWidget *parent) :
    QErrorMessage(parent)
{
}
