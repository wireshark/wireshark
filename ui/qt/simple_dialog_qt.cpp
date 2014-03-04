/* simple_dialog_qt.cpp
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>

#include <glib.h>

#include <epan/strutil.h>

#include "ui/simple_dialog.h"

#include "simple_dialog_qt.h"

#include <QMessageBox>

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

const char *
simple_dialog_primary_start(void) {
    return "";
}

const char *
simple_dialog_primary_end(void) {
    return "";
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

static void
do_simple_message_box(ESD_TYPE_E type, gboolean *notagain,
                      const char *secondary_msg, const char *msg_format,
                      va_list ap)
{
    QMessageBox *msg_dialog;
    gchar *message;

    if (notagain != NULL) {
        if (*notagain) {
        /*
         * The user had checked the "Don't show this message again" checkbox
         * in the past; don't bother showing it.
         */
        return;
        }
    }

    /*
     * XXX - this should be passed the main window.
     * Also, this should be set to window modal by setting its window
     * modality to Qt::WindowModal, so it shows up as a sheet in
     * OS X.
     */
    msg_dialog = new QMessageBox(NULL);
    switch (type) {

    case ESD_TYPE_INFO:
        msg_dialog->setIcon(QMessageBox::Information);
        break;

    case ESD_TYPE_WARN:
        msg_dialog->setIcon(QMessageBox::Warning);
        break;

    case ESD_TYPE_ERROR:
        msg_dialog->setIcon(QMessageBox::Critical);
        break;

    default:
        g_assert_not_reached();
        return;
    }

    /* Format the message. */
    message = g_strdup_vprintf(msg_format, ap);
    msg_dialog->setText(message);
    g_free(message);

    /* Add the secondary text. */
    if (secondary_msg != NULL)
        msg_dialog->setInformativeText(secondary_msg);

#if 0
    if (notagain != NULL) {
        checkbox = gtk_check_button_new_with_label("Don't show this message again.");
        gtk_container_set_border_width(GTK_CONTAINER(checkbox), 12);
        gtk_box_pack_start(GTK_BOX(gtk_message_dialog_get_message_area(GTK_MESSAGE_DIALOG(msg_dialog))), checkbox,
                           TRUE, TRUE, 0);
        gtk_widget_show(checkbox);
    }
#endif

    msg_dialog->exec();
#if 0
    if (notagain != NULL) {
        /*
         * OK, did they check the checkbox?
        */
        *notagain = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(checkbox));
    }
#endif
    delete msg_dialog;
}

/*
 * Alert box, with optional "don't show this message again" variable
 * and checkbox, and optional secondary text.
 */
void
simple_message_box(ESD_TYPE_E type, gboolean *notagain,
                   const char *secondary_msg, const char *msg_format, ...)
{
    va_list ap;

    va_start(ap, msg_format);
    do_simple_message_box(type, notagain, secondary_msg, msg_format, ap);
    va_end(ap);
}

/*
 * Error alert box, taking a format and a va_list argument.
 */
void
vsimple_error_message_box(const char *msg_format, va_list ap)
{
    do_simple_message_box(ESD_TYPE_ERROR, NULL, NULL, msg_format, ap);
}

/*
 * Error alert box, taking a format and a list of arguments.
 */
void
simple_error_message_box(const char *msg_format, ...)
{
    va_list ap;

    va_start(ap, msg_format);
    do_simple_message_box(ESD_TYPE_ERROR, NULL, NULL, msg_format, ap);
    va_end(ap);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
