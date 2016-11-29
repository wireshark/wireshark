/* simple_dialog.h
 * Definitions for alert box routines with toolkit-independent APIs but
 * toolkit-dependent implementations.
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

#ifndef __SIMPLE_DIALOG_UI_H__
#define __SIMPLE_DIALOG_UI_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 *  Simple dialog box.
 *  @ingroup dialog_group
 */


/** Dialog types. */
typedef enum {
    ESD_TYPE_INFO,          /**< tells the user something they should know, but not requiring
                                    any action; the only button should be "OK" */
    ESD_TYPE_WARN,          /**< tells the user about a problem; the only button should be "OK" */
    ESD_TYPE_CONFIRMATION,  /**< asks the user for confirmation; there should be more than
                                    one button */
    ESD_TYPE_ERROR,         /**< tells the user about a serious problem; the only button should be "OK" */
    ESD_TYPE_STOP           /**< tells the user a stop action is in progress, there should be no button */
} ESD_TYPE_E;

/** display no buttons at all */
#define ESD_BTN_NONE   0x00
/** display an "Ok" button */
#define ESD_BTN_OK     0x01
/** display a "Cancel" button */
#define ESD_BTN_CANCEL 0x02
/** display a "Yes" button */
#define ESD_BTN_YES    0x04
/** display a "No" button */
#define ESD_BTN_NO     0x08
/** display a "Clear" button */
#define ESD_BTN_CLEAR  0x10
/** display a "Save" button */
#define ESD_BTN_SAVE   0x20
/** display a "Continue without Saving" button */
#define ESD_BTN_DONT_SAVE 0x40
/** display a "Quit without Saving" button */
#define ESD_BTN_QUIT_DONT_SAVE 0x80

/** Standard button combination "Ok" + "Cancel". */
#define ESD_BTNS_OK_CANCEL      (ESD_BTN_OK|ESD_BTN_CANCEL)
/** Standard button combination "Yes" + "No". */
#define ESD_BTNS_YES_NO         (ESD_BTN_YES|ESD_BTN_NO)
/** Standard button combination "Yes" + "No" + "Cancel". */
#define ESD_BTNS_YES_NO_CANCEL  (ESD_BTN_YES|ESD_BTN_NO|ESD_BTN_CANCEL)
/** Standard button combination "No" + "Cancel" + "Save". */
#define ESD_BTNS_SAVE_DONTSAVE  (ESD_BTN_SAVE|ESD_BTN_DONT_SAVE)
#define ESD_BTNS_SAVE_DONTSAVE_CANCEL (ESD_BTN_DONT_SAVE|ESD_BTN_CANCEL|ESD_BTN_SAVE)
/** Standard button combination "Quit without saving" + "Cancel" + "Save". */
#define ESD_BTNS_SAVE_QUIT_DONTSAVE_CANCEL (ESD_BTN_QUIT_DONT_SAVE|ESD_BTN_CANCEL|ESD_BTN_SAVE)
/** Standard button combination "Quit without saving" + "Cancel". */
#define ESD_BTNS_QUIT_DONTSAVE_CANCEL (ESD_BTN_QUIT_DONT_SAVE|ESD_BTN_CANCEL)

/** Create and show a simple dialog.
 *
 * @param Type type of dialog, e.g. ESD_TYPE_WARN
 * @param btn_mask The buttons to display, e.g. ESD_BTNS_OK_CANCEL
 * @param msg_format Printf like message format. Text must be plain.
 * @param ... Printf like parameters
 * @return The newly created dialog
 */
/*
 * XXX This is a bit clunky. We typically pass in:
 * - simple_dialog_primary_start
 * - The primary message
 * - simple_dialog_primary_end
 * - Optionally, the secondary message.
 *
 * In the GTK+ UI primary_start and primary_end make up a <span> that adds
 * text formatting. The whole string is then shoved into a GtkLabel.
 *
 * In the Qt UI we use primary_start and _end to split the primary and
 * secondary messages. They are then added to a QMessageBox via setText and
 * setInformativeText respectively. No formatting is applied.
 *
 * Callers are responsible for wrapping the primary message and formatting
 * the message text.
 *
 * Explicitly passing in separate primary and secondary messages would let us
 * get rid of primary_start and primary_end and reduce the amount of
 * gymnastics we have to to in the Qt UI.
 */
extern gpointer simple_dialog(ESD_TYPE_E type, gint btn_mask,
    const gchar *msg_format, ...)
    G_GNUC_PRINTF(3, 4);

/** Surround the primary dialog message text by
 *  simple_dialog_primary_start() and simple_dialog_primary_end().
 *  To highlight the first sentence (will take effect on GTK2 only).
 */
extern const char *simple_dialog_primary_start(void);
/** Surround the primary dialog message text by
 *  simple_dialog_primary_start() and simple_dialog_primary_end().
 *  To highlight the first sentence (will take effect on GTK2 only).
 */
extern const char *simple_dialog_primary_end(void);

/** Escape the message text, if it probably contains Pango escape sequences.
 *  For example html like tags starting with a <.
 *
 * @param msg the string to escape
 * @return the escaped message text, must be freed with g_free() later
 */
extern char *simple_dialog_format_message(const char *msg);

/*
 * Alert box, with optional "don't show this message again" variable
 * and checkbox, and optional secondary text.
 */
extern void simple_message_box(ESD_TYPE_E type, gboolean *notagain,
                               const char *secondary_msg,
                               const char *msg_format, ...) G_GNUC_PRINTF(4, 5);

/*
 * Error alert box, taking a format and a va_list argument.
 */
extern void vsimple_error_message_box(const char *msg_format, va_list ap);

/*
 * Error alert box, taking a format and a list of arguments.
 */
extern void simple_error_message_box(const char *msg_format, ...) G_GNUC_PRINTF(1, 2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SIMPLE_DIALOG_UI_H__ */

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
