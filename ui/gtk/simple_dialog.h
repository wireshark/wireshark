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

#ifndef __SIMPLE_DIALOG_H__
#define __SIMPLE_DIALOG_H__

#include "ui/simple_dialog.h"

/** @file
 *  Simple dialog box.
 *  @ingroup dialog_group
 */

/** Callback function type for simple_dialog_set_cb() */
typedef void (* simple_dialog_cb_t) (gpointer dialog, gint btn, gpointer data);

/** Set the callback function for the dialog, called when a button was pressed.
 *
 * @param dialog the dialog from simple_dialog()
 * @param callback_fct the callback function to set
 * @param data data to be passed to the callback function
 */
extern void simple_dialog_set_cb(gpointer dialog, simple_dialog_cb_t callback_fct, gpointer data);

/** Close the dialog, useful for "no button" dialogs.
 *
 * @param dialog the dialog to close from simple_dialog()
 */
extern void simple_dialog_close(gpointer dialog);

/** Add a check button to the dialog (e.g. "Don't show this message again")
 *
 * @param dialog the dialog from simple_dialog()
 * @param text the text to display
 */
extern void simple_dialog_check_set(gpointer dialog, const gchar *text);

/** Get the check buttons state.
 *
 * @param dialog the dialog from simple_dialog()
 * @return current button state (TRUE is checked)
 */
extern gboolean simple_dialog_check_get(gpointer dialog);

/**
 * Display all queued messages.
 * If a routine is called to display a dialog before there are any windows
 * open, information to use to display the dialog is queued up.  This
 * routine should be called once there are windows open, so that the queued
 * up dialogs are displayed on top of those windows.
 */
extern void display_queued_messages(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SIMPLE_DIALOG_H__ */

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
