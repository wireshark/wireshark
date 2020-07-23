/* uihandler.cpp
 * Author: Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <glib.h>

#include <QObject>
#include <QApplication>

#include <epan/plugin_if.h>
#include <epan/tap.h>

#if defined(_WIN32)
#define _WINSOCKAPI_
#endif

#include <ui/qt/main_window.h>

#include <ui/uihandler.h>
#include <ui/simple_dialog.h>

static void
reset_dialog(void *data _U_)
{
    GuiHandler::getInstance()->doReset();
}

void pluginifdemo_ui_main(ext_menubar_gui_type gui_type, gpointer gui_data)
{
    /* ensures, that the dialog is closing, if scm udid is set or a filter is applied */
    GString *error_string = register_tap_listener("frame", NULL, NULL, 0, reset_dialog, NULL, NULL, NULL);

    if (error_string != NULL) {
		fprintf(stderr, "%s ", error_string->str);
        g_string_free(error_string, TRUE);
    }
    GuiHandler::getInstance()->showMainDialog(gui_type, gui_data);
}

void pluginifdemo_ui_about(ext_menubar_gui_type gui_type, gpointer gui_data)
{
    GuiHandler::getInstance()->showAboutDialog(gui_type, gui_data);
}

void pluginifdemo_toolbar_log(const gchar * message)
{
    GuiHandler::getInstance()->addLogMessage(QString(message));
}

void pluginifdemo_toolbar_register(ext_toolbar_t * toolbar)
{
    GuiHandler::getInstance()->setToolbar(toolbar);
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
