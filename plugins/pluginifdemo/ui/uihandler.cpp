/* uihandler.cpp
 * Author: Roland Knall <rknall@gmail.com>
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

static void
reset_dialog(void *data _U_)
{
    GuiHandler::getInstance()->doReset();
}

void pluginifdemo_ui_main(ext_menubar_gui_type gui_type, gpointer gui_data)
{
    /* ensures, that the dialog is closing, if scm udid is set or a filter is applied */
    register_tap_listener("frame", NULL, NULL, 0, reset_dialog, NULL, NULL );

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
