/* uihandler.h
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

#ifndef PLUGINIFDEMO_UI_UIHANDLER_H_
#define PLUGINIFDEMO_UI_UIHANDLER_H_

#ifdef __cplusplus

#include <QObject>
#include <QDialog>
#include <QMutex>

#include <epan/plugin_if.h>

#include "ws_symbol_export.h"

class WS_DLL_PUBLIC_DEF GuiHandler : public QObject
{
    Q_OBJECT

public:

    static GuiHandler * getInstance();

    void showAboutDialog(ext_menubar_gui_type gui_type, gpointer gui_data);
    void showMainDialog(ext_menubar_gui_type gui_type, gpointer gui_data);

    void doReset();

    void addLogMessage(QString message);

    void setToolbar(ext_toolbar_t * toolbar);
    ext_toolbar_t * toolBar();

signals:
    void reset();
    void logChanged(QString newEntry);

protected:

    GuiHandler();

    // Stop the compiler generating methods of "copy the object"
    GuiHandler(GuiHandler const& copy); // Not implemented
    GuiHandler& operator=(GuiHandler const& copy); // Not implemented

private:

    static QMutex * singletonMutex;

    ext_toolbar_t * _toolbar;

    void executeDialog(QDialog * object);
};

extern "C" {
#endif

extern void pluginifdemo_ui_about(ext_menubar_gui_type gui_type, gpointer gui_data);
extern void pluginifdemo_ui_main(ext_menubar_gui_type gui_type, gpointer gui_data);
extern void pluginifdemo_toolbar_log(const gchar * message);

extern void pluginifdemo_toolbar_register(ext_toolbar_t * toolbar);

#ifdef __cplusplus
}
#endif

#endif /* BURANALYZER_UI_UIHANDLER_H_ */

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
