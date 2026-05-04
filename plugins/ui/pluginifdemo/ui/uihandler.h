/* uihandler.h
 * Author: Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PLUGINIFDEMO_UI_UIHANDLER_H_
#define PLUGINIFDEMO_UI_UIHANDLER_H_

#ifdef __cplusplus

#include <QObject>
#include <QDialog>
#include <QMutex>

#include <ui/plugins/include/plugin_if.h>

#include "ws_symbol_export.h"

class GuiHandler : public QObject
{
    Q_OBJECT

public:

    static GuiHandler * getInstance();

    void showAboutDialog(ext_menubar_gui_type gui_type, void *gui_data);
    void showMainDialog(ext_menubar_gui_type gui_type, void *gui_data);

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

/**
 * @brief Handles the "About" dialog for different GUI types.
 *
 * @param gui_type The type of GUI (e.g., Qt, GTK).
 * @param gui_data Pointer to GUI-specific data.
 */
extern void pluginifdemo_ui_about(ext_menubar_gui_type gui_type, void *gui_data);

/**
 * @brief Registers a toolbar for the plugin.
 *
 * This function registers a new toolbar entry with the given name and associates it with a callback function that will be executed when the toolbar item is activated.
 *
 * @param toolbar A pointer to the ext_toolbar_t structure representing the toolbar to be registered.
 */
extern void pluginifdemo_ui_main(ext_menubar_gui_type gui_type, void *gui_data);

/**
 * @brief Logs a message to the plugin's toolbar log.
 *
 * @param message The message to be logged.
 */
extern void pluginifdemo_toolbar_log(const char * message);

/**
 * @brief Registers a toolbar for the plugin.
 *
 * This function registers a new toolbar entry with the given name and associates it with a callback function that will be executed when the toolbar item is activated.
 *
 * @param toolbar A pointer to the ext_toolbar_t structure representing the toolbar to be registered.
 */
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
