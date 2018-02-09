/* uiclasshandler.cpp
 *
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
#include <QMutex>

#include <epan/plugin_if.h>

#if defined(_WIN32)
#define _WINSOCKAPI_
#endif

#include <ui/qt/main_window.h>

#include <ui/uihandler.h>
#include <ui/pluginifdemo_main.h>
#include <ui/pluginifdemo_about.h>

QMutex * GuiHandler::singletonMutex = new QMutex();

GuiHandler::GuiHandler()
{
}

GuiHandler * GuiHandler::getInstance()
{
    static GuiHandler * instance = 0;

    QMutexLocker locker(singletonMutex);

    if ( instance == 0 )
    {
        instance = new GuiHandler();
    }

    return instance;
}

void GuiHandler::showAboutDialog(ext_menubar_gui_type gui_type _U_, gpointer gui_data _U_)
{
    PluginIFDemo_About * mainwindow = new PluginIFDemo_About();
    executeDialog((QDialog*)mainwindow);
}

void GuiHandler::showMainDialog(ext_menubar_gui_type gui_type _U_, gpointer gui_data _U_)
{
    PluginIFDemo_Main * mainwindow = new PluginIFDemo_Main();
    mainwindow->setToolbar(_toolbar);
    executeDialog((QDialog*)mainwindow);
}

void GuiHandler::executeDialog(QDialog * dialog)
{
    bool hasGuiApp = (qobject_cast<QApplication*>(QCoreApplication::instance())!=0);

    if ( ! hasGuiApp )
    {
        /* Necessity for creating the correct app context */
        int argc = 1;
        char * argv = (char *) "Test";

        /* In Gtk there is no application context, must be created and displayed */
        QApplication app(argc, &argv);

        dialog->show();

        app.exec();
    }
    else
    {
        /* With Wireshark Qt, an application context already exists, therefore just
         * displaying the dialog using show to have it non-modal */
        dialog->show();
    }
}

void GuiHandler::doReset()
{
    emit reset();
}

void GuiHandler::addLogMessage(QString message)
{
    emit logChanged(message);
}

void GuiHandler::setToolbar(ext_toolbar_t * toolbar)
{
    _toolbar = toolbar;
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
