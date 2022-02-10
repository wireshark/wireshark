/* main_window.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "ui/preference_utils.h"

#include "main_window.h"

#include "packet_list.h"
#include "widgets/display_filter_combo.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    main_stack_(nullptr),
    welcome_page_(nullptr),
    cur_layout_(QVector<unsigned>()),
    packet_list_(nullptr),
    proto_tree_(nullptr),
    byte_view_tab_(nullptr),
    packet_diagram_(nullptr),
    df_combo_box_(nullptr),
    main_status_bar_(nullptr)
{

}

bool MainWindow::hasSelection()
{
    if (packet_list_)
        return packet_list_->multiSelectActive();
    return false;
}

QList<int> MainWindow::selectedRows(bool useFrameNum)
{
    if (packet_list_)
        return packet_list_->selectedRows(useFrameNum);
    return QList<int>();
}

void MainWindow::insertColumn(QString name, QString abbrev, gint pos)
{
    gint colnr = 0;
    if (name.length() > 0 && abbrev.length() > 0)
    {
        colnr = column_prefs_add_custom(COL_CUSTOM, name.toStdString().c_str(), abbrev.toStdString().c_str(), pos);
        packet_list_->columnsChanged();
        packet_list_->resizeColumnToContents(colnr);
        prefs_main_write();
    }
}

void MainWindow::gotoFrame(int packet_num)
{
    if (packet_num > 0) {
        packet_list_->goToPacket(packet_num);
    }
}

QString MainWindow::getFilter()
{
    return df_combo_box_->currentText();
}

MainStatusBar *MainWindow::statusBar()
{
    return main_status_bar_;
}

void MainWindow::setDisplayFilter(QString filter, FilterAction::Action action, FilterAction::ActionType filterType)
{
    emit filterAction(filter, action, filterType);
}


