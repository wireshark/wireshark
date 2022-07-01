/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TRAFFIC_TABLE_DIALOG_H
#define TRAFFIC_TABLE_DIALOG_H

#include <config.h>

#include "file.h"

#include "epan/conversation_table.h"

#include "epan/follow.h"

#include "capture_file.h"
#include "filter_action.h"
#include "wireshark_dialog.h"

#include <QMenu>
#include <QTreeWidgetItem>

class QCheckBox;
class QDialogButtonBox;
class QPushButton;
class QTabWidget;
class QTreeWidget;
class TrafficTab;
class TrafficTypesList;

namespace Ui {
class TrafficTableDialog;
}

class TrafficTableDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /** Create a new conversation window.
     *
     * @param parent Parent widget.
     * @param cf Capture file. No statistics will be calculated if this is NULL.
     * @param table_name If valid, add this protocol and bring it to the front.
     */
    explicit TrafficTableDialog(QWidget &parent, CaptureFile &cf, const QString &table_name = tr("Unknown"));
    ~TrafficTableDialog();

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);
    void openFollowStreamDialog(follow_type_t type);
    void openTcpStreamGraph(int graph_type);

protected:
    Ui::TrafficTableDialog *ui;

    QPushButton *copy_bt_;

    void addProgressFrame(QObject *parent);

    // UI getters
    QDialogButtonBox *buttonBox() const;
    QCheckBox *displayFilterCheckBox() const;
    QCheckBox *absoluteTimeCheckBox() const;
    TrafficTab *trafficTab() const;
    TrafficTypesList *trafficList() const;

protected slots:
    virtual void currentTabChanged();

private slots:
    void on_nameResolutionCheckBox_toggled(bool checked);
    void on_displayFilterCheckBox_toggled(bool checked);
    void captureEvent(CaptureEvent e);

    virtual void on_buttonBox_helpRequested() = 0;
};

#endif // TRAFFIC_TABLE_DIALOG_H
