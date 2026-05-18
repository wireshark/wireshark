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
#include <QVBoxLayout>

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

/**
 * @brief Base dialog for traffic-statistics tables (Conversations, Endpoints, etc.),
 *        providing a shared tab bar, filter controls, name resolution toggle, and
 *        copy/export infrastructure that concrete subclasses build upon.
 */
class TrafficTableDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Creates a new traffic table dialog.
     * @param parent     Parent widget.
     * @param cf         Capture file to compute statistics from; no statistics are
     *                   calculated if this is @c NULL.
     * @param table_name Protocol table name to add and bring to the front on open;
     *                   use the default if the name is not known in advance.
     */
    explicit TrafficTableDialog(QWidget &parent, CaptureFile &cf,
                                 const QString &table_name = tr("Unknown"));

    /**
     * @brief Destroys the dialog and releases all associated resources.
     */
    ~TrafficTableDialog();

signals:
    /**
     * @brief Emitted when the user triggers a filter action from a table context menu.
     * @param filter The filter expression to apply.
     * @param action The action to perform (apply, prepare, etc.).
     * @param type   The action type (selected, not selected, etc.).
     */
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

    /**
     * @brief Emitted to request that a Follow Stream dialog be opened for the given protocol.
     * @param proto_id Protocol ID of the stream to follow.
     */
    void openFollowStreamDialog(int proto_id);

    /**
     * @brief Emitted to request that a TCP stream graph be opened.
     * @param graph_type TCP stream graph type constant (e.g. time-sequence, throughput).
     */
    void openTcpStreamGraph(int graph_type);

protected:
    Ui::TrafficTableDialog *ui;   /**< Qt Designer-generated UI object. */
    QPushButton            *copy_bt_; /**< "Copy" button for exporting table contents. */

    /**
     * @brief Inserts a ProgressFrame into the dialog layout and connects it to
     *        the capture-file read progress signal.
     * @param parent QObject to use as the ProgressFrame's parent.
     */
    void addProgressFrame(QObject *parent);

    /**
     * @brief Returns the dialog's button box.
     * @return Pointer to the internal QDialogButtonBox.
     */
    QDialogButtonBox *buttonBox() const;

    /**
     * @brief Returns the "Limit to display filter" check box.
     * @return Pointer to the internal QCheckBox.
     */
    QCheckBox *displayFilterCheckBox() const;

    /**
     * @brief Returns the "Absolute time" check box.
     * @return Pointer to the internal QCheckBox.
     */
    QCheckBox *absoluteTimeCheckBox() const;

    /**
     * @brief Returns the main vertical layout of the dialog for subclass use.
     * @return Pointer to the internal QVBoxLayout.
     */
    QVBoxLayout *getVerticalLayout() const;

    /**
     * @brief Returns the traffic tab widget that hosts per-protocol statistics tabs.
     * @return Pointer to the internal TrafficTab widget.
     */
    TrafficTab *trafficTab() const;

    /**
     * @brief Returns the protocol selector list widget.
     * @return Pointer to the internal TrafficTypesList widget.
     */
    TrafficTypesList *trafficList() const;

protected slots:
    /**
     * @brief Called when the active statistics tab changes; subclasses may override
     *        to update toolbar or button states for the newly visible tab.
     */
    virtual void currentTabChanged();

private slots:
    /**
     * @brief Toggles name resolution on all visible traffic tables.
     * @param checked @c true to enable name resolution; @c false to disable it.
     */
    void on_nameResolutionCheckBox_toggled(bool checked);

    /**
     * @brief Restricts or unrestricts statistics to packets matching the current
     *        display filter.
     * @param checked @c true to limit results to the display filter.
     */
    void displayFilterCheckBoxToggled(bool checked);

    /**
     * @brief Toggles whether aggregated statistics show a summary-only view.
     * @param checked @c true to show summary only; @c false to show full detail.
     */
    void aggregationSummaryOnlyCheckBoxToggled(bool checked);

    /**
     * @brief Responds to capture lifecycle events (start, stop, etc.) to enable
     *        or disable controls appropriately.
     * @param e The capture event to handle.
     */
    void captureEvent(CaptureEvent e);

    /**
     * @brief Pure virtual slot; subclasses must implement this to open the
     *        correct help page for their specific traffic table dialog.
     */
    virtual void on_buttonBox_helpRequested() = 0;
};

#endif // TRAFFIC_TABLE_DIALOG_H
