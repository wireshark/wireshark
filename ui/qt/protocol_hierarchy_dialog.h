/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROTOCOL_HIERARCHY_DIALOG_H
#define PROTOCOL_HIERARCHY_DIALOG_H

#include <QMenu>
#include <QSet>

#include "filter_action.h"
#include <ui/qt/models/percent_bar_delegate.h>
#include "wireshark_dialog.h"

class QPushButton;
class QTreeWidgetItem;

namespace Ui {
class ProtocolHierarchyDialog;
}

/**
 * @brief Dialog for displaying protocol hierarchy statistics.
 */
class ProtocolHierarchyDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a ProtocolHierarchyDialog.
     * @param parent The parent widget.
     * @param cf The capture file to analyze.
     */
    explicit ProtocolHierarchyDialog(QWidget &parent, CaptureFile &cf);

    /**
     * @brief Destroys the ProtocolHierarchyDialog.
     */
    ~ProtocolHierarchyDialog();

signals:
    /**
     * @brief Signal emitted to apply a filter action based on the selected protocol.
     * @param filter The filter string.
     * @param action The specific action to perform.
     * @param type The type of filter action.
     */
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

private slots:
    /**
     * @brief Shows the protocol hierarchy context menu.
     * @param pos The position to show the menu.
     */
    void showProtoHierMenu(QPoint pos);

    /**
     * @brief Handles a triggered filter action from the context menu.
     */
    void filterActionTriggered();

    /**
     * @brief Triggered to copy the protocol hierarchy data as a CSV.
     */
    void on_actionCopyAsCsv_triggered();

    /**
     * @brief Triggered to copy the protocol hierarchy data as YAML.
     */
    void on_actionCopyAsYaml_triggered();

    /**
     * @brief Triggered to copy the list of displayed protocols.
     */
    void on_actionCopyProtoList_triggered();

    /**
     * @brief Triggered to disable the currently selected protocols.
     */
    void on_actionDisableProtos_triggered();

    /**
     * @brief Triggered to revert protocol enablement states to their defaults.
     */
    void on_actionRevertProtos_triggered();

    /**
     * @brief Handles help requests from the dialog button box.
     */
    void on_buttonBox_helpRequested();

private:
    Ui::ProtocolHierarchyDialog *ui; /**< Pointer to the user interface form elements. */
    QAction *proto_disable_; /**< Action used to disable a selected protocol. */
    QAction *proto_revert_; /**< Action used to revert protocol disablement. */
    QMenu ctx_menu_; /**< The context menu for the tree widget. */
    PercentBarDelegate percent_bar_delegate_; /**< Delegate for drawing percentage bars in the tree. */
    QString display_filter_; /**< The current display filter string. */
    QSet<QString> used_protos_; /**< Set of protocols present in the hierarchy. */

    /**
     * @brief Callback function used by g_node_children_foreach to populate the tree.
     * @param node The GNode representing a protocol in the hierarchy.
     * @param data Pointer to user data (typically the dialog or current parent item).
     */
    static void addTreeNode(GNode *node, void *data);

    /**
     * @brief Updates the dialog's widgets based on the current capture state.
     */
    void updateWidgets() override;

    /**
     * @brief Extracts data from a tree widget item into a generic variant list.
     * @param item The tree widget item to extract data from.
     * @return A list of QVariant items corresponding to the columns of the row.
     */
    QList<QVariant> protoHierRowData(QTreeWidgetItem *item) const;
};

#endif // PROTOCOL_HIERARCHY_DIALOG_H
