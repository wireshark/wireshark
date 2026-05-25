/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPERT_INFO_DIALOG_H
#define EXPERT_INFO_DIALOG_H

#include <config.h>

#include "filter_action.h"
#include "wireshark_dialog.h"
#include <ui/qt/models/expert_info_model.h>
#include <ui/qt/models/expert_info_proxy_model.h>
#include <ui/qt/widgets/expert_info_view.h>

#include <QMenu>

namespace Ui {
class ExpertInfoDialog;
}

/**
 * @brief A dialog window displaying expert information from a capture file.
 */
class ExpertInfoDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ExpertInfoDialog.
     * @param parent The parent widget.
     * @param capture_file The capture file containing the expert information.
     * @param displayFilter The initial display filter to apply to the dialog.
     */
    explicit ExpertInfoDialog(QWidget &parent, CaptureFile& capture_file, QString displayFilter);

    /**
     * @brief Destroys the ExpertInfoDialog.
     */
    ~ExpertInfoDialog();

    /**
     * @brief Clears all currently displayed expert information data.
     */
    void clearAllData();

    /**
     * @brief Retrieves the tree view widget used to display expert information.
     * @return A pointer to the ExpertInfoTreeView.
     */
    ExpertInfoTreeView* getExpertInfoView();

signals:
    /**
     * @brief Signal emitted to trigger a display filter action.
     * @param filter The filter string to be applied.
     * @param action The filter action to perform.
     * @param type The type of the filter action.
     */
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

private:
    /** Pointer to the generated UI elements. */
    Ui::ExpertInfoDialog *ui;

    /** Model managing the underlying expert information data. */
    ExpertInfoModel* expert_info_model_;

    /** Proxy model for sorting and filtering the expert information tree. */
    ExpertInfoProxyModel* proxyModel_;

    /** Context menu for the expert information view. */
    QMenu ctx_menu_;

    /** The current display filter applied to the expert info dialog. */
    QString display_filter_;

private slots:
    /**
     * @brief Slot triggered to retap the packets and rebuild expert information.
     */
    void retapPackets();

    /**
     * @brief Slot triggered to handle capture-related events.
     * @param e The capture event.
     */
    void captureEvent(CaptureEvent e);

    /**
     * @brief Slot triggered to update the dialog widgets based on the current data state.
     */
    void updateWidgets() override;

    /**
     * @brief Slot triggered when the "Show Error" action is toggled.
     * @param checked True to show errors, false to hide them.
     */
    void on_actionShowError_toggled(bool checked);

    /**
     * @brief Slot triggered when the "Show Warning" action is toggled.
     * @param checked True to show warnings, false to hide them.
     */
    void on_actionShowWarning_toggled(bool checked);

    /**
     * @brief Slot triggered when the "Show Note" action is toggled.
     * @param checked True to show notes, false to hide them.
     */
    void on_actionShowNote_toggled(bool checked);

    /**
     * @brief Slot triggered when the "Show Chat" action is toggled.
     * @param checked True to show chat messages, false to hide them.
     */
    void on_actionShowChat_toggled(bool checked);

    /**
     * @brief Slot triggered when the "Show Comment" action is toggled.
     * @param checked True to show comments, false to hide them.
     */
    void on_actionShowComment_toggled(bool checked);

    /**
     * @brief Slot triggered to display the expert info context menu.
     * @param pos The position to display the menu at.
     */
    void showExpertInfoMenu(QPoint pos);

    /**
     * @brief Slot triggered when a filter action is selected from the context menu.
     */
    void filterActionTriggered();

    /**
     * @brief Slot triggered to collapse all items in the expert info tree.
     */
    void collapseTree();

    /**
     * @brief Slot triggered to expand all items in the expert info tree.
     */
    void expandTree();

    /**
     * @brief Slot triggered when the limit to display filter checkbox is toggled.
     */
    void limitCheckBoxToggled(bool);

    /**
     * @brief Slot triggered when the group by summary checkbox is toggled.
     */
    void on_groupBySummaryCheckBox_toggled(bool);

    /**
     * @brief Slot triggered when the text in the search line edit changes.
     * @param search_re The new search regular expression string.
     */
    void on_searchLineEdit_textChanged(const QString &search_re);

    /**
     * @brief Slot triggered when help is requested from the dialog's button box.
     */
    void on_buttonBox_helpRequested();
};

#endif // EXPERT_INFO_DIALOG_H
