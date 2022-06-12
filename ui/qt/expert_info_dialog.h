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

#include <glib.h>

#include "filter_action.h"
#include "wireshark_dialog.h"
#include <ui/qt/models/expert_info_model.h>
#include <ui/qt/models/expert_info_proxy_model.h>
#include <ui/qt/widgets/expert_info_view.h>

#include <QMenu>

namespace Ui {
class ExpertInfoDialog;
}

class ExpertInfoDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit ExpertInfoDialog(QWidget &parent, CaptureFile& capture_file, QString displayFilter);
    ~ExpertInfoDialog();

    void clearAllData();

    ExpertInfoTreeView* getExpertInfoView();

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

private:
    Ui::ExpertInfoDialog *ui;

    ExpertInfoModel* expert_info_model_;
    ExpertInfoProxyModel* proxyModel_;

    QMenu ctx_menu_;

    QString display_filter_;

private slots:
    void retapPackets();
    void captureEvent(CaptureEvent e);

    void updateWidgets();

    void on_actionShowError_toggled(bool checked);
    void on_actionShowWarning_toggled(bool checked);
    void on_actionShowNote_toggled(bool checked);
    void on_actionShowChat_toggled(bool checked);
    void on_actionShowComment_toggled(bool checked);

    void showExpertInfoMenu(QPoint pos);
    void filterActionTriggered();
    void collapseTree();
    void expandTree();

    void on_limitCheckBox_toggled(bool);
    void on_groupBySummaryCheckBox_toggled(bool);
    void on_searchLineEdit_textChanged(const QString &search_re);
    void on_buttonBox_helpRequested();
};

#endif // EXPERT_INFO_DIALOG_H
