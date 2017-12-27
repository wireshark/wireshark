/* expert_info_dialog.h
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
    explicit ExpertInfoDialog(QWidget &parent, CaptureFile& capture_file);
    ~ExpertInfoDialog();

    void clearAllData();
    void setDisplayFilter(const QString &display_filter = QString());

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
    void captureEvent(CaptureEvent *e);

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
