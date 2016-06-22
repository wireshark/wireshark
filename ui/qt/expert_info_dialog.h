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

#include <QMenu>
#include <QTreeWidgetItem>

struct epan_dissect;
struct expert_info_s;
struct _packet_info;

namespace Ui {
class ExpertInfoDialog;
}

class ExpertPacketTreeWidgetItem;

class ExpertInfoDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit ExpertInfoDialog(QWidget &parent, CaptureFile& capture_file);
    ~ExpertInfoDialog();

    void clearAllData();
    void setDisplayFilter(const QString &display_filter = QString());

signals:
    void goToPacket(int packet_num, int hf_id);
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

private:
    Ui::ExpertInfoDialog *ui;

    int comment_events_;
//    int disp_events;
    int chat_events_;
    int note_events_;
    int warn_events_;
    int error_events_;

    bool need_show_hide_;

    QMenu ctx_menu_;

    QHash<QString, QTreeWidgetItem*> ei_to_ti_;
    QHash<QTreeWidgetItem*, QList<QTreeWidgetItem *> > gti_packets_;
    QList<QAction *> severity_actions_;

    QString display_filter_;

    void addExpertInfo(ExpertPacketTreeWidgetItem *packet_ti);
    // Called from tapPacket
    void addExpertInfo(struct expert_info_s *expert_info);
    // Called from tapDraw
    void updateCounts();

    // Callbacks for register_tap_listener
    static void tapReset(void *eid_ptr);
    static gboolean tapPacket(void *eid_ptr, struct _packet_info *pinfo, struct epan_dissect *, const void *data);
    static void tapDraw(void *eid_ptr);

    QTreeWidgetItem *ensureGroupTreeWidgetItem(ExpertPacketTreeWidgetItem *packet_ti);
    void addPacketTreeItems();

private slots:
    void retapPackets();
    void retapStarted();
    void retapFinished();

    void updateWidgets();

    void actionShowToggled();
    void showProtoHierMenu(QPoint pos);
    void filterActionTriggered();
    void captureFileClosing();

    void on_expertInfoTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *);
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
