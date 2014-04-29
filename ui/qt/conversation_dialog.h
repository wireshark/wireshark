/* conversation_dialog.h
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

#ifndef CONVERSATION_DIALOG_H
#define CONVERSATION_DIALOG_H

#include <conversation_tree_widget.h>

#include <file.h>

#include "ui/follow.h"

#include <QAction>
#include <QMenu>

#include <QDialog>

namespace Ui {
class ConversationDialog;
}

class ConversationDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ConversationDialog(QWidget *parent = 0, capture_file *cf = NULL, const char *stat_arg = NULL);
    ~ConversationDialog();

public slots:
    void setCaptureFile(capture_file *cf);

signals:
    void filterAction(QString& filter, FilterAction::Action action, FilterAction::ActionType type);
    void openFollowStreamDialog(follow_type_t type);
    void openTcpStreamGraph(int graph_type);

private:
    Ui::ConversationDialog *ui;

    capture_file *cap_file_;
    QString filter_;
    QMenu conv_type_menu_;
    QMap<conversation_type_e, ConversationTreeWidget *> conv_type_to_tree_;
    QList<QAction> conv_actions_;
    QPushButton *copy_bt_;
    QPushButton *follow_bt_;
    QPushButton *graph_bt_;

    void initStatCmdMap();
    // Adds a conversation tree. Returns true if the tree was freshly created, false if it was cached.
    bool addConversationType(conversation_type_e conv_type);
    conversation_type_e tabType(int index);
    conv_item_t *currentConversation();

private slots:
    void updateWidgets();
    void toggleConversation();
    void itemSelectionChanged();
    void on_nameResolutionCheckBox_toggled(bool checked);
    void on_displayFilterCheckBox_toggled(bool checked);
    void setTabText(QWidget *tree, const QString &text);
    void chainFilterAction(QString& filter, FilterAction::Action action, FilterAction::ActionType type);
    void followStream();
    void copyAsCsv();
    void copyAsYaml();
    void graphTcp();
    void on_buttonBox_helpRequested();
};

#endif // CONVERSATION_DIALOG_H

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
