/* main_status_bar.h
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

#ifndef MAIN_STATUS_BAR_H
#define MAIN_STATUS_BAR_H

#include "wireshark_application.h"
#include "label_stack.h"
#include "progress_bar.h"

#include <QStatusBar>
#include <QLabel>
#include <QMenu>

#include "cfile.h"

class MainStatusBar : public QStatusBar
{
    Q_OBJECT
public:
    explicit MainStatusBar(QWidget *parent = 0);
    void showExpert();
    void hideExpert();
    void expertUpdate();

private:
    QLabel expert_status_;
    LabelStack info_status_;
    ProgressBar progress_bar_;
    LabelStack packet_status_;
    LabelStack profile_status_;
    capture_file *cap_file_;
    QMenu profile_menu_;
    QMenu ctx_menu_;
    QAction *edit_action_;
    QAction *delete_action_;

signals:

public slots:
    void setCaptureFile(capture_file *cf);
    void pushTemporaryStatus(QString &message);
    void popTemporaryStatus();
    void pushFileStatus(QString &message);
    void popFileStatus();
    void pushFieldStatus(QString &message);
    void popFieldStatus();
    void pushFilterStatus(QString &message);
    void popFilterStatus();
    void pushProfileName();
    void updateCaptureStatistics(capture_session * cap_session);

private slots:
    void pushPacketStatus(QString &message);
    void popPacketStatus();
    void pushProfileStatus(QString &message);
    void popProfileStatus();
    void toggleBackground(bool enabled);
    void switchToProfile();
    void manageProfile();
    void showProfileMenu(const QPoint &global_pos, Qt::MouseButton button);
};

#endif // MAIN_STATUS_BAR_H

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
