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

#include "config.h"

#include "cfile.h"

#include "capchild/capture_session.h"

#include "label_stack.h"
#include "progress_frame.h"
#include "wireshark_application.h"

#include <QLabel>
#include <QMenu>
#include <QStatusBar>

class CaptureFile;
class QToolButton;

class MainStatusBar : public QStatusBar
{
    Q_OBJECT
public:
    explicit MainStatusBar(QWidget *parent = 0);
    void showExpert();
    void captureFileClosing();
    void expertUpdate();
    void setFileName(CaptureFile &cf);

private:
    QToolButton *expert_button_;
    QToolButton *comment_button_;
    LabelStack info_status_;
    ProgressFrame progress_frame_;
    LabelStack packet_status_;
    LabelStack profile_status_;
    capture_file *cap_file_;
    QMenu profile_menu_;
    QMenu ctx_menu_;
    QAction *edit_action_;
    QAction *delete_action_;

signals:
    void showExpertInfo();
    void editCaptureComment();
    void stopLoading();

public slots:
    void setCaptureFile(capture_file *cf);
    void pushTemporaryStatus(const QString &message);
    void popTemporaryStatus();
    void pushFileStatus(const QString &message, const QString &messagetip = QString());
    void popFileStatus();
    void pushFieldStatus(const QString &message);
    void popFieldStatus();
    void pushByteStatus(const QString &message);
    void popByteStatus();
    void pushFilterStatus(const QString &message);
    void popFilterStatus();
    void pushProfileName();
    void pushBusyStatus(const QString &message, const QString &messagetip = QString());
    void popBusyStatus();
    void pushProgressStatus(const QString &message, bool animate, bool terminate_is_stop = false, gboolean *stop_flag = NULL);
    void updateProgressStatus(int value);
    void popProgressStatus();

    void updateCaptureStatistics(capture_session * cap_session);
    void updateCaptureFixedStatistics(capture_session * cap_session);

private slots:
    void pushPacketStatus(const QString &message);
    void popPacketStatus();
    void pushProfileStatus(const QString &message);
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
