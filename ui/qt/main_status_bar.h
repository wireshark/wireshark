/* main_status_bar.h
 *
 * $Id$
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

#include "label_stack.h"
#include "progress_bar.h"

#include <QStatusBar>
#include <QLabel>

class MainStatusBar : public QStatusBar
{
    Q_OBJECT
public:
    explicit MainStatusBar(QWidget *parent = 0);
    void showExpert();
    void hideExpert();

private:
    QLabel expert_status_;
    LabelStack info_status_;
    ProgressBar progress_bar_;
    LabelStack packet_status_;
    LabelStack profile_status_;

    void expertUpdate();

signals:

public slots:
    void pushTemporaryStatus(QString &message);
    void popTemporaryStatus();
    void pushFileStatus(QString &message);
    void popFileStatus();
    void pushFieldStatus(QString &message);
    void popFieldStatus();
    void pushFilterStatus(QString &message);
    void popFilterStatus();
    void pushPacketStatus(QString &message);
    void popPacketStatus();
    void pushProfileStatus(QString &message);
    void popProfileStatus();
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
