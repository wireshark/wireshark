/* main_welcome.h
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

#ifndef MAIN_WELCOME_H
#define MAIN_WELCOME_H

#include <QFrame>
#include <QListWidget>

//class MWOverlay : public QWidget
//{
//public:
//    MWOverlay(QWidget *parent);

//protected:
//    void paintEvent(QPaintEvent *event);
//};

namespace Ui {
    class MainWelcome;
}

class MainWelcome : public QFrame
{
    Q_OBJECT
public:
    explicit MainWelcome(QWidget *parent = 0);

protected:
//    void resizeEvent(QResizeEvent *event);

private:
    // QListWidget doesn't activate items when the return or enter keys are pressed on OS X.
    // We may want to subclass it at some point.
    Ui::MainWelcome *welcome_ui_;
    QListWidget *task_list_;
    QListWidget *recent_files_;
//    MWOverlay *overlay;


signals:
    void recentFileActivated(QString& cfile);

private slots:
    void showTask();
    void updateRecentFiles();
    void openRecentItem(QListWidgetItem *item);

};

#endif // MAIN_WELCOME_H

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
