/* main_window.h
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

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <stdio.h>

#include "config.h"

#include <glib.h>

#include "file.h"

#include <QMainWindow>
#include <QSplitter>
#include "main_welcome.h"
#include "packet_list.h"
#include "display_filter_combo.h"
#include "progress_bar.h"

class QAction;

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

protected:
    void keyPressEvent(QKeyEvent *event);

private:
    Ui::MainWindow *main_ui_;
    QMenu *open_recent_menu_;
    QSplitter *splitter_v_;
    MainWelcome *main_welcome_;
    DisplayFilterCombo *df_combo_box_;
    capture_file *cap_file_;
    PacketList *packet_list_;

signals:
    void showProgress(progdlg_t **dlg_p, bool animate, const QString message, bool terminate_is_stop, bool *stop_flag, float pct);

public slots:
    void captureFileReadStarted(const capture_file *cf);
    void captureFileReadFinished(const capture_file *cf);
    void captureFileClosing(const capture_file *cf);
    void captureFileClosed(const capture_file *cf);

private slots:
    void updateRecentFiles();
    void openRecentCaptureFile(QString& cfPath = *new QString());
    void on_actionFileClose_triggered();
    void recentActionTriggered();
    void on_actionGoGoToPacket_triggered();
    void on_actionHelpWebsite_triggered();
    void on_actionHelpFAQ_triggered();
    void on_actionHelpAsk_triggered();
    void on_actionHelpDownloads_triggered();
    void on_actionHelpWiki_triggered();
    void on_actionHelpSampleCaptures_triggered();
    void on_goToCancel_clicked();
    void on_goToGo_clicked();
    void on_goToLineEdit_returnPressed();
};


#endif // MAINWINDOW_H
