/* capture_file_progress_frame.h
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

#ifndef CAPTURE_FILE_PROGRESS_FRAME_H
#define CAPTURE_FILE_PROGRESS_FRAME_H

#include <glib.h>

#include <QFrame>

namespace Ui {
class CaptureFileProgressFrame;
}

#if defined(Q_OS_WIN) && QT_VERSION >= QT_VERSION_CHECK(5, 2, 0)
#include <QWinTaskbarButton>
#include <QWinTaskbarProgress>
#endif

class CaptureFileProgressFrame;

// Define the structure describing a progress dialog.
struct progdlg {
    CaptureFileProgressFrame *progress_frame;  // This progress frame
    QWidget *top_level_window;  // Progress frame's main window
};

class CaptureFileProgressFrame : public QFrame
{
    Q_OBJECT

public:
    explicit CaptureFileProgressFrame(QWidget *parent = 0);
    ~CaptureFileProgressFrame();

    struct progdlg *show(bool animate, bool terminate_is_stop, gboolean *stop_flag, int value);
#ifdef QWINTASKBARPROGRESS_H
    void hide();
#endif

public slots:
    void setValue(int value);

signals:
    void stopLoading();

private slots:
    void on_pushButton_clicked();

private:
    Ui::CaptureFileProgressFrame *ui;

    struct progdlg progress_dialog_;
    QString message_;
    QString status_;
    bool terminate_is_stop_;
    gboolean *stop_flag_;
#ifdef QWINTASKBARPROGRESS_H
    QWinTaskbarProgress *taskbar_progress_;
#endif
};

#endif // CAPTURE_FILE_PROGRESS_FRAME_H

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
