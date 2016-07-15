/* progress_frame.h
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

#ifndef PROGRESS_FRAME_H
#define PROGRESS_FRAME_H

#include <glib.h>

#include <QFrame>

namespace Ui {
class ProgressFrame;
}

#if defined(Q_OS_WIN) && QT_VERSION >= QT_VERSION_CHECK(5, 2, 0)
#include <QWinTaskbarButton>
#include <QWinTaskbarProgress>
#endif

class ProgressFrame;
class QDialogButtonBox;
class QElapsedTimer;
class QGraphicsOpacityEffect;
class QPropertyAnimation;

// Define the structure describing a progress dialog.
struct progdlg {
    ProgressFrame *progress_frame;  // This progress frame
    QWidget *top_level_window;  // Progress frame's main window
};

class ProgressFrame : public QFrame
{
    Q_OBJECT

public:
    explicit ProgressFrame(QWidget *parent = 0);
    ~ProgressFrame();

#ifdef QWINTASKBARPROGRESS_H
    void enableTaskbarUpdates(bool enable = true) { update_taskbar_ = enable; }
#endif
    static void addToButtonBox(QDialogButtonBox *button_box, QObject *main_window);
    void captureFileClosing();

public slots:
    struct progdlg *showProgress(bool animate, bool terminate_is_stop, gboolean *stop_flag, int value = 0);
    struct progdlg *showBusy(bool animate, bool terminate_is_stop, gboolean *stop_flag);
    void setValue(int value);
    void hide();

signals:
    void showRequested(bool animate, bool terminate_is_stop, gboolean *stop_flag);
    void valueChanged(int value);
    void maximumValueChanged(int value);
    void setHidden();
    void stopLoading();

protected:
#if !defined(Q_OS_MAC) || QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
    void timerEvent(QTimerEvent *event);
#endif

private:
    Ui::ProgressFrame *ui;

    struct progdlg progress_dialog_;
    QString message_;
    QString status_;
    bool terminate_is_stop_;
    gboolean *stop_flag_;
#if !defined(Q_OS_MAC) || QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
    int show_timer_;
    QGraphicsOpacityEffect *effect_;
    QPropertyAnimation *animation_;
#endif
#ifdef QWINTASKBARPROGRESS_H
    bool update_taskbar_;
    QWinTaskbarProgress *taskbar_progress_;
#endif

private slots:
    void on_stopButton_clicked();

    void show(bool animate, bool terminate_is_stop, gboolean *stop_flag);
    void setMaximumValue(int value);
};

#endif // PROGRESS_FRAME_H

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
