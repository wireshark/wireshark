/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROGRESS_FRAME_H
#define PROGRESS_FRAME_H

#include <QFrame>

namespace Ui {
class ProgressFrame;
}

#if (QT_VERSION < QT_VERSION_CHECK(6, 0, 0)) && defined(Q_OS_WIN)
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
    struct progdlg *showProgress(const QString &title, bool animate, bool terminate_is_stop, bool *stop_flag, int value = 0);
    struct progdlg *showBusy(bool animate, bool terminate_is_stop, bool *stop_flag);
    void setValue(int value);
    void hide();

signals:
    void showRequested(bool animate, bool terminate_is_stop, bool *stop_flag);
    void valueChanged(int value);
    void maximumValueChanged(int value);
    void setHidden();
    void stopLoading();

protected:
    void timerEvent(QTimerEvent *event);

private:
    Ui::ProgressFrame *ui;

    struct progdlg progress_dialog_;
    QString message_;
    QString status_;
    bool terminate_is_stop_;
    bool *stop_flag_;
    int show_timer_;
    QGraphicsOpacityEffect *effect_;
    QPropertyAnimation *animation_;
#ifdef QWINTASKBARPROGRESS_H
    bool update_taskbar_;
    QWinTaskbarProgress *taskbar_progress_;
#endif

private slots:
    void on_stopButton_clicked();

    void show(bool animate, bool terminate_is_stop, bool *stop_flag);
    void setMaximumValue(int value);
};

#endif // PROGRESS_FRAME_H
