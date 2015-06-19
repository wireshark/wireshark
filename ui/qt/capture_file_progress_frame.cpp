/* capture_file_progress_frame.cpp
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

#include "config.h"

#include "capture_file_progress_frame.h"
#include "ui_capture_file_progress_frame.h"

#include "ui/progress_dlg.h"

#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>

#include "stock_icon.h"
#include "wireshark_application.h"

// To do:
// - Use a different icon?
// - Add an NSProgressIndicator to the dock icon on OS X.
// - Start adding the progress bar to dialogs.
// - Don't complain so loudly when the user stops a capture.

progdlg_t *
delayed_create_progress_dlg(const gpointer top_level_window, const gchar *task_title, const gchar *item_title,
                            gboolean terminate_is_stop, gboolean *stop_flag,
                            const GTimeVal *start_time, gfloat progress)
{
    Q_UNUSED(task_title);
    Q_UNUSED(item_title);
    Q_UNUSED(start_time);

    CaptureFileProgressFrame *cfpf;
    QWidget *main_window;

    if (!top_level_window) {
        return NULL;
    }

    main_window = qobject_cast<QWidget *>((QObject *)top_level_window);

    if (!main_window) {
        return NULL;
    }

    cfpf = main_window->findChild<CaptureFileProgressFrame *>();

    if (!cfpf) {
        return NULL;
    }
    return cfpf->show(true, terminate_is_stop, stop_flag, progress * 100);
}

/*
 * Update the progress information of the progress bar box.
 */
void
update_progress_dlg(progdlg_t *dlg, gfloat percentage, const gchar *status)
{
    Q_UNUSED(status);
    if (!dlg) return;

    dlg->progress_frame->setValue(percentage * 100);

    /*
     * Flush out the update and process any input events.
     */
    WiresharkApplication::processEvents();
}

/*
 * Destroy the progress bar.
 */
void
destroy_progress_dlg(progdlg_t *dlg)
{
    dlg->progress_frame->hide();
}

CaptureFileProgressFrame::CaptureFileProgressFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::CaptureFileProgressFrame)
  , terminate_is_stop_(false)
  , stop_flag_(NULL)
#ifdef QWINTASKBARPROGRESS_H
  , taskbar_progress_(NULL)
#endif
{
    ui->setupUi(this);

    progress_dialog_.progress_frame = this;
    progress_dialog_.top_level_window = window();

    ui->progressBar->setStyleSheet(QString(
            "QProgressBar {"
            "  max-width: 20em;"
            "  min-height: 0.8em;"
            "  max-height: 1em;"
            "  border-bottom: 0px;"
            "  border-top: 0px;"
            "  background: transparent;"
            "}"));

    int one_em = fontMetrics().height();
    ui->pushButton->setIconSize(QSize(one_em, one_em));
    ui->pushButton->setStyleSheet(QString(
            "QPushButton {"
            "  image: url(:/dfilter/dfilter_erase_normal.png) center;"
            "  min-height: 0.8em;"
            "  max-height: 1em;"
            "  min-width: 0.8em;"
            "  max-width: 1em;"
            "  border: 0px;"
            "  padding: 0px;"
            "  margin: 0px;"
            "  background: transparent;"
            "}"
            "QPushButton:hover {"
            "  image: url(:/dfilter/dfilter_erase_active.png) center;"
            "}"
            "QPushButton:pressed {"
            "  image: url(:/dfilter/dfilter_erase_selected.png) center;"
            "}"));
    hide();
}

CaptureFileProgressFrame::~CaptureFileProgressFrame()
{
    delete ui;
}

struct progdlg *CaptureFileProgressFrame::show(bool animate, bool terminate_is_stop, gboolean *stop_flag, int value)
{
    terminate_is_stop_ = terminate_is_stop;
    stop_flag_ = stop_flag;

    ui->progressBar->setValue(value);

#if !defined(Q_OS_MAC) || QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
    if (animate) {
        QGraphicsOpacityEffect *effect = new QGraphicsOpacityEffect(this);
        this->setGraphicsEffect(effect);

        QPropertyAnimation *animation = new QPropertyAnimation(effect, "opacity");

        animation->setDuration(750);
        animation->setStartValue(0.1);
        animation->setEndValue(1.0);
        animation->setEasingCurve(QEasingCurve::InOutQuad);
        animation->start();
    }
#else
    Q_UNUSED(animate);
#endif

#ifdef QWINTASKBARPROGRESS_H
    // windowHandle() is picky about returning a non-NULL value so we check it
    // each time.
    if (!taskbar_progress_ && window()->windowHandle()) {
        QWinTaskbarButton *taskbar_button = new QWinTaskbarButton(this);
        if (taskbar_button) {
            taskbar_button->setWindow(window()->windowHandle());
            taskbar_progress_ = taskbar_button->progress();
            connect(this, SIGNAL(valueChanged(int)), taskbar_progress_, SLOT(setValue(int)));
        }
    }
    if (taskbar_progress_) {
        taskbar_progress_->show();
    }
    taskbar_progress_->resume();
#endif

    QFrame::show();
    return &progress_dialog_;
}

void CaptureFileProgressFrame::setValue(int value)
{
    ui->progressBar->setValue(value);
}

#ifdef QWINTASKBARPROGRESS_H
void CaptureFileProgressFrame::hide()
{
    if (taskbar_progress_) {
        taskbar_progress_->reset();
        taskbar_progress_->hide();
    }
    QFrame::hide();
}
#endif

void CaptureFileProgressFrame::on_pushButton_clicked()
{
    emit stopLoading();
}

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
