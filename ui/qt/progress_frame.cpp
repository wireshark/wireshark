/* progress_frame.cpp
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

#include "progress_frame.h"
#include <ui_progress_frame.h>

#include "ui/progress_dlg.h"

#include <QDialogButtonBox>
#include <QGraphicsOpacityEffect>
#include <QBoxLayout>
#include <QPropertyAnimation>

#include "stock_icon_tool_button.h"
#include "wireshark_application.h"

// To do:
// - Add an NSProgressIndicator to the dock icon on OS X.
// - Start adding the progress bar to dialogs.
// - Don't complain so loudly when the user stops a capture.

progdlg_t *
create_progress_dlg(gpointer top_level_window, const gchar *, const gchar *,
                               gboolean terminate_is_stop, gboolean *stop_flag) {
    ProgressFrame *pf;
    QWidget *main_window;

    if (!top_level_window) {
        return NULL;
    }

    main_window = qobject_cast<QWidget *>((QObject *)top_level_window);

    if (!main_window) {
        return NULL;
    }

    pf = main_window->findChild<ProgressFrame *>();

    if (!pf) {
        return NULL;
    }
    return pf->showProgress(true, terminate_is_stop, stop_flag, 0);
}

progdlg_t *
delayed_create_progress_dlg(gpointer top_level_window, const gchar *task_title, const gchar *item_title,
                            gboolean terminate_is_stop, gboolean *stop_flag,
                            const GTimeVal *, gfloat progress)
{
    progdlg_t *progress_dialog = create_progress_dlg(top_level_window, task_title, item_title, terminate_is_stop, stop_flag);
    update_progress_dlg(progress_dialog, progress, item_title);
    return progress_dialog;
}

/*
 * Update the progress information of the progress bar box.
 */
void
update_progress_dlg(progdlg_t *dlg, gfloat percentage, const gchar *)
{
    if (!dlg) return;

    dlg->progress_frame->setValue(percentage * 100);

    /*
     * Flush out the update and process any input events.
     */
    WiresharkApplication::processEvents();

    /* Redraw so the progress bar shows the update */
    dlg->progress_frame->update();
}

/*
 * Destroy the progress bar.
 */
void
destroy_progress_dlg(progdlg_t *dlg)
{
    dlg->progress_frame->hide();
}

ProgressFrame::ProgressFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::ProgressFrame)
  , terminate_is_stop_(false)
  , stop_flag_(NULL)
#if !defined(Q_OS_MAC) || QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
  , show_timer_(-1)
  , effect_(NULL)
  , animation_(NULL)
#endif
#ifdef QWINTASKBARPROGRESS_H
  , update_taskbar_(false)
  , taskbar_progress_(NULL)
#endif
{
    ui->setupUi(this);

    progress_dialog_.progress_frame = this;
    progress_dialog_.top_level_window = window();

    ui->progressBar->setStyleSheet(QString(
            "QProgressBar {"
            "  max-width: 20em;"
            "  min-height: 0.5em;"
            "  max-height: 1em;"
            "  border-bottom: 0px;"
            "  border-top: 0px;"
            "  background: transparent;"
            "}"));

    ui->stopButton->setStockIcon("x-filter-clear");
    ui->stopButton->setIconSize(QSize(14, 14));
    ui->stopButton->setStyleSheet(
            "QToolButton {"
            "  border: none;"
            "  background: transparent;" // Disables platform style on Windows.
            "  padding: 0px;"
            "  margin: 0px;"
            "  min-height: 0.8em;"
            "  max-height: 1em;"
            "  min-width: 0.8em;"
            "  max-width: 1em;"
            "}"
            );

#if !defined(Q_OS_MAC) || QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
    effect_ = new QGraphicsOpacityEffect(this);
    animation_ = new QPropertyAnimation(effect_, "opacity", this);
#endif

    connect(this, SIGNAL(showRequested(bool,bool,gboolean*)),
            this, SLOT(show(bool,bool,gboolean*)));
    hide();
}

ProgressFrame::~ProgressFrame()
{
    delete ui;
}

struct progdlg *ProgressFrame::showProgress(bool animate, bool terminate_is_stop, gboolean *stop_flag, int value)
{
    setMaximumValue(100);
    ui->progressBar->setValue(value);
    emit showRequested(animate, terminate_is_stop, stop_flag);
    return &progress_dialog_;
}

progdlg *ProgressFrame::showBusy(bool animate, bool terminate_is_stop, gboolean *stop_flag)
{
    setMaximumValue(0);
    emit showRequested(animate, terminate_is_stop, stop_flag);
    return &progress_dialog_;
}

void ProgressFrame::addToButtonBox(QDialogButtonBox *button_box, QObject *main_window)
{
    // We have a ProgressFrame in the main status bar which is controlled
    // from the capture file and other parts of the application via
    // create_progress_dlg and delayed_create_progress_dlg.
    // Create a new ProgressFrame and pair it with the main instance.
    ProgressFrame *main_progress_frame = main_window->findChild<ProgressFrame *>();
    if (!button_box || !main_progress_frame) return;

    QBoxLayout *layout = qobject_cast<QBoxLayout *>(button_box->layout());
    if (!layout) return;

    ProgressFrame *progress_frame = new ProgressFrame(button_box);

    // Insert ourselves after the first spacer we find, otherwise the
    // far right of the button box.
    int idx = layout->count();
    for (int i = 0; i < layout->count(); i++) {
        if (layout->itemAt(i)->spacerItem()) {
            idx = i + 1;
            break;
        }
    }
    layout->insertWidget(idx, progress_frame);

    int one_em = progress_frame->fontMetrics().height();
    progress_frame->setMaximumWidth(one_em * 8);
    connect(main_progress_frame, SIGNAL(showRequested(bool,bool,gboolean*)),
            progress_frame, SLOT(show(bool,bool,gboolean*)));
    connect(main_progress_frame, SIGNAL(maximumValueChanged(int)),
            progress_frame, SLOT(setMaximumValue(int)));
    connect(main_progress_frame, SIGNAL(valueChanged(int)),
            progress_frame, SLOT(setValue(int)));
    connect(main_progress_frame, SIGNAL(setHidden()),
            progress_frame, SLOT(hide()));

    connect(progress_frame, SIGNAL(stopLoading()),
            main_progress_frame, SIGNAL(stopLoading()));
}

void ProgressFrame::captureFileClosing()
{
    // Hide any paired ProgressFrames and disconnect from them.
    emit setHidden();
    disconnect(SIGNAL(showRequested(bool,bool,gboolean*)));
    disconnect(SIGNAL(maximumValueChanged(int)));
    disconnect(SIGNAL(valueChanged(int)));

    connect(this, SIGNAL(showRequested(bool,bool,gboolean*)),
            this, SLOT(show(bool,bool,gboolean*)));
}

void ProgressFrame::setValue(int value)
{
    ui->progressBar->setValue(value);
    emit valueChanged(value);
}

#if !defined(Q_OS_MAC) || QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
void ProgressFrame::timerEvent(QTimerEvent *event)
{
    if (event->timerId() == show_timer_) {
        killTimer(show_timer_);
        show_timer_ = -1;

        this->setGraphicsEffect(effect_);

        animation_->setDuration(750);
        animation_->setStartValue(0.1);
        animation_->setEndValue(1.0);
        animation_->setEasingCurve(QEasingCurve::InOutQuad);
        animation_->start();

        QFrame::show();
    } else {
        QFrame::timerEvent(event);
    }
}
#endif

void ProgressFrame::hide()
{
#if !defined(Q_OS_MAC) || QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
    show_timer_ = -1;
#endif
    emit setHidden();
    QFrame::hide();
#ifdef QWINTASKBARPROGRESS_H
    if (taskbar_progress_) {
        disconnect(this, SIGNAL(valueChanged(int)), taskbar_progress_, SLOT(setValue(int)));
        taskbar_progress_->reset();
        taskbar_progress_->hide();
    }
#endif
}

void ProgressFrame::on_stopButton_clicked()
{
    emit stopLoading();
}

#if !defined(Q_OS_MAC) || QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
const int show_delay_ = 500; // ms
#endif

void ProgressFrame::show(bool animate, bool terminate_is_stop, gboolean *stop_flag)
{
    terminate_is_stop_ = terminate_is_stop;
    stop_flag_ = stop_flag;

    if (stop_flag) {
        ui->stopButton->show();
    } else {
        ui->stopButton->hide();
    }

#if !defined(Q_OS_MAC) || QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
    if (animate) {
        show_timer_ = startTimer(show_delay_);
    } else {
        QFrame::show();
    }
#else
    Q_UNUSED(animate);
    QFrame::show();
#endif

#ifdef QWINTASKBARPROGRESS_H
    // windowHandle() is picky about returning a non-NULL value so we check it
    // each time.
    if (update_taskbar_ && !taskbar_progress_ && window()->windowHandle()) {
        QWinTaskbarButton *taskbar_button = new QWinTaskbarButton(this);
        if (taskbar_button) {
            taskbar_button->setWindow(window()->windowHandle());
            taskbar_progress_ = taskbar_button->progress();
        }
    }
    if (taskbar_progress_) {
        taskbar_progress_->show();
        taskbar_progress_->reset();
        connect(this, SIGNAL(valueChanged(int)), taskbar_progress_, SLOT(setValue(int)));
    }
#endif
}

void ProgressFrame::setMaximumValue(int value)
{
    ui->progressBar->setMaximum(value);
    emit maximumValueChanged(value);
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
