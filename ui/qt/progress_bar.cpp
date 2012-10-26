/* progress_bar.cpp
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

#include "config.h"

#include "progress_bar.h"

#include "wireshark_application.h"

#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>

static progdlg_t *
common_create_progress_dlg(bool animate, const gpointer top_level_window,
                           gboolean terminate_is_stop, gboolean *stop_flag,
                           int value)
{
    ProgressBar *pb;
    QWidget *main_window;

    if (!top_level_window) {
        return NULL;
    }

    main_window = qobject_cast<QWidget *>((QObject *)top_level_window);

    if (!main_window) {
        return NULL;
    }

    pb = main_window->findChild<ProgressBar *>();

    if (!pb) {
        return NULL;
    }
    return pb->show(animate, terminate_is_stop, stop_flag, value);
}

progdlg_t *
create_progress_dlg(const gpointer top_level_window, const gchar *task_title, const gchar *item_title,
                            gboolean terminate_is_stop, gboolean *stop_flag,
                            const GTimeVal *start_time, gfloat progress)
{
    Q_UNUSED(task_title);
    Q_UNUSED(item_title);
    Q_UNUSED(start_time);

    return common_create_progress_dlg(false, top_level_window, terminate_is_stop, stop_flag, progress * 100);
}

progdlg_t *
delayed_create_progress_dlg(const gpointer top_level_window, const gchar *task_title, const gchar *item_title,
                            gboolean terminate_is_stop, gboolean *stop_flag,
                            const GTimeVal *start_time, gfloat progress)
{
    Q_UNUSED(task_title);
    Q_UNUSED(item_title);
    Q_UNUSED(start_time);

    return common_create_progress_dlg(true, top_level_window, terminate_is_stop, stop_flag, progress * 100);
}

/*
 * Update the progress information of the progress bar box.
 */
void
update_progress_dlg(progdlg_t *dlg, gfloat percentage, const gchar *status)
{
    Q_UNUSED(status);

    dlg->progressBar->setValue(percentage * 100);

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
    dlg->progressBar->hide();
}

// XXX - Add a "stop what you're doing this instant" button.
// XXX - We need to show the task and item titles. Maybe as a tooltip or popped
//       into our sibling status message?
ProgressBar::ProgressBar(QWidget *parent) :
    QProgressBar(parent), m_terminate_is_stop(false), m_stop_flag(NULL)
{
    m_dlg.progressBar = this;
    m_dlg.topLevelWindow = window();

//#ifdef Q_WS_MAC
//    // https://bugreports.qt-project.org/browse/QTBUG-11569
//    setAttribute(Qt::WA_MacSmallSize, true);
//#endif
    setTextVisible(false);
    setStyleSheet(QString(
            "ProgressBar {"
            "  max-width: 20em;"
            "  min-height: 0.8em;"
            "  max-height: 1em;"
            "  border-bottom: 0;"
            "  background: transparent;"
            "}"));

    hide();
}

progdlg_t * ProgressBar::show(bool animate, bool terminate_is_stop, gboolean *stop_flag, int value) {

    m_terminate_is_stop = terminate_is_stop;
    m_stop_flag = stop_flag;

    setValue(value);

#ifndef Q_WS_MAC
    if (animate) {
        QGraphicsOpacityEffect *effect = new QGraphicsOpacityEffect(this);
        this->setGraphicsEffect(effect);

        QPropertyAnimation *animation = new QPropertyAnimation(effect, "opacity");

        animation->setDuration(750);
        animation->setStartValue(0.1);
        animation->setEndValue(1.0);
        animation->start();
    }
#else
    Q_UNUSED(animate);
#endif

    QProgressBar::show();
    return &m_dlg;
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
