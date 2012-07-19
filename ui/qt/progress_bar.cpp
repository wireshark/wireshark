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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "progress_bar.h"

#include "wireshark_application.h"

#include <QPropertyAnimation>

static progdlg_t *
common_create_progress_dlg(bool animate, const gpointer top_level_window,
                           gboolean terminate_is_stop, gboolean *stop_flag,
                           int value)
{
    ProgressBar *pb;
    QWidget *main_window;

    g_warning("ccpd %d  %p", animate, top_level_window);
    if (!top_level_window) {
        return NULL;
    }

    g_warning("got tlw");
    main_window = qobject_cast<QWidget *>((QObject *)top_level_window);

    if (!main_window) {
        return NULL;
    }

    g_warning("got mw");
    pb = main_window->findChild<ProgressBar *>();

    if (!pb) {
        return NULL;
    }
    g_warning("got pb");
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
//        GtkWidget *dlg_w = dlg->dlg_w;
//        GtkWidget *prog_bar;

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
    QProgressBar(parent)
{
    m_dlg.progressBar = this;
    m_dlg.topLevelWindow = window();
    hide();
}

progdlg_t * ProgressBar::show(bool animate, bool terminate_is_stop, gboolean *stop_flag, int value) {

    m_terminate_is_stop = terminate_is_stop;
    m_stop_flag = stop_flag;

    setValue(value);

    // http://stackoverflow.com/questions/3930904/how-to-animate-widget-transparency-in-qt4
    if (animate) {
        QPropertyAnimation animate = new QPropertyAnimation(this, "windowOpacity", this);

        animate.setDuration(2 * 1000);
        animate.setStartValue(1);
        animate.setEndValue(0);
        animate.start();
    }
    QProgressBar::show();

    return &m_dlg;
}
