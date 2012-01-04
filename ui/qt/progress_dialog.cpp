/* progress_dialog.cpp
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include "progress_dialog.h"

#include "progress_dlg.h"

progdlg_t *
delayed_create_progress_dlg(const gchar *task_title, const gchar *item_title,
                            gboolean terminate_is_stop, gboolean *stop_flag,
                            const GTimeVal *start_time, gfloat progress)
{
    GTimeVal    time_now;
    gdouble     delta_time;
    gdouble     min_display;
    progdlg_t  *dlg = NULL;

#define INIT_DELAY          0.1 * 1e6
#define MIN_DISPLAY_DEFAULT 2.0 * 1e6

    /* Create a progress dialog, but only if it's not likely to disappear
     * immediately, which can be disconcerting for the user.
     *
     * Arguments are as for create_progress_dlg(), plus:
     *
     * (a) A pointer to a GTimeVal structure which holds the time at which
     *     the caller started to process the data.
     * (b) The current progress as a real number between 0 and 1.
     */

    g_get_current_time(&time_now);

    /* Get the time elapsed since the caller started processing the data */

    delta_time = (time_now.tv_sec - start_time->tv_sec) * 1e6 +
        time_now.tv_usec - start_time->tv_usec;

    /* Do nothing for the first INIT_DELAY microseconds */

    if (delta_time < INIT_DELAY)
        return NULL;

    /* If we create the progress dialog we want it to be displayed for a
     * minimum of MIN_DISPLAY_DEFAULT microseconds.  However, if we
     * previously estimated that the progress dialog didn't need to be
     * created and the caller's processing is slowing down (perhaps due
     * to the action of the operating system's scheduler on a compute-
     * intensive task), we tail off the minimum display time such that
     * the progress dialog will always be created after
     * 2*MIN_DISPLAY_DEFAULT microseconds.
     */

    if (delta_time <= INIT_DELAY + MIN_DISPLAY_DEFAULT)
        min_display = MIN_DISPLAY_DEFAULT;
    else
        min_display = 2 * MIN_DISPLAY_DEFAULT - delta_time;
    /* = MIN_DISPLAY_DEFAULT - (delta_time - MIN_DISPLAY_DEFAULT) */

    /* Assuming the progress increases linearly, see if the progress
     * dialog would be displayed for at least min_display microseconds if
     * we created it now.
     */

    if (progress >= (delta_time / (delta_time + min_display)))
        return NULL;

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: delayed_create_progress_dlg tt: %s it: %s", task_title, item_title);
//    dlg = create_progress_dlg(task_title, item_title, terminate_is_stop,
//                              stop_flag);

    /*
     * Flush out the dialog so we don't see an "empty" one until first update.
     */
    //WiresharkApplication::processEvents();

    /* set dialog start_time to the start of processing, not box creation */
//    dlg->start_time = *start_time;

    return dlg;
}

/*
 * Update the progress information of the progress dialog box.
 */
void
update_progress_dlg(progdlg_t *dlg, gfloat percentage, const gchar *status)
{
//        GtkWidget *dlg_w = dlg->dlg_w;
//        GtkWidget *prog_bar;
        GTimeVal   time_now;
        gdouble    delta_time;
        gulong     ul_left;
        gulong     ul_elapsed;
        gulong     ul_percentage;
        gchar      tmp[100];


        /* calculate some timing values */
        g_get_current_time(&time_now);

//        delta_time = (time_now.tv_sec - dlg->last_time.tv_sec) * 1e6 +
//                time_now.tv_usec - dlg->last_time.tv_usec;

        g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: update_progress_dlg: %0.2f %s", percentage, status);

//        /* after the first time don't update more than every 100ms */
//        if (dlg->last_time.tv_sec && delta_time < 100*1000)
//            return;

//        dlg->last_time = time_now;
//        delta_time = (time_now.tv_sec - dlg->start_time.tv_sec) * 1e6 +
//                     time_now.tv_usec - dlg->start_time.tv_usec;

//        ul_percentage = (gulong) (percentage * 100);
//        ul_elapsed = (gulong) (delta_time / 1000 / 1000);

//        /* update labels */
//        g_snprintf(tmp, sizeof(tmp), "%lu%% of %s", ul_percentage, dlg->title);
//        gtk_window_set_title(GTK_WINDOW(dlg_w), tmp);

//        gtk_label_set_text(dlg->status_lb, status);

//        g_snprintf(tmp, sizeof(tmp), "%lu%%", ul_percentage);
//        gtk_label_set_text(dlg->percentage_lb, tmp);

//        g_snprintf(tmp, sizeof(tmp), "%02lu:%02lu", ul_elapsed / 60,
//                   ul_elapsed % 60);
//        gtk_label_set_text(dlg->elapsed_lb, tmp);

//        /* show "Time Left" only,
//         * if at least 5% and 3 seconds running (to get a useful estimation) */
//        if (ul_percentage >= 5 && delta_time >= 3 * 1e6) {
//            ul_left = (gulong) ((delta_time / percentage - delta_time) / 1000 / 1000);

//            g_snprintf(tmp, sizeof(tmp), "%02lu:%02lu", ul_left / 60,
//                       ul_left % 60);
//            gtk_label_set_text(dlg->time_left_lb, tmp);
//        }

//        /* update progress bar */
//        prog_bar = g_object_get_data(G_OBJECT(dlg_w), PROG_BAR_KEY);
//        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(prog_bar), percentage);

        /*
         * Flush out the update and process any input events.
         */
//        WiresharkApplication::processEvents();
    }

/*
 * Destroy the progress dialog.
 */
void
destroy_progress_dlg(progdlg_t *dlg)
{
//    GtkWidget *dlg_w = dlg->dlg_w;

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: destroy_progress_dlg");
//    window_destroy(GTK_WIDGET(dlg_w));
//    g_free(dlg->title);
//    g_free(dlg);
}


ProgressDialog::ProgressDialog(QWidget *parent) :
    QProgressDialog(parent)
{
}
