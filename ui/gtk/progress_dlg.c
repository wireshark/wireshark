/* progress_dlg.c
 * Routines for progress-bar (modal) dialog
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

#include <string.h>

#include <gtk/gtk.h>

#include "ui/progress_dlg.h"

#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"


#define	PROG_BAR_KEY	"progress_bar"

static gboolean delete_event_cb(GtkWidget *w, GdkEvent *event, gpointer data);
static void stop_cb(GtkWidget *w, gpointer data);

/*
 * Define the structure describing a progress dialog.
 */
struct progdlg {
	GtkWidget *dlg_w;	/* top-level window widget */
	GTimeVal   start_time;
	GTimeVal   last_time;   /* last time it was updated */

	GtkLabel  *status_lb;
	GtkLabel  *elapsed_lb;
	GtkLabel  *time_left_lb;
	GtkLabel  *percentage_lb;
	gchar     *title;
};

/*
 * Create and pop up the progress dialog; allocate a "progdlg_t"
 * and initialize it to contain all information the implementation
 * needs in order to manipulate the dialog, and return a pointer to
 * it.
 *
 * The first argument is the task to do, e.g. "Loading".
 * The second argument is the item to do, e.g. "capture.cap".
 * The third argument is TRUE if the "terminate this operation" button should
 * be a "Stop" button (meaning that the operation is stopped, but not undone),
 * and FALSE if it should be a "Cancel" button (meaning that it's stopped
 * and anything it's done would be undone)
 * The fourth argument is a pointer to a Boolean variable that will be
 *   set to TRUE if the user hits that button.
 *
 * XXX - provide a way to specify the progress in units, with the total
 * number of units specified as an argument when the progress dialog
 * is created; updates would be given in units, with the progress dialog
 * code computing the percentage, and the progress bar would have a
 * label "0" on the left and <total number of units> on the right, with
 * a label in the middle giving the number of units we've processed
 * so far.  This could be used when filtering packets, for example; we
 * wouldn't always use it, as we have no idea how many packets are to
 * be read.
 */
progdlg_t *
create_progress_dlg(const gpointer top_level_window _U_, const gchar *task_title, const gchar *item_title,
                    gboolean terminate_is_stop, gboolean *stop_flag)
{
    progdlg_t *dlg;
    GtkWidget *dlg_w, *main_vb, *title_lb, *status_lb, *elapsed_lb, *time_left_lb, *percentage_lb;
    GtkWidget *prog_bar, *bbox, *cancel_bt;
    GtkWidget *static_vb, *tmp_lb, *main_hb, *dynamic_vb, *percentage_hb;
    gchar     *task_title_dup;
    gchar     *item_title_dup;

    dlg = g_malloc(sizeof (progdlg_t));

    /* limit the item_title to some reasonable length */
    item_title_dup = g_strdup(item_title);
    if (strlen(item_title_dup) > 110) {
        g_strlcpy(&item_title_dup[100], "...", 4);
    }

    dlg->title = g_strdup_printf("%s: %s", task_title, item_title_dup);

    dlg_w = dlg_window_new(dlg->title);
    gtk_window_set_modal(GTK_WINDOW(dlg_w), TRUE);

    /*
     * Container for dialog widgets.
     */
    main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 1, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(dlg_w), main_vb);

    /*
     * Static labels (left dialog side, labels aligned to the right)
     */
    static_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 1, FALSE);
    task_title_dup = g_strdup_printf ("%s:", task_title);
    tmp_lb = gtk_label_new(task_title_dup);
    gtk_misc_set_alignment(GTK_MISC(tmp_lb), 1.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(static_vb), tmp_lb, FALSE, TRUE, 3);
    tmp_lb = gtk_label_new("Status:");
    gtk_misc_set_alignment(GTK_MISC(tmp_lb), 1.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(static_vb), tmp_lb, FALSE, TRUE, 3);
    tmp_lb = gtk_label_new("Elapsed Time:");
    gtk_misc_set_alignment(GTK_MISC(tmp_lb), 1.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(static_vb), tmp_lb, FALSE, TRUE, 3);
    tmp_lb = gtk_label_new("Time Left:");
    gtk_misc_set_alignment(GTK_MISC(tmp_lb), 1.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(static_vb), tmp_lb, FALSE, TRUE, 3);
    tmp_lb = gtk_label_new("Progress:");
    gtk_misc_set_alignment(GTK_MISC(tmp_lb), 1.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(static_vb), tmp_lb, FALSE, TRUE, 3);


    /*
     * Dynamic labels (right dialog side, labels aligned to the left)
     */
    dynamic_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 1, FALSE);

    /*
     * Put the item_title here as a label indicating what we're
     * doing; set its alignment and padding so it's aligned on the
     * left.
     */
    title_lb = gtk_label_new(item_title_dup);
    gtk_box_pack_start(GTK_BOX(dynamic_vb), title_lb, FALSE, TRUE, 3);
    gtk_misc_set_alignment(GTK_MISC(title_lb), 0.0f, 0.0f);
    gtk_misc_set_padding(GTK_MISC(title_lb), 0, 0);

    /* same for "Status" */
    status_lb = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(dynamic_vb), status_lb, FALSE, TRUE, 3);
    gtk_misc_set_alignment(GTK_MISC(status_lb), 0.0f, 0.0f);
    gtk_misc_set_padding(GTK_MISC(status_lb), 0, 0);
    dlg->status_lb = (GtkLabel *) status_lb;

    /* same for "Elapsed Time" */
    elapsed_lb = gtk_label_new("00:00");
    gtk_box_pack_start(GTK_BOX(dynamic_vb), elapsed_lb, FALSE, TRUE, 3);
    gtk_misc_set_alignment(GTK_MISC(elapsed_lb), 0.0f, 0.0f);
    gtk_misc_set_padding(GTK_MISC(elapsed_lb), 0, 0);
    dlg->elapsed_lb = (GtkLabel *) elapsed_lb;

    /* same for "Time Left" */
    time_left_lb = gtk_label_new("--:--");
    gtk_box_pack_start(GTK_BOX(dynamic_vb), time_left_lb, FALSE, TRUE, 3);
    gtk_misc_set_alignment(GTK_MISC(time_left_lb), 0.0f, 0.0f);
    gtk_misc_set_padding(GTK_MISC(time_left_lb), 0, 0);
    dlg->time_left_lb = (GtkLabel *) time_left_lb;

    /*
     * The progress bar (in its own horizontal box, including
     * percentage value)
     */
    percentage_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1, FALSE);
    gtk_box_pack_start(GTK_BOX(dynamic_vb), percentage_hb, FALSE, TRUE, 3);

    prog_bar = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(percentage_hb), prog_bar, FALSE, TRUE, 3);

    percentage_lb = gtk_label_new("  0%");
    gtk_misc_set_alignment(GTK_MISC(percentage_lb), 0.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(percentage_hb), percentage_lb, FALSE, TRUE, 3);
    dlg->percentage_lb = (GtkLabel *) percentage_lb;

    /*
     * Attach a pointer to the progress bar widget to the top-level widget.
     */
    g_object_set_data(G_OBJECT(dlg_w), PROG_BAR_KEY, prog_bar);

    /*
     * Static and dynamic boxes are now complete
     */
    main_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1, FALSE);
    gtk_box_pack_start(GTK_BOX(main_hb), static_vb, FALSE, TRUE, 3);
    gtk_box_pack_start(GTK_BOX(main_hb), dynamic_vb, FALSE, TRUE, 3);
    gtk_box_pack_start(GTK_BOX(main_vb), main_hb, FALSE, TRUE, 3);

    /* Button row */
    bbox = dlg_button_row_new(terminate_is_stop ? GTK_STOCK_STOP :
                              GTK_STOCK_CANCEL, NULL);
    gtk_container_add(GTK_CONTAINER(main_vb), bbox);
    gtk_widget_show(bbox);

    cancel_bt = g_object_get_data(G_OBJECT(bbox), terminate_is_stop ? GTK_STOCK_STOP :
                                GTK_STOCK_CANCEL);
    gtk_widget_grab_default(cancel_bt);

    /*
     * Allow user to either click the "Cancel"/"Stop" button, or
     * the close button on the window, to stop an operation in
     * progress.
     */
    g_signal_connect(cancel_bt, "clicked", G_CALLBACK(stop_cb), stop_flag);
    g_signal_connect(dlg_w, "delete_event", G_CALLBACK(delete_event_cb), stop_flag);

    gtk_widget_show_all(dlg_w);

    dlg->dlg_w = dlg_w;

    g_get_current_time(&dlg->start_time);
    memset(&dlg->last_time, 0, sizeof(dlg->last_time));

    g_free(task_title_dup);
    g_free(item_title_dup);

    return dlg;
}

progdlg_t *
delayed_create_progress_dlg(const gpointer top_level_window, const gchar *task_title,
			    const gchar *item_title, gboolean terminate_is_stop,
			    gboolean *stop_flag, const GTimeVal *start_time, gfloat progress)
{
    GTimeVal    time_now;
    gdouble     delta_time;
    gdouble     min_display;
    progdlg_t  *dlg;

#define INIT_DELAY          0.1 * 1e6 /* .1 second = 0.1e6 microseconds */
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

    dlg = create_progress_dlg(top_level_window, task_title, item_title, terminate_is_stop,
                              stop_flag);

    /*
     * Flush out the dialog so we don't see an "empty" one until first update.
     */
    while (gtk_events_pending())
	    gtk_main_iteration();

    /* set dialog start_time to the start of processing, not box creation */
    dlg->start_time = *start_time;

    return dlg;
}

/*
 * Called when the dialog box is to be deleted.
 * Set the "stop" flag to TRUE, and return TRUE - we don't want the dialog
 * box deleted now, our caller will do so when they see that the
 * "stop" flag is TRUE and abort the operation.
 */
static gboolean
delete_event_cb(GtkWidget *w _U_, GdkEvent *event _U_, gpointer data)
{
	gboolean *stop_flag = (gboolean *) data;

	*stop_flag = TRUE;
	return TRUE;
}

/*
 * Called when the "stop this operation" button is clicked.
 * Set the "stop" flag to TRUE; we don't have to destroy the dialog
 * box, as our caller will do so when they see that the "stop" flag is
 * true and abort the operation.
 */
static void
stop_cb(GtkWidget *w _U_, gpointer data)
{
	gboolean *stop_flag = (gboolean *) data;

	*stop_flag = TRUE;
}

/*
 * Update the progress information of the progress dialog box.
 */
void
update_progress_dlg(progdlg_t *dlg, gfloat percentage, const gchar *status)
{
	GtkWidget *dlg_w = dlg->dlg_w;
	GtkWidget *prog_bar;
	GTimeVal   time_now;
	gdouble    delta_time;
	gulong     ul_left;
	gulong     ul_elapsed;
	gulong     ul_percentage;
	gchar      tmp[100];


	/* calculate some timing values */
	g_get_current_time(&time_now);

	delta_time = (time_now.tv_sec - dlg->last_time.tv_sec) * 1e6 +
		time_now.tv_usec - dlg->last_time.tv_usec;

	/* after the first time don't update more than every 100ms */
	if (dlg->last_time.tv_sec && delta_time < 100*1000)
		return;

	dlg->last_time = time_now;
	delta_time = (time_now.tv_sec - dlg->start_time.tv_sec) * 1e6 +
		time_now.tv_usec - dlg->start_time.tv_usec;

	ul_percentage = (gulong) (percentage * 100);
	ul_elapsed = (gulong) (delta_time / 1000 / 1000);

	/* update labels */
	g_snprintf(tmp, sizeof(tmp), "%lu%% of %s", ul_percentage, dlg->title);
	gtk_window_set_title(GTK_WINDOW(dlg_w), tmp);

	gtk_label_set_text(dlg->status_lb, status);

	g_snprintf(tmp, sizeof(tmp), "%lu%%", ul_percentage);
	gtk_label_set_text(dlg->percentage_lb, tmp);

	g_snprintf(tmp, sizeof(tmp), "%02lu:%02lu", ul_elapsed / 60,
                   ul_elapsed % 60);
	gtk_label_set_text(dlg->elapsed_lb, tmp);

	/* show "Time Left" only,
	 * if at least 5% and 3 seconds running (to get a useful estimation) */
	if (ul_percentage >= 5 && delta_time >= 3 * 1e6) {
		ul_left = (gulong) ((delta_time / percentage - delta_time) / 1000 / 1000);

		g_snprintf(tmp, sizeof(tmp), "%02lu:%02lu", ul_left / 60,
                           ul_left % 60);
		gtk_label_set_text(dlg->time_left_lb, tmp);
	}

	/* update progress bar */
	prog_bar = g_object_get_data(G_OBJECT(dlg_w), PROG_BAR_KEY);
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(prog_bar), percentage);

	/*
	 * Flush out the update and process any input events.
	 */
	while (gtk_events_pending())
		gtk_main_iteration();
}

/*
 * Destroy the progress dialog.
 */
void
destroy_progress_dlg(progdlg_t *dlg)
{
    GtkWidget *dlg_w = dlg->dlg_w;

    window_destroy(GTK_WIDGET(dlg_w));
    g_free(dlg->title);
    g_free(dlg);
}
