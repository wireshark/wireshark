#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <stdio.h>

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "epan/epan.h"
#include "color.h"
#include "ui_util.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"

#include "progress_dlg.h"     /* In the source tree root */
#include "progress-dialog.h"  /* In the "generated" directory */

struct progdlg {
    GString         *title;
    HWND             h_wnd;
    gboolean        *stop_flag;
    GTimeVal         start_time;
    GTimeVal         last_time;
    win32_element_t *task_title_ds;
    win32_element_t *item_title_ds;
    win32_element_t *status_ds;
    win32_element_t *elapsed_ds;
    win32_element_t *time_left_ds;
    win32_element_t *progress_pm;
    win32_element_t *percentage_ds;
};

#define DIALOG_DATA_KEY "progress-dialog.data"

/* Routines defined in progress_dlg.h */

/*
 * Create and pop up the progress dialog {
} allocate a "progdlg_t"
 * and initialize it to contain all information the implementation
 * needs in order to manipulate the dialog, and return a pointer to
 * it.
 *
 * The first argument is the task to do, e.g. "Loading".
 * The second argument is the item to do, e.g. "capture.cap".
 * The third argument is the string to put in the "stop this operation" button.
 * The fourth argument is a pointer to a Boolean variable that will be
 *   set to TRUE if the user hits that button.
 */
progdlg_t *create_progress_dlg(const gchar *task_title, const gchar *item_title,
	gboolean *stop_flag) {
    win32_element_t *dlg_box, *cancel_bt;
    progdlg_t       *dlg;
    GString         *item_title_dup, *task_title_dup;

    dlg = g_malloc(sizeof (progdlg_t));

    dlg->h_wnd = progress_dialog_dialog_create(g_hw_mainwin);
    dlg->stop_flag = stop_flag;

    dlg_box = (win32_element_t *) GetWindowLong(dlg->h_wnd, GWL_USERDATA);
    win32_element_set_data(dlg_box, DIALOG_DATA_KEY, dlg);

    item_title_dup = g_string_new(item_title);
    if (item_title_dup->len > 110) {
	g_string_truncate(item_title_dup, 100);
	g_string_append(item_title_dup, "...");
    }

    dlg->title = g_string_new(task_title);
    g_string_sprintfa(dlg->title, ": %s", item_title_dup->str);
    SetWindowText(dlg->h_wnd, dlg->title->str);

    dlg->task_title_ds = win32_identifier_get_str("progress-dlg.task_title");
    win32_element_assert(dlg->task_title_ds);
    task_title_dup = g_string_new(task_title);
    g_string_append(task_title_dup, ":");
    SetWindowText(dlg->task_title_ds->h_wnd, task_title_dup->str);

    dlg->item_title_ds = win32_identifier_get_str("progress-dlg.item_title");
    win32_element_assert(dlg->item_title_ds);
    SetWindowText(dlg->item_title_ds->h_wnd, item_title_dup->str);

    dlg->status_ds = win32_identifier_get_str("progress-dlg.status");
    win32_element_assert(dlg->status_ds);

    dlg->elapsed_ds = win32_identifier_get_str("progress-dlg.time.elapsed");
    win32_element_assert(dlg->elapsed_ds);

    dlg->time_left_ds = win32_identifier_get_str("progress-dlg.time.left");
    win32_element_assert(dlg->time_left_ds);

    dlg->progress_pm = win32_identifier_get_str("progress-dlg.progress");
    win32_element_assert(dlg->progress_pm);

    dlg->percentage_ds = win32_identifier_get_str("progress-dlg.percentage");
    win32_element_assert(dlg->percentage_ds);

    cancel_bt = win32_identifier_get_str("progress-dlg.cancel");
    win32_element_assert(cancel_bt);
    win32_element_set_data(cancel_bt, DIALOG_DATA_KEY, dlg);

    g_get_current_time(&dlg->start_time);
    ZeroMemory(&dlg->last_time, sizeof(dlg->last_time));

    g_string_free(item_title_dup, TRUE);
    g_string_free(task_title_dup, TRUE);
    progress_dialog_dialog_show(dlg->h_wnd);
    return dlg;
}

/* Create a progress dialog, but only if it's not likely to disappear
 * immediately, which can be disconcerting for the user.
 *
 * The first four arguments are as for create_progress_dlg().
 * Following those is a pointer to a GTimeVal structure which holds
 * the time at which the caller started to process the data, and the
 * current progress (0..1).
 */
/* XXX - Copied verbatim from gtk/progress_dlg.c */
progdlg_t *
delayed_create_progress_dlg(const gchar *task_title, const gchar *item_title,
	gboolean *stop_flag, const GTimeVal *start_time, gfloat progress) {
    GTimeVal    time_now;
    gdouble     delta_time;
    gdouble     min_display;
    progdlg_t  *dlg;

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

   dlg = create_progress_dlg(task_title, item_title, stop_flag);

   /* set dialog start_time to the start of processing, not box creation */
   dlg->start_time = *start_time;

   return dlg;
}

/*
 * Update the progress information of the progress dialog box.
 */
void update_progress_dlg(progdlg_t *dlg, gfloat percentage, gchar *status) {
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
    g_snprintf(tmp, sizeof(tmp), "%lu%% of %s", ul_percentage, dlg->title->str);
    SetWindowText(dlg->h_wnd, tmp);

    SetWindowText(dlg->status_ds->h_wnd, status);

    g_snprintf(tmp, sizeof(tmp), "%lu%%", ul_percentage);
    SetWindowText(dlg->percentage_ds->h_wnd, tmp);

    g_snprintf(tmp, sizeof(tmp), "%02lu:%02lu", ul_elapsed / 60,
	    ul_elapsed % 60);
    SetWindowText(dlg->elapsed_ds->h_wnd, tmp);

    /* show "Time Left" only,
    * if at least 5% and 3 seconds running (to get a useful estimation) */
    if (ul_percentage >= 5 && delta_time >= 3 * 1e6) {
	ul_left = (gulong) ((delta_time / percentage - delta_time) / 100 / 1000);

	g_snprintf(tmp, sizeof(tmp), "%02lu:%02lu", ul_left / 60,
		ul_left % 60);
	SetWindowText(dlg->time_left_ds->h_wnd, tmp);
    }

    /* update progress bar */

    SendMessage(dlg->progress_pm->h_wnd, PBM_SETPOS, (int) (percentage * 100.0), 0);

    /*
     * Flush out the update and process any input events.
     */
    main_window_update();
}

/*
 * Destroy the progress dialog.
 */
void destroy_progress_dlg(progdlg_t *dlg) {
    win32_element_t *dlg_el;

    dlg_el = (win32_element_t *) GetWindowLong(dlg->h_wnd, GWL_USERDATA);
    win32_element_assert(dlg_el);
    win32_element_destroy(dlg_el, TRUE);

    g_string_free(dlg->title, TRUE);
    g_free(dlg);
}

/* Command sent by element type <button>, id "progress-dlg.cancel" */
void progress_dialog_destroy (win32_element_t *cancel_bt) {
    progdlg_t *dlg;

    win32_element_assert(cancel_bt);
    dlg = (progdlg_t *) win32_element_get_data(cancel_bt, DIALOG_DATA_KEY);
    *dlg->stop_flag = TRUE;
}

BOOL CALLBACK
progress_dialog_dlg_proc(HWND hw_progress, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;
    progdlg_t *dlg;

    switch( msg ) {
	case WM_INITDIALOG:
	    progress_dialog_handle_wm_initdialog(hw_progress);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_progress, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    return 0;
	    break;
	case WM_COMMAND:
	    return 0;
	    break;
	case WM_CLOSE:
	    dlg_box = (win32_element_t *) GetWindowLong(hw_progress, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    dlg = (progdlg_t *) win32_element_get_data(dlg_box, DIALOG_DATA_KEY);
	    *dlg->stop_flag = TRUE;
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}
