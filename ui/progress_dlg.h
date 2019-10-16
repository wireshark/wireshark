/* progress_dlg.h
 * Definitions for progress dialog box routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PROGRESS_DLG_H__
#define __PROGRESS_DLG_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 *  Progress (modal) dialog box routines.
 *  @ingroup dialog_group
 */

/** Progress dialog data. */
struct progdlg;

/** Progress dialog data. */
typedef struct progdlg progdlg_t;

/**
 * Create and pop up the progress dialog. Allocates a "progdlg_t"
 * and initialize it to contain all information the implementation
 * needs in order to manipulate the dialog, and return a pointer to
 * it.
 *
 * @param top_level_window UI widget to associate with the progress dialog, e.g.
 *   the main window.
 * @param task_title The task to do, e.g. "Loading"
 * @param item_title The item to do, e.g. "capture.cap"
 * @param terminate_is_stop TRUE if the operation can't be cancelled, just
 *   stopped (i.e., it has a "Stop" button and clicking it doesn't undo
 *   anything already done), FALSE if it can
 * @param stop_flag A pointer to a Boolean variable that will be
 *   set to TRUE if the user hits that button
 * @return The newly created progress dialog
 */
progdlg_t *create_progress_dlg(gpointer top_level_window, const gchar *task_title, const gchar *item_title,
    gboolean terminate_is_stop, gboolean *stop_flag);

/**
 * Create a progress dialog, but only if it's not likely to disappear
 * immediately. This can be disconcerting for the user.
 *
 * @param top_level_window The top-level window associated with the progress update.
 *   May be NULL.
 * @param task_title The task to do, e.g. "Loading"
 * @param item_title The item to do, e.g. "capture.cap"
 * @param terminate_is_stop TRUE if the operation can't be cancelled, just
 *   stopped (i.e., it has a "Stop" button and clicking it doesn't undo
 *   anything already done), FALSE if it can
 * @param stop_flag A pointer to a Boolean variable that will be
 *   set to TRUE if the user hits that button
 * @param progress The current progress (0..1)
 * @return The newly created progress dialog
 */
progdlg_t *delayed_create_progress_dlg(gpointer top_level_window, const gchar *task_title, const gchar *item_title,
    gboolean terminate_is_stop, gboolean *stop_flag, gfloat progress);

/**
 * Update the progress information of the progress dialog box.
 *
 * @param dlg The progress dialog from create_progress_dlg()
 * @param percentage The current percentage value (0..1)
 * @param status the New status string to show, e.g. "3000KB of 6000KB"
 */
void update_progress_dlg(progdlg_t *dlg, gfloat percentage, const gchar *status);

/**
 * Destroy or hide the progress bar.
 *
 * @param dlg The progress dialog from create_progress_dlg()
 */
void destroy_progress_dlg(progdlg_t *dlg);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PROGRESS_DLG_H__ */

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
