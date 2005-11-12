/* progress_dlg.h
 * Definitions for progress dialog box routines
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __PROGRESS_DLG_H__
#define __PROGRESS_DLG_H__

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
 * @param task_title the task to do, e.g. "Loading"
 * @param item_title the item to do, e.g. "capture.cap"
 * @param terminate_is_stop TRUE if the operation can't be cancelled, just
 *   stopped (i.e., it has a "Stop" button and clicking it doesn't undo
 *   anything already done), FALSE if it can
 * @param stop_flag a pointer to a Boolean variable that will be
 *   set to TRUE if the user hits that button
 * @return the newly created progress dialog
 */
progdlg_t *create_progress_dlg(const gchar *task_title, const gchar *item_title,
    gboolean terminate_is_stop, gboolean *stop_flag);

/**
 * Create a progress dialog, but only if it's not likely to disappear
 * immediately. This can be disconcerting for the user. 
 *
 * @param task_title the task to do, e.g. "Loading"
 * @param item_title the item to do, e.g. "capture.cap"
 * @param terminate_is_stop TRUE if the operation can't be cancelled, just
 *   stopped (i.e., it has a "Stop" button and clicking it doesn't undo
 *   anything already done), FALSE if it can
 * @param stop_flag a pointer to a Boolean variable that will be
 *   set to TRUE if the user hits that button
 * @param start_time a pointer to a GTimeVal structure which holds
 *   the time at which the caller started to process the data
 * @param progress the current progress (0..1)
 * @return the newly created progress dialog
 */
progdlg_t *
delayed_create_progress_dlg(const gchar *task_title, const gchar *item_title,
    gboolean terminate_is_stop, gboolean *stop_flag,
    const GTimeVal *start_time, gfloat progress);

/**
 * Update the progress information of the progress dialog box.
 *
 * @param dlg the progress dialog from create_progress_dlg()
 * @param percentage the current percentage value (0..1)
 * @param status the new status string to show, e.g. "3000KB of 6000KB"
 */
void update_progress_dlg(progdlg_t *dlg, gfloat percentage, const gchar *status);

/**
 * Destroy the progress bar.
 *
 * @param dlg the progress dialog from create_progress_dlg()
 */
void destroy_progress_dlg(progdlg_t *dlg);

#endif /* __PROGRESS_DLG_H__ */
