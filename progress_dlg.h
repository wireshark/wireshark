/* progress_dlg.h
 * Definitions for progress dialog box routines
 *
 * $Id: progress_dlg.h,v 1.3 2002/08/28 10:07:28 guy Exp $
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

/*
 * Progress (modal) dialog box routines.
 */

struct progdlg;

typedef struct progdlg progdlg_t;

/*
 * Create and pop up the progress dialog; allocate a "progdlg_t"
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
    const gchar *stop_title, gboolean *stop_flag);

/* Create a progress dialog, but only if it's not likely to disappear
 * immediately, which can be disconcerting for the user.
 *
 * The first four arguments are as for create_progress_dlg().
 * Following those is a pointer to a GTimeVal structure which holds
 * the time at which the caller started to process the data, and the
 * current progress (0..1).
 */
progdlg_t *
delayed_create_progress_dlg(const gchar *task_title, const gchar *item_title, 
    const gchar *stop_title, gboolean *stop_flag, GTimeVal *start_time,
    gfloat progress);

/*
 * Update the progress information of the progress dialog box.
 */
void update_progress_dlg(progdlg_t *dlg, gfloat percentage, gchar *status);

/*
 * Destroy the progress bar.
 */
void destroy_progress_dlg(progdlg_t *dlg);

#endif /* __PROGRESS_DLG_H__ */
