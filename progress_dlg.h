/* progress_dlg.h
 * Definitions for progress dialog box routines
 *
 * $Id: progress_dlg.h,v 1.1 2001/03/24 02:07:20 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 * The first argument is the title to give the dialog box; the second
 * argument is the string to put in the "stop this operation" button;
 * the third argument is a pointer to a Boolean variable that will be
 * set to TRUE if the user hits that button.
 */
progdlg_t *create_progress_dlg(const gchar *title, const gchar *stop_title,
    gboolean *stop_flag);

/*
 * Set the percentage value of the progress bar.
 */
void update_progress_dlg(progdlg_t *dlg, gfloat percentage);

/*
 * Destroy the progress bar.
 */
void destroy_progress_dlg(progdlg_t *dlg);

#endif /* __PROGRESS_DLG_H__ */
