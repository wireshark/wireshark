/* filter_prefs.h
 * Definitions for dialog boxes for filter editing
 * (This used to be a notebook page under "Preferences", hence the
 * "prefs" in the file name.)
 *
 * $Id: filter_prefs.h,v 1.9 2001/01/21 02:27:24 guy Exp $
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

#ifndef __FILTER_H__
#define __FILTER_H__

/*
 * Structure giving properties of the filter editing dialog box to be
 * created.
 */
typedef struct {
	gchar    *title;		/* title of dialog box */
	gboolean wants_apply_button;	/* if it should have an Apply button */
	gboolean activate_on_ok;	/* if parent text widget should be
					   activated on "Ok" or "Apply" */
} construct_args_t;

void capture_filter_construct_cb(GtkWidget *w, gpointer user_data);
void display_filter_construct_cb(GtkWidget *w, gpointer construct_args_ptr);
void filter_dialog_cb(GtkWidget *);

#define E_FILT_TE_KEY		"filter_te"
#define E_FILT_TE_PTR_KEY	"filter_te_ptr"
#define E_FILT_CALLER_PTR_KEY	"filter_caller_ptr"
#define E_FILT_DIALOG_PTR_KEY	"filter_dialog_ptr"

#endif /* filter.h */
