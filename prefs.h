/* prefs.h
 * Definitions for preference handling routines
 *
 * $Id: prefs.h,v 1.3 1998/10/12 01:40:55 gerald Exp $
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

#ifndef __PREFS_H__
#define __PREFS_H__

#define E_PR_PG_NONE     -1
#define E_PR_PG_PRINTING  0
#define E_PR_PG_FILTER    1

#define E_PRINT_PAGE_KEY  "printer_options_page"
#define E_FILTER_PAGE_KEY "filter_options_page"

#define E_FILT_TE_PTR_KEY "filter_te_ptr"

void prefs_cb(GtkWidget *, gpointer);
void prefs_main_ok_cb(GtkWidget *, gpointer);
void prefs_main_save_cb(GtkWidget *, gpointer);
void prefs_main_cancel_cb(GtkWidget *, gpointer);

#endif /* prefs.h */
