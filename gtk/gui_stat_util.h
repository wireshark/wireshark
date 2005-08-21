/* gui_stat_util.h
 * gui functions used by stats
 * Copyright 2003 Lars Roland
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


#ifndef __gtk_stat_util__
#define __gtk_stat_util__

#include <gtk/gtk.h>

/** @file
 *  Utilities for statistics.
 */


/** Init a window for stats, set title and display used filter in window.
 *
 * @param window the window
 * @param mainbox the vbox for the window
 * @param title the title for the window
 * @param filter the filter string
 */
extern void init_main_stat_window(GtkWidget *window, GtkWidget *mainbox, const char *title, const char *filter);

/** Create a stats table, using a scrollable gtkclist.
 *
 * @param scrolled_window the scrolled window
 * @param vbox the vbox for the window
 * @param columns number of columns
 * @param titles 
 */
extern GtkCList *create_stat_table(GtkWidget *scrolled_window, GtkWidget *vbox, int columns, const char *titles[]);

#endif
