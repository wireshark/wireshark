/* gtk_stat_util.h
 * gui functions used by stats
 * Copyright 2003 Lars Roland
 *
 * $Id: gtk_stat_util.h,v 1.2 2003/04/27 21:50:59 guy Exp $
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

typedef struct _gtk_table {
	GtkWidget *widget;
	int height;
	int width;
}gtk_table;

extern void add_table_entry(gtk_table *tab, char *str, int x, int y);
extern void init_main_stat_window(GtkWidget *window, GtkWidget *mainbox, char *title, char *filter);

#if GTK_MAJOR_VERSION < 2
extern GtkCList *create_stat_table(GtkWidget *scrolled_window, GtkWidget *vbox, int columns, char *titles[]);
#endif
#endif
