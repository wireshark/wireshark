/* colors.h
 * Definitions for color structures and routines
 *
 * $Id: colors.h,v 1.3 2000/08/11 13:33:00 deniel Exp $
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
#ifndef  __COLORS_H__
#define  __COLORS_H__

#include  "proto.h"
#include  "dfilter.h"
#include <gtk/gtk.h>

#define MAXCOLORS	255
#define MAX_COLOR_FILTER_NAME_LEN 33
#define MAX_COLOR_FILTER_STRING_LEN 256

#define CFILTERS_CONTAINS_FILTER(filter) \
	((filter)->num_of_filters != 0)

extern GdkColor WHITE;
extern GdkColor BLACK;

/* Data for a color filter. */
typedef struct _color_filter {
	gchar *filter_name;	/* name of the filter */
	gchar *filter_text;	/* text of the filter expression */
	GdkColor bg_color;	/* background color for packets that match */
	GdkColor fg_color;	/* foreground color for packets that match */
	dfilter *c_colorfilter;	/* compiled filter expression */
	GtkWidget *edit_dialog;	/* if filter is being edited, dialog box for it */
} color_filter_t;

/* List of all color filters. */
extern GSList *filter_list;

typedef struct _colfilter  {
	gint      num_of_filters;  /* first num_of_filters rows filled */
	gint	  row_selected;	   /* row in color_filters that is selected */
} colfilter;

colfilter *colfilter_new(void);

gboolean write_filters(colfilter *filter);

color_filter_t *new_color_filter(colfilter *filters, gchar *name,
				 gchar *filter_string);
void delete_color_filter(color_filter_t *colorf);

gboolean get_color (GdkColor *new_color);

#endif
