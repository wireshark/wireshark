/* colors.h
 * Definitions for color structures and routines
 *
 * $Id: colors.h,v 1.9 1999/12/19 07:28:35 guy Exp $
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

#ifndef   __DFILTER_H__
#include  "proto.h"
#include  "dfilter.h"
#endif

#ifndef __GTK_H__
#include <gtk/gtk.h>
#endif

#define MAXCOLORS	255
#define MAX_COLOR_FILTER_NAME_LEN 33
#define MAX_COLOR_FILTER_STRING_LEN 256

#define CFILTERS_CONTAINS_FILTER(filter) \
	((filter)->num_of_filters != 0)

extern GdkColor WHITE;
extern GdkColor BLACK;

/* This struct is used in the GtkCList which holds the filter information.
 * The filter name and text string for the filter are the clist data
 */

typedef struct _color_filter {
	gchar *filter_name;
	gchar *filter_text;
	GdkColor bg_color;
	GdkColor fg_color;
	dfilter *c_colorfilter;
} color_filter_t;

/* List of all color filters. */
extern GSList *filter_list;

typedef struct _colfilter  {
	GtkWidget  *color_filters;
	gint      num_of_filters;  /* first num_of_filters rows filled */
	gint	  row_selected;	   /* row in color_filters that is selected */
} colfilter;

colfilter *colfilter_new(void);

color_filter_t *color_filter(gint n);

/* ===================== USER INTERFACE ====================== */

void
color_display_cb(GtkWidget *w, gpointer d);


#endif
