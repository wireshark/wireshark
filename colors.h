/* colors.h
 * Definitions for color structures and routines
 *
 * $Id: colors.h,v 1.3 1999/10/05 04:34:00 gram Exp $
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

#define CFILTERS_CONTAINS_FILTER(cf) \
	((cf)->colors->num_of_filters != 0)

extern GdkColor 	proto_colors[MAXCOLORS];
extern GdkColormap*	sys_cmap;
extern GdkColor	color_light_gray;
extern GdkColor WHITE;
extern GdkColor BLACK;

/* This struct is used in the GtkCList which holds the filter information.
 * The filter name and text string for the filter are the clist data
 */

typedef struct _color_filter {
	GdkColor bg_color;
	GdkColor fg_color;
	dfilter *c_colorfilter;
} color_filter_t;

typedef struct _colfilter  {
	GtkWidget  *color_filters;
	gint      num_of_filters;  /* first num_of_filters rows filled */
	gint	  row_selected;	   /* row in color_filters that is selected */
} colfilter;



typedef struct _capture_file cap_file;


void colors_init(cap_file *cf);
void set_color_filter_name(cap_file *cf, gint n, gchar *str);
gchar* get_color_filter_name(cap_file *cf, gint n);

void set_color_filter_string(cap_file *cf, gint n, gchar *str);

gchar* get_color_filter_string(cap_file *cf, gint n);
color_filter_t *color_filter(cap_file *cf, gint n);

void new_color_filter(colfilter *filters, gchar *name, gchar *filter_string);

/* ===================== USER INTERFACE ====================== */

void
color_display_cb(GtkWidget *w, gpointer d);

void
color_delete_cb                        (GtkWidget       *widget,
                                        gpointer         user_data);
void
color_cancel_cb                        (GtkWidget       *widget,
                                        gpointer         user_data);
void
color_filt_up_cb                       (GtkButton       *button,
                                        gpointer         user_data);

void
color_filter_down_cb                   (GtkButton       *button,
                                        gpointer         user_data);

void
rembember_selected_row                 (GtkCList        *clist,
                                        gint             row,
                                        gint             column,
                                        GdkEvent        *event,
                                        gpointer         user_data);

void
create_new_cb                          (GtkButton       *button,
                                        gpointer         user_data);

void
color_change_cb                        (GtkButton       *button,
                                        gpointer         user_data);

void
color_save_cb                          (GtkButton       *button,
                                        gpointer         user_data);

void
color_ok_cb                            (GtkButton       *button,
                                        gpointer         user_data);

void
color_apply_cb                         (GtkButton       *button,
                                        gpointer         user_data);

void
colorize_cancel_cb                     (GtkObject       *object,
                                        gpointer         user_data);

void
colorize_fg_cb                         (GtkButton       *button,
                                        gpointer         user_data);

void
colorize_bg_cb                         (GtkButton       *button,
                                        gpointer         user_data);

void
colorize_ok_cb                         (GtkButton       *button,
                                        gpointer         user_data);

void
color_cel_cancel_cb                    (GtkObject       *object,
                                        gpointer         user_data);

void
color_sel_ok_cb                        (GtkButton       *button,
                                        gpointer         user_data);

GtkWidget* create_color_win (cap_file *cf);
GtkWidget* create_colorize_win (cap_file *cf,
				 GtkWidget **colorize_filter_name,
				 GtkWidget **colorize_filter_text);
GtkWidget* create_color_sel_win (cap_file  *cf, GdkColor *);


#endif
