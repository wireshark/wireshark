/* colors.c
 * Definitions for color structures and routines
 *
 * $Id: colors.c,v 1.18 2002/01/08 21:35:17 guy Exp $
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
/*
 * Updated 1 Dec 10 jjm
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <epan/filesystem.h>

#include "gtk/main.h"
#include "packet.h"
#include "colors.h"
#include "file.h"
#include "dfilter/dfilter.h"
#include "simple_dialog.h"

extern capture_file cf;

static gboolean read_filters(colfilter *filter);

GSList *filter_list;

static GdkColormap*	sys_cmap;
static GdkColormap*	our_cmap = NULL;

GdkColor	WHITE = { 0, 65535, 65535, 65535 };
GdkColor	BLACK = { 0, 0, 0, 0 };

/* Initialize the filter structures (reading from file) */
colfilter *
colfilter_new(void)
{
	colfilter *filter;
	gboolean got_white, got_black;

	/* Create the filter header */
	filter = (colfilter *)g_malloc(sizeof(colfilter));
	filter->num_of_filters = 0;

	sys_cmap = gdk_colormap_get_system();

	/* Allocate "constant" colors. */
	got_white = get_color(&WHITE);
	got_black = get_color(&BLACK);

	/* Got milk? */
	if (!got_white) {
		if (!got_black)
			simple_dialog(ESD_TYPE_WARN, NULL,
			    "Could not allocate colors black or white.");
		else
			simple_dialog(ESD_TYPE_WARN, NULL,
			    "Could not allocate color white.");
	} else {
		if (!got_black)
			simple_dialog(ESD_TYPE_WARN, NULL,
			    "Could not allocate color black.");
	}

	read_filters(filter);
	return filter;
}

/* Create a new filter */
color_filter_t *
new_color_filter(colfilter *filters,    /* The filter list (unused) */
                 gchar *name,           /* The name of the filter to create */
                 gchar *filter_string)  /* The string representing the filter */
{
	color_filter_t *colorf;

	colorf = (color_filter_t *)g_malloc(sizeof (color_filter_t));
	colorf->filter_name = g_strdup(name);
	colorf->filter_text = g_strdup(filter_string);
	colorf->bg_color = WHITE;
	colorf->fg_color = BLACK;
	colorf->c_colorfilter = NULL;
	colorf->edit_dialog = NULL;
	filter_list = g_slist_append(filter_list, colorf);
        return colorf;
}

/* delete the specified filter */
void
delete_color_filter(color_filter_t *colorf)
{
	if (colorf->filter_name != NULL)
		g_free(colorf->filter_name);
	if (colorf->filter_text != NULL)
		g_free(colorf->filter_text);
	if (colorf->c_colorfilter != NULL)
		dfilter_free(colorf->c_colorfilter);
	filter_list = g_slist_remove(filter_list, colorf);
	g_free(colorf);
}

static void
prime_edt(gpointer data, gpointer user_data)
{
	color_filter_t  *colorf = data;
	epan_dissect_t   *edt = user_data;

	if (colorf->c_colorfilter != NULL)
		epan_dissect_prime_dfilter(edt, colorf->c_colorfilter);
} 

/* Prime the epan_dissect_t with all the compiler
 * color filters in 'filter_list'. */
void
filter_list_prime_edt(epan_dissect_t *edt)
{
	g_slist_foreach(filter_list, prime_edt, edt);
}


/* read filters from the file */
static gboolean
read_filters(colfilter *filter)
{
	/* TODO: Lots more syntax checking on the file */
	/* I hate these fixed length names! TODO: make more dynamic */
	/* XXX - buffer overflow possibility here
	 * sscanf blocks max size of name and filter_exp; buf is used for
	 * reading only */
	gchar name[256],filter_exp[256], buf[1024];
	guint16 fg_r, fg_g, fg_b, bg_r, bg_g, bg_b;
	GdkColor fg_color, bg_color;
	color_filter_t *colorf;
	const gchar *path;
	FILE *f;
	dfilter_t *temp_dfilter;

	/* decide what file to open (from dfilter code) */

	/* should only be called by colors_init */
	if (filter == NULL)
		return FALSE;
	/* we have a clist */

	path = get_persconffile_path("colorfilters", FALSE);
	if ((f = fopen(path, "r")) == NULL) {
		if (errno != ENOENT) {
			simple_dialog(ESD_TYPE_CRIT, NULL,
			    "Could not open filter file\n\"%s\": %s.", path,
			    strerror(errno));
		}
		return FALSE;
	}

	do {
		if (fgets(buf,sizeof buf, f) == NULL)
			break;
		
		if (strspn(buf," \t") == (size_t)((strchr(buf,'*') - buf))) {
			/* leading # comment */
			continue;
		}

		/* we get the @ delimiter.  It is not in any strings
		 * Format is:
		 * @name@filter expression@[background r,g,b][foreground r,g,b]
		 */
		if (sscanf(buf," @%256[^@]@%256[^@]@[%hu,%hu,%hu][%hu,%hu,%hu]",
		    name, filter_exp, &bg_r, &bg_g, &bg_b, &fg_r, &fg_g, &fg_b)
		    == 8) {
			/* we got a filter */

			if (!dfilter_compile(filter_exp, &temp_dfilter)) {
				simple_dialog(ESD_TYPE_CRIT, NULL,
		"Could not compile color filter %s from saved filters.\n%s",
				    name, dfilter_error_msg);
				continue;
			}
			if (!get_color(&fg_color)) {
				/* oops */
				simple_dialog(ESD_TYPE_CRIT, NULL,
				    "Could not allocate foreground color "
				    "specified in input file for %s.", name);
				dfilter_free(temp_dfilter);
				continue;
			}
			if (!get_color(&bg_color)) {
				/* oops */
				simple_dialog(ESD_TYPE_CRIT, NULL,
				    "Could not allocate background color "
				    "specified in input file for %s.", name);
				dfilter_free(temp_dfilter);
				continue;
			}

			colorf = new_color_filter(filter, name, filter_exp);
			colorf->c_colorfilter = temp_dfilter;
			filter->num_of_filters++;
			fg_color.red = fg_r;
			fg_color.green = fg_g;
			fg_color.blue = fg_b;
			bg_color.red = bg_r;
			bg_color.green = bg_g;
			bg_color.blue = bg_b;

			colorf->bg_color = bg_color;
			colorf->fg_color = fg_color;
		}    /* if sscanf */
	} while(!feof(f));
	return TRUE;
}

static void
write_filter(gpointer filter_arg, gpointer file_arg)
{
	color_filter_t *colorf = filter_arg;
	FILE *f = file_arg;

	fprintf(f,"@%s@%s@[%d,%d,%d][%d,%d,%d]\n",
	    colorf->filter_name,
	    colorf->filter_text,
	    colorf->bg_color.red,
	    colorf->bg_color.green,
	    colorf->bg_color.blue,
	    colorf->fg_color.red,
	    colorf->fg_color.green,
	    colorf->fg_color.blue);
}

/* save filters in filter file */
gboolean
write_filters(colfilter *filter)
{
	gchar *pf_dir_path;
	const gchar *path;
	FILE *f;

	/* Create the directory that holds personal configuration files,
	   if necessary.  */
	if (create_persconffile_dir(&pf_dir_path) == -1) {
		simple_dialog(ESD_TYPE_WARN, NULL,
		    "Can't create directory\n\"%s\"\nfor color files: %s.",
		    pf_dir_path, strerror(errno));
		g_free(pf_dir_path);
		return FALSE;
	}

	path = get_persconffile_path("colorfilters", TRUE);
	if ((f = fopen(path, "w+")) == NULL) {
		simple_dialog(ESD_TYPE_CRIT, NULL,
		    "Could not open\n%s\nfor writing: %s.",
		    path, strerror(errno));
		return FALSE;
	}
        fprintf(f,"# DO NOT EDIT THIS FILE!  It was created by Ethereal\n");
        g_slist_foreach(filter_list, write_filter, f);
	fclose(f);
	return TRUE;
}

/* allocate a color from the color map */
gboolean
get_color (GdkColor *new_color)
{
    GdkVisual *pv;

    if (!our_cmap) {
      if ( !gdk_colormap_alloc_color (sys_cmap, new_color, FALSE, TRUE)) {
        pv = gdk_visual_get_best();
	      if ( !(our_cmap = gdk_colormap_new(pv, TRUE)))
		      simple_dialog(ESD_TYPE_WARN, NULL, "Could not create new colormap");
      } else
	      return (TRUE);
    }
    return ( gdk_colormap_alloc_color ( our_cmap, new_color, FALSE, TRUE) );
}
