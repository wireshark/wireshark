/* color_filters.c
 * Routines for color filters
 *
 * $Id: color_filters.c,v 1.7 2004/01/31 03:22:39 guy Exp $
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

#include <string.h>

#include <epan/filesystem.h>

#include <epan/packet.h>
#include "color.h"
#include "colors.h"
#include "color_filters.h"
#include "color_utils.h"
#include "color_dlg.h"
#include "file.h"
#include <epan/dfilter/dfilter.h>
#include "simple_dialog.h"
#include "gtkglobals.h"

static gboolean read_filters(void);
static gboolean read_global_filters(void);

GSList *filter_list;
GSList *removed_filter_list;

/* Remove the specified filter from the list of existing color filters,
 * and add it to the list of removed color filters.
 * This way, unmarking and marking a packet which matches a now removed
 * color filter will still be colored correctly as the color filter is
 * still reachable. */
void remove_color_filter(color_filter_t *colorf)
{
	/* Remove colorf from the list of color filters */
	filter_list = g_slist_remove(filter_list, colorf);
	/* Add colorf to the list of removed color filters */
	removed_filter_list = g_slist_prepend(removed_filter_list, colorf);
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

/* delete the specified filter as an iterator*/
static void
delete_color_filter_it(gpointer filter_arg, gpointer ignored _U_)
{
	color_filter_t *colorf = filter_arg;
	
	delete_color_filter(colorf);
}

/* delete all the filters */

static void
delete_all_color_filters (void)
{
        g_slist_foreach(filter_list, delete_color_filter_it, NULL);
        g_slist_foreach(removed_filter_list, delete_color_filter_it, NULL);
}

/* Initialize the filter structures (reading from file) for general running, including app startup */
void
colfilter_init(void)
{
	delete_all_color_filters();
	if (!read_filters())
		read_global_filters();
}

/* Create a new filter */
color_filter_t *
new_color_filter(gchar *name,           /* The name of the filter to create */
                 gchar *filter_string)  /* The string representing the filter */
{
	color_filter_t *colorf;
        GtkStyle       *style;

	colorf = (color_filter_t *)g_malloc(sizeof (color_filter_t));
	colorf->filter_name = g_strdup(name);
	colorf->filter_text = g_strdup(filter_string);
        style = gtk_widget_get_style(packet_list);
	gdkcolor_to_color_t(&colorf->bg_color, &style->base[GTK_STATE_NORMAL]);
	gdkcolor_to_color_t(&colorf->fg_color, &style->text[GTK_STATE_NORMAL]);
	colorf->c_colorfilter = NULL;
	colorf->edit_dialog = NULL;
	colorf->marked = FALSE;
	filter_list = g_slist_append(filter_list, colorf);
        return colorf;
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


/* read filters from the given file */
static gboolean
read_filters_file(FILE *f, gpointer arg)
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
	dfilter_t *temp_dfilter;

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
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Could not compile color filter %s from saved filters.\n%s",
				    name, dfilter_error_msg);
				continue;
			}
			if (!get_color(&fg_color)) {
				/* oops */
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "Could not allocate foreground color "
				    "specified in input file for %s.", name);
				dfilter_free(temp_dfilter);
				continue;
			}
			if (!get_color(&bg_color)) {
				/* oops */
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "Could not allocate background color "
				    "specified in input file for %s.", name);
				dfilter_free(temp_dfilter);
				continue;
			}

			colorf = new_color_filter(name, filter_exp);
			colorf->c_colorfilter = temp_dfilter;
			fg_color.red = fg_r;
			fg_color.green = fg_g;
			fg_color.blue = fg_b;
			bg_color.red = bg_r;
			bg_color.green = bg_g;
			bg_color.blue = bg_b;

			gdkcolor_to_color_t(&colorf->bg_color, &bg_color);
			gdkcolor_to_color_t(&colorf->fg_color, &fg_color);

			if (arg != NULL)
				color_add_filter_cb (colorf, arg);
		}    /* if sscanf */
	} while(!feof(f));
	return TRUE;
}

/* read filters from the user's filter file */
static gboolean
read_filters(void)
{
	/* TODO: Lots more syntax checking on the file */
	/* I hate these fixed length names! TODO: make more dynamic */
	/* XXX - buffer overflow possibility here
	 * sscanf blocks max size of name and filter_exp; buf is used for
	 * reading only */
	gchar *path;
	FILE *f;
	gboolean ret;

	/* decide what file to open (from dfilter code) */
	path = get_persconffile_path("colorfilters", FALSE);
	if ((f = fopen(path, "r")) == NULL) {
		if (errno != ENOENT) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			    "Could not open filter file\n\"%s\": %s.", path,
			    strerror(errno));
		}
		g_free((gchar *)path);
		return FALSE;
	}
	g_free((gchar *)path);
	path = NULL;

	ret = read_filters_file(f, NULL);
	fclose(f);
	return ret;
}

/* read filters from the filter file */
static gboolean
read_global_filters(void)
{
	gchar *path;
	FILE *f;
	gboolean ret;

	/* decide what file to open (from dfilter code) */
	path = get_datafile_path("colorfilters");
	if ((f = fopen(path, "r")) == NULL) {
		if (errno != ENOENT) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			    "Could not open global filter file\n\"%s\": %s.", path,
			    strerror(errno));
		}
		g_free((gchar *)path);
		return FALSE;
	}
	g_free((gchar *)path);
	path = NULL;

	ret = read_filters_file(f, NULL);
	fclose(f);
	return ret;
}

/* save filters in some other filter file */

gboolean
read_other_filters(gchar *path, gpointer arg)
{
	FILE *f;
	gboolean ret;

	if ((f = fopen(path, "r")) == NULL) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Could not open\n%s\nfor reading: %s.",
		    path, strerror(errno));
		return FALSE;
	}

	ret = read_filters_file(f, arg);
	fclose(f);
	return ret;
}

struct write_filter_data
{
  FILE * f;
  gboolean only_marked;
};

static void
write_filter(gpointer filter_arg, gpointer data_arg)
{
	struct write_filter_data *data = data_arg;
	color_filter_t *colorf = filter_arg;
	FILE *f = data->f;

	if (colorf->marked || !data->only_marked) {
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
}

/* save filters in a filter file */
gboolean
write_filters_file(FILE *f, gboolean only_marked)
{
	struct write_filter_data data;

	data.f = f;
	data.only_marked = only_marked;
  
	fprintf(f,"# DO NOT EDIT THIS FILE!  It was created by Ethereal\n");
        g_slist_foreach(filter_list, write_filter, &data);
	return TRUE;
}

/* save filters in users filter file */

gboolean
write_filters(void)
{
	gchar *pf_dir_path;
	const gchar *path;
	FILE *f;

	/* Create the directory that holds personal configuration files,
	   if necessary.  */
	if (create_persconffile_dir(&pf_dir_path) == -1) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Can't create directory\n\"%s\"\nfor color files: %s.",
		    pf_dir_path, strerror(errno));
		g_free(pf_dir_path);
		return FALSE;
	}

	path = get_persconffile_path("colorfilters", TRUE);
	if ((f = fopen(path, "w+")) == NULL) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Could not open\n%s\nfor writing: %s.",
		    path, strerror(errno));
		return FALSE;
	}
	write_filters_file(f, FALSE);
	fclose(f);
	return TRUE;
}

/* delete users filter file and reload global filters*/

gboolean
revert_filters(void)
{
	gchar *pf_dir_path;
	const gchar *path;

	/* Create the directory that holds personal configuration files,
	   if necessary.  */
	if (create_persconffile_dir(&pf_dir_path) == -1) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Can't create directory\n\"%s\"\nfor color files: %s.",
		    pf_dir_path, strerror(errno));
		g_free(pf_dir_path);
		return FALSE;
	}

	path = get_persconffile_path("colorfilters", TRUE);
	if (!deletefile(path))
		return FALSE;

	/* Reload the (global) filters - Note: this does not update the dialog. */
	colfilter_init();
        return TRUE;
}


/* save filters in some other filter file */

gboolean
write_other_filters(gchar *path, gboolean only_marked)
{
	FILE *f;

	if ((f = fopen(path, "w+")) == NULL) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Could not open\n%s\nfor writing: %s.",
		    path, strerror(errno));
		return FALSE;
	}
	write_filters_file(f, only_marked);
	fclose(f);
	return TRUE;
}
