/* color_filters.c
 * Routines for color filters
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <glib.h>
#include <ctype.h>
#include <string.h>

#include <epan/filesystem.h>
#include "file_util.h"

#include <epan/packet.h>
#include "color.h"
#include "color_filters.h"
#include "file.h"
#include <epan/dfilter/dfilter.h>
#include "simple_dialog.h"
#include "ui_util.h"

static gboolean read_filters(void);
static gboolean read_global_filters(void);

/* Variables and routines defined in color.h */

GSList *color_filter_list = NULL;
GSList *removed_filter_list = NULL;

/* Color Filters can en-/disabled. */
gboolean filters_enabled = TRUE;

/* Remove the specified filter from the list of existing color filters,
 * and add it to the list of removed color filters.
 * This way, unmarking and marking a packet which matches a now removed
 * color filter will still be colored correctly as the color filter is
 * still reachable. */
void color_filter_remove(color_filter_t *colorf)
{
	/* Remove colorf from the list of color filters */
	color_filter_list = g_slist_remove(color_filter_list, colorf);
	/* Add colorf to the list of removed color filters */
	removed_filter_list = g_slist_prepend(removed_filter_list, colorf);
}

/* delete the specified filter */
static void
delete_color_filter(color_filter_t *colorf)
{
	if (colorf->filter_name != NULL)
		g_free(colorf->filter_name);
	if (colorf->filter_text != NULL)
		g_free(colorf->filter_text);
	if (colorf->c_colorfilter != NULL)
		dfilter_free(colorf->c_colorfilter);
	g_free(colorf);
}

/* delete the specified filter as an iterator */
static void
delete_color_filter_it(gpointer filter_arg, gpointer unused _U_)
{
	color_filter_t *colorf = filter_arg;
	delete_color_filter(colorf);
}

/* delete all the filters */
static void
delete_all_color_filters (void)
{
        g_slist_foreach(color_filter_list, delete_color_filter_it, NULL);
	g_slist_free(color_filter_list);
	color_filter_list = NULL;
        g_slist_foreach(removed_filter_list, delete_color_filter_it, NULL);
	g_slist_free(removed_filter_list);
	removed_filter_list = NULL;
}

/* Initialize the filter structures (reading from file) for general running, including app startup */
void
color_filters_init(void)
{
	delete_all_color_filters();
	if (!read_filters())
		read_global_filters();
}

/* Create a new filter */
color_filter_t *
color_filter_new(const gchar *name,    /* The name of the filter to create */
                 const gchar *filter_string, /* The string representing the filter */
                 color_t *bg_color,    /* The background color */
                 color_t *fg_color)    /* The foreground color */
{
	color_filter_t *colorf;

	colorf = g_malloc(sizeof (color_filter_t));
	colorf->filter_name = g_strdup(name);
	colorf->filter_text = g_strdup(filter_string);
	colorf->bg_color = *bg_color;
	colorf->fg_color = *fg_color;
	colorf->c_colorfilter = NULL;
	colorf->edit_dialog = NULL;
	colorf->marked = FALSE;
	color_filter_list = g_slist_append(color_filter_list, colorf);
        return colorf;
}

gboolean 
color_filters_used(void)
{
    return color_filter_list != NULL && filters_enabled;
}

void
color_filters_enable(gboolean enable)
{
    filters_enabled = enable;
}


/* prepare the epan_dissect_t for the filter */
static void
prime_edt(gpointer data, gpointer user_data)
{
	color_filter_t  *colorf = data;
	epan_dissect_t   *edt = user_data;

	if (colorf->c_colorfilter != NULL)
		epan_dissect_prime_dfilter(edt, colorf->c_colorfilter);
}

/* Prime the epan_dissect_t with all the compiler
 * color filters in 'color_filter_list'. */
void
color_filters_prime_edt(epan_dissect_t *edt)
{
	g_slist_foreach(color_filter_list, prime_edt, edt);
}

/* Colorize a single packet of the packet list */
color_filter_t *
color_filters_colorize_packet(gint row, epan_dissect_t *edt)
{
    GSList *curr;
    color_filter_t *colorf;

    /* If we have color filters, "search" for the matching one. */
    if (color_filters_used()) {
        curr = color_filter_list;

        while( (curr = g_slist_next(curr)) != NULL) {
            colorf = curr->data;
            if ((colorf->c_colorfilter != NULL) &&
                 dfilter_apply_edt(colorf->c_colorfilter, edt)) {
                    /* this is the filter to use, apply it to the packet list */
                    packet_list_set_colors(row, &(colorf->fg_color), &(colorf->bg_color));
                    return colorf;
            }
        }
    }

    return NULL;
}

/* read filters from the given file */

/* XXX - Would it make more sense to use GStrings here instead of reallocing
   our buffers? */
static gboolean
read_filters_file(FILE *f, gpointer arg)
{
#define INIT_BUF_SIZE 128
	gchar  *name = NULL;
	gchar  *filter_exp = NULL;
	guint32 name_len = INIT_BUF_SIZE;
	guint32 filter_exp_len = INIT_BUF_SIZE;
	guint32 i = 0;
	gint32  c;
	guint16 fg_r, fg_g, fg_b, bg_r, bg_g, bg_b;
	gboolean skip_end_of_line = FALSE;

	name = g_malloc(name_len + 1);
	filter_exp = g_malloc(filter_exp_len + 1);

	while (1) {

		if (skip_end_of_line) {
			do {
				c = getc(f);
			} while (c != EOF && c != '\n');
			if (c == EOF)
				break;
			skip_end_of_line = FALSE;
		}

		while ((c = getc(f)) != EOF && isspace(c)) {
			if (c == '\n') {
				continue;
			}
		}

		if (c == EOF)
			break;

		/* skip # comments and invalid lines */
		if (c != '@') {	
			skip_end_of_line = TRUE;
			continue;
		}

		/* we get the @ delimiter.
		 * Format is:
		 * @name@filter expression@[background r,g,b][foreground r,g,b]
		 */

		/* retrieve name */
		i = 0;
		while (1) {
			c = getc(f);
			if (c == EOF || c == '@')
				break;
			if (i >= name_len) {
				/* buffer isn't long enough; double its length.*/
				name_len *= 2;
				name = g_realloc(name, name_len + 1);
			}
			name[i++] = c;		  
		}
		name[i] = '\0';

		if (c == EOF) {
			break;
		} else if (i == 0) {
			skip_end_of_line = TRUE;
			continue;
		}

		/* retrieve filter expression */
		i = 0;
		while (1) {
			c = getc(f);
			if (c == EOF || c == '@')
				break;
			if (i >= filter_exp_len) {
				/* buffer isn't long enough; double its length.*/
				filter_exp_len *= 2;
				filter_exp = g_realloc(filter_exp, filter_exp_len + 1);
			}
			filter_exp[i++] = c;
		}
		filter_exp[i] = '\0';

		if (c == EOF) {
			break;
		} else if (i == 0) {
			skip_end_of_line = TRUE;
			continue;
		}

		/* retrieve background and foreground colors */
		if (fscanf(f,"[%hu,%hu,%hu][%hu,%hu,%hu]",
			&bg_r, &bg_g, &bg_b, &fg_r, &fg_g, &fg_b) == 6) {

			/* we got a complete color filter */

			color_t bg_color, fg_color;
			color_filter_t *colorf;
			dfilter_t *temp_dfilter;

			if (!dfilter_compile(filter_exp, &temp_dfilter)) {
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				"Could not compile color filter %s from saved filters.\n%s",
					      name, dfilter_error_msg);
				skip_end_of_line = TRUE;
				continue;
			}

			if (!initialize_color(&fg_color, fg_r, fg_g, fg_b)) {
				/* oops */
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "Could not allocate foreground color "
				    "specified in input file for %s.", name);
				dfilter_free(temp_dfilter);
				skip_end_of_line = TRUE;
				continue;
			}
			if (!initialize_color(&bg_color, bg_r, bg_g, bg_b)) {
				/* oops */
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "Could not allocate background color "
				    "specified in input file for %s.", name);
				dfilter_free(temp_dfilter);
				skip_end_of_line = TRUE;
				continue;
			}

			colorf = color_filter_new(name, filter_exp, &bg_color,
			    &fg_color);
			colorf->c_colorfilter = temp_dfilter;

			if (arg != NULL)
				color_filter_add_cb (colorf, arg);
		}    /* if sscanf */

		skip_end_of_line = TRUE;
	}

	g_free(name);
	g_free(filter_exp);
	return TRUE;
}

/* read filters from the user's filter file */
static gboolean
read_filters(void)
{
	gchar *path;
	FILE *f;
	gboolean ret;

	/* decide what file to open (from dfilter code) */
	path = get_persconffile_path("colorfilters", FALSE);
	if ((f = eth_fopen(path, "r")) == NULL) {
		if (errno != ENOENT) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			    "Could not open filter file\n\"%s\": %s.", path,
			    strerror(errno));
		}
		g_free(path);
		return FALSE;
	}
	g_free(path);
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
	if ((f = eth_fopen(path, "r")) == NULL) {
		if (errno != ENOENT) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			    "Could not open global filter file\n\"%s\": %s.", path,
			    strerror(errno));
		}
		g_free(path);
		return FALSE;
	}
	g_free(path);
	path = NULL;

	ret = read_filters_file(f, NULL);
	fclose(f);
	return ret;
}

/* read filters from some other filter file (import) */
gboolean
color_filters_import(gchar *path, gpointer arg)
{
	FILE *f;
	gboolean ret;

	if ((f = eth_fopen(path, "r")) == NULL) {
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

/* save a single filter */
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
static gboolean
write_filters_file(FILE *f, gboolean only_marked)
{
	struct write_filter_data data;

	data.f = f;
	data.only_marked = only_marked;
  
	fprintf(f,"# DO NOT EDIT THIS FILE!  It was created by Wireshark\n");
        g_slist_foreach(color_filter_list, write_filter, &data);
	return TRUE;
}

/* save filters in users filter file */
gboolean
color_filters_write(void)
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
	if ((f = eth_fopen(path, "w+")) == NULL) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Could not open\n%s\nfor writing: %s.",
		    path, strerror(errno));
		return FALSE;
	}
	write_filters_file(f, FALSE);
	fclose(f);
	return TRUE;
}

/* save filters in some other filter file (export) */
gboolean
color_filters_export(gchar *path, gboolean only_marked)
{
	FILE *f;

	if ((f = eth_fopen(path, "w+")) == NULL) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Could not open\n%s\nfor writing: %s.",
		    path, strerror(errno));
		return FALSE;
	}
	write_filters_file(f, only_marked);
	fclose(f);
	return TRUE;
}

/* delete users filter file and reload global filters */
gboolean
color_filters_revert(void)
{
	gchar *path;

	path = get_persconffile_path("colorfilters", TRUE);
	if (!deletefile(path)) {
		g_free(path);
		return FALSE;
	}

	g_free(path);

	/* Reload the (global) filters - Note: this does not update the dialog. */
	color_filters_init();
        return TRUE;
}
