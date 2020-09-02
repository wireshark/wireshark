/* color_filters.c
 * Routines for color filters
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/*
 * Updated 1 Dec 10 jjm
 */

#include <config.h>

#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>

#include <epan/packet.h>
#include "color_filters.h"
#include "file.h"
#include <epan/dfilter/dfilter.h>
#include <epan/prefs.h>
#include <epan/epan_dissect.h>

#define RED_COMPONENT(x)   (guint16) (((((x) >> 16) & 0xff) * 65535 / 255))
#define GREEN_COMPONENT(x) (guint16) (((((x) >>  8) & 0xff) * 65535 / 255))
#define BLUE_COMPONENT(x)  (guint16) ( (((x)        & 0xff) * 65535 / 255))

static int read_filters_file(const gchar *path, FILE *f, gpointer user_data, color_filter_add_cb_func add_cb);

/* the currently active filters */
static GSList *color_filter_list = NULL;

/* keep "old" deleted filters in this list until
 * the dissection no longer needs them (e.g. file is closed) */
static GSList *color_filter_deleted_list = NULL;
static GSList *color_filter_valid_list   = NULL;

/* Color Filters can en-/disabled. */
static gboolean filters_enabled = TRUE;

/* Remember if there are temporary coloring filters set to
 * add sensitivity to the "Reset Coloring 1-10" menu item
 */
static gboolean tmp_colors_set = FALSE;

/* Create a new filter */
color_filter_t *
color_filter_new(const gchar *name,          /* The name of the filter to create */
                 const gchar *filter_string, /* The string representing the filter */
                 color_t     *bg_color,      /* The background color */
                 color_t     *fg_color,      /* The foreground color */
                 gboolean     disabled)      /* Is the filter disabled? */
{
    color_filter_t *colorf;

    colorf                      = (color_filter_t *)g_malloc0(sizeof (color_filter_t));
    colorf->filter_name         = g_strdup(name);
    colorf->filter_text         = g_strdup(filter_string);
    colorf->bg_color            = *bg_color;
    colorf->fg_color            = *fg_color;
    colorf->disabled            = disabled;
    return colorf;
}

/* Add ten empty (temporary) colorfilters for easy coloring */
static void
color_filters_add_tmp(GSList **cfl)
{
    gchar          *name = NULL;
    guint32         i;
    gchar**         bg_colors;
    gchar**         fg_colors;
    gulong          cval;
    color_t         bg_color, fg_color;
    color_filter_t *colorf;

    g_assert(strlen(prefs.gui_colorized_fg)==69);
    g_assert(strlen(prefs.gui_colorized_bg)==69);
    fg_colors = g_strsplit(prefs.gui_colorized_fg, ",", -1);
    bg_colors = g_strsplit(prefs.gui_colorized_bg, ",", -1);

    for ( i=1 ; i<=10 ; i++ ) {
        name = g_strdup_printf("%s%02d",CONVERSATION_COLOR_PREFIX,i);

        /* retrieve background and foreground colors */
        cval = strtoul(fg_colors[i-1], NULL, 16);
        fg_color.red = RED_COMPONENT(cval);
        fg_color.green = GREEN_COMPONENT(cval);
        fg_color.blue = BLUE_COMPONENT(cval);
        cval = strtoul(bg_colors[i-1], NULL, 16);
        bg_color.red = RED_COMPONENT(cval);
        bg_color.green = GREEN_COMPONENT(cval);
        bg_color.blue = BLUE_COMPONENT(cval);
        colorf = color_filter_new(name, NULL, &bg_color, &fg_color, TRUE);
        colorf->filter_text = g_strdup("frame");
        *cfl = g_slist_append(*cfl, colorf);

        g_free(name);
    }

    g_strfreev(fg_colors);
    g_strfreev(bg_colors);
}

static gint
color_filters_find_by_name_cb(gconstpointer arg1, gconstpointer arg2)
{
    const color_filter_t *colorf = (const color_filter_t *)arg1;
    const gchar          *name   = (const gchar *)arg2;

    return strcmp(colorf->filter_name, name);
}

/* Get the filter of a temporary color filter */
gchar*
color_filters_get_tmp(guint8 filt_nr)
{
    gchar* name = NULL;
    gchar* filter = NULL;
    GSList* cfl;
    color_filter_t* colorf;
    /* Only perform a lookup if the supplied filter number is in the expected range */
    if (filt_nr < 1 || filt_nr > 10)
        return NULL;

    name = g_strdup_printf("%s%02d", CONVERSATION_COLOR_PREFIX, filt_nr);
    cfl = g_slist_find_custom(color_filter_list, name, color_filters_find_by_name_cb);
    colorf = (color_filter_t*)cfl->data;

    if (!colorf->disabled)
        filter = g_strdup(colorf->filter_text);

    g_free(name);

    return filter;
}

/* Set the filter off a temporary colorfilters and enable it */
gboolean
color_filters_set_tmp(guint8 filt_nr, const gchar *filter, gboolean disabled, gchar **err_msg)
{
    gchar          *name = NULL;
    const gchar    *tmpfilter = NULL;
    GSList         *cfl;
    color_filter_t *colorf;
    dfilter_t      *compiled_filter;
    guint8         i;
    gchar          *local_err_msg = NULL;
    /* Go through the temporary filters and look for the same filter string.
     * If found, clear it so that a filter can be "moved" up and down the list
     */
    for ( i=1 ; i<=10 ; i++ ) {
        /* If we need to reset the temporary filter (filter==NULL), don't look
         * for other rules with the same filter string
         */
        if( i!=filt_nr && filter==NULL )
            continue;

        name = g_strdup_printf("%s%02d",CONVERSATION_COLOR_PREFIX,i);
        cfl = g_slist_find_custom(color_filter_list, name, color_filters_find_by_name_cb);
        colorf = (color_filter_t *)cfl->data;

        /* Only change the filter rule if this is the rule to change or if
         * a matching filter string has been found
         */
        if(colorf && ( (i==filt_nr) || (!strcmp(filter, colorf->filter_text)) ) ) {
            /* set filter string to "frame" if we are resetting the rules
             * or if we found a matching filter string which need to be cleared
             */
            tmpfilter = ( (filter==NULL) || (i!=filt_nr) ) ? "frame" : filter;
            if (!dfilter_compile(tmpfilter, &compiled_filter, &local_err_msg)) {
                *err_msg = g_strdup_printf( "Could not compile color filter name: \"%s\" text: \"%s\".\n%s", name, filter, local_err_msg);
                g_free(local_err_msg);
                g_free(name);
                return FALSE;
            } else {
                g_free(colorf->filter_text);
                dfilter_free(colorf->c_colorfilter);
                colorf->filter_text = g_strdup(tmpfilter);
                colorf->c_colorfilter = compiled_filter;
                colorf->disabled = ((i!=filt_nr) ? TRUE : disabled);
                /* Remember that there are now temporary coloring filters set */
                if( filter )
                    tmp_colors_set = TRUE;
            }
        }
        g_free(name);
    }
    return TRUE;
}

const color_filter_t *
color_filters_tmp_color(guint8 filter_num) {
    gchar          *name;
    color_filter_t *colorf = NULL;
    GSList         *cfl;

    name = g_strdup_printf("%s%02d", CONVERSATION_COLOR_PREFIX, filter_num);
    cfl = g_slist_find_custom(color_filter_list, name, color_filters_find_by_name_cb);
    if (cfl) {
        colorf = (color_filter_t *)cfl->data;
    }
    g_free(name);

    return colorf;
}

/* Reset the temporary colorfilters */
gboolean
color_filters_reset_tmp(gchar **err_msg)
{
    guint8 i;

    for ( i=1 ; i<=10 ; i++ ) {
        if (!color_filters_set_tmp(i, NULL, TRUE, err_msg))
            return FALSE;
    }
    /* Remember that there are now *no* temporary coloring filters set */
    tmp_colors_set = FALSE;
    return TRUE;
}

/* delete the specified filter */
void
color_filter_delete(color_filter_t *colorf)
{
    g_free(colorf->filter_name);
    g_free(colorf->filter_text);
    dfilter_free(colorf->c_colorfilter);
    g_free(colorf);
}

/* delete the specified filter (called from g_slist_foreach) */
static void
color_filter_delete_cb(gpointer filter_arg)
{
    color_filter_t *colorf = (color_filter_t *)filter_arg;

    color_filter_delete(colorf);
}

/* delete the specified list */
void
color_filter_list_delete(GSList **cfl)
{
    g_slist_free_full(*cfl, color_filter_delete_cb);
    *cfl = NULL;
}

/* clone a single list entries from normal to edit list */
static color_filter_t *
color_filter_clone(color_filter_t *colorf)
{
    color_filter_t *new_colorf;

    new_colorf                      = (color_filter_t *)g_malloc(sizeof (color_filter_t));
    new_colorf->filter_name         = g_strdup(colorf->filter_name);
    new_colorf->filter_text         = g_strdup(colorf->filter_text);
    new_colorf->bg_color            = colorf->bg_color;
    new_colorf->fg_color            = colorf->fg_color;
    new_colorf->disabled            = colorf->disabled;
    new_colorf->c_colorfilter       = NULL;

    return new_colorf;
}

static void
color_filter_list_clone_cb(gpointer filter_arg, gpointer cfl_arg)
{
    GSList **cfl = (GSList **)cfl_arg;
    color_filter_t *new_colorf;

    new_colorf = color_filter_clone((color_filter_t *)filter_arg);
    *cfl = g_slist_append(*cfl, new_colorf);
}

/* clone the specified list */
static GSList *
color_filter_list_clone(GSList *cfl)
{
    GSList *new_list = NULL;

    g_slist_foreach(cfl, color_filter_list_clone_cb, &new_list);

    return new_list;
}

static gboolean
color_filters_get(gchar** err_msg, color_filter_add_cb_func add_cb)
{
    gchar    *path;
    FILE     *f;
    int       ret;

    /* start the list with the temporary colorizing rules */
    color_filters_add_tmp(&color_filter_list);

    /*
     * Try to get the user's filters.
     *
     * Get the path for the file that would have their filters, and
     * try to open it.
     */
    path = get_persconffile_path(COLORFILTERS_FILE_NAME, TRUE);
    if ((f = ws_fopen(path, "r")) == NULL) {
        if (errno != ENOENT) {
            /* Error trying to open the file; give up. */
            *err_msg = g_strdup_printf("Could not open filter file\n\"%s\": %s.", path,
                                       g_strerror(errno));
            g_free(path);
            return FALSE;
	}
        /* They don't have any filters; try to read the global filters */
        g_free(path);
        return color_filters_read_globals(&color_filter_list, err_msg, add_cb);
    }

    /*
     * We've opened it; try to read it.
     */
    ret = read_filters_file(path, f, &color_filter_list, add_cb);
    if (ret != 0) {
        *err_msg = g_strdup_printf("Error reading filter file\n\"%s\": %s.",
                                   path, g_strerror(errno));
        fclose(f);
        g_free(path);
        return FALSE;
    }

    /* Success. */
    fclose(f);
    g_free(path);
    return TRUE;
}

/* Initialize the filter structures (reading from file) for general running, including app startup */
gboolean
color_filters_init(gchar** err_msg, color_filter_add_cb_func add_cb)
{
    /* delete all currently existing filters */
    color_filter_list_delete(&color_filter_list);

    /* now try to construct the filters list */
    return color_filters_get(err_msg, add_cb);
}

gboolean
color_filters_reload(gchar** err_msg, color_filter_add_cb_func add_cb)
{
    /* "move" old entries to the deleted list
     * we must keep them until the dissection no longer needs them */
    color_filter_deleted_list = g_slist_concat(color_filter_deleted_list, color_filter_list);
    color_filter_list = NULL;

    /* now try to construct the filters list */
    return color_filters_get(err_msg, add_cb);
}

void
color_filters_cleanup(void)
{
    /* delete the previously deleted filters */
    color_filter_list_delete(&color_filter_deleted_list);
}

typedef struct _color_clone
{
    gpointer user_data;
    color_filter_add_cb_func add_cb;
} color_clone_t;

static void
color_filters_clone_cb(gpointer filter_arg, gpointer user_data)
{
    color_clone_t* clone_data = (color_clone_t*)user_data;
    color_filter_t * new_colorf = color_filter_clone((color_filter_t *)filter_arg);

    clone_data->add_cb (new_colorf, clone_data->user_data);
}

void
color_filters_clone(gpointer user_data, color_filter_add_cb_func add_cb)
{
    color_clone_t clone_data;

    clone_data.user_data = user_data;
    clone_data.add_cb = add_cb;
    g_slist_foreach(color_filter_list, color_filters_clone_cb, &clone_data);
}


static void
color_filter_compile_cb(gpointer filter_arg, gpointer err)
{
    color_filter_t *colorf = (color_filter_t *)filter_arg;
    gchar **err_msg = (gchar**)err;
    gchar *local_err_msg = NULL;

    g_assert(colorf->c_colorfilter == NULL);

    /* If the filter is disabled it doesn't matter if it compiles or not. */
    if (colorf->disabled) return;

    if (!dfilter_compile(colorf->filter_text, &colorf->c_colorfilter, &local_err_msg)) {
        *err_msg = g_strdup_printf("Could not compile color filter name: \"%s\" text: \"%s\".\n%s",
                      colorf->filter_name, colorf->filter_text, local_err_msg);
        g_free(local_err_msg);
        /* this filter was compilable before, so this should never happen */
        /* except if the OK button of the parent window has been clicked */
        /* so don't use g_assert_not_reached() but check the filters again */
    }
}

static void
color_filter_validate_cb(gpointer filter_arg, gpointer err)
{
    color_filter_t *colorf = (color_filter_t *)filter_arg;
    gchar **err_msg = (gchar**)err;
    gchar *local_err_msg;

    g_assert(colorf->c_colorfilter == NULL);

    /* If the filter is disabled it doesn't matter if it compiles or not. */
    if (colorf->disabled) return;

    if (!dfilter_compile(colorf->filter_text, &colorf->c_colorfilter, &local_err_msg)) {
        *err_msg = g_strdup_printf("Disabling color filter name: \"%s\" filter: \"%s\".\n%s",
                      colorf->filter_name, colorf->filter_text, local_err_msg);
        g_free(local_err_msg);

        /* Disable the color filter in the list of color filters. */
        colorf->disabled = TRUE;
    }
}

/* apply changes from the edit list */
gboolean
color_filters_apply(GSList *tmp_cfl, GSList *edit_cfl, gchar** err_msg)
{
    gboolean ret = TRUE;

    *err_msg = NULL;

    /* "move" old entries to the deleted list
     * we must keep them until the dissection no longer needs them */
    color_filter_deleted_list = g_slist_concat(color_filter_deleted_list, color_filter_list);
    color_filter_list = NULL;

    /* clone all list entries from tmp/edit to normal list */
    color_filter_valid_list = NULL;
    color_filter_valid_list = color_filter_list_clone(tmp_cfl);
    color_filter_valid_list = g_slist_concat(color_filter_valid_list,
                                             color_filter_list_clone(edit_cfl) );

    /* compile all filter */
    g_slist_foreach(color_filter_valid_list, color_filter_validate_cb, err_msg);
    if (*err_msg != NULL) {
        ret = FALSE;
    }

    /* clone all list entries from tmp/edit to normal list */
    color_filter_list = color_filter_list_clone(color_filter_valid_list);

    /* compile all filter */
    g_slist_foreach(color_filter_list, color_filter_compile_cb, err_msg);
    if (*err_msg != NULL) {
        ret = FALSE;
    }

    return ret;
}

gboolean
color_filters_used(void)
{
    return color_filter_list != NULL && filters_enabled;
}

gboolean
tmp_color_filters_used(void)
{
    return tmp_colors_set;
}

/* prepare the epan_dissect_t for the filter */
static void
prime_edt(gpointer data, gpointer user_data)
{
    color_filter_t *colorf = (color_filter_t *)data;
    epan_dissect_t *edt    = (epan_dissect_t *)user_data;

    if (colorf->c_colorfilter != NULL)
        epan_dissect_prime_with_dfilter(edt, colorf->c_colorfilter);
}

/* Prime the epan_dissect_t with all the compiler
 * color filters in 'color_filter_list'. */
void
color_filters_prime_edt(epan_dissect_t *edt)
{
    if (color_filters_used())
        g_slist_foreach(color_filter_list, prime_edt, edt);
}

/* * Return the color_t for later use */
const color_filter_t *
color_filters_colorize_packet(epan_dissect_t *edt)
{
    GSList         *curr;
    color_filter_t *colorf;

    /* If we have color filters, "search" for the matching one. */
    if ((edt->tree != NULL) && (color_filters_used())) {
        curr = color_filter_list;

        while(curr != NULL) {
            colorf = (color_filter_t *)curr->data;
            if ( (!colorf->disabled) &&
                 (colorf->c_colorfilter != NULL) &&
                 dfilter_apply_edt(colorf->c_colorfilter, edt)) {
                return colorf;
            }
            curr = g_slist_next(curr);
        }
    }

    return NULL;
}

/* read filters from the given file */
/* XXX - Would it make more sense to use GStrings here instead of reallocing
   our buffers? */
static int
read_filters_file(const gchar *path, FILE *f, gpointer user_data, color_filter_add_cb_func add_cb)
{
#define INIT_BUF_SIZE 128
    gchar    *name;
    gchar    *filter_exp;
    guint32   name_len         = INIT_BUF_SIZE;
    guint32   filter_exp_len   = INIT_BUF_SIZE;
    guint32   i                = 0;
    int       c;
    guint16   fg_r, fg_g, fg_b, bg_r, bg_g, bg_b;
    gboolean  disabled         = FALSE;
    gboolean  skip_end_of_line = FALSE;
    int       ret = 0;

    name = (gchar *)g_malloc(name_len + 1);
    filter_exp = (gchar *)g_malloc(filter_exp_len + 1);

    prefs.unknown_colorfilters = FALSE;

    while (1) {

        if (skip_end_of_line) {
            do {
                c = ws_getc_unlocked(f);
            } while (c != EOF && c != '\n');
            if (c == EOF)
                break;
            disabled = FALSE;
            skip_end_of_line = FALSE;
        }

        while ((c = ws_getc_unlocked(f)) != EOF && g_ascii_isspace(c)) {
            if (c == '\n') {
                continue;
            }
        }

        if (c == EOF)
            break;

        if (c == '!') {
            disabled = TRUE;
            continue;
        }

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
            c = ws_getc_unlocked(f);
            if (c == EOF || c == '@')
                break;
            if (i >= name_len) {
                /* buffer isn't long enough; double its length.*/
                name_len *= 2;
                name = (gchar *)g_realloc(name, name_len + 1);
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
            c = ws_getc_unlocked(f);
            if (c == EOF || c == '@')
                break;
            if (i >= filter_exp_len) {
                /* buffer isn't long enough; double its length.*/
                filter_exp_len *= 2;
                filter_exp = (gchar *)g_realloc(filter_exp, filter_exp_len + 1);
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
            dfilter_t *temp_dfilter = NULL;
            gchar *local_err_msg = NULL;

            if (!disabled && !dfilter_compile(filter_exp, &temp_dfilter, &local_err_msg)) {
                g_warning("Could not compile \"%s\" in colorfilters file \"%s\".\n%s",
                          name, path, local_err_msg);
                g_free(local_err_msg);
                prefs.unknown_colorfilters = TRUE;

                /* skip_end_of_line = TRUE; */
                disabled = TRUE;
            }

            fg_color.red = fg_r;
            fg_color.green = fg_g;
            fg_color.blue = fg_b;

            bg_color.red = bg_r;
            bg_color.green = bg_g;
            bg_color.blue = bg_b;

            colorf = color_filter_new(name, filter_exp, &bg_color,
                                      &fg_color, disabled);
            if(user_data == &color_filter_list) {
                GSList **cfl = (GSList **)user_data;

                /* internal call */
                colorf->c_colorfilter = temp_dfilter;
                *cfl = g_slist_append(*cfl, colorf);
            } else {
                /* external call */
                /* just editing, don't need the compiled filter */
                dfilter_free(temp_dfilter);
                add_cb(colorf, user_data);
            }
        }    /* if sscanf */

        skip_end_of_line = TRUE;
    }

    if (ferror(f))
        ret = errno;

    g_free(name);
    g_free(filter_exp);
    return ret;
}

/* read filters from the filter file */
gboolean
color_filters_read_globals(gpointer user_data, gchar** err_msg, color_filter_add_cb_func add_cb)
{
    gchar    *path;
    FILE     *f;
    int       ret;

    /*
     * Try to get the global filters.
     *
     * Get the path for the file that would have the global filters, and
     * try to open it.
     */
    path = get_datafile_path(COLORFILTERS_FILE_NAME);
    if ((f = ws_fopen(path, "r")) == NULL) {
        if (errno != ENOENT) {
            /* Error trying to open the file; give up. */
            *err_msg = g_strdup_printf("Could not open global filter file\n\"%s\": %s.", path,
                                       g_strerror(errno));
            g_free(path);
            return FALSE;
        }

        /*
         * There is no global filter file; treat that as equivalent to
         * that file existing bug being empty, and say we succeeded.
         */
        g_free(path);
        return TRUE;
    }

    ret = read_filters_file(path, f, user_data, add_cb);
    if (ret != 0) {
        *err_msg = g_strdup_printf("Error reading global filter file\n\"%s\": %s.",
                                   path, g_strerror(errno));
        fclose(f);
        g_free(path);
        return FALSE;
    }

    fclose(f);
    g_free(path);
    return TRUE;
}

/* read filters from some other filter file (import) */
gboolean
color_filters_import(const gchar *path, gpointer user_data, gchar **err_msg, color_filter_add_cb_func add_cb)
{
    FILE     *f;
    int       ret;

    if ((f = ws_fopen(path, "r")) == NULL) {
        *err_msg = g_strdup_printf("Could not open filter file\n%s\nfor reading: %s.",
                      path, g_strerror(errno));
        return FALSE;
    }

    ret = read_filters_file(path, f, user_data, add_cb);
    if (ret != 0) {
        *err_msg = g_strdup_printf("Error reading filter file\n\"%s\": %s.",
                                   path, g_strerror(errno));
        fclose(f);
        return FALSE;
    }

    fclose(f);
    return TRUE;
}

struct write_filter_data
{
    FILE     *f;
    gboolean  only_selected;
};

/* save a single filter */
static void
write_filter(gpointer filter_arg, gpointer data_arg)
{
    struct write_filter_data *data = (struct write_filter_data *)data_arg;
    color_filter_t *colorf = (color_filter_t *)filter_arg;
    FILE *f = data->f;

    if ( (!data->only_selected) &&
         (strstr(colorf->filter_name,CONVERSATION_COLOR_PREFIX)==NULL) ) {
        fprintf(f,"%s@%s@%s@[%u,%u,%u][%u,%u,%u]\n",
                colorf->disabled ? "!" : "",
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
write_filters_file(GSList *cfl, FILE *f, gboolean only_selected)
{
    struct write_filter_data data;

    data.f = f;
    data.only_selected = only_selected;

    fprintf(f,"# DO NOT EDIT THIS FILE!  It was created by Wireshark\n");
    g_slist_foreach(cfl, write_filter, &data);
    return TRUE;
}

/* save filters in users filter file */
gboolean
color_filters_write(GSList *cfl, gchar** err_msg)
{
    gchar *pf_dir_path;
    gchar *path;
    FILE  *f;

    /* Create the directory that holds personal configuration files,
       if necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
        *err_msg = g_strdup_printf("Can't create directory\n\"%s\"\nfor color files: %s.",
                      pf_dir_path, g_strerror(errno));
        g_free(pf_dir_path);
        return FALSE;
    }

    path = get_persconffile_path(COLORFILTERS_FILE_NAME, TRUE);
    if ((f = ws_fopen(path, "w+")) == NULL) {
        *err_msg = g_strdup_printf("Could not open\n%s\nfor writing: %s.",
                      path, g_strerror(errno));
        g_free(path);
        return FALSE;
    }
    g_free(path);
    write_filters_file(cfl, f, FALSE);
    fclose(f);
    return TRUE;
}

/* save filters in some other filter file (export) */
gboolean
color_filters_export(const gchar *path, GSList *cfl, gboolean only_marked, gchar** err_msg)
{
    FILE *f;

    if ((f = ws_fopen(path, "w+")) == NULL) {
        *err_msg = g_strdup_printf("Could not open\n%s\nfor writing: %s.",
                      path, g_strerror(errno));
        return FALSE;
    }
    write_filters_file(cfl, f, only_marked);
    fclose(f);
    return TRUE;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
