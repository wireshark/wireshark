/* color_filters.h
 * Definitions for color filters
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
#ifndef  __COLOR_FILTERS_H__
#define  __COLOR_FILTERS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CONVERSATION_COLOR_PREFIX       "___conversation_color_filter___"
/** @file
 *  Color filters.
 */

/* Data for a color filter. */
typedef struct _color_filter {
    gchar     *filter_name;   /* name of the filter */
    gchar     *filter_text;   /* text of the filter expression */
    color_t    bg_color;      /* background color for packets that match */
    color_t    fg_color;      /* foreground color for packets that match */
    gboolean   disabled;      /* set if the filter is disabled */
    gboolean   selected;      /* set if the filter is selected in the color dialog box */

    /* only used inside of color_filters.c */
    dfilter_t *c_colorfilter; /* compiled filter expression */

    /* only used outside of color_filters.c (beside init) */
    void      *edit_dialog;   /* if filter is being edited, dialog
                               * box for it */
} color_filter_t;


/** Init the color filters (incl. initial read from file). */
void color_filters_init(void);

/** Reload the color filters */
void color_filters_reload(void);

/** Cleanup remaining color filter zombies */
void color_filters_cleanup(void);

/** Color filters currently used?
 *
 * @return TRUE, if filters are used
 */
gboolean color_filters_used(void);

/** Are there any temporary coloring filters used?
 *
 * @return TRUE, if temporary coloring filters are used
 */
gboolean tmp_color_filters_used(void);

/** En-/disable color filters
 *
 * @param enable TRUE to enable (default)
 */
void
color_filters_enable(gboolean enable);

/** Set the filter string of a temporary color filter
 *
 * @param filt_nr a number 1-10 pointing to a temporary color
 * @param filter the new filter-string
 * @param disabled whether the filter-rule should be disabled
 */
void
color_filters_set_tmp(guint8 filt_nr, gchar *filter, gboolean disabled);

/** Reset the temporary color filters
 *
 */
void
color_filters_reset_tmp(void);

/* Prime the epan_dissect_t with all the compiler
 * color filters of the current filter list.
 *
 * @param the epan dissector details
 */
void color_filters_prime_edt(epan_dissect_t *edt);

/** Colorize a specific packet.
 *
 * @param row the row in the packet list
 * @param edt the dissected packet
 * @return the matching color filter or NULL
 */
const color_filter_t *
color_filters_colorize_packet(epan_dissect_t *edt);

/** Clone the currently active filter list.
 *
 * @param user_data will be returned by each call to to color_filter_add_cb()
 */
void color_filters_clone(gpointer user_data);

/** Load filters (import) from some other filter file.
 *
 * @param path the path to the import file
 * @param user_data will be returned by each call to to color_filter_add_cb()
 * @return TRUE, if read succeeded
 */
gboolean color_filters_import(gchar *path, gpointer user_data);

/** Read filters from the global filter file (not the users file).
 *
 * @param user_data will be returned by each call to to color_filter_add_cb()
 * @return TRUE, if read succeeded
 */
gboolean color_filters_read_globals(gpointer user_data);

/** A color filter was added (while importing).
 * (color_filters.c calls this for every filter coming in)
 *
 * @param colorf the new color filter
 * @param user_data from caller
 */
void color_filter_add_cb (color_filter_t *colorf, gpointer user_data);



/** Apply a changed filter list.
 *
 * @param tmp_cfl the temporary color filter list to apply
 * @param edit_cfl the edited permanent color filter list to apply
 */
void color_filters_apply(GSList *tmp_cfl, GSList *edit_cfl);

/** Save filters in users filter file.
 *
 * @param cfl the filter list to write
 * @return TRUE if write succeeded
 */
gboolean color_filters_write(GSList *cfl);

/** Save filters (export) to some other filter file.
 *
 * @param path the path to the filter file
 * @param cfl the filter list to write
 * @param only_selected TRUE if only the selected filters should be saved
 * @return TRUE, if write succeeded
 */
gboolean color_filters_export(gchar *path, GSList *cfl, gboolean only_selected);



/** Create a new color filter (g_malloc'ed).
 *
 * @param name the name of the filter
 * @param filter_string the filter string
 * @param bg_color background color
 * @param fg_color foreground color
 * @param disabled gboolean
 * @return the new color filter
 */
color_filter_t *color_filter_new(
    const gchar *name, const gchar *filter_string,
    color_t *bg_color, color_t *fg_color, gboolean disabled);

/** Delete a single color filter (g_free'ed).
 *
 * @param colorf the color filter to be removed
 */
void color_filter_delete(color_filter_t *colorf);




/** Delete a filter list including all entries.
 *
 * @param cfl the filter list to delete
 */
void color_filter_list_delete(GSList **cfl);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
