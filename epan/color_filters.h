/* color_filters.h
 * Definitions for color filters
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef  __COLOR_FILTERS_H__
#define  __COLOR_FILTERS_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct epan_dissect;

/*
 * Data structure holding RGB value for a color.
 */
typedef struct {
	guint16 red;
	guint16 green;
	guint16 blue;
} color_t;

#define CONVERSATION_COLOR_PREFIX       "___conversation_color_filter___"
/** @file
 *  Color filters.
 */

/* Data for a color filter. */
typedef struct _color_filter {
    gchar     *filter_name;         /* name of the filter */
    gchar     *filter_text;         /* text of the filter expression */
    color_t    bg_color;            /* background color for packets that match */
    color_t    fg_color;            /* foreground color for packets that match */
    gboolean   disabled;            /* set if the filter is disabled */
    gboolean   selected;            /* set if the filter is selected in the color dialog box. GTK+ only. */

                                    /* only used inside of color_filters.c */
    struct epan_dfilter *c_colorfilter;  /* compiled filter expression */

                                    /* only used outside of color_filters.c (beside init) */
    void      *color_edit_dlg_info; /* if filter is being edited, ptr to req'd info. GTK+ only. */
} color_filter_t;

inline static unsigned int
color_t_to_rgb(const color_t *color) {
    return (((color->red >> 8) << 16)
        | ((color->green >> 8) << 8)
        | (color->blue >> 8));
}

/** A color filter was added (while importing).
 * (color_filters.c calls this for every filter coming in)
 *
 * @param colorf the new color filter
 * @param user_data from caller
 */
typedef void (*color_filter_add_cb_func)(color_filter_t *colorf, gpointer user_data);

/** Init the color filters (incl. initial read from file). */
WS_DLL_PUBLIC gboolean color_filters_init(gchar** err_msg, color_filter_add_cb_func add_cb);

/** Reload the color filters */
WS_DLL_PUBLIC gboolean color_filters_reload(gchar** err_msg, color_filter_add_cb_func add_cb);

/** Cleanup remaining color filter zombies */
WS_DLL_PUBLIC void color_filters_cleanup(void);

/** Color filters currently used?
 *
 * @return TRUE, if filters are used
 */
WS_DLL_PUBLIC gboolean color_filters_used(void);

/** Are there any temporary coloring filters used?
 *
 * @return TRUE, if temporary coloring filters are used
 */
WS_DLL_PUBLIC gboolean tmp_color_filters_used(void);

/** Set the filter string of a temporary color filter
 *
 * @param filt_nr a number 1-10 pointing to a temporary color
 * @param filter the new filter-string
 * @param disabled whether the filter-rule should be disabled
 * @param err_msg a string with error message
 */
WS_DLL_PUBLIC gboolean
color_filters_set_tmp(guint8 filt_nr, const gchar *filter, gboolean disabled, gchar **err_msg);

/** Get a temporary color filter.
 *
 * @param filter_num A number from 1 to 10 specifying the color to fetch.
 * @return The corresponding color or NULL.
 */
WS_DLL_PUBLIC const color_filter_t *
color_filters_tmp_color(guint8 filter_num);

/** Reset the temporary color filters
 *
 */
WS_DLL_PUBLIC gboolean
color_filters_reset_tmp(gchar **err_msg);

/* Prime the epan_dissect_t with all the compiler
 * color filters of the current filter list.
 *
 * @param the epan dissector details
 */
WS_DLL_PUBLIC void color_filters_prime_edt(struct epan_dissect *edt);

/** Colorize a specific packet.
 *
 * @param edt the dissected packet
 * @return the matching color filter or NULL
 */
WS_DLL_PUBLIC const color_filter_t *
color_filters_colorize_packet(struct epan_dissect *edt);

/** Clone the currently active filter list.
 *
 * @param user_data will be returned by each call to to color_filter_add_cb()
 * @param add_cb the callback function to add color filter
 */
WS_DLL_PUBLIC void color_filters_clone(gpointer user_data, color_filter_add_cb_func add_cb);

/** Load filters (import) from some other filter file.
 *
 * @param path the path to the import file
 * @param user_data will be returned by each call to to color_filter_add_cb()
 * @param err_msg a string with error message
 * @param add_cb the callback function to add color filter
 * @return TRUE, if read succeeded
 */
WS_DLL_PUBLIC gboolean color_filters_import(const gchar *path, gpointer user_data, gchar **err_msg, color_filter_add_cb_func add_cb);

/** Read filters from the global filter file (not the users file).
 *
 * @param user_data will be returned by each call to to color_filter_add_cb()
 * @param err_msg a string with error message
 * @param add_cb the callback function to add color filter
 * @return TRUE, if read succeeded
 */
WS_DLL_PUBLIC gboolean color_filters_read_globals(gpointer user_data, gchar** err_msg, color_filter_add_cb_func add_cb);


/** Apply a changed filter list.
 *
 * @param tmp_cfl the temporary color filter list to apply
 * @param edit_cfl the edited permanent color filter list to apply
 * @param err_msg a string with error message
 */
WS_DLL_PUBLIC gboolean color_filters_apply(GSList *tmp_cfl, GSList *edit_cfl, gchar** err_msg);

/** Save filters in users filter file.
 *
 * @param cfl the filter list to write
 * @param err_msg a string with error message
 * @return TRUE if write succeeded
 */
WS_DLL_PUBLIC gboolean color_filters_write(GSList *cfl, gchar** err_msg);

/** Save filters (export) to some other filter file.
 *
 * @param path the path to the filter file
 * @param cfl the filter list to write
 * @param only_selected TRUE if only the selected filters should be saved
 * @param err_msg a string with error message
 * @return TRUE, if write succeeded
 */
WS_DLL_PUBLIC gboolean color_filters_export(const gchar *path, GSList *cfl, gboolean only_selected, gchar** err_msg);

/** Create a new color filter (g_malloc'ed).
 *
 * @param name the name of the filter
 * @param filter_string the filter string
 * @param bg_color background color
 * @param fg_color foreground color
 * @param disabled gboolean
 * @return the new color filter
 */
WS_DLL_PUBLIC color_filter_t *color_filter_new(
    const gchar *name, const gchar *filter_string,
    color_t *bg_color, color_t *fg_color, gboolean disabled);

/** Delete a single color filter (g_free'ed).
 *
 * @param colorf the color filter to be removed
 */
WS_DLL_PUBLIC void color_filter_delete(color_filter_t *colorf);

/** Delete a filter list including all entries.
 *
 * @param cfl the filter list to delete
 */
WS_DLL_PUBLIC void color_filter_list_delete(GSList **cfl);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
