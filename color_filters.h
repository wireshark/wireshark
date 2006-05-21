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

/** @file
 *  Color filters.
 */

/* Data for a color filter. */
typedef struct _color_filter {
        gchar     *filter_name;   /* name of the filter */
        gchar     *filter_text;   /* text of the filter expression */
        color_t    bg_color;      /* background color for packets that match */
        color_t    fg_color;      /* foreground color for packets that match */
        dfilter_t *c_colorfilter; /* compiled filter expression */
        void      *edit_dialog;   /* if filter is being edited, dialog
                                   * box for it */
	gboolean    marked;         /* set if the filter is marked in the color dialog box */
} color_filter_t;

/* List of all color filters. */
extern GSList *color_filter_list;

/** Init the color filters. */
void color_filters_init(void);

/** Save filters in users filter file.
 *
 * @return TRUE if write succeeded
 */
gboolean color_filters_write(void);

/** Delete users filter file and reload global filters.
 *
 * @return TRUE if write succeeded
 */
gboolean color_filters_revert(void);

/** Load filters (import) from some other filter file.
 *
 * @param path the path to the filter file
 * @param arg the color filter widget
 * @return TRUE, if read succeeded
 */
gboolean color_filters_import(gchar *path, gpointer arg);

/** Save filters (export) to some other filter file.
 *
 * @param path the path to the filter file
 * @param only_marked TRUE if only the marked filters should be saved
 * @return TRUE, if write succeeded
 */
gboolean color_filters_export(gchar *path, gboolean only_marked);

/** @todo don't what this function is for, please add explanation
 */
void color_filters_prime_edt(epan_dissect_t *edt);

/** Color filters currently used?
 *
 * @return TRUE, if filters are used
 */
gboolean color_filters_used(void);

/** En-/disable color filters
 *
 * @param enable TRUE to enable (default)
 */
void
color_filters_enable(gboolean enable);

/** Colorize a specific packet.
 *
 * @param row the row in the packet list
 * @param edt the dissected packet
 * @return the matching color filter or NULL
 */
color_filter_t *
color_filters_colorize_packet(gint row, epan_dissect_t *edt);

/** Create a new color filter.
 *
 * @param name the name of the filter
 * @param filter_string the filter string
 * @param bg_color background color
 * @param fg_color foreground color
 * @return the new color filter
 */
color_filter_t *color_filter_new(const gchar *name, const gchar *filter_string,
    color_t *bg_color, color_t *fg_color);

/** Remove the color filter.
 *
 * @param colorf the color filter to be removed
 */
void color_filter_remove(color_filter_t *colorf);

/** Add a color filter.
 *
 * @param colorf the new color filter
 * @param arg the color filter widget
 */
void color_filter_add_cb (color_filter_t *colorf, gpointer arg);

#endif
