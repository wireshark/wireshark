/* color_filters.h
 * Definitions for color filters
 *
 * $Id: color_filters.h,v 1.7 2004/06/01 20:28:04 ulfl Exp $
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
#ifndef  __COLOR_FILTERS_H__
#define  __COLOR_FILTERS_H__

/** @file
 *  Color filters.
 */

/** Init the color filters. */
void colfilter_init(void);

/** Save filters in users filter file.
 *
 * @return TRUE if write succeeded
 */
gboolean write_filters(void);

/** Delete users filter file and reload global filters.
 *
 * @return TRUE if write succeeded
 */
gboolean revert_filters(void);

/** Create a new color filter.
 *
 * @param name the name of the filter
 * @param filter_string the filter string
 * @param bg_color background color
 * @param fg_color foreground color
 * @return the new color filter
 */
color_filter_t *new_color_filter(gchar *name, gchar *filter_string,
    GdkColor *bg_color, GdkColor *fg_color);

/** Remove the color filter.
 *
 * @param colorf the color filter to be removed
 */
void remove_color_filter(color_filter_t *colorf);

/** Load filters from some other filter file.
 *
 * @param path the path to the filter file
 * @param arg the color filter widget
 * @return TRUE, if read succeeded
 */
gboolean read_other_filters(gchar *path, gpointer arg);

/** Save filters to some other filter file.
 *
 * @param path the path to the filter file
 * @param only_marked TRUE if only the marked filters should be saved
 * @return TRUE, if write succeeded
 */
gboolean write_other_filters(gchar *path, gboolean only_marked);

#endif
