/* colors.h
 * Definitions for color structures and routines
 *
 * $Id: colors.h,v 1.10 2002/09/23 19:09:49 oabad Exp $
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
#ifndef  __COLORS_H__
#define  __COLORS_H__

#include "../color.h"

#define MAXCOLORS	255
#define MAX_COLOR_FILTER_NAME_LEN 33
#define MAX_COLOR_FILTER_STRING_LEN 256

#define CFILTERS_CONTAINS_FILTER(filter) \
	((filter)->num_of_filters != 0)

extern GdkColor WHITE;
extern GdkColor BLACK;

void colfilter_init(void);

gboolean write_filters(void);

color_filter_t *new_color_filter(gchar *name, gchar *filter_string);
void delete_color_filter(color_filter_t *colorf);

gboolean get_color (GdkColor *new_color);

#endif
