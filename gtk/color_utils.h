/* colors.h
 * Definitions for color structures and routines
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

#ifndef  __COLORS_H__
#define  __COLORS_H__

/** @file
 *  Definitions for color structures and routines
 */

/** The color white. */
extern GdkColor WHITE;

/** The color light-grey. */
extern GdkColor LTGREY;

/** The color black. */
extern GdkColor BLACK;

/** Initialize the colors. */
void colors_init(void);

/** Allocate a color from the color map.
 *
 * @param new_color the new color
 * @return TRUE if the allocation succeeded
 */
gboolean get_color(GdkColor *new_color);

/** Convert color_t to GdkColor.
 *
 * @param target the GdkColor to be filled
 * @param source the source color_t
 */
void color_t_to_gdkcolor(GdkColor *target, const color_t *source);

/** Convert GdkColor to color_t.
 *
 * @param target the source color_t
 * @param source the GdkColor to be filled
 */
void gdkcolor_to_color_t(color_t *target, const GdkColor *source);

#endif /* __COLORS_H__ */
