/* color_utils.h
 * Declarations of utilities for converting between "toolkit-independent"
 * and GDK notions of color
 *
 * $Id$
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

#ifndef __COLOR_UTILS_H__
#define __COLOR_UTILS_H__

/** @file
 * Toolkit-dependent implementations of routines to handle colors.
 */

/** Create a color from R, G, and B values, and do whatever toolkit-dependent
 ** work needs to be done.
 *
 * @param color the color_t to be filled
 * @param red the red value for the color
 * @param green the green value for the color
 * @param blue the blue value for the color
 * @param source the GdkColor to be filled
 * @return TRUE if it succeeds, FALSE if it fails
 */
gboolean create_color(color_t *color, guint16 red, guint16 green, guint16 blue);

#endif
