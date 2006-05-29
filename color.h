/* color.h
 * Definitions for "toolkit-independent" colors
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

#ifndef __COLOR_H__
#define __COLOR_H__

/*
 * Data structure holding RGB value for a color.
 *
 * XXX - yes, I know, there's a "pixel" value in there as well; for
 * now, it's intended to look just like a GdkColor but not to require
 * that any GTK+ header files be included in order to use it.
 * The way we handle colors needs to be cleaned up somewhat, in order
 * to keep toolkit-specific stuff separate from toolkit-independent stuff.
 */
typedef struct {
	guint32 pixel;
	guint16 red;
	guint16 green;
	guint16 blue;
} color_t;

/** Initialize a color with R, G, and B values, including any toolkit-dependent
 ** work that needs to be done.
 *
 * @param color the color_t to be filled
 * @param red the red value for the color
 * @param green the green value for the color
 * @param blue the blue value for the color
 * @return TRUE if it succeeds, FALSE if it fails
 */
gboolean initialize_color(color_t *color, guint16 red, guint16 green, guint16 blue);

#endif
