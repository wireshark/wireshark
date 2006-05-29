/* color_utils.c
 * Toolkit-dependent implementations of routines to handle colors.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtk/gtk.h>

#include "color.h"

#include "colors.h"

/*
 * Initialize a color with R, G, and B values, including any toolkit-dependent
 * work that needs to be done.
 * Returns TRUE if it succeeds, FALSE if it fails.
 */
gboolean
initialize_color(color_t *color, guint16 red, guint16 green, guint16 blue)
{
	GdkColor gdk_color;

	gdk_color.red = red;
	gdk_color.green = green;
	gdk_color.blue = blue;
	if (!get_color(&gdk_color))
		return FALSE;
	gdkcolor_to_color_t(color, &gdk_color);
	return TRUE;
}
