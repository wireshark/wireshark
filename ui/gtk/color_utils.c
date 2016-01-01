/* color_utils.c
 * Toolkit-dependent implementations of routines to handle colors.
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

#include "config.h"

#include <string.h>

#include <gtk/gtk.h>

#include "ui/gtk/color_utils.h"
/* static GdkColor	WHITE = { 0, 65535, 65535, 65535 }; */
/*static GdkColor	LTGREY = { 0, 57343, 57343, 57343 };*/
/* static GdkColor	BLACK = { 0, 0, 0, 0 }; */

/*
 * Initialize a color with R, G, and B values, including any toolkit-dependent
 * work that needs to be done.
 * Returns TRUE if it succeeds, FALSE if it fails.
 */
gboolean
initialize_color(color_t *color, guint16 red, guint16 green, guint16 blue)
{
	GdkColor gdk_color;

	gdk_color.pixel = 0;
	gdk_color.red = red;
	gdk_color.green = green;
	gdk_color.blue = blue;

	gdkcolor_to_color_t(color, &gdk_color);
	return TRUE;
}

void
color_t_to_gdkcolor(GdkColor *target, const color_t *source)
{
	target->pixel = source->pixel;
	target->red   = source->red;
	target->green = source->green;
	target->blue  = source->blue;
}

void
color_t_to_gdkRGBAcolor(GdkRGBA *target, const color_t *source)
{
	target->alpha = 1;
	target->red   = source->red / 65535.0;
	target->green = source->green / 65535.0;
	target->blue  = source->blue / 65535.0;
}
void
gdkcolor_to_color_t(color_t *target, const GdkColor *source)
{
	target->pixel = source->pixel;
	target->red   = source->red;
	target->green = source->green;
	target->blue  = source->blue;
}

void
gdkRGBAcolor_to_color_t(color_t *target, const GdkRGBA *source)
{
	target->pixel = 0;
	target->red   = (guint16)(source->red*65535);
	target->green = (guint16)(source->green*65535);
	target->blue  = (guint16)(source->blue*65535);
}


void
GdkColor_to_GdkRGBA(GdkRGBA *target, const GdkColor *source)
{
	target->alpha = 1;
	target->red   = (double)source->red / 65535.0;
	target->green = (double)source->green / 65535.0;
	target->blue  = (double)source->blue / 65535.0;
}

void
gdkRGBAcolor_to_GdkColor(GdkColor *target, const GdkRGBA *source)
{
	target->pixel = 0;
	target->red   = (guint16)(source->red*65535);
	target->green = (guint16)(source->green*65535);
	target->blue  = (guint16)(source->blue*65535);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
