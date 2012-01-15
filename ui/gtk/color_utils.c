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

#include <string.h>

#include <gtk/gtk.h>

#include "../color.h"
#include "../simple_dialog.h"

#include "ui/gtk/color_utils.h"
#include "ui/gtk/gtkglobals.h"
#if 0
static GdkColormap*	sys_cmap;
static GdkColormap*	our_cmap = NULL;
#endif
GdkColor	WHITE = { 0, 65535, 65535, 65535 };
/*GdkColor	LTGREY = { 0, 57343, 57343, 57343 };*/
GdkColor	BLACK = { 0, 0, 0, 0 };

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
#if 0
	if (!get_color(&gdk_color))
		return FALSE;
#endif
	gdkcolor_to_color_t(color, &gdk_color);
	return TRUE;
}

/* Initialize the colors */
void
colors_init(void)
{
#if 0
	gboolean got_white, got_black;

	sys_cmap = gdk_colormap_get_system();

	/* Allocate "constant" colors. */
	got_white = get_color(&WHITE);
	got_black = get_color(&BLACK);
	/* Got milk? */
	if (!got_white) {
		if (!got_black)
			simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
				"Could not allocate colors black or white.");
		else
			simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
				"Could not allocate color white.");
	} else {
		if (!got_black)
			simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
				"Could not allocate color black.");
	}
#endif

}
#if 0
/* allocate a color from the color map */
gboolean
get_color(GdkColor *new_color)
{
	GdkVisual *pv;

	if (!our_cmap) {
		if (!gdk_colormap_alloc_color (sys_cmap, new_color, FALSE,
			TRUE)) {
			pv = gdk_visual_get_best();
			if (!(our_cmap = gdk_colormap_new(pv, TRUE))) {
				simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
					"Could not create new colormap");
			}
		} else
			return (TRUE);
	}
	return (gdk_colormap_alloc_color(our_cmap, new_color, FALSE, TRUE));
}
#endif
void
color_t_to_gdkcolor(GdkColor *target, const color_t *source)
{
	target->pixel = source->pixel;
	target->red   = source->red;
	target->green = source->green;
	target->blue  = source->blue;
}
#if GTK_CHECK_VERSION(3,0,0)
void
color_t_to_gdkRGBAcolor(GdkRGBA *target, const color_t *source)
{
	target->alpha = 1;
	target->red   = source->red / 65535.0;
	target->green = source->green / 65535.0;
	target->blue  = source->blue / 65535.0;
}
#endif
void
gdkcolor_to_color_t(color_t *target, const GdkColor *source)
{
	target->pixel = source->pixel;
	target->red   = source->red;
	target->green = source->green;
	target->blue  = source->blue;
}
#if GTK_CHECK_VERSION(3,0,0)
void
gdkRGBAcolor_to_color_t(color_t *target, const GdkRGBA *source)
{
	target->pixel = 0;
	target->red   = source->red*65535;
	target->green = source->green*65535;
	target->blue  = source->blue*65535;
}
#endif

