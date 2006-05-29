/* colors.c
 * Routines for colors
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
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <string.h>

#include "color.h"	/* to declare "color_t" */

#include "colors.h"
#include "simple_dialog.h"
#include "gtkglobals.h"

static GdkColormap*	sys_cmap;
static GdkColormap*	our_cmap = NULL;

GdkColor	WHITE = { 0, 65535, 65535, 65535 };
GdkColor	BLACK = { 0, 0, 0, 0 };

/* Initialize the colors */
void
colors_init(void)
{
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
}

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

void
color_t_to_gdkcolor(GdkColor *target, color_t *source)
{
	target->pixel = source->pixel;
	target->red   = source->red;
	target->green = source->green;
	target->blue  = source->blue;
}

void
gdkcolor_to_color_t(color_t *target, GdkColor *source)
{
	target->pixel = source->pixel;
	target->red   = source->red;
	target->green = source->green;
	target->blue  = source->blue;
}
