/* color_utils.c
 * Utilities for converting between "toolkit-independent" and GDK
 * notions of color
 *
 * $Id: color_utils.c,v 1.1 2000/11/21 23:54:09 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#include <glib.h>

#include <gtk/gtk.h>

#include "prefs.h"	/* to declare "color_t" */

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
