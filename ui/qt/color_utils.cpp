/* color_utils.cpp
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

#include <glib.h>

#include "color_utils.h"

#include "color.h"

/*
 * Initialize a color with R, G, and B values, including any toolkit-dependent
 * work that needs to be done.
 */
gboolean
initialize_color(color_t *color, guint16 red, guint16 green, guint16 blue)
{
    QColor qc;

    // color_t uses 16-bit components to match Gtk+. Qt use 8.
    qc.setRgb(red>>8, green>>8, blue>>8);
    if (!qc.isValid())
        return FALSE;

    // Match what color_filters.c does.
    color->red = red;
    color->green = green;
    color->blue = blue;
    color->pixel = 0;
    return TRUE;
}

// XXX - We probably don't need a class.
ColorUtils::ColorUtils(QWidget *parent) :
    QWidget(parent)
{
}
