/* color_dialog.cpp
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

#include "color_dialog.h"

#include <epan/packet.h>
#include <epan/dfilter/dfilter.h>
#include <epan/prefs.h>

#include "color.h"
#include "color_filters.h"

/* a new color filter was read in from a filter file */
void
color_filter_add_cb(color_filter_t *colorf, gpointer user_data)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: color_filter_add_cb");
//    GtkWidget        *color_filters = user_data;

//    add_filter_to_list(colorf, color_filters);

//    gtk_widget_grab_focus(color_filters);
}

ColorDialog::ColorDialog(QWidget *parent) :
    QDialog(parent)
{
}
