/* packet_list.c
 * packet list related functions   2002 Olivier Abad
 *
 * $Id: packet_list.c,v 1.3 2002/11/03 17:38:34 oabad Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include "gtkglobals.h"
#include "epan/epan.h"
#include "color.h"
#include "../ui_util.h"
#include "color_utils.h"
#include "column.h"
#include "epan/column_info.h"

void
packet_list_clear(void)
{
    gtk_clist_clear(GTK_CLIST(packet_list));
}

void
packet_list_freeze(void)
{
    gtk_clist_freeze(GTK_CLIST(packet_list));
}

void
packet_list_thaw(void)
{
    gtk_clist_thaw(GTK_CLIST(packet_list));
}

void
packet_list_select_row(gint row)
{
    gtk_signal_emit_by_name(GTK_OBJECT(packet_list), "select_row", row);
}

void
packet_list_set_column_auto_resize(gint column, gboolean auto_resize)
{
    gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), column,
                                     auto_resize);
}

void
packet_list_set_column_resizeable(gint column, gboolean resizeable)
{
    gtk_clist_set_column_resizeable(GTK_CLIST(packet_list), column, resizeable);
}

void
packet_list_set_column_width(gint column, gint width)
{
    gtk_clist_set_column_width(GTK_CLIST(packet_list), column, width);
}

void
packet_list_moveto_end(void)
{
    gtk_clist_moveto(GTK_CLIST(packet_list),
                     GTK_CLIST(packet_list)->rows - 1, -1, 1.0, 1.0);
}

gint
packet_list_append(gchar *text[], gpointer data)
{
    gint row;

    row = gtk_clist_append(GTK_CLIST(packet_list), text);
    gtk_clist_set_row_data(GTK_CLIST(packet_list), row, data);
    return row;
}

void
packet_list_set_colors(gint row, color_t *fg, color_t *bg)
{
    GdkColor gdkfg, gdkbg;

    if (fg)
    {
        color_t_to_gdkcolor(&gdkfg, fg);
        gtk_clist_set_foreground(GTK_CLIST(packet_list), row, &gdkfg);
    }
    if (bg)
    {
        color_t_to_gdkcolor(&gdkbg, bg);
        gtk_clist_set_background(GTK_CLIST(packet_list), row, &gdkbg);
    }
}

gint
packet_list_find_row_from_data(gpointer data)
{
    return gtk_clist_find_row_from_data(GTK_CLIST(packet_list), data);
}

void
packet_list_set_text(gint row, gint column, const gchar *text)
{
    gtk_clist_set_text(GTK_CLIST(packet_list), row, column, text);
}

/* Set the column widths of those columns that show the time in
 * "command-line-specified" format. */
void
packet_list_set_cls_time_width(gint column)
{
    GtkStyle *pl_style;
    gint      width;

    pl_style = gtk_widget_get_style(packet_list);
#if GTK_MAJOR_VERSION < 2
    width = gdk_string_width(pl_style->font,
                             get_column_longest_string(COL_CLS_TIME));
#else
    width = gdk_string_width(gdk_font_from_description(pl_style->font_desc),
                             get_column_longest_string(COL_CLS_TIME));
#endif
    packet_list_set_column_width(column, width);
}

gpointer
packet_list_get_row_data(gint row)
{
    return gtk_clist_get_row_data(GTK_CLIST(packet_list), row);
}

/* Set the selected row and the focus row of the packet list to the specified
 * row, and make it visible if it's not currently visible. */
void
packet_list_set_selected_row(gint row)
{
    if (gtk_clist_row_is_visible(GTK_CLIST(packet_list), row) !=
        GTK_VISIBILITY_FULL)
        gtk_clist_moveto(GTK_CLIST(packet_list), row, -1, 0.0, 0.0);

    /* XXX - why is there no "gtk_clist_set_focus_row()", so that we
     * can make the row for the frame we found the focus row?
     *
     * See http://www.gnome.org/mailing-lists/archives/gtk-list/2000-January/0038.shtml
     */
    GTK_CLIST(packet_list)->focus_row = row;

    gtk_clist_select_row(GTK_CLIST(packet_list), row, -1);
}
