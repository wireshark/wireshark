/* prefs_protocols.c
 * Dialog box for preferences common for all protocols
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

#include <epan/prefs.h>

#include "gtk/prefs_protocols.h"
#include "gtk/prefs_dlg.h"

#define PROTOCOLS_SHOW_HIDDEN_KEY   "display_hidden_items"
#define PROTOCOLS_TABLE_ROWS 1

GtkWidget*
protocols_prefs_show(void)
{
        GtkWidget   *main_tb, *main_vb;
        GtkWidget   *display_hidden_cb;
        int pos = 0;

        /* Main vertical box */
        main_vb = gtk_vbox_new(FALSE, 7);
        gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);

        /* Main table */
        main_tb = gtk_table_new(PROTOCOLS_TABLE_ROWS, 1, FALSE);
        gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
        gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
        gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
        gtk_widget_show(main_tb);

        /* Show hidden protocol items in packet list */
        display_hidden_cb = create_preference_check_button(main_tb, pos++,
            "Display hidden protocol items:", 
            "Display all hidden protocol items in the packet list.",
            prefs.display_hidden_proto_items);
        g_object_set_data(G_OBJECT(main_vb), PROTOCOLS_SHOW_HIDDEN_KEY, display_hidden_cb);

        /* Show 'em what we got */
        gtk_widget_show_all(main_vb);

        return main_vb;
}

void
protocols_prefs_fetch(GtkWidget *w _U_)
{
        GtkWidget *display_hidden_cb;

        display_hidden_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), PROTOCOLS_SHOW_HIDDEN_KEY);
        prefs.display_hidden_proto_items = (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (display_hidden_cb)) ? TRUE : FALSE);
}

void
protocols_prefs_apply(GtkWidget *w _U_)
{
}

void
protocols_prefs_destroy(GtkWidget *w _U_)
{
}

