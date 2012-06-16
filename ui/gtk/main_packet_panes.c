/* main_packet_panes.c
 * Routines for GTK+ packet display in the main window (packet details
 * and hex dump panes)
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

#include <epan/epan_dissect.h>
#include <epan/prefs.h>

#include <gtk/gtk.h>

#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/main_packet_panes.h"
#include "ui/gtk/packet_panes.h"

void
add_main_byte_views(epan_dissect_t *edt)
{
    add_byte_views(edt, tree_view_gbl, byte_nb_ptr_gbl);
}

void
main_proto_tree_draw(proto_tree *protocol_tree)
{
    proto_tree_draw(protocol_tree, tree_view_gbl);
}

/*
 * Clear the hex dump and protocol tree panes in the main window.
 */
void
main_clear_tree_and_hex_views(void)
{
    /* Clear the hex dump by getting rid of all the byte views. */
    while (gtk_notebook_get_nth_page(GTK_NOTEBOOK(byte_nb_ptr_gbl), 0) != NULL)
        gtk_notebook_remove_page(GTK_NOTEBOOK(byte_nb_ptr_gbl), 0);

    /* Add a placeholder byte view so that there's at least something
       displayed in the byte view notebook. */
    add_byte_tab(byte_nb_ptr_gbl, "", NULL, NULL, tree_view_gbl);

    /* Clear the protocol tree */
    main_proto_tree_draw(NULL);
}
