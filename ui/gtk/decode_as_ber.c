/* decode_as_ber.c
 *
 * $Id$
 *
 * Routines to modify BER decoding on the fly.
 *
 * Copyright 2006 Graeme Lunt
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

#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include <epan/dissectors/packet-ber.h>

#include "ui/simple_dialog.h"

#include "ui/gtk/decode_as_dlg.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/decode_as_dcerpc.h"
#include "ui/gtk/decode_as_ber.h"


/**************************************************/
/* Action routines for the "Decode As..." dialog  */
/*   - called when the OK button pressed          */
/**************************************************/

/*
 * This routine is called when the user clicks the "OK" button in the
 * "Decode As..." dialog window and the ASN.1 page is foremost.
 * This routine takes care of making any changes requested to the ASN.1
 * decoding.
 *
 * @param notebook_pg A pointer to the "ASN.1" notebook page.
 */
static void
decode_ber(GtkWidget *notebook_pg)
{
    GtkWidget *list;
    gchar              *syntax;
    GtkTreeSelection  *selection;
    GtkTreeModel      *model;
    GtkTreeIter        iter;

    syntax = NULL;
    list = g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_LIST);

    if (requested_action == E_DECODE_NO)
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(list)));

    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
    if (gtk_tree_selection_get_selected(selection, &model, &iter) == FALSE)
    {
	syntax = NULL;
    } else {
      gtk_tree_model_get(model, &iter, E_LIST_S_PROTO_NAME, &syntax, -1);
    }

    if ((syntax != NULL && strcmp(syntax, "(default)") == 0) ) {
      ber_decode_as(NULL);
    } else {
      ber_decode_as(syntax);
    }
    g_free(syntax);
}


/**************************************************/
/*                  Dialog setup                  */
/**************************************************/


/* add an interface to the list */
static void
decode_ber_add_to_list(gpointer key, gpointer value, gpointer user_data)
{
    decode_add_to_list("ASN.1", key, value, user_data);
}


/* add all interfaces to the list */
static GtkWidget *
decode_add_ber_menu (GtkWidget *page, const gchar *table_name _U_)
{
    GtkWidget *scrolled_window;
    GtkWidget *list;

    decode_list_menu_start(page, &list, &scrolled_window);

    ber_decode_as_foreach(decode_ber_add_to_list, list);
    decode_list_menu_finish(list);
    return(scrolled_window);
}


/* add a BER page to the notebook */
GtkWidget *
decode_ber_add_page (packet_info *pinfo _U_)
{
    GtkWidget	*page_hb, *info_vb, *label, *scrolled_window;

    /* create page content */
    page_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5, FALSE);
    g_object_set_data(G_OBJECT(page_hb), E_PAGE_ACTION, decode_ber);
    g_object_set_data(G_OBJECT(page_hb), E_PAGE_TABLE, "ASN.1");
    g_object_set_data(G_OBJECT(page_hb), E_PAGE_TITLE, "ASN.1");

    info_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 5, FALSE);
    gtk_box_pack_start(GTK_BOX(page_hb), info_vb, TRUE, TRUE, 0);

    /* Always enabled */
    label = gtk_label_new("Decode ASN.1 file as:");
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);

    scrolled_window = decode_add_ber_menu(page_hb, "ber" /*table_name*/);
    gtk_box_pack_start(GTK_BOX(page_hb), scrolled_window, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, scrolled_window);

    return(page_hb);
}
