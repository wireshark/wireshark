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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <string.h>

#include "decode_as_dlg.h"
#include "dlg_utils.h"
#include "globals.h"
#include "simple_dialog.h"
#include <epan/packet.h>
#include <epan/ipproto.h>
#include "gui_utils.h"
#include <epan/epan_dissect.h>
#include "compat_macros.h"
#include "decode_as_dcerpc.h"
#include "decode_as_ber.h"

#include <epan/dissectors/packet-ber.h>


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
#if GTK_MAJOR_VERSION < 2
    gint               row;
#else
    GtkTreeSelection  *selection;
    GtkTreeModel      *model;
    GtkTreeIter        iter;
#endif

    syntax = NULL;
    list = OBJECT_GET_DATA(notebook_pg, E_PAGE_LIST);

    if (requested_action == E_DECODE_NO)
#if GTK_MAJOR_VERSION < 2
	gtk_clist_unselect_all(GTK_CLIST(list));
#else
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(list)));
#endif

#if GTK_MAJOR_VERSION < 2
    if (!GTK_CLIST(list)->selection)
    {
	syntax = NULL;
    } else {
	row = GPOINTER_TO_INT(GTK_CLIST(list)->selection->data);
	gtk_clist_get_text(GTK_CLIST(list), row, E_LIST_S_PROTO_NAME, &syntax);
    }
#else
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
    if (gtk_tree_selection_get_selected(selection, &model, &iter) == FALSE)
    {
	syntax = NULL;
    } else {
      gtk_tree_model_get(model, &iter, E_LIST_S_PROTO_NAME, &syntax, -1);
    }
#endif

    if ((syntax != NULL && strcmp(syntax, "(default)") == 0) ) {
      ber_decode_as(NULL);
    } else {
      ber_decode_as(syntax);
    }
#if GTK_MAJOR_VERSION >= 2
    if (syntax != NULL)
	g_free(syntax);
#endif

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
decode_ber_add_page (packet_info *pinfo)
{
    GtkWidget	*page_hb, *info_vb, *label, *scrolled_window;

    /* create page content */
    page_hb = gtk_hbox_new(FALSE, 5);
    OBJECT_SET_DATA(page_hb, E_PAGE_ACTION, decode_ber);
    OBJECT_SET_DATA(page_hb, E_PAGE_TABLE, "ASN.1");
    OBJECT_SET_DATA(page_hb, E_PAGE_TITLE, "ASN.1");
    
    info_vb = gtk_vbox_new(FALSE, 5);
    gtk_box_pack_start(GTK_BOX(page_hb), info_vb, TRUE, TRUE, 0);

    /* Always enabled */
    label = gtk_label_new("Decode ASN.1 file as:");
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);

    scrolled_window = decode_add_ber_menu(page_hb, "ber" /*table_name*/);
    gtk_box_pack_start(GTK_BOX(page_hb), scrolled_window, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, scrolled_window);

    return(page_hb);
}
