/* decode_as_dlg.c
 *
 * $Id: decode_as_dlg.c,v 1.28 2002/11/03 17:38:33 oabad Exp $
 *
 * Routines to modify dissector tables on the fly.
 *
 * By David Hampton <dhampton@mac.com>
 * Copyright 2001 David Hampton
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
#include "ipproto.h"
#include "ui_util.h"
#include <epan/epan_dissect.h>

#undef DEBUG

/**************************************************/
/*                Typedefs & Enums                */
/**************************************************/

/*
 * Enum used to track which radio button is currently selected in the
 * dialog. These buttons are labeled "Decode" and "Do not decode".
 */
enum action_type {
    /* The "Decode" button is currently selected. */
    E_DECODE_YES,

    /* The "Do not decode" button is currently selected. */
    E_DECODE_NO
};

/*
 * Enum used to track which transport layer port menu item is
 * currently selected in the dialog.  These items are labeled "source",
 * "destination", and "source/destination".
 */
enum srcdst_type {
    /* The "source port" menu item is currently selected. */
    E_DECODE_SPORT,
    /* The "destination port" menu item is currently selected. */
    E_DECODE_DPORT,
    /* The "source/destination port" menu item is currently selected. */
    E_DECODE_BPORT
};

#define E_DECODE_MIN_HEIGHT 100
#define E_NOTEBOOK "notebook"

#define E_MENU_SRCDST "menu_src_dst"

#define E_PAGE_ACTION "notebook_page_action"
#define E_PAGE_LIST   "notebook_page_list"
#define E_PAGE_TABLE  "notebook_page_table_name"
#define E_PAGE_TITLE  "notebook_page_title"
#define E_PAGE_VALUE  "notebook_page_value"

/*
 * Columns for a "Select" list.
 * Note that most of these columns aren't displayed; they're attached
 * to the row of the table as additional information.
 */
#define E_LIST_S_PROTO_NAME 0
#define E_LIST_S_TABLE	    1
/* The following is for debugging in decode_add_to_list */
#define E_LIST_S_MAX	    E_LIST_S_TABLE
#define E_LIST_S_COLUMNS   (E_LIST_S_MAX + 1)

/*
 * Columns for a "Display" list
 */
#define E_LIST_D_TABLE	    0
#define E_LIST_D_PORT	    1
#define E_LIST_D_INITIAL    2
#define E_LIST_D_CURRENT    3
#define E_LIST_D_MAX	    E_LIST_D_CURRENT
#define E_LIST_D_COLUMNS   (E_LIST_D_MAX + 1)

/**************************************************/
/*             File Global Variables              */
/**************************************************/

/*
 * Keep a static pointer to the current "Decode As" window.  This is
 * kept so that if somebody tries to do "Tools:Decode As" while
 * there's already a "Decode As" window up, we just pop up the
 * existing one, rather than creating a new one.
 */
static GtkWidget *decode_w = NULL;

/*
 * A static pointer to the current "Decode As:Show" window.  This is
 * kept so that if somebody tries to do clock the "Show Current"
 * button or slect the "Display:User Specified Decodes" menu item
 * while there's already a "Decode As:Show" window up, we just pop up
 * the existing one, rather than creating a new one.
 */
static GtkWidget *decode_show_w = NULL;

/*
 * A list of the dialog items that only have meaning when the user has
 * selected the "Decode" radio button.  When the "Do not decode"
 * button is selected these items should be dimmed.
 */
static GSList *decode_dimmable = NULL;

/*
 * Remember the "action" radio button that is currently selected in
 * the dialog.  This value is initialized when the dialog is created,
 * modified in a callback routine, and read in the routine that
 * handles a click in the "OK" button for the dialog.
 */
static enum action_type	requested_action = -1;

/**************************************************/
/*            Resett Changed Dissectors           */
/**************************************************/

/*
 * Data structure for tracking which dissector need to be reset.  This
 * structure is necessary as a hash table entry cannot be removed
 * while a g_hash_table_foreach walk is in progress.
 */
struct dissector_delete_item {
    /* The name of the dissector table */
    const gchar *ddi_table_name;
    /* The port number in the dissector table */
    guint   ddi_port;
};

/*
 * A typedef for the data structure to track the original dissector
 * used for any given port on any given protocol.
 */
typedef struct dissector_delete_item dissector_delete_item_t;

/*
 * A list of dissectors that need to be reset.
 */
GSList *dissector_reset_list = NULL;

/*
 * This routine creates one entry in the list of protocol dissector
 * that need to be reset. It is called by the g_hash_table_foreach
 * routine once for each changed entry in a dissector table.
 * Unfortunately it cannot delete the entry immediately as this screws
 * up the foreach function, so it builds a list of dissectors to be
 * reset once the foreach routine finishes.
 *
 * @param table_name The table name in which this dissector is found.
 *
 * @param key A pointer to the key for this entry in the dissector
 * hash table.  This is generally the numeric selector of the
 * protocol, i.e. the ethernet type code, IP port number, TCP port
 * number, etc.
 *
 * @param value A pointer to the value for this entry in the dissector
 * hash table.  This is an opaque pointer that can only be handed back
 * to routine in the file packet.c - but it's unused.
 *
 * @param user_data Unused.
 */
static void
decode_build_reset_list (gchar *table_name, gpointer key,
			 gpointer value _U_, gpointer user_data _U_)
{
    dissector_delete_item_t *item;

    item = g_malloc(sizeof(dissector_delete_item_t));
    item->ddi_table_name = table_name;
    item->ddi_port = GPOINTER_TO_UINT(key);
    dissector_reset_list = g_slist_prepend(dissector_reset_list, item);
}


/**************************************************/
/*             Show Changed Dissectors            */
/**************************************************/

/*
 * This routine creates one entry in the list of protocol dissector
 * that have been changed.  It is called by the g_hash_foreach routine
 * once for each changed entry in a dissector table.
 *
 * @param table_name The table name in which this dissector is found.
 *
 * @param key A pointer to the key for this entry in the dissector
 * hash table.  This is generally the numeric selector of the
 * protocol, i.e. the ethernet type code, IP port number, TCP port
 * number, etc.
 *
 * @param value A pointer to the value for this entry in the dissector
 * hash table.  This is an opaque pointer that can only be handed back
 * to routine in the file packet.c
 *
 * @param user_data A pointer to the list in which this information
 * should be stored.
 */
static void
decode_build_show_list (gchar *table_name, gpointer key,
			gpointer value, gpointer user_data)
{
#if GTK_MAJOR_VERSION < 2
    GtkCList  *clist;
    gint       row;
#else
    GtkListStore *store;
    GtkTreeIter   iter;
#endif
    dissector_handle_t current, initial;
    gchar     *current_proto_name, *initial_proto_name, *text[E_LIST_D_COLUMNS];
    gchar      string1[20];

    g_assert(user_data);
    g_assert(value);

#if GTK_MAJOR_VERSION < 2
    clist = (GtkCList *)user_data;
#else
    store = (GtkListStore *)user_data;
#endif
    current = dtbl_entry_get_handle(value);
    if (current == NULL)
	current_proto_name = "(none)";
    else
	current_proto_name = dissector_handle_get_short_name(current);
    initial = dtbl_entry_get_initial_handle(value);
    if (initial == NULL)
	initial_proto_name = "(none)";
    else
	initial_proto_name = dissector_handle_get_short_name(initial);

    text[E_LIST_D_TABLE] = get_dissector_table_ui_name(table_name);
    switch (get_dissector_table_base(table_name)) {

    case BASE_DEC:
	sprintf(string1, "%u", GPOINTER_TO_UINT(key));
	break;

    case BASE_HEX:
	switch (get_dissector_table_type(table_name)) {

	case FT_UINT8:
	    sprintf(string1, "0x%02x", GPOINTER_TO_UINT(key));
	    break;

	case FT_UINT16:
	    sprintf(string1, "0x%04x", GPOINTER_TO_UINT(key));
	    break;

	case FT_UINT24:
	    sprintf(string1, "0x%06x", GPOINTER_TO_UINT(key));
	    break;

	case FT_UINT32:
	    sprintf(string1, "0x%08x", GPOINTER_TO_UINT(key));
	    break;

	default:
	    g_assert_not_reached();
	    break;
	}
	break;

    case BASE_OCT:
	sprintf(string1, "%#o", GPOINTER_TO_UINT(key));
	break;
    }
    text[E_LIST_D_PORT] = string1;
    text[E_LIST_D_INITIAL] = initial_proto_name;
    text[E_LIST_D_CURRENT] = current_proto_name;
#if GTK_MAJOR_VERSION < 2
    row = gtk_clist_prepend(clist, text);
#else
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, E_LIST_D_TABLE, text[E_LIST_D_TABLE],
                       E_LIST_D_PORT, text[E_LIST_D_PORT],
                       E_LIST_D_INITIAL, text[E_LIST_D_INITIAL],
                       E_LIST_D_CURRENT, text[E_LIST_D_CURRENT], -1);
#endif
}


/*
 * This routine is called when the user clicks the "OK" button in
 * the "Decode As:Show..." dialog window.  This routine destroys the
 * dialog box and performs other housekeeping functions.
 *
 * @param GtkWidget * A pointer to the "OK" button.
 *
 * @param gpointer A pointer to the dialog window.
 */
static void
decode_show_ok_cb (GtkWidget *ok_bt _U_, gpointer parent_w)
{
    gtk_widget_destroy(GTK_WIDGET(parent_w));
}


/*
 * This routine is called when the user clicks the "Reset" button in
 * the "Decode As:Show..." dialog window.  This routine resets all the
 * dissector values and then destroys the dialog box and performs
 * other housekeeping functions.
 *
 * @param GtkWidget * A pointer to the "Reset" button.
 *
 * @param gpointer A pointer to the dialog window.
 */
static void
decode_show_reset_cb (GtkWidget *reset_bt _U_, gpointer parent_w)
{
    dissector_delete_item_t *item;
    GSList *tmp;

    dissector_all_tables_foreach_changed(decode_build_reset_list, NULL);

    for (tmp = dissector_reset_list; tmp; tmp = g_slist_next(tmp)) {
	item = tmp->data;
	dissector_reset(item->ddi_table_name, item->ddi_port);
	g_free(item);
    }
    g_slist_free(dissector_reset_list);
    dissector_reset_list = NULL;

    redissect_packets(&cfile);

    gtk_widget_destroy(GTK_WIDGET(parent_w));
}


/*
 * This routine is called when the user clicks the "Close" button in
 * the "Decode As:Show..." dialog window.  This routine simply calls the
 * cancel routine as if the user had clicked the cancel button instead
 * of the close button.
 *
 * @param GtkWidget * A pointer to the dialog box.
 *
 * @param gpointer Unknown
 */
static gboolean
decode_show_delete_cb (GtkWidget *decode_w _U_, gpointer dummy _U_)
{
    decode_show_ok_cb(NULL, decode_show_w);
    return FALSE;
}


/*
 * This routine is called at the destruction of the "Decode As:Show"
 * dialog box.  It clears the pointer maintained by this file, so that
 * the next time the user clicks the "Decode As:Show" button a new
 * dialog box will be created.
 *
 * @param GtkWidget * A pointer to the dialog box.
 *
 * @param gpointer Unknown
 */
static void
decode_show_destroy_cb (GtkWidget *win _U_, gpointer user_data _U_)
{
    /* Note that we no longer have a "Decode As:Show" dialog box. */
    decode_show_w = NULL;
}


/*
 * This routine creates the "Decode As:Show" dialog box. This dialog box
 * shows the user which protocols have had their dissectors changed.
 *
 * @param w Unknown
 * @param data Unknown
 */
void
decode_show_cb (GtkWidget * w _U_, gpointer data _U_)
{
    GtkWidget         *main_vb, *bbox, *ok_bt, *button, *scrolled_window;
    gchar             *titles[E_LIST_D_COLUMNS] = {
        "Table", "Port", "Initial", "Current"
    };
    gint               column;
#if GTK_MAJOR_VERSION < 2
    GtkCList          *list;
#else
    GtkListStore      *store;
    GtkTreeView       *list;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *tc;
    GtkTreeIter        iter;
#endif

    if (decode_show_w != NULL) {
	/* There's already a "Decode As" dialog box; reactivate it. */
	reactivate_window(decode_show_w);
	return;
    }

    decode_show_w = dlg_window_new("Ethereal: Decode As: Show");
#if GTK_MAJOR_VERSION < 2
    gtk_signal_connect(GTK_OBJECT(decode_show_w), "delete_event",
		       GTK_SIGNAL_FUNC(decode_show_delete_cb), NULL);
    gtk_signal_connect(GTK_OBJECT(decode_show_w), "destroy",
		       GTK_SIGNAL_FUNC(decode_show_destroy_cb), NULL);
#else
    g_signal_connect(G_OBJECT(decode_show_w), "delete_event",
                     G_CALLBACK(decode_show_delete_cb), NULL);
    g_signal_connect(G_OBJECT(decode_show_w), "destroy",
                     G_CALLBACK(decode_show_destroy_cb), NULL);
#endif

    /* Container for each row of widgets */
    main_vb = gtk_vbox_new(FALSE, 2);
    gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(decode_show_w), main_vb);

    {
	/* Initialize list */
#if GTK_MAJOR_VERSION < 2
	list = GTK_CLIST(gtk_clist_new_with_titles(E_LIST_D_COLUMNS, titles));
	gtk_clist_column_titles_passive(list);
	for (column = 0; column < E_LIST_D_COLUMNS; column++)
	    gtk_clist_set_column_auto_resize(list, column, TRUE);
	gtk_clist_set_selection_mode(list, GTK_SELECTION_EXTENDED);
#else
        store = gtk_list_store_new(E_LIST_D_COLUMNS, G_TYPE_STRING,
                                   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
        list = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
        gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(list), TRUE);
        gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(list), FALSE);
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(list),
                                    GTK_SELECTION_MULTIPLE);

	for (column = 0; column < E_LIST_D_COLUMNS; column++) {
            renderer = gtk_cell_renderer_text_new();
            tc = gtk_tree_view_column_new_with_attributes(titles[column],
                                                          renderer, "text",
                                                          column, NULL);
	    gtk_tree_view_column_set_sizing(tc, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
            gtk_tree_view_append_column(list, tc);
        }
#endif

	/* Add data */
#if GTK_MAJOR_VERSION < 2
	dissector_all_tables_foreach_changed(decode_build_show_list, list);
	gtk_clist_sort(list);
#else
	dissector_all_tables_foreach_changed(decode_build_show_list, store);
	g_object_unref(G_OBJECT(store));
#endif

	/* Put clist into a scrolled window */
	scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
				       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolled_window),
                          GTK_WIDGET(list));
	gtk_box_pack_start(GTK_BOX(main_vb), scrolled_window, TRUE, TRUE, 0);
	/* Provide a minimum of a couple of rows worth of data */
#if GTK_MAJOR_VERSION < 2
	gtk_widget_set_usize(scrolled_window, -1, E_DECODE_MIN_HEIGHT);
#else
	gtk_widget_set_size_request(scrolled_window, -1, E_DECODE_MIN_HEIGHT);
#endif
    }

    /* Button row: OK and reset buttons */
    bbox = gtk_hbutton_box_new();
    gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);
    gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 10);

    button = gtk_button_new_with_label("Reset Changes");
#if GTK_MAJOR_VERSION < 2
    gtk_signal_connect(GTK_OBJECT(button), "clicked",
		       GTK_SIGNAL_FUNC(decode_show_reset_cb),
		       GTK_OBJECT(decode_show_w));
#else
    g_signal_connect(G_OBJECT(button), "clicked",
                     G_CALLBACK(decode_show_reset_cb), G_OBJECT(decode_show_w));
#endif
    GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
    gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);
#if GTK_MAJOR_VERSION < 2
    gtk_widget_set_sensitive(button, (list->rows != 0));

    ok_bt = gtk_button_new_with_label("OK");
    gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		       GTK_SIGNAL_FUNC(decode_show_ok_cb),
		       GTK_OBJECT(decode_show_w));
#else
    gtk_widget_set_sensitive(button,
                             gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter));

    ok_bt = gtk_button_new_from_stock(GTK_STOCK_OK);
    g_signal_connect(G_OBJECT(ok_bt), "clicked",
                     G_CALLBACK(decode_show_ok_cb), G_OBJECT(decode_show_w));
#endif
    GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
    gtk_box_pack_start(GTK_BOX(bbox), ok_bt, FALSE, FALSE, 0);
    gtk_widget_grab_default(ok_bt);
    dlg_set_cancel(decode_show_w, ok_bt);

    gtk_widget_show_all(decode_show_w);
}


/**************************************************/
/*         Modify the dissector routines          */
/**************************************************/

/*
 * Modify a single dissector.  This routine first takes care of
 * updating the internal table of original protocol/port/dissector
 * combinations by adding a new entry (or removing an existing entry
 * if the value is being set back to its default).  This routine then
 * performs the actual modification to the packet dissector tables.
 *
 * @param s Pointer to a string buffer.  This buffer is used to build
 * up a message indicating which ports have had their dissector
 * changed. This output will be displayed all at once after all
 * dissectors have been modified.
 *
 * @param table_name The table name in which the dissector should be
 * modified.
 *
 * @param selector An enum value indication which selector value
 * (i.e. IP protocol number, TCP port number, etc.)is to be changed.
 *
 * @param list The List in which all the selection information can
 * be found.
 *
 * @return gchar * Pointer to the next free location in the string
 * buffer.
 */
static void
decode_change_one_dissector(gchar *table_name, gint selector, GtkWidget *list)
{
    dissector_handle_t handle;
    gchar              *abbrev;
#if GTK_MAJOR_VERSION < 2
    gint               row;
#else
    GtkTreeSelection  *selection;
    GtkTreeModel      *model;
    GtkTreeIter        iter;
#endif

#if GTK_MAJOR_VERSION < 2
    if (!GTK_CLIST(list)->selection)
    {
	abbrev = "(NULL)";
	handle = NULL;
    } else {
	row = GPOINTER_TO_INT(GTK_CLIST(list)->selection->data);
	handle = gtk_clist_get_row_data(GTK_CLIST(list), row);
	gtk_clist_get_text(GTK_CLIST(list), row, E_LIST_S_PROTO_NAME, &abbrev);
    }
#else
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
    if (gtk_tree_selection_get_selected(selection, &model, &iter) == FALSE)
    {
	abbrev = "(NULL)";
	handle = NULL;
    } else {
        gtk_tree_model_get(model, &iter, E_LIST_S_PROTO_NAME, &abbrev,
                           E_LIST_S_TABLE+1, &handle, -1);
    }
#endif

    if (strcmp(abbrev, "(default)") == 0) {
	dissector_reset(table_name, selector);
    } else {
	dissector_change(table_name, selector, handle);
    }
#if GTK_MAJOR_VERSION >= 2
    g_free(abbrev);
#endif
}



/**************************************************/
/* Action routines for the "Decode As..." dialog  */
/*   - called when the OK button pressed          */
/*   - one per notebook page                      */
/**************************************************/


#ifdef DEBUG
/*
 * Print debugging information about clist selection.  Extract all
 * information from the clist entry that was selected and print it to
 * a dialog window.
 *
 * @param clist The clist to dump.
 *
 * @param leadin A string to print at the start of each line.
 */
static void
decode_debug (GtkCList *clist, gchar *leadin)
{
    gchar *string, *text[E_LIST_S_COLUMNS];
    dissector_handle_t handle;
    gint row;

    string = g_malloc(1024);
    if (clist->selection) {
	row = GPOINTER_TO_INT(clist->selection->data);
	gtk_clist_get_text(clist, row, E_LIST_S_PROTO_NAME, &text[E_LIST_S_PROTO_NAME]);
	gtk_clist_get_text(clist, row, E_LIST_S_TABLE, &text[E_LIST_S_TABLE]);
	handle = gtk_clist_get_row_data(clist, row);
	sprintf(string, "%s clist row %d: <put handle here>, name %s, table %s",
		leadin, row, text[E_LIST_S_PROTO_NAME],
		text[E_LIST_S_TABLE]);
    } else {
	sprintf(string, "%s clist row (none), aka do not decode", leadin);
    }
    simple_dialog(ESD_TYPE_INFO, NULL, string);
    g_free(string);
}
#endif


/*
 * This routine is called when the user clicks the "OK" button in the
 * "Decode As..." dialog window and a 'simple' page is foremost.
 * This routine takes care of making any changes requested to the
 * dissector tables.  This routine is currently used for IP and
 * Ethertypes.  Any 'single change' notebook page can use this
 * routine.
 *
 * @param notebook_pg A pointer to the "network" notebook page.
 */
static void
decode_simple (GtkWidget *notebook_pg)
{
    GtkWidget *list;
#ifdef DEBUG
    gchar *string;
#endif
    gchar *table_name;
    gint value;

#if GTK_MAJOR_VERSION < 2
    list = gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_LIST);
    if (requested_action == E_DECODE_NO)
	gtk_clist_unselect_all(GTK_CLIST(list));
#else
    list = g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_LIST);
    if (requested_action == E_DECODE_NO)
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(list)));
#endif

#ifdef DEBUG
    string = gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_TITLE);
    decode_debug(GTK_CLIST(list), string);
#endif

#if GTK_MAJOR_VERSION < 2
    table_name = gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_TABLE);
    value = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(notebook_pg),
						E_PAGE_VALUE));
#else
    table_name = g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_TABLE);
    value = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(notebook_pg),
                                              E_PAGE_VALUE));
#endif
    decode_change_one_dissector(table_name, value, list);
}


/*
 * This routine is called when the user clicks the "OK" button in the
 * "Decode As..." dialog window and the transport page is foremost.
 * This routine takes care of making any changes requested to the TCP
 * or UDP dissector tables.
 *
 * @param notebook_pg A pointer to the "transport" notebook page.
 */
#if GTK_MAJOR_VERSION < 2
static void
decode_transport(GtkObject *notebook_pg)
#else
static void
decode_transport(GObject *notebook_pg)
#endif
{
    GtkWidget *menu, *menuitem;
    GtkWidget *list;
    gchar *table_name;
    gint requested_srcdst;

#if GTK_MAJOR_VERSION < 2
    list = gtk_object_get_data(notebook_pg, E_PAGE_LIST);
    if (requested_action == E_DECODE_NO)
	gtk_clist_unselect_all(GTK_CLIST(list));

    menu = gtk_object_get_data(notebook_pg, E_MENU_SRCDST);
#else
    list = g_object_get_data(notebook_pg, E_PAGE_LIST);
    if (requested_action == E_DECODE_NO)
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(list)));

    menu = g_object_get_data(notebook_pg, E_MENU_SRCDST);
#endif

    menuitem = gtk_menu_get_active(GTK_MENU(menu));
    requested_srcdst = GPOINTER_TO_INT(gtk_object_get_user_data(GTK_OBJECT(menuitem)));

#ifdef DEBUG
    string = gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_TITLE);
    decode_debug(GTK_CLIST(list), string);
#endif

#if GTK_MAJOR_VERSION < 2
    table_name = gtk_object_get_data(notebook_pg, E_PAGE_TABLE);
#else
    table_name = g_object_get_data(notebook_pg, E_PAGE_TABLE);
#endif
    if (requested_srcdst != E_DECODE_DPORT)
	decode_change_one_dissector(table_name, cfile.edt->pi.srcport, list);
    if (requested_srcdst != E_DECODE_SPORT)
	decode_change_one_dissector(table_name, cfile.edt->pi.destport, list);
}

/**************************************************/
/*      Signals from the "Decode As..." dialog    */
/**************************************************/

/*
 * This routine is called when the user clicks the "OK" button in the
 * "Decode As..." dialog window.  This routine calls various helper
 * routines to set/clear dissector values as requested by the user.
 * These routines accumulate information on what actions they have
 * taken, and this summary information is printed by this routine.
 * This routine then destroys the dialog box and performs other
 * housekeeping functions.
 *
 * @param ok_bt A pointer to the "OK" button.
 *
 * @param parent_w A pointer to the dialog window.
 */
static void
decode_ok_cb (GtkWidget *ok_bt _U_, gpointer parent_w)
{
    GtkWidget *notebook, *notebook_pg;
    void (* func)(GtkWidget *);
    gint page_num;

    /* Call the right routine for the page that was currently in front. */
    notebook =  gtk_object_get_data(GTK_OBJECT(parent_w), E_NOTEBOOK);
    page_num = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));
    notebook_pg = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), page_num);

    func = gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_ACTION);
    func(notebook_pg);

    /* Now destroy the "Decode As" dialog. */
    gtk_widget_destroy(GTK_WIDGET(parent_w));
    g_slist_free(decode_dimmable);
    decode_dimmable = NULL;

    redissect_packets(&cfile);
}


/*
 * This routine is called when the user clicks the "Cancel" button in
 * the "Decode As..." dialog window.  This routine then destroys the
 * dialog box and performs other housekeeping functions.
 *
 * @param cancel_bt A pointer to the "Cancel" button.
 *
 * @param parent_w A pointer to the dialog window.
 */
static void
decode_cancel_cb (GtkWidget *cancel_bt _U_, gpointer parent_w)
{
    gtk_widget_destroy(GTK_WIDGET(parent_w));
    g_slist_free(decode_dimmable);
    decode_dimmable = NULL;
}


/*
 * This routine is called when the user clicks the "Close" button in
 * the "Decode As..." dialog window.  This routine simply calls the
 * cancel routine as if the user had clicked the cancel button instead
 * of the close button.
 *
 * @param decode_w A pointer to the dialog box.
 *
 * @param dummy Unknown
 */
static gboolean
decode_delete_cb (GtkWidget *decode_w, gpointer dummy _U_)
{
    decode_cancel_cb(NULL, decode_w);
    return FALSE;
}


/*
 * This routine is called at the destruction of the "Decode As..."
 * dialog box.  It clears the pointer maintained by this file, so that
 * the next time the user selects the "Decode As..." menu item a new
 * dialog box will be created.
 *
 * @param decode_w A pointer to the dialog box.
 *
 * @param user_data Unknown
 *
 * @return void
 */
static void
decode_destroy_cb (GtkWidget *win _U_, gpointer user_data _U_)
{
    /* Note that we no longer have a "Decode As" dialog box. */
    decode_w = NULL;
}


/**************************************************/
/*          Dialog setup - radio buttons          */
/**************************************************/

/*
 * Update the requested action field of the dialog.  This routine is
 * called by GTK when either of the two radio buttons in the dialog is
 * clicked.
 *
 * @param w The radio button that was clicked.
 *
 * @param data The enum value assigned to this radio button.  This
 * will be either E_DECODE_YES or E_DECODE_NO
 */
static void
decode_update_action (GtkWidget *w _U_, gpointer data)
{
    GSList *tmp;
    gboolean enable;

    requested_action = GPOINTER_TO_INT(data);
    enable = (requested_action == E_DECODE_YES);
    for (tmp = decode_dimmable; tmp; tmp = g_slist_next(tmp)) {
	gtk_widget_set_sensitive(tmp->data, enable);
    }
}

/*
 * This routine is called to create the "Decode" and "Do not decode"
 * radio buttons.  These buttons are installed into a vbox, and set up
 * as a format group.
 *
 * @return GtkWidget * A pointer to the vbox containing the buttons
 */
static GtkWidget *
decode_add_yes_no (void)
{
    GtkWidget	*format_vb, *radio_button;
    GSList	*format_grp;

    format_vb = gtk_vbox_new(FALSE, 2);

    radio_button = gtk_radio_button_new_with_label(NULL, "Decode");
    format_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(radio_button));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_button), TRUE);
#if GTK_MAJOR_VERSION < 2
    gtk_signal_connect(GTK_OBJECT(radio_button), "clicked",
		       GTK_SIGNAL_FUNC(decode_update_action),
		       GINT_TO_POINTER(E_DECODE_YES));
#else
    g_signal_connect(G_OBJECT(radio_button), "clicked",
                     G_CALLBACK(decode_update_action),
                     GINT_TO_POINTER(E_DECODE_YES));
#endif
    gtk_box_pack_start(GTK_BOX(format_vb), radio_button, TRUE, TRUE, 0);

    radio_button = gtk_radio_button_new_with_label(format_grp, "Do not decode");
    format_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(radio_button));
#if GTK_MAJOR_VERSION < 2
    gtk_signal_connect(GTK_OBJECT(radio_button), "clicked",
		       GTK_SIGNAL_FUNC(decode_update_action),
		       GINT_TO_POINTER(E_DECODE_NO));
#else
    g_signal_connect(G_OBJECT(radio_button), "clicked",
                     G_CALLBACK(decode_update_action),
                     GINT_TO_POINTER(E_DECODE_NO));
#endif
    gtk_box_pack_start(GTK_BOX(format_vb), radio_button, TRUE, TRUE, 0);

    return(format_vb);
}

/**************************************************/
/*          Dialog setup - simple menus           */
/**************************************************/

/*
 * This routine is called to pack an option menu into an aligment, so
 * that it doesn't expand vertically to fill up the space available to
 * it.
 *
 * @param optmenu A pointer to the option menu to be so packed.
 *
 * @return GtkWidget * A pointer to the newly created alignment.
 */
static GtkWidget *
decode_add_pack_menu (GtkWidget *optmenu)
{
    GtkWidget *alignment;

    alignment = gtk_alignment_new(0.0, 0.5, 0.0, 0.0);
    gtk_container_add(GTK_CONTAINER(alignment), optmenu);

    return(alignment);
}


/*
 * This routine is called to add the transport port selection menu to
 * the dialog box.  This is a three choice menu: source, destination
 * and both.  The default choice for the menu is set to the source
 * port number of the currently selected packet.
 *
 * @param page A pointer notebook page that will contain all
 * widgets created by this routine.
 *
 * @return GtkWidget * A pointer to the newly created alignment into
 * which we've packed the newly created option menu.
 */
static GtkWidget *
decode_add_srcdst_menu (GtkWidget *page)
{
    GtkWidget *optmenu, *menu, *menuitem, *alignment;
    gchar      tmp[100];

    optmenu = gtk_option_menu_new();
    menu = gtk_menu_new();
    sprintf(tmp, "source (%u)", cfile.edt->pi.srcport);
    menuitem = gtk_menu_item_new_with_label(tmp);
    gtk_object_set_user_data(GTK_OBJECT(menuitem),
			     GINT_TO_POINTER(E_DECODE_SPORT));
    gtk_menu_append(GTK_MENU(menu), menuitem);
    gtk_widget_show(menuitem);	/* gtk_widget_show_all() doesn't show this */

    sprintf(tmp, "destination (%u)", cfile.edt->pi.destport);
    menuitem = gtk_menu_item_new_with_label(tmp);
    gtk_object_set_user_data(GTK_OBJECT(menuitem),
			     GINT_TO_POINTER(E_DECODE_DPORT));
    gtk_menu_append(GTK_MENU(menu), menuitem);
    gtk_widget_show(menuitem);	/* gtk_widget_show_all() doesn't show this */

    menuitem = gtk_menu_item_new_with_label("both");
    gtk_object_set_user_data(GTK_OBJECT(menuitem),
			     GINT_TO_POINTER(E_DECODE_BPORT));
    gtk_menu_append(GTK_MENU(menu), menuitem);
    gtk_widget_show(menuitem);	/* gtk_widget_show_all() doesn't show this */

    gtk_object_set_data(GTK_OBJECT(page), E_MENU_SRCDST, menu);
    gtk_option_menu_set_menu(GTK_OPTION_MENU(optmenu), menu);

    alignment = decode_add_pack_menu(optmenu);

    return(alignment);
}

/*************************************************/
/*        Dialog setup - list based menus        */
/*************************************************/

#if GTK_MAJOR_VERSION >= 2
struct handle_lookup_info {
    dissector_handle_t handle;
    gboolean           found;
};

static gboolean
lookup_handle(GtkTreeModel *model, GtkTreePath *path _U_, GtkTreeIter *iter,
              gpointer data)
{
    dissector_handle_t handle;
    struct handle_lookup_info *hli = (struct handle_lookup_info *)data;

    gtk_tree_model_get(model, iter, E_LIST_S_TABLE+1, &handle, -1);
    if (hli->handle == handle) {
        hli->found = TRUE;
        return TRUE;
    }
    return FALSE;
}
#endif

/*
 * This routine creates one entry in the list of protocol dissector
 * that can be used.  It is called by the dissector_table_foreach_handle
 * routine once for each entry in a dissector table's list of handles
 * for dissectors that could be used in that table.  It guarantees unique
 * entries by iterating over the list of entries build up to this point,
 * looking for a duplicate name.  If there is no duplicate, then this
 * entry is added to the list of possible dissectors.
 *
 * @param table_name The name of the dissector table currently
 * being walked.
 *
 * @param value The dissector handle for this entry.  This is an opaque
 * pointer that can only be handed back to routines in the file packet.c
 *
 * @param user_data A data block passed into each instance of this
 * routine.  It contains information from the caller of the foreach
 * routine, specifying information about the dissector table and where
 * to store any information generated by this routine.
 */
static void
decode_add_to_list (gchar *table_name, gpointer value, gpointer user_data)
{
    gchar     *proto_name;
    gchar     *text[E_LIST_S_COLUMNS];
    dissector_handle_t handle;
#if GTK_MAJOR_VERSION < 2
    GtkCList  *list;
    gint       row;
#else
    GtkTreeView  *list;
    GtkListStore *store;
    GtkTreeIter   iter;
    struct handle_lookup_info hli;
#endif

    g_assert(user_data);
    g_assert(value);

    list = user_data;
    handle = value;
    proto_name = dissector_handle_get_short_name(handle);

#if GTK_MAJOR_VERSION < 2
    row = gtk_clist_find_row_from_data(list, handle);
    /* We already have an entry for this handle.
     * XXX - will this ever happen? */
    if (row != -1) return;
#else
    hli.handle = handle;
    hli.found = FALSE;
    store = GTK_LIST_STORE(gtk_tree_view_get_model(list));
    gtk_tree_model_foreach(GTK_TREE_MODEL(store), lookup_handle, &hli);
    /* We already have an entry for this handle.
     * XXX - will this ever happen? */
    if (hli.found) return;
#endif

    text[E_LIST_S_PROTO_NAME] = proto_name;
    text[E_LIST_S_TABLE] = table_name;
#if GTK_MAJOR_VERSION < 2
    row = gtk_clist_prepend(list, text);
    gtk_clist_set_row_data(list, row, handle);
#else
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter,
                       E_LIST_S_PROTO_NAME, text[E_LIST_S_PROTO_NAME],
                       E_LIST_S_TABLE, text[E_LIST_S_TABLE],
                       E_LIST_S_TABLE+1, handle, -1);
#endif
}


/*
 * This routine starts the creation of a List on a notebook page.  It
 * creates both a scrolled window and a list, adds the list to the
 * window, and attaches the list as a data object on the page.
 *
 * @param page A pointer to the notebook page being created.
 *
 * @param list_p Will be filled in with the address of a newly
 * created List.
 *
 * @param scrolled_win_p Will be filled in with the address of a newly
 * created GtkScrolledWindow.
 */
static void
decode_list_menu_start(GtkWidget *page, GtkWidget **list_p,
                       GtkWidget **scrolled_win_p)
{
    GtkWidget *window;
#if GTK_MAJOR_VERSION < 2
    gchar             *titles[E_LIST_S_COLUMNS] = {"Short Name", "Table Name"};
    GtkCList          *list;
    gint               column;
#else
    GtkTreeView       *list;
    GtkListStore      *store;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *tc;
#endif

#if GTK_MAJOR_VERSION < 2
    list = GTK_CLIST(gtk_clist_new_with_titles(E_LIST_S_COLUMNS, titles));
    gtk_clist_column_titles_passive(list);
#ifndef DEBUG
    gtk_clist_column_titles_hide(list);
    for (column = 1; column < E_LIST_S_COLUMNS; column++)
	gtk_clist_set_column_visibility (list, column, FALSE);
#endif
    for (column = 0; column < E_LIST_S_COLUMNS; column++)
	gtk_clist_set_column_auto_resize(list, column, TRUE);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_LIST, list);
#else
    store = gtk_list_store_new(E_LIST_S_COLUMNS+1, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_POINTER);
    list = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
    gtk_tree_view_set_headers_clickable(list, FALSE);
#ifndef DEBUG
    gtk_tree_view_set_headers_visible(list, FALSE);
#endif
    renderer = gtk_cell_renderer_text_new();
    tc = gtk_tree_view_column_new_with_attributes("Short Name", renderer,
                                                  "text", E_LIST_S_PROTO_NAME,
                                                  NULL);
    gtk_tree_view_column_set_sizing(tc, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(list, tc);
    g_object_set_data(G_OBJECT(page), E_PAGE_LIST, list);
#endif

    *scrolled_win_p = window = gtk_scrolled_window_new(NULL, NULL);
    /* Provide a minimum of a couple of rows worth of data */
#if GTK_MAJOR_VERSION < 2
    gtk_widget_set_usize(window, -1, E_DECODE_MIN_HEIGHT);
#else
    gtk_widget_set_size_request(window, -1, E_DECODE_MIN_HEIGHT);
#endif
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(window),
				   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
#if GTK_MAJOR_VERSION < 2
    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(window),
					  GTK_WIDGET(list));
#else
    gtk_container_add(GTK_CONTAINER(window), GTK_WIDGET(list));
#endif

    *list_p = GTK_WIDGET(list);
}

/*
 * This routine finishes the creation of a List on a notebook page.
 * It adds the default entry, sets the default entry as the
 * highlighted entry, and sorts the List.
 *
 * @param list A pointer the the List to finish.
 */
static void
decode_list_menu_finish(GtkWidget *list)
{
    gchar *text[E_LIST_S_COLUMNS];
#if GTK_MAJOR_VERSION < 2
    gint row;
#else
    GtkListStore *store;
    GtkTreeIter   iter;
#endif

    text[E_LIST_S_PROTO_NAME] = "(default)";
    text[E_LIST_S_TABLE] = "(none)";
#if GTK_MAJOR_VERSION < 2
    row = gtk_clist_prepend(GTK_CLIST(list), text);
    gtk_clist_set_row_data(GTK_CLIST(list), row, NULL);

    gtk_clist_select_row(GTK_CLIST(list), 0, -1);
    gtk_clist_sort(GTK_CLIST(list));
#else
    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
    gtk_list_store_prepend(store, &iter);
    gtk_list_store_set(store, &iter,
                       E_LIST_S_PROTO_NAME, text[E_LIST_S_PROTO_NAME],
                       E_LIST_S_TABLE, text[E_LIST_S_TABLE],
                       E_LIST_S_TABLE+1, NULL, -1);

    gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(list)), &iter);
#endif
}

/*
 * This routine is called to add the dissector selection list to a
 * notebook page.  This scrolled list contains an entry labeled
 * "default", and an entry for each protocol that has had a dissector
 * registered.  The default choice for the list is set to the
 * "default" choice, which will return the protocol/port selections to
 * their original dissector(s).
 *
 * @param page A pointer to the notebook page currently being created.
 *
 * @param table_name The name of the dissector table to use to build
 * this (list) menu.
 *
 * @return GtkWidget * A pointer to the newly created list within a
 * scrolled window.
 */
static GtkWidget *
decode_add_simple_menu (GtkWidget *page, gchar *table_name)
{
    GtkWidget *scrolled_window;
    GtkWidget *list;

    decode_list_menu_start(page, &list, &scrolled_window);
    dissector_table_foreach_handle(table_name, decode_add_to_list, list);
    decode_list_menu_finish(list);
    return(scrolled_window);
}

/**************************************************/
/*                  Dialog setup                  */
/**************************************************/

/*
 * This routine creates a sample notebook page in the dialog box.
 * This notebook page provides a prompt specifying what is being
 * changed and its current value (e.g. "IP Protocol number (17)"), and
 * a list specifying all the available choices.  The list of choices
 * is conditionally enabled, based upon the setting of the
 * "decode"/"do not decode" radio buttons.
 *
 * @param prompt The prompt for this notebook page
 *
 * @param title A title for this page to use when debugging.
 *
 * @param table_name The name of the dissector table to use to
 * build this page.
 *
 * @param value The protocol/port value that is to be changed.
 *
 * @return GtkWidget * A pointer to the notebook page created by this
 * routine.
 */
static GtkWidget *
decode_add_simple_page (gchar *prompt, gchar *title, gchar *table_name,
			gint value)
{
    GtkWidget	*page, *label, *scrolled_window;

    page = gtk_hbox_new(FALSE, 5);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_ACTION, decode_simple);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_TABLE, table_name);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_TITLE, title);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_VALUE, GINT_TO_POINTER(value));

    /* Always enabled */
    label = gtk_label_new(prompt);
    gtk_box_pack_start(GTK_BOX(page), label, TRUE, TRUE, 0);

    /* Conditionally enabled - only when decoding packets */
    label = gtk_label_new("as");
    gtk_box_pack_start(GTK_BOX(page), label, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, label);
    scrolled_window = decode_add_simple_menu(page, table_name);
    gtk_box_pack_start(GTK_BOX(page), scrolled_window, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, scrolled_window);

    return(page);
}


/*
 * This routine creates the TCP or UDP notebook page in the dialog box.
 * All items created by this routine are packed into a single
 * horizontal box.  First is a label indicating whether the port(s) for
 * which the user can set the dissection is a TCP port or a UDP port.
 * Second is a menu allowing the user to select whether the source port,
 * destination port, or both ports will have dissectors added for them.
 * Last is a (conditionally enabled) popup menu listing all possible
 * dissectors that can be used to decode the packets, and the choice
 * or returning to the default dissector for these ports.
 *
 * The defaults for these items are the transport layer protocol of
 * the currently selected packet, the source port of the currently
 * selected packet, and the "default dissector".
 *
 * @param prompt The prompt for this notebook page
 *
 * @param table_name The name of the dissector table to use to
 * build this page.
 *
 * @return GtkWidget * A pointer to the notebook page created by
 * this routine.
 */
static GtkWidget *
decode_add_tcpudp_page (gchar *prompt, gchar *table_name)
{
    GtkWidget	*page, *label, *scrolled_window, *optmenu;

    page = gtk_hbox_new(FALSE, 5);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_ACTION, decode_transport);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_TABLE, table_name);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_TITLE, "Transport");

    /* Always enabled */
    label = gtk_label_new(prompt);
    gtk_box_pack_start(GTK_BOX(page), label, TRUE, TRUE, 0);
    optmenu = decode_add_srcdst_menu(page);
    gtk_box_pack_start(GTK_BOX(page), optmenu, TRUE, TRUE, 0);
    label = gtk_label_new("port(s)");
    gtk_box_pack_start(GTK_BOX(page), label, TRUE, TRUE, 0);

    /* Conditionally enabled - only when decoding packets */
    label = gtk_label_new("as");
    gtk_box_pack_start(GTK_BOX(page), label, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, label);
    scrolled_window = decode_add_simple_menu(page, table_name);
    gtk_box_pack_start(GTK_BOX(page), scrolled_window, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, scrolled_window);

    return(page);
}

/*
 * This routine indicates whether we'd actually have any pages in the
 * notebook in a "Decode As" dialog box; if there wouldn't be, we
 * inactivate the menu item for "Decode As".
 */
gboolean
decode_as_ok(void)
{
    return cfile.edt->pi.ethertype || cfile.edt->pi.ipproto ||
	cfile.edt->pi.ptype == PT_TCP || cfile.edt->pi.ptype == PT_UDP;
}


/*
 * This routine creates the bulk of the "Decode As" dialog box.  All
 * items created by this routine are packed as pages into a notebook.
 * There will be a page for each protocol layer that can be change.
 *
 * @param GtkWidget * A pointer to the widget in which the notebook
 * should be installed.
 */
static void
decode_add_notebook (GtkWidget *format_hb)
{
    GtkWidget *notebook, *page, *label;
    gchar buffer[40];

    /* Start a nootbook for flipping between sets of changes */
    notebook = gtk_notebook_new();
    gtk_container_add(GTK_CONTAINER(format_hb), notebook);
    gtk_object_set_data(GTK_OBJECT(decode_w), E_NOTEBOOK, notebook);

    /* Add link level selection page */
    if (cfile.edt->pi.ethertype) {
	sprintf(buffer, "Ethertype 0x%04x", cfile.edt->pi.ethertype);
	page = decode_add_simple_page(buffer, "Link", "ethertype", cfile.edt->pi.ethertype);
	label = gtk_label_new("Link");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page, label);
    }

    /* Add network selection page */
    if (cfile.edt->pi.ipproto) {
	/*
	 * The network-layer protocol is IP.
	 */
	sprintf(buffer, "IP protocol %u", cfile.edt->pi.ipproto);
	page = decode_add_simple_page(buffer, "Network", "ip.proto", cfile.edt->pi.ipproto);
	gtk_object_set_data(GTK_OBJECT(page), E_PAGE_ACTION, decode_simple);
	label = gtk_label_new("Network");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page, label);
    }

    /* Add transport selection page */
    switch (cfile.edt->pi.ptype) {

    case PT_TCP:
	page = decode_add_tcpudp_page("TCP", "tcp.port");
	break;

    case PT_UDP:
	page = decode_add_tcpudp_page("UDP", "udp.port");
	break;

    default:
	page = NULL;
	break;
    }
    if (page != NULL) {
	label = gtk_label_new("Transport");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page, label);
    }

    /* Select the last added page (selects first by default) */
    /* Notebook must be visible for set_page to work. */
    gtk_widget_show_all(notebook);
    gtk_notebook_set_page(GTK_NOTEBOOK(notebook), -1);
}


/*
 * This routine creates the "Decode As" dialog box. This dialog box
 * asks the user which protocol to use for decoding the currently
 * selected packet.  This will affect the last packet that we called a
 * dissection routine on belongs (this might be the most recently
 * selected packet, or it might be the last packet in the file).
 *
 * This routine uses an auxiliary function to create the bulk of the
 * dialog box, and then hand crafts the button box at the bottom of
 * the dialog.
 *
 * @param w Unknown
 * @param data Unknown
 */
void
decode_as_cb (GtkWidget * w _U_, gpointer data _U_)
{
    GtkWidget	*main_vb, *format_hb, *bbox, *ok_bt, *cancel_bt, *button;
    GtkWidget   *button_vb;

    if (decode_w != NULL) {
	/* There's already a "Decode As" dialog box; reactivate it. */
	reactivate_window(decode_w);
	return;
    }

    requested_action = E_DECODE_YES;
    decode_w = dlg_window_new("Ethereal: Decode As");
#if GTK_MAJOR_VERSION < 2
    gtk_signal_connect(GTK_OBJECT(decode_w), "delete_event",
		       GTK_SIGNAL_FUNC(decode_delete_cb), NULL);
    gtk_signal_connect(GTK_OBJECT(decode_w), "destroy",
		       GTK_SIGNAL_FUNC(decode_destroy_cb), NULL);
#else
    g_signal_connect(G_OBJECT(decode_w), "delete_event",
                     G_CALLBACK(decode_delete_cb), NULL);
    g_signal_connect(G_OBJECT(decode_w), "destroy",
                     G_CALLBACK(decode_destroy_cb), NULL);
#endif

    /* Container for each row of widgets */
    main_vb = gtk_vbox_new(FALSE, 2);
    gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(decode_w), main_vb);

    /* First row - Buttons and Notebook */
    {
	format_hb = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(main_vb), format_hb, TRUE, TRUE, 10);

	button_vb = decode_add_yes_no();
	gtk_box_pack_start(GTK_BOX(format_hb), button_vb, TRUE, TRUE, 10);

	decode_add_notebook(format_hb);
    }

    /* Button row: OK and cancel buttons */
    bbox = gtk_hbutton_box_new();
    gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);
    gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 10);

#if GTK_MAJOR_VERSION < 2
    ok_bt = gtk_button_new_with_label("OK");
    gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		       GTK_SIGNAL_FUNC(decode_ok_cb), GTK_OBJECT(decode_w));
#else
    ok_bt = gtk_button_new_from_stock(GTK_STOCK_OK);
    g_signal_connect(G_OBJECT(ok_bt), "clicked",
                     G_CALLBACK(decode_ok_cb), G_OBJECT(decode_w));
#endif
    GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
    gtk_box_pack_start(GTK_BOX(bbox), ok_bt, FALSE, FALSE, 0);
    gtk_widget_grab_default(ok_bt);

    button = gtk_button_new_with_label("Show Current");
#if GTK_MAJOR_VERSION < 2
    gtk_signal_connect(GTK_OBJECT(button), "clicked",
		       GTK_SIGNAL_FUNC(decode_show_cb),
		       GTK_OBJECT(decode_w));
#else
    g_signal_connect(G_OBJECT(button), "clicked",
		     G_CALLBACK(decode_show_cb), G_OBJECT(decode_w));
#endif
    GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
    gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);

#if GTK_MAJOR_VERSION < 2
    cancel_bt = gtk_button_new_with_label("Cancel");
    gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
		       GTK_SIGNAL_FUNC(decode_cancel_cb), GTK_OBJECT(decode_w));
#else
    cancel_bt = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
    g_signal_connect(G_OBJECT(cancel_bt), "clicked",
                     G_CALLBACK(decode_cancel_cb), G_OBJECT(decode_w));
#endif
    GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
    gtk_box_pack_start(GTK_BOX(bbox), cancel_bt, FALSE, FALSE, 0);

    /*
     * Catch the "key_press_event" signal in the window, so that
     * we can catch the ESC key being pressed and act as if the
     * "Cancel" button had been selected.
     */
    dlg_set_cancel(decode_w, cancel_bt);

    gtk_widget_show_all(decode_w);
}


/*
 * Local Variables:
 * mode:c
 * c-basic-offset: 4
 * End:
 */
