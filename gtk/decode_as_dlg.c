/* decode_as_dlg.c
 *
 * $Id: decode_as_dlg.c,v 1.13 2001/11/21 23:16:25 gram Exp $
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "decode_as_dlg.h"
#include "dlg_utils.h"
#include "globals.h"
#include "simple_dialog.h"
#include "packet.h"
#include "ipproto.h"
#include "ui_util.h"

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
 * Enum used to track which transport layer protocol menu item is
 * currently selected in the dialog.  These items are labeled "TCP",
 * "UDP", and "TCP/UDP".
 */
enum tcpudp_type {
    /* The "TCP" menu item is currently selected. */
    E_DECODE_TCP,

    /* The "TCP" menu item is currently selected. */
    E_DECODE_UDP,

    /* The "TCP/UDP" menu item is currently selected. */
    E_DECODE_TCPUDP
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

#define E_MENU_TCPUDP "menu_tcp_udp"
#define E_MENU_SRCDST "menu_src_dst"

#define E_PAGE_ACTION "notebook_page_action"
#define E_PAGE_CLIST  "notebook_page_clist"
#define E_PAGE_TABLE  "notebook_page_table_name"
#define E_PAGE_TITLE  "notebook_page_title"
#define E_PAGE_VALUE  "notebook_page_value"

/*
 * Clist columns for a "Select" clist
 */
#define E_CLIST_S_PROTO_NAME 0
#define E_CLIST_S_TABLE	     1
/* The following is for debugging in decode_add_to_clist */
#define E_CLIST_S_ISCONV     2
#define E_CLIST_S_MAX	     E_CLIST_S_ISCONV
#define E_CLIST_S_COLUMNS   (E_CLIST_S_MAX + 1)

/*
 * Clist columns for a "Display" clist
 */
#define E_CLIST_D_TABLE	     0
#define E_CLIST_D_PORT	     1
#define E_CLIST_D_INITIAL    2
#define E_CLIST_D_CURRENT    3
#define E_CLIST_D_MAX	     E_CLIST_D_CURRENT
#define E_CLIST_D_COLUMNS   (E_CLIST_D_MAX + 1)

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
 * A list of additional IP port numbers that are currently being
 * decodes as either TCP or UDP.  This is used to determine whether or
 * not to include a "transport" page in the dialog notebook.  This
 * list never includes values for the standard TCP or UDP protocol
 * numbers.
 */
static GSList *decode_as_tcpudp = NULL;

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
    gint   ddi_port;
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
 * to routine in the file packet.c
 *
 * @param user_data Unused.
 */
static void
decode_build_reset_list (gchar *table_name, gpointer key,
			 gpointer value, gpointer user_data)
{
    dissector_delete_item_t *item;

    item = g_malloc(sizeof(dissector_delete_item_t));
    item->ddi_table_name = table_name;
    item->ddi_port = GPOINTER_TO_INT(key);
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
 * @param user_data A pointer to the clist in which this information
 * should be stored.
 */
static void
decode_build_show_list (gchar *table_name, gpointer key,
			gpointer value, gpointer user_data)
{
    GtkCList  *clist;
    gchar     *current_proto_name, *initial_proto_name, *text[E_CLIST_D_COLUMNS];
    gchar      string1[20];
    gint       current_proto, initial_proto, row;

    g_assert(user_data);
    g_assert(value);

    clist = (GtkCList *)user_data;
    current_proto = dissector_get_proto(value);
    current_proto_name = proto_get_protocol_short_name(current_proto);
    initial_proto = dissector_get_initial_proto(value);
    initial_proto_name = proto_get_protocol_short_name(initial_proto);

    text[E_CLIST_D_TABLE] = table_name;
    sprintf(string1, "%d", GPOINTER_TO_INT(key));
    text[E_CLIST_D_PORT] = string1;
    text[E_CLIST_D_INITIAL] = initial_proto_name;
    text[E_CLIST_D_CURRENT] = current_proto_name;
    row = gtk_clist_prepend(clist, text);
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
decode_show_ok_cb (GtkWidget *ok_bt, gpointer parent_w)
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
decode_show_reset_cb (GtkWidget *reset_bt, gpointer parent_w)
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
decode_show_delete_cb (GtkWidget *decode_w, gpointer dummy)
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
decode_show_destroy_cb (GtkWidget *win, gpointer user_data)
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
decode_show_cb (GtkWidget * w, gpointer data)
{
    GtkWidget *main_vb, *bbox, *ok_bt, *button, *scrolled_window;
    GtkCList  *clist;
    gchar     *titles[E_CLIST_D_COLUMNS] = {"Table", "Port", "Initial", "Current"};
    gint       column;

    if (decode_show_w != NULL) {
	/* There's already a "Decode As" dialog box; reactivate it. */
	reactivate_window(decode_show_w);
	return;
    }

    decode_show_w = dlg_window_new("Ethereal: Decode As: Show");
    gtk_signal_connect(GTK_OBJECT(decode_show_w), "delete_event",
		       GTK_SIGNAL_FUNC(decode_show_delete_cb), NULL);
    gtk_signal_connect(GTK_OBJECT(decode_show_w), "destroy",
		       GTK_SIGNAL_FUNC(decode_show_destroy_cb), NULL);
  
    /* Container for each row of widgets */
    main_vb = gtk_vbox_new(FALSE, 2);
    gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(decode_show_w), main_vb);

    {
	/* Initialize clist */
	clist = GTK_CLIST(gtk_clist_new_with_titles(E_CLIST_D_COLUMNS, titles));
	gtk_clist_column_titles_passive(clist);
	for (column = 0; column < E_CLIST_D_COLUMNS; column++)
	    gtk_clist_set_column_auto_resize(clist, column, TRUE);
	gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);

	/* Add data */
	dissector_all_tables_foreach_changed(decode_build_show_list, clist);
	gtk_clist_sort(clist);

	/* Put clist into a scrolled window */
	scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
				       GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
	gtk_container_add(GTK_CONTAINER(scrolled_window),
					      GTK_WIDGET(clist));
	gtk_box_pack_start(GTK_BOX(main_vb), scrolled_window, TRUE, TRUE, 0);
	/* Provide a minimum of a couple of rows worth of data */
	gtk_widget_set_usize(scrolled_window, 0, E_DECODE_MIN_HEIGHT);
    }

    /* Button row: OK and reset buttons */
    bbox = gtk_hbutton_box_new();
    gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);
    gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 10);

    button = gtk_button_new_with_label("Reset Changes");
    gtk_signal_connect(GTK_OBJECT(button), "clicked",
		       GTK_SIGNAL_FUNC(decode_show_reset_cb),
		       GTK_OBJECT(decode_show_w));
    GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
    gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);
    gtk_widget_set_sensitive(button, (clist->rows != 0));

    ok_bt = gtk_button_new_with_label("OK");
    gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		       GTK_SIGNAL_FUNC(decode_show_ok_cb),
		       GTK_OBJECT(decode_show_w));
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
 * @param clist The CList in which all the selection information can
 * be found.
 *
 * @return gchar * Pointer to the next free location in the string
 * buffer.
 */
static void
decode_change_one_dissector (gchar *table_name, gint selector, GtkCList *clist)
{
    dissector_t  dissector;
    gchar       *abbrev;
    gint         row, proto_num;

    if (!clist->selection) {
	proto_num = -1;
	abbrev = "(NULL)";
	dissector = NULL;
    } else {
	row = GPOINTER_TO_INT(clist->selection->data);
	proto_num = GPOINTER_TO_INT(gtk_clist_get_row_data(clist, row));
	gtk_clist_get_text(clist, row, E_CLIST_S_PROTO_NAME, &abbrev);
	dissector = proto_get_protocol_dissector(proto_num);
	if ((proto_num != -1) && (dissector == NULL)) {
	    simple_dialog(ESD_TYPE_CRIT, NULL,
			  "Protocol dissector structure disappeared");
	    return;
	}
    }

    if (strcmp(abbrev, "(default)") == 0) {
	dissector_reset(table_name, selector);
    } else {
	dissector_change(table_name, selector, dissector, proto_num);
    }
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
    gchar *string, *text[E_CLIST_S_COLUMNS];
    gint row, proto_num;

    string = g_malloc(1024);
    if (clist->selection) {
	row = GPOINTER_TO_INT(clist->selection->data);
	gtk_clist_get_text(clist, row, E_CLIST_S_PROTO_NAME, &text[E_CLIST_S_PROTO_NAME]);
	gtk_clist_get_text(clist, row, E_CLIST_S_TABLE, &text[E_CLIST_S_TABLE]);
	proto_num = GPOINTER_TO_INT(gtk_clist_get_row_data(clist, row));
	sprintf(string, "%s clist row %d: proto %d, name %s, table %s",
		leadin, row, proto_num, text[E_CLIST_S_PROTO_NAME],
		text[E_CLIST_S_TABLE]);
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
    GtkCList *clist;
    gchar *table_name;
    gint value;

    clist = GTK_CLIST(gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_CLIST));
    if (requested_action == E_DECODE_NO)
	gtk_clist_unselect_all(clist);

#ifdef DEBUG
    string = gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_TITLE);
    decode_debug(clist, string);
#endif

    table_name = gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_TABLE);
    value = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(notebook_pg),
						E_PAGE_VALUE));
    decode_change_one_dissector(table_name, value, clist);
}


/*
 * This routine is called when the user clicks the "OK" button in the
 * "Decode As..." dialog window and the network page is foremost.
 * This routine takes care of making any changes requested to the
 * dissector tables.  This routine uses the decode_simple() routine to
 * perform the heavy lifting, and then updates a list of protocol that
 * are being decoded as TCP/UDP. *
 *
 * @param notebook_pg A pointer to the "network" notebook page.
 */
static void
decode_network (GtkWidget *notebook_pg)
{
    GtkCList *clist;
    GSList *item;
    gint row, assigned, port_num;

    /* Do the real work */
    decode_simple(notebook_pg);

    /* Now tweak a local table of protocol ids currently decoded as TCP/UDP */
    port_num = GPOINTER_TO_INT(gtk_object_get_data(GTK_OBJECT(notebook_pg),
						E_PAGE_VALUE));

    /* Ignore changes to the normal TCP and UDP protocol numbers */
    if ((port_num == IP_PROTO_TCP) || (port_num == IP_PROTO_UDP))
	return;

    /* Not decoding - remove any entry for this IP protocol number */
    if (requested_action == E_DECODE_NO) {
	decode_as_tcpudp =
	    g_slist_remove(decode_as_tcpudp, GINT_TO_POINTER(port_num));
	return;
    }

    /* Not assigning TCP or UDP - remove any entry for this IP protocol number.
       Note: if the action was E_DECODE_NO, the selection on the clist
       was cleared, so the code to get "row" below would blow up. */
    clist = GTK_CLIST(gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_CLIST));
    row = GPOINTER_TO_INT(clist->selection->data);
    assigned = GPOINTER_TO_INT(gtk_clist_get_row_data(clist, row));
    if ((assigned != IP_PROTO_TCP) && (assigned != IP_PROTO_UDP)) {
	decode_as_tcpudp =
	    g_slist_remove(decode_as_tcpudp, GINT_TO_POINTER(port_num));
	return;
    }

    /* Assigning TCP or UDP - add if not already present */
    item = g_slist_find(decode_as_tcpudp, GINT_TO_POINTER(port_num));
    if (!item) {
	decode_as_tcpudp =
	    g_slist_prepend(decode_as_tcpudp, GINT_TO_POINTER(port_num));
    }
}


/*
 * This routine is called when the user clicks the "OK" button in the
 * "Decode As..." dialog window and the transport page is foremost.
 * This routine takes care of making any changes requested to the TCP
 * and UDP dissector tables.
 *
 * Note: The negative tests catch multiple cases.  For example, if the
 * user didn't select UDP, then they either selected TCP or TCP/UDP.
 * Either way they *did* select TCP.
 *
 * @param notebook_pg A pointer to the "transport" notebook page.
 */
static void
decode_transport (GtkObject *notebook_pg)
{
    GtkWidget *menu, *menuitem;
    GtkCList *clist;
    gint requested_tcpudp, requested_srcdst;

    clist = GTK_CLIST(gtk_object_get_data(notebook_pg, E_PAGE_CLIST));
    if (requested_action == E_DECODE_NO)
	gtk_clist_unselect_all(clist);

    menu = gtk_object_get_data(notebook_pg, E_MENU_TCPUDP);
    menuitem = gtk_menu_get_active(GTK_MENU(menu));
    requested_tcpudp = GPOINTER_TO_INT(gtk_object_get_user_data(GTK_OBJECT(menuitem)));

    menu = gtk_object_get_data(notebook_pg, E_MENU_SRCDST);
    menuitem = gtk_menu_get_active(GTK_MENU(menu));
    requested_srcdst = GPOINTER_TO_INT(gtk_object_get_user_data(GTK_OBJECT(menuitem)));

#ifdef DEBUG
    string = gtk_object_get_data(GTK_OBJECT(notebook_pg), E_PAGE_TITLE);
    decode_debug(clist, string);
#endif

    if (requested_tcpudp != E_DECODE_UDP) {
	if (requested_srcdst != E_DECODE_DPORT)
	    decode_change_one_dissector("tcp.port", cfile.edt->pi.srcport, clist);
	if (requested_srcdst != E_DECODE_SPORT)
	    decode_change_one_dissector("tcp.port", cfile.edt->pi.destport, clist);
    }
    if (requested_tcpudp != E_DECODE_TCP) {
	if (requested_srcdst != E_DECODE_DPORT)
	    decode_change_one_dissector("udp.port", cfile.edt->pi.srcport, clist);
	if (requested_srcdst != E_DECODE_SPORT)
	    decode_change_one_dissector("udp.port", cfile.edt->pi.destport, clist);
    }
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
decode_ok_cb (GtkWidget *ok_bt, gpointer parent_w)
{
    GtkWidget *notebook, *notebook_pg;
    GtkSignalFunc func;
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
decode_cancel_cb (GtkWidget *cancel_bt, gpointer parent_w)
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
decode_delete_cb (GtkWidget *decode_w, gpointer dummy)
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
decode_destroy_cb (GtkWidget *win, gpointer user_data)
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
decode_update_action (GtkWidget *w, gpointer data)
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
    gtk_signal_connect(GTK_OBJECT(radio_button), "clicked",
		       GTK_SIGNAL_FUNC(decode_update_action),
		       GINT_TO_POINTER(E_DECODE_YES));
    gtk_box_pack_start(GTK_BOX(format_vb), radio_button, TRUE, TRUE, 0);

    radio_button = gtk_radio_button_new_with_label(format_grp, "Do not decode");
    format_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(radio_button));
    gtk_signal_connect(GTK_OBJECT(radio_button), "clicked",
		       GTK_SIGNAL_FUNC(decode_update_action),
		       GINT_TO_POINTER(E_DECODE_NO));
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
 * This routine is called to add the transport protocol selection menu
 * to the dialog box.  This is a three choice menu: TCP, UDP, and
 * TCP/UDP.  The default choice for the menu is set to the transport
 * layer protocol of the currently selected packet.
 *
 * @param page A pointer notebook page that will contain all
 * widgets created by this routine.
 *
 * @return GtkWidget * A pointer to the newly created alignment into
 * which we've packed the newly created option menu.
 */
static GtkWidget *
decode_add_tcpudp_menu (GtkWidget *page)
{
    GtkWidget *optmenu, *menu, *menuitem, *alignment;
    gint requested_tcpudp;

    optmenu = gtk_option_menu_new();
    menu = gtk_menu_new();
    menuitem = gtk_menu_item_new_with_label("TCP");
    gtk_object_set_user_data(GTK_OBJECT(menuitem),
			     GINT_TO_POINTER(E_DECODE_TCP));
    gtk_menu_append(GTK_MENU(menu), menuitem);
    gtk_widget_show(menuitem);	/* gtk_widget_show_all() doesn't show this */

    menuitem = gtk_menu_item_new_with_label("UDP");
    gtk_object_set_user_data(GTK_OBJECT(menuitem),
			     GINT_TO_POINTER(E_DECODE_UDP));
    gtk_menu_append(GTK_MENU(menu), menuitem);
    gtk_widget_show(menuitem);	/* gtk_widget_show_all() doesn't show this */

    menuitem = gtk_menu_item_new_with_label("TCP/UDP");
    gtk_object_set_user_data(GTK_OBJECT(menuitem),
			     GINT_TO_POINTER(E_DECODE_TCPUDP));
    gtk_menu_append(GTK_MENU(menu), menuitem);
    gtk_widget_show(menuitem);	/* gtk_widget_show_all() doesn't show this */

    requested_tcpudp = (cfile.edt->pi.ipproto == IP_PROTO_TCP) ? E_DECODE_TCP : E_DECODE_UDP;
    gtk_menu_set_active(GTK_MENU(menu), requested_tcpudp == E_DECODE_UDP);
    gtk_object_set_data(GTK_OBJECT(page), E_MENU_TCPUDP, menu);
    gtk_option_menu_set_menu(GTK_OPTION_MENU(optmenu), menu);

    alignment = decode_add_pack_menu(optmenu);

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

/**************************************************/
/*        Dialog setup - clist based menus        */
/**************************************************/


typedef struct decode_build_clist_info {
    GtkCList *clist;
    gboolean conv;
} decode_build_clist_info_t;

/*
 * This routine creates one entry in the list of protocol dissector
 * that can be used.  It is called by the g_hash_foreach routine once
 * for each entry in a dissector table.  It guarantees unique entries
 * by iterating over the list of entries build up to this point,
 * looking for a duplicate name.  If there is no duplicate, then this
 * entry is added to the list of possible dissectors.
 *
 * @param table_name The name of the dissector hash table currently
 * being walked.
 *
 * @param key A pointer to the key for this entry in the
 * dissector hash table.  This is generally the numeric selector of
 * the protocol, i.e. the ethernet type code, IP port number, TCP port
 * number, etc.
 *
 * @param value A pointer to the value for this entry in the
 * dissector hash table.  This is an opaque pointer that can only be
 * handed back to routines in the file packet.c
 *
 * @param user_data A data block passed into each instance of this
 * routine.  It contains information from the caller of the foreach
 * routine, specifying information about the dissector table and where
 * to store any information generated by this routine.
 */
static void
decode_add_to_clist (gchar *table_name, gpointer key,
		     gpointer value, gpointer user_data)
{
    GtkCList  *clist;
    gchar     *proto_name, *isconv;
    gchar     *text[E_CLIST_S_COLUMNS];
    gint proto, row;
    decode_build_clist_info_t *info;

    g_assert(user_data);
    g_assert(value);

    info = user_data;
    clist = info->clist;
    if (info->conv) {
	proto = conv_dissector_get_proto(value);
	isconv = "TRUE";
    } else {
	proto = dissector_get_proto(value);
	isconv = "FALSE";
    }
    proto_name = proto_get_protocol_short_name(proto);

    row = gtk_clist_find_row_from_data(clist, GINT_TO_POINTER(proto));
    if (row != -1) {
	return;
    }

    text[E_CLIST_S_PROTO_NAME] = proto_name;
    text[E_CLIST_S_TABLE] = table_name;
    text[E_CLIST_S_ISCONV] = isconv;
    row = gtk_clist_prepend(clist, text);
    gtk_clist_set_row_data(clist, row, GINT_TO_POINTER(proto));
}


/*
 * This routine starts the creation of a CList on a notebook page.  It
 * creates both a scrolled window and a clist, adds the clist to the
 * window, and attaches the clist as a data object on the page.
 *
 * @param page A pointer to the notebook page being created.
 *
 * @param clist_p Will be filled in with the address of a newly
 * created CList.
 *
 * @param scrolled_win_p Will be filled in with the address of a newly
 * created GtkScrolledWindow.
 */
static void
decode_clist_menu_start (GtkWidget *page, GtkCList **clist_p,
			 GtkWidget **scrolled_win_p)
{
    gchar *titles[E_CLIST_S_COLUMNS] = {"Short Name", "Table Name",
					"Is Conversation"};
    GtkCList  *clist;
    GtkWidget *window;
    gint column;

    *clist_p = clist =
	GTK_CLIST(gtk_clist_new_with_titles(E_CLIST_S_COLUMNS, titles));
    gtk_clist_column_titles_passive(clist);
#ifndef DEBUG
    gtk_clist_column_titles_hide(clist);
    for (column = 1; column < E_CLIST_S_COLUMNS; column++)
	gtk_clist_set_column_visibility (clist, column, FALSE);
#endif
    for (column = 0; column < E_CLIST_S_COLUMNS; column++)
	gtk_clist_set_column_auto_resize(clist, column, TRUE);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_CLIST, clist);

    *scrolled_win_p = window = gtk_scrolled_window_new(NULL, NULL);
    /* Provide a minimum of a couple of rows worth of data */
    gtk_widget_set_usize(window, 0, E_DECODE_MIN_HEIGHT);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(window),
				   GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(window),
					  GTK_WIDGET(clist));
}

/*
 * This routine finishes the creation of a CList on a notebook page.
 * It adds the default entry, sets the default entry as the
 * highlighted entry, and sorts the CList.
 *
 * @param clist A pointer the the CList to finish.
 */
static void
decode_clist_menu_finish (GtkCList *clist)
{
    gchar *text[E_CLIST_S_COLUMNS];
    gint row;

    text[E_CLIST_S_PROTO_NAME] = "(default)";
    text[E_CLIST_S_TABLE] = "(none)";
    text[E_CLIST_S_ISCONV] = "(who cares)";
    row = gtk_clist_prepend(clist, text);
    gtk_clist_set_row_data(clist, row, GINT_TO_POINTER(-1));

    gtk_clist_select_row(clist, 0, -1);
    gtk_clist_sort(clist);
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
 * @param table_name The name of the dissector hash table to use to
 * build this (clist) menu.
 *
 * @return GtkWidget * A pointer to the newly created clist within a
 * scrolled window.
 */
static GtkWidget *
decode_add_simple_menu (GtkWidget *page, gchar *table_name)
{
    GtkWidget *scrolled_window;
    GtkCList  *clist;
    decode_build_clist_info_t info;

    decode_clist_menu_start(page, &clist, &scrolled_window);
    {
	info.clist = clist;
	info.conv = FALSE;
	dissector_table_foreach(table_name, decode_add_to_clist, &info);
    }
    decode_clist_menu_finish(clist);
    return(scrolled_window);
}

/*
 * This routine is called to add the dissector selection list to 
 * notebook page.  This scrolled list contains an entry labeled
 * "default", and an entry for each protocol that has had a dissector
 * registered.  The default choice for the list is set to the
 * "default" choice, which will return the protocol/port selections to
 * their original dissector(s).
 *
 * @param page A pointer to the notebook page currently being created.
 *
 * @return GtkWidget * A pointer to the newly created option menu.
 */
static GtkWidget *
decode_add_transport_menu (GtkWidget *page)
{
    GtkWidget *scrolled_window;
    GtkCList  *clist;
    decode_build_clist_info_t info;

    decode_clist_menu_start(page, &clist, &scrolled_window);
    {
	info.clist = clist;
	info.conv = FALSE;
	dissector_table_foreach("tcp.port", decode_add_to_clist, &info);
	dissector_table_foreach("udp.port", decode_add_to_clist, &info);

	info.conv = TRUE;
	dissector_conv_foreach("udp", decode_add_to_clist, &info);
	dissector_conv_foreach("tcp", decode_add_to_clist, &info);
    }
    decode_clist_menu_finish(clist);
    return(scrolled_window);
}

/**************************************************/
/*                  Dialog setup                  */
/**************************************************/

/*
 * This routine creates a sample notebook page in the dialog box.
 * This notebook page provides a prompt specifying what is being
 * changed and its current value (e.g. "IP Protocol number (17)"), and
 * a clist specifying all the available choices.  The list of choices
 * is conditionally enabled, based upon the setting of the
 * "decode"/"do not decode" radio buttons.
 *
 * @param prompt The prompt for this notebook page
 *
 * @param title A table name from which all dissector names will
 * be extracted.
 *
 * @param table_name The name of the dissector hash table to use to
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
 * This routine creates the TCP/UDP notebook page in the dialog box.
 * All items created by this routine are packed into a single
 * horizontal box.  First is a menu allowing the user to select the
 * TCP or UDP transport layer protocol.  Second is a menu allowing the
 * user to select whether the source port, destination port, or both
 * ports will have dissectors added for them.  Last is a
 * (conditionally enabled) popup menu listing all possible dissectors
 * that can be used to decode the packets, and the choice or returning
 * to the default dissector for these ports.
 *
 * The defaults for these items are the transport layer protocol of
 * the currently selected packet, the source port of the currently
 * selected packet, and the "default dissector".
 *
 * @return GtkWidget * A pointer to the notebook page created by
 * this routine.
 */
static GtkWidget *
decode_add_tcpudp_page (void)
{
    GtkWidget	*page, *label, *scrolled_window, *optmenu;

    page = gtk_hbox_new(FALSE, 5);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_ACTION, decode_transport);
    gtk_object_set_data(GTK_OBJECT(page), E_PAGE_TITLE, "Transport");

    /* Always enabled */
    optmenu = decode_add_tcpudp_menu(page);
    gtk_box_pack_start(GTK_BOX(page), optmenu, TRUE, TRUE, 0);
    optmenu = decode_add_srcdst_menu(page);
    gtk_box_pack_start(GTK_BOX(page), optmenu, TRUE, TRUE, 0);
    label = gtk_label_new("port(s)");
    gtk_box_pack_start(GTK_BOX(page), label, TRUE, TRUE, 0);

    /* Conditionally enabled - only when decoding packets */
    label = gtk_label_new("as");
    gtk_box_pack_start(GTK_BOX(page), label, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, label);
    scrolled_window = decode_add_transport_menu(page);
    gtk_box_pack_start(GTK_BOX(page), scrolled_window, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, scrolled_window);

    return(page);
}

/*
 * Indicate if a transport page should be included, based upon the iP
 * protocol number.
 *
 * @param ip_protocol The IP protocol number in question.
 *
 * @return gboolean TRUE if this protocol is being decoded as TCP or
 * UDP.
 */
static gboolean
decode_as_transport_ok (gint ip_protocol)
{
    if ((ip_protocol == IP_PROTO_TCP) || (ip_protocol == IP_PROTO_UDP))
	return(TRUE);

    if (g_slist_find(decode_as_tcpudp, GINT_TO_POINTER(ip_protocol)))
	return(TRUE);
    return(FALSE);
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
	sprintf(buffer, "IP protocol %u", cfile.edt->pi.ipproto);
	page = decode_add_simple_page(buffer, "Network", "ip.proto", cfile.edt->pi.ipproto);
	gtk_object_set_data(GTK_OBJECT(page), E_PAGE_ACTION, decode_network);
	label = gtk_label_new("Network");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page, label);
    }

    /* Add transport selection page */
    if (decode_as_transport_ok(cfile.edt->pi.ipproto)) {
	page = decode_add_tcpudp_page();
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
decode_as_cb (GtkWidget * w, gpointer data)
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
    gtk_signal_connect(GTK_OBJECT(decode_w), "delete_event",
		       GTK_SIGNAL_FUNC(decode_delete_cb), NULL);
    gtk_signal_connect(GTK_OBJECT(decode_w), "destroy",
		       GTK_SIGNAL_FUNC(decode_destroy_cb), NULL);
  
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

    ok_bt = gtk_button_new_with_label("OK");
    gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		       GTK_SIGNAL_FUNC(decode_ok_cb),
		       GTK_OBJECT(decode_w));
    GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
    gtk_box_pack_start(GTK_BOX(bbox), ok_bt, FALSE, FALSE, 0);
    gtk_widget_grab_default(ok_bt);

    button = gtk_button_new_with_label("Show Current");
    gtk_signal_connect(GTK_OBJECT(button), "clicked",
		       GTK_SIGNAL_FUNC(decode_show_cb),
		       GTK_OBJECT(decode_w));
    GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);
    gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);

    cancel_bt = gtk_button_new_with_label("Cancel");
    gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
		       GTK_SIGNAL_FUNC(decode_cancel_cb),
		       GTK_OBJECT(decode_w));
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
 * This routine indicates whether we'd actually have any pages in the
 * notebook in a "Decode As" dialog box; if there wouldn't be, we
 * inactivate the menu item for "Decode As".
 */
gboolean
decode_as_ok(void)
{
    return cfile.edt->pi.ethertype || cfile.edt->pi.ipproto || decode_as_transport_ok(cfile.edt->pi.ipproto);
}


/*
 * Local Variables:
 * mode:c
 * c-basic-offset: 4
 * End:
 */
