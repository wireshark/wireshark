/*
 * Copyright 2004, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
 * Copyright 2009, Varun Notibala <nbvarun [AT] gmail.com>
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
#  include <config.h>
#endif
#include <string.h>

#include <gtk/gtk.h>

#include "epan/filesystem.h"

#include "../globals.h"

#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/main.h"
#include "gtk/sctp_stat.h"

static GtkWidget *clist = NULL;
static GList *last_list = NULL;
static sctp_assoc_info_t* selected_stream = NULL;  /* current selection */

#define NUM_COLS   14
#define FRAME_LIMIT 8

enum chunk_types {
    DATA          = 0,
    INIT          = 1,
    INIT_ACK      = 2,
    SACK          = 3,
    HEARTBEAT     = 4,
    HEARTBEAT_ACK = 5,
    ABORT         = 6,
    SHUTDOWN      = 7,
    SHUTDOWN_ACK  = 8,
    SCTP_ERROR    = 9,
    COOKIE_ECHO   = 10,
    COOKIE_ACK    = 11,
    ECNE          = 12,
    CWR           = 13,
    SHUT_COMPLETE = 14,
    AUTH          = 15,
    NR_SACK       = 16,
    ASCONF_ACK    = 0x80,
    PKTDROP       = 0x81,
    FORWARD_TSN   = 0xC0,
    ASCONF        = 0xC1
};
enum
{
   IP_ADDR_COLUMN,
   DATA_COLUMN,
   INIT_COLUMN,
   INIT_ACK_COLUMN,
   SACK_COLUMN,
   HEARTBEAT_COLUMN,
   HEARTBEAT_ACK_COLUMN,
   ABORT_COLUMN,
   SHUTDOWN_COLUMN,
   SHUTDOWN_ACK_COLUMN,
   ERROR_COLUMN,
   COOKIE_ECHO_COLUMN,
   COOKIE_ACK_COLUMN,
   ECNE_COLUMN,
   CWR_COLUMN,
   SHUT_COMPLETE_COLUMN,
   AUTH_COLUMN,
   NR_SACK_COLUMN,
   ASCONF_ACK_COLUMN,
   PKTDROP_COLUMN,
   FORWARD_TSN_COLUMN,
   ASCONF_COLUMN,
   OTHERS_COLUMN,
   N_COLUMN /* The number of columns */
};

/* Create list */
static
GtkWidget* create_list(void)
{

    GtkListStore *list_store;
    GtkWidget *list;
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;
    GtkTreeSortable *sortable;
    GtkTreeView     *list_view;
    GtkTreeSelection  *selection;

    /* Create the store */
    list_store = gtk_list_store_new(N_COLUMN,      /* Total number of columns XXX */
                                    G_TYPE_STRING, /* IP Address                  */
                                    G_TYPE_INT,    /* DATA                        */
                                    G_TYPE_INT,    /* INIT                        */
                                    G_TYPE_INT,    /* INIT_ACK                    */
                                    G_TYPE_INT,    /* SACK                        */
                                    G_TYPE_INT,    /* HEARTBEAT                   */
                                    G_TYPE_INT,    /* HEARTBEAT_ACK               */
                                    G_TYPE_INT,    /* ABORT                       */
                                    G_TYPE_INT,    /* SHUTDOWN                    */
                                    G_TYPE_INT,    /* SHUTDOWN_ACK                */
                                    G_TYPE_INT,    /* ERROR                       */
                                    G_TYPE_INT,    /* COOKIE_ECHO                 */
                                    G_TYPE_INT,    /* COOKIE_ACK                  */
                                    G_TYPE_INT,    /* ECNE                        */
                                    G_TYPE_INT,    /* CWR                         */
                                    G_TYPE_INT,    /* SHUT_COMPLETE               */
                                    G_TYPE_INT,    /* AUTH                        */
                                    G_TYPE_INT,    /* NR_SACK                     */
                                    G_TYPE_INT,    /* ASCONF_ACK                  */
                                    G_TYPE_INT,    /* PKTDROP                     */
                                    G_TYPE_INT,    /* FORWARD_TSN                 */
                                    G_TYPE_INT,    /* ASCONF                      */
                                    G_TYPE_INT);   /* Others                      */
    /* Create a view */
    list = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));

    list_view = GTK_TREE_VIEW(list);
    sortable = GTK_TREE_SORTABLE(list_store);

    /* Speed up the list display */
    gtk_tree_view_set_fixed_height_mode(list_view, TRUE);

    /* Setup the sortable columns */
    gtk_tree_sortable_set_sort_column_id(sortable, IP_ADDR_COLUMN, GTK_SORT_ASCENDING);
    gtk_tree_view_set_headers_clickable(list_view, FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (list_store));

    /*
     * Create the first column packet, associating the "text" attribute of the
     * cell_renderer to the first column of the model
     */
    /* 1:st column */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("IP Address", renderer,
                "text", IP_ADDR_COLUMN,
                NULL);

    gtk_tree_view_column_set_sort_column_id(column, IP_ADDR_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 135);

    /* Add the column to the view. */
    gtk_tree_view_append_column (list_view, column);

    /* 2:nd column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("DATA", renderer,
                "text", DATA_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, DATA_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 70);
    gtk_tree_view_append_column (list_view, column);

    /* 3:d column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("INIT", renderer,
                "text", INIT_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, INIT_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 70);
    gtk_tree_view_append_column (list_view, column);

    /* 4:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("INIT-ACK", renderer,
                "text", INIT_ACK_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, INIT_ACK_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 90);
    gtk_tree_view_append_column (list_view, column);

    /* 5:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("SACK", renderer,
                "text", SACK_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, SACK_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 70);
    gtk_tree_view_append_column (list_view, column);

    /* 6:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("HEARTBEAT", renderer,
                "text", HEARTBEAT_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, HEARTBEAT_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 110);
    gtk_tree_view_append_column (list_view, column);

    /* 7:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("HEARTBEAT-ACK", renderer,
                "text", HEARTBEAT_ACK_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, HEARTBEAT_ACK_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 140);
    gtk_tree_view_append_column (list_view, column);

    /* 8:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("ABORT", renderer,
                "text", ABORT_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, ABORT_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (list_view, column);


    /* 9:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("SHUTDOWN", renderer,
                "text", SHUTDOWN_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, SHUTDOWN_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 120);
    gtk_tree_view_append_column (list_view, column);

    /* 10:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("SHUTDOWN-ACK", renderer,
                "text", SHUTDOWN_ACK_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, SHUTDOWN_ACK_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 150);
    gtk_tree_view_append_column (list_view, column);

    /* 11:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("ERROR", renderer,
                "text", ERROR_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, ERROR_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (list_view, column);

    /* 12:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("COOKIE-ECHO", renderer,
                "text", COOKIE_ECHO_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, COOKIE_ECHO_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 130);
    gtk_tree_view_append_column (list_view, column);

    /* 13:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("COOKIE-ACK", renderer,
                "text", COOKIE_ACK_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, COOKIE_ACK_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 130);
    gtk_tree_view_append_column (list_view, column);

    /* 14:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("ECNE", renderer,
                "text", ECNE_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, ECNE_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 70);
    gtk_tree_view_append_column (list_view, column);

    /* 15:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("CWR", renderer,
                "text", CWR_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, CWR_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 70);
    gtk_tree_view_append_column (list_view, column);

    /* 16:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("SHUT-COMPLETE", renderer,
                "text", SHUT_COMPLETE_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, SHUT_COMPLETE_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 150);
    gtk_tree_view_append_column (list_view, column);

    /* 17:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("AUTH", renderer,
                "text", AUTH_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, AUTH_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (list_view, column);

    /* 18:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("NR-SACK", renderer,
                "text", NR_SACK_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, NR_SACK_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 19:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("ASCONF-ACK", renderer,
                "text", ASCONF_ACK_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, ASCONF_ACK_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 120);
    gtk_tree_view_append_column (list_view, column);

    /* 20:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("PKTDROP", renderer,
                "text", PKTDROP_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, PKTDROP_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 21:st column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("FORWARD-TSN", renderer,
                "text", FORWARD_TSN_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, FORWARD_TSN_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 140);
    gtk_tree_view_append_column (list_view, column);

    /* 22:nd column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("ASCONF", renderer,
                "text", ASCONF_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, ASCONF_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 90);
    gtk_tree_view_append_column (list_view, column);

    /* 23:rd column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Others", renderer,
                "text", OTHERS_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, OTHERS_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (list_view, column);

    /* Now enable the sorting of each column */
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(list_view), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(list_view), TRUE);

    /* Setup the selection handler */
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
    gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

    return list;

}

static const char *
chunk_name(int type)
{
#define CASE(x) case x: s=#x; break
    const char *s = "unknown";
    switch (type)
    {
        CASE(DATA);
        CASE(INIT);
        CASE(INIT_ACK);
        CASE(SACK);
        CASE(HEARTBEAT);
        CASE(HEARTBEAT_ACK);
        CASE(ABORT);
        CASE(SHUTDOWN);
        CASE(SHUTDOWN_ACK);
        CASE(SCTP_ERROR);
        CASE(COOKIE_ECHO);
        CASE(COOKIE_ACK);
        CASE(ECNE);
        CASE(CWR);
        CASE(SHUT_COMPLETE);
        CASE(AUTH);
        CASE(NR_SACK);
        CASE(ASCONF_ACK);
        CASE(PKTDROP);
        CASE(FORWARD_TSN);
        CASE(ASCONF);
    }
    return s;
}

typedef struct column_arrows {
    GtkWidget *table;
    GtkWidget *ascend_pm;
    GtkWidget *descend_pm;
} column_arrows;


static void
chunk_dlg_destroy(GtkObject *object _U_, gpointer user_data)
{
    struct sctp_udata *u_data=(struct sctp_udata*)user_data;
    decrease_childcount(u_data->parent);
    remove_child(u_data, u_data->parent);
    g_free(u_data->io);
    g_free(u_data);
}

static void
on_destroy(GtkObject *object _U_, gpointer user_data)
{
    struct sctp_udata *u_data=(struct sctp_udata*)user_data;
    decrease_childcount(u_data->parent);
    remove_child(u_data, u_data->parent);
    g_free(u_data->io);
    g_free(u_data);
}


static void
add_to_clist(sctp_addr_chunk* sac)
{
    GtkListStore *list_store = NULL;
    GtkTreeIter  iter;
    gchar field[1][MAX_ADDRESS_LEN];

    list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (clist))); /* Get store */

    if (sac->addr->type==AT_IPv4) {
        g_snprintf(field[0], MAX_ADDRESS_LEN, "%s", ip_to_str((const guint8 *)(sac->addr->data)));
    } else if (sac->addr->type==AT_IPv6) {
        g_snprintf(field[0], MAX_ADDRESS_LEN, "%s", ip6_to_str((const struct e_in6_addr *)(sac->addr->data)));
    }

    gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
         IP_ADDR_COLUMN,         field[0],
         DATA_COLUMN,            sac->addr_count[SCTP_DATA_CHUNK_ID],
         INIT_COLUMN,            sac->addr_count[SCTP_INIT_CHUNK_ID],
         INIT_ACK_COLUMN,        sac->addr_count[SCTP_INIT_ACK_CHUNK_ID],
         SACK_COLUMN,            sac->addr_count[SCTP_SACK_CHUNK_ID],
         HEARTBEAT_COLUMN,       sac->addr_count[SCTP_HEARTBEAT_CHUNK_ID],
         HEARTBEAT_ACK_COLUMN,   sac->addr_count[SCTP_HEARTBEAT_ACK_CHUNK_ID],
         ABORT_COLUMN,           sac->addr_count[SCTP_ABORT_CHUNK_ID],
         SHUTDOWN_COLUMN,        sac->addr_count[SCTP_SHUTDOWN_CHUNK_ID],
         SHUTDOWN_ACK_COLUMN,    sac->addr_count[SCTP_SHUTDOWN_ACK_CHUNK_ID],
         ERROR_COLUMN,           sac->addr_count[SCTP_ERROR_CHUNK_ID],
         COOKIE_ECHO_COLUMN,     sac->addr_count[SCTP_COOKIE_ECHO_CHUNK_ID],
         COOKIE_ACK_COLUMN,      sac->addr_count[SCTP_COOKIE_ACK_CHUNK_ID],
         ECNE_COLUMN,            sac->addr_count[SCTP_ECNE_CHUNK_ID],
         CWR_COLUMN,             sac->addr_count[SCTP_CWR_CHUNK_ID],
         SHUT_COMPLETE_COLUMN,   sac->addr_count[SCTP_SHUTDOWN_COMPLETE_CHUNK_ID],
         AUTH_COLUMN,            sac->addr_count[SCTP_AUTH_CHUNK_ID],
         NR_SACK_COLUMN,         sac->addr_count[SCTP_NR_SACK_CHUNK_ID],
         ASCONF_ACK_COLUMN,      sac->addr_count[SCTP_ASCONF_ACK_CHUNK_ID],
         PKTDROP_COLUMN,         sac->addr_count[SCTP_PKTDROP_CHUNK_ID],
         FORWARD_TSN_COLUMN,     sac->addr_count[SCTP_FORWARD_TSN_CHUNK_ID],
         ASCONF_COLUMN,          sac->addr_count[SCTP_ASCONF_CHUNK_ID],
         OTHERS_COLUMN,          sac->addr_count[OTHER_CHUNKS_INDEX],
         -1);
}

void sctp_chunk_stat_dlg_update(struct sctp_udata* udata, unsigned int direction)
{
    GList *list=NULL;
    sctp_addr_chunk* sac;

    if (udata->io->window != NULL)
    {
        gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(clist))));
        if (udata->assoc->addr_chunk_count!=NULL)
        {
            list = g_list_first(udata->assoc->addr_chunk_count);

            while (list)
            {
                sac = (sctp_addr_chunk*)(list->data);
                if (sac->direction==direction)
                {
                    add_to_clist(sac);
                    list = g_list_next(list);
                }
                else
                    list = g_list_next(list);
            }
        }
    }
    last_list = list;
}



static void
sctp_chunk_stat_on_close (GtkButton *button _U_, gpointer         user_data)
{
    struct sctp_udata *udata;

    udata = (struct sctp_udata *)user_data;
    gtk_grab_remove(udata->io->window);
    gtk_widget_destroy(udata->io->window);
}

static void
on_close_dlg (GtkButton *button _U_, gpointer user_data)
{
    struct sctp_udata *udata;

    udata = (struct sctp_udata *)user_data;
    gtk_grab_remove(udata->io->window);
    gtk_widget_destroy(udata->io->window);
}


static void
path_window_set_title(struct sctp_udata *u_data, unsigned int direction)
{
    char *title;
    if(!u_data->io->window){
        return;
    }
    title = g_strdup_printf("SCTP Path Chunk Statistics for Endpoint %u: %s Port1 %u  Port2 %u",direction,
                            cf_get_display_name(&cfile), u_data->assoc->port1, u_data->assoc->port2);
    gtk_window_set_title(GTK_WINDOW(u_data->io->window), title);
    g_free(title);
}

static void
gtk_sctpstat_dlg(struct sctp_udata *u_data, unsigned int direction)
{
    GtkWidget *vbox1;
    GtkWidget *scrolledwindow1;
    GtkWidget *hbuttonbox2;
    GtkWidget *bt_close;


    sctp_graph_t* io=g_malloc(sizeof(sctp_graph_t));
    io->window=NULL;
    u_data->io=io;
    u_data->io->window= gtk_window_new (GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(u_data->io->window), 850, 200);
    gtk_window_set_position (GTK_WINDOW (u_data->io->window), GTK_WIN_POS_CENTER);
    path_window_set_title(u_data, direction);
    g_signal_connect(u_data->io->window, "destroy", G_CALLBACK(chunk_dlg_destroy), u_data);

    /* Container for each row of widgets */
    vbox1 = gtk_vbox_new(FALSE, 2);
    gtk_container_set_border_width(GTK_CONTAINER(vbox1), 8);
    gtk_container_add(GTK_CONTAINER(u_data->io->window), vbox1);
    gtk_widget_show(vbox1);

    scrolledwindow1 = scrolled_window_new (NULL, NULL);
    gtk_widget_show (scrolledwindow1);
    gtk_box_pack_start (GTK_BOX (vbox1), scrolledwindow1, TRUE, TRUE, 0);

    clist = create_list();
    gtk_widget_show (clist);
    gtk_container_add (GTK_CONTAINER (scrolledwindow1), clist);

    gtk_widget_show(u_data->io->window);


    hbuttonbox2 = gtk_hbutton_box_new();
    gtk_box_pack_start(GTK_BOX(vbox1), hbuttonbox2, FALSE, FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(hbuttonbox2), 10);
    gtk_button_box_set_layout(GTK_BUTTON_BOX (hbuttonbox2), GTK_BUTTONBOX_SPREAD);
    gtk_box_set_spacing(GTK_BOX (hbuttonbox2), 0);
    gtk_widget_show(hbuttonbox2);

    bt_close = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
    gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_close);
    gtk_widget_show (bt_close);

    g_signal_connect(bt_close, "clicked", G_CALLBACK(sctp_chunk_stat_on_close), u_data);

    cf_retap_packets(&cfile);

}


static void
chunk_window_set_title(struct sctp_udata *u_data)
{
    char *title;
    if(!u_data->io->window){
        return;
    }
    title = g_strdup_printf("SCTP Association Chunk Statistics: %s Port1 %u  Port2 %u",
                            cf_get_display_name(&cfile), u_data->assoc->port1, u_data->assoc->port2);
    gtk_window_set_title(GTK_WINDOW(u_data->io->window), title);
    g_free(title);
}

static void
sctp_chunk_dlg(struct sctp_udata *u_data)
{
    GtkWidget *main_vb, *table;
    GtkWidget *label, *h_button_box;
    GtkWidget *close_bt;
    gchar label_txt[50];
    int i, row;

    sctp_graph_t* io=g_malloc(sizeof(sctp_graph_t));
    io->window=NULL;
    u_data->io=io;
    u_data->io->window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    gtk_window_set_position (GTK_WINDOW (u_data->io->window), GTK_WIN_POS_CENTER);
    gtk_widget_set_size_request(u_data->io->window, 500, 650);
    g_signal_connect(u_data->io->window, "destroy", G_CALLBACK(on_destroy), u_data);

    /* Container for each row of widgets */
    main_vb = gtk_vbox_new(FALSE, 12);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 12);
    gtk_container_add(GTK_CONTAINER(u_data->io->window), main_vb);

    /* table */
    table = gtk_table_new(1, 4, FALSE);
    gtk_table_set_col_spacings(GTK_TABLE(table), 6);
    gtk_table_set_row_spacings(GTK_TABLE(table), 3);
    gtk_container_add(GTK_CONTAINER(main_vb), table);
    row = 0;

    label = gtk_label_new("ChunkType");
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, row, row+1);
    label = gtk_label_new("Association");
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_table_attach_defaults(GTK_TABLE(table), label, 1, 2, row, row+1);
    label = gtk_label_new("Endpoint 1");
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_table_attach_defaults(GTK_TABLE(table), label, 2, 3, row, row+1);
    label = gtk_label_new("Endpoint 2");
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_table_attach_defaults(GTK_TABLE(table), label, 3, 4, row, row+1);
    row ++;
    label = gtk_label_new("");
    gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, row, row+1);
    label = gtk_label_new("");
    gtk_table_attach_defaults(GTK_TABLE(table), label, 1, 2, row, row+1);
    label = gtk_label_new("");
    gtk_table_attach_defaults(GTK_TABLE(table), label, 2, 3, row, row+1);
    label = gtk_label_new("");
    gtk_table_attach_defaults(GTK_TABLE(table), label, 3, 4, row, row+1);
    row ++;

    for (i=0; i<NUM_CHUNKS; i++)
    {
        if (IS_SCTP_CHUNK_TYPE(i))
        {
            label = gtk_label_new(chunk_name(i));
            gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
            gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, row, row+1);
            g_snprintf(label_txt, 10, "%u", selected_stream->chunk_count[i]);
            label = gtk_label_new(label_txt);
            gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
            gtk_table_attach_defaults(GTK_TABLE(table), label, 1, 2, row, row+1);
            g_snprintf(label_txt, 10, "%u", selected_stream->ep1_chunk_count[i]);
            label = gtk_label_new(label_txt);
            gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
            gtk_table_attach_defaults(GTK_TABLE(table), label, 2, 3, row, row+1);
            g_snprintf(label_txt, 10, "%u", selected_stream->ep2_chunk_count[i]);
            label = gtk_label_new(label_txt);
            gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
            gtk_table_attach_defaults(GTK_TABLE(table), label, 3, 4, row, row+1);
            row ++;
        }
    }

    label = gtk_label_new("Others");
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, row, row+1);
    g_snprintf(label_txt, 10, "%u", selected_stream->chunk_count[OTHER_CHUNKS_INDEX]);
    label = gtk_label_new(label_txt);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_table_attach_defaults(GTK_TABLE(table), label, 1, 2, row, row+1);
    g_snprintf(label_txt, 10, "%u", selected_stream->ep1_chunk_count[OTHER_CHUNKS_INDEX]);
    label = gtk_label_new(label_txt);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_table_attach_defaults(GTK_TABLE(table), label, 2, 3, row, row+1);
    g_snprintf(label_txt, 10, "%u", selected_stream->ep2_chunk_count[OTHER_CHUNKS_INDEX]);
    label = gtk_label_new(label_txt);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_table_attach_defaults(GTK_TABLE(table), label, 3, 4, row, row+1);

    h_button_box=gtk_hbutton_box_new();
    gtk_box_pack_start(GTK_BOX(main_vb), h_button_box, FALSE, FALSE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(h_button_box), 10);
    gtk_button_box_set_layout(GTK_BUTTON_BOX (h_button_box), GTK_BUTTONBOX_SPREAD);
    gtk_box_set_spacing(GTK_BOX (h_button_box), 0);
    gtk_widget_show(h_button_box);

    close_bt = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
    gtk_box_pack_start(GTK_BOX(h_button_box), close_bt, FALSE, FALSE, 0);
    gtk_widget_show(close_bt);
    g_signal_connect(close_bt, "clicked", G_CALLBACK(on_close_dlg), u_data);

    gtk_widget_show_all(u_data->io->window);
    chunk_window_set_title(u_data);
}

void
sctp_chunk_dlg_show(struct sctp_analyse* userdata)
{
    gint i;
    struct sctp_udata *u_data;

    u_data=g_malloc(sizeof(struct sctp_udata));
    u_data->assoc=g_malloc(sizeof(sctp_assoc_info_t));
    u_data->assoc=userdata->assoc;
    u_data->io=NULL;
    u_data->parent = userdata;

    if (selected_stream==NULL)
        selected_stream=g_malloc(sizeof(sctp_assoc_info_t));

    selected_stream=u_data->assoc;
    for (i=0; i<NUM_CHUNKS; i++)
    {
        if (IS_SCTP_CHUNK_TYPE(i) || i == OTHER_CHUNKS_INDEX)
            selected_stream->chunk_count[i]=u_data->assoc->chunk_count[i];
    }
    set_child(u_data, u_data->parent);
    increase_childcount(u_data->parent);
    sctp_chunk_dlg(u_data);
}

void
sctp_chunk_stat_dlg_show(unsigned int direction, struct sctp_analyse* userdata)
{
    struct sctp_udata *u_data;

    u_data=g_malloc(sizeof(struct sctp_udata));
    u_data->assoc=g_malloc(sizeof(sctp_assoc_info_t));
    u_data->assoc=userdata->assoc;
    u_data->io=NULL;
    u_data->parent = userdata;

    if (selected_stream==NULL)
        selected_stream=g_malloc(sizeof(sctp_assoc_info_t));
    selected_stream=u_data->assoc;
    selected_stream->addr_chunk_count=u_data->assoc->addr_chunk_count;

    set_child(u_data, u_data->parent);
    increase_childcount(u_data->parent);
    gtk_sctpstat_dlg(u_data, direction);
    sctp_chunk_stat_dlg_update(u_data,direction);
}
