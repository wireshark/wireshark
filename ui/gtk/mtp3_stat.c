/* mtp3_stat.c
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Modified from gsm_map_stat.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This TAP provides statistics for MTP3:
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <gtk/gtk.h>

#include "epan/packet_info.h"
#include "epan/epan.h"
#include "epan/value_string.h"
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-mtp3.h>

#include "../stat_menu.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/mtp3_stat.h"

#include "ui/gtk/old-gtk-compat.h"

void register_tap_listener_gtkmtp3_stat(void);

enum
{
    OPC_COLUMN,
    DPC_COLUMN,
    SI_COLUMN,
    NUM_MSUS_COLUMN,
    NUM_BYTES_COLUMN,
    AVG_BYTES_COLUMN,
    N_COLUMN /* The number of columns */
};


typedef struct _mtp3_stat_dlg_t {
    GtkWidget       *win;
    GtkWidget       *scrolled_win;
    GtkWidget       *table;
    char        *entries[N_COLUMN];
} mtp3_stat_dlg_t;

static mtp3_stat_dlg_t  dlg;

mtp3_stat_t     mtp3_stat[MTP3_MAX_NUM_OPC_DPC];
guint8          mtp3_num_used;



/* Create list */
static
GtkWidget* create_list(void)
{

    GtkListStore      *list_store;
    GtkWidget         *list;
    GtkTreeViewColumn *column;
    GtkCellRenderer   *renderer;
    GtkTreeSortable   *sortable;
    GtkTreeView       *list_view;
    GtkTreeSelection  *selection;

    /* Create the store */
    list_store = gtk_list_store_new(N_COLUMN,   /* Total number of columns XXX*/
                               G_TYPE_STRING,   /* OPC              */
                               G_TYPE_STRING,   /* DPC              */
                               G_TYPE_STRING,   /* SI               */
                               G_TYPE_INT,      /* Num MSUs         */
                               G_TYPE_INT,      /* Num Bytes        */
                               G_TYPE_FLOAT);   /* Avg Bytes        */

    /* Create a view */
    list = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));

    list_view = GTK_TREE_VIEW(list);
    sortable = GTK_TREE_SORTABLE(list_store);

    /* Speed up the list display */
    gtk_tree_view_set_fixed_height_mode(list_view, TRUE);

    /* Setup the sortable columns */
    gtk_tree_sortable_set_sort_column_id(sortable, OPC_COLUMN, GTK_SORT_ASCENDING);
    gtk_tree_view_set_headers_clickable(list_view, FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (list_store));

    /*
     * Create the first column packet, associating the "text" attribute of the
     * cell_renderer to the first column of the model
     */
    /* 1:st column */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("OPC", renderer,
        "text", OPC_COLUMN,
        NULL);

    gtk_tree_view_column_set_sort_column_id(column, OPC_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);

    /* Add the column to the view. */
    gtk_tree_view_append_column (list_view, column);

    /* 2:nd column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("DPC", renderer,
        "text", DPC_COLUMN,
        NULL);
    gtk_tree_view_column_set_sort_column_id(column, DPC_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (list_view, column);

    /* 3:d column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("SI", renderer,
        "text", SI_COLUMN,
        NULL);
    gtk_tree_view_column_set_sort_column_id(column, SI_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 110);
    gtk_tree_view_append_column (list_view, column);

    /* 4:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Num MSUs", renderer,
        "text", NUM_MSUS_COLUMN,
        NULL);


    gtk_tree_view_column_set_sort_column_id(column, NUM_MSUS_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (list_view, column);

    /* 5:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Num Bytes", renderer,
        "text", NUM_BYTES_COLUMN,
        NULL);

    gtk_tree_view_column_set_sort_column_id(column, NUM_BYTES_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 6:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Avg Bytes", renderer,
        "text", AVG_BYTES_COLUMN,
        NULL);
    gtk_tree_view_column_set_cell_data_func(column, renderer, float_data_func,
        GINT_TO_POINTER(AVG_BYTES_COLUMN), NULL);

    gtk_tree_view_column_set_sort_column_id(column, AVG_BYTES_COLUMN);
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

static void
mtp3_stat_reset(
    void        *tapdata)
{
    mtp3_stat_t     (*stat_p)[MTP3_MAX_NUM_OPC_DPC] = (mtp3_stat_t(*)[MTP3_MAX_NUM_OPC_DPC])tapdata;

    mtp3_num_used = 0;
    memset(stat_p, 0, MTP3_MAX_NUM_OPC_DPC * sizeof(mtp3_stat_t));

    if (dlg.win != NULL)
    {
        gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(dlg.table))));
    }
}


static gboolean
mtp3_stat_packet(
    void            *tapdata,
    packet_info     *pinfo _U_,
    epan_dissect_t  *edt _U_,
    const void      *data)
{
    mtp3_stat_t           (*stat_p)[MTP3_MAX_NUM_OPC_DPC] = (mtp3_stat_t(*)[MTP3_MAX_NUM_OPC_DPC])tapdata;
    const mtp3_tap_rec_t  *data_p = (const mtp3_tap_rec_t *)data;
    int                    i;

    if (data_p->si_code >= MTP3_NUM_SI_CODE)
    {
        /*
         * we thought this si_code was not used ?
         * is MTP3_NUM_SI_CODE out of date ?
         */
        return(FALSE);
    }

    /*
     * look for opc/dpc pair
     */
    i = 0;
    while (i < mtp3_num_used)
    {
        if (memcmp(&data_p->addr_opc, &(*stat_p)[i].addr_opc, sizeof(mtp3_addr_pc_t)) == 0)
        {
            if (memcmp(&data_p->addr_dpc, &(*stat_p)[i].addr_dpc, sizeof(mtp3_addr_pc_t)) == 0)
            {
                break;
            }
        }

        i++;
    }

    if (i == mtp3_num_used)
    {
        if (mtp3_num_used == MTP3_MAX_NUM_OPC_DPC)
        {
            /*
             * too many
             */
            return(FALSE);
        }

        mtp3_num_used++;
    }

    (*stat_p)[i].addr_opc = data_p->addr_opc;
    (*stat_p)[i].addr_dpc = data_p->addr_dpc;
    (*stat_p)[i].si_code[data_p->si_code].num_msus++;
    (*stat_p)[i].si_code[data_p->si_code].size += data_p->size;

    return(TRUE);
}


static void
mtp3_stat_draw(
    void        *tapdata)
{
    mtp3_stat_t   (*stat_p)[MTP3_MAX_NUM_OPC_DPC] = (mtp3_stat_t(*)[MTP3_MAX_NUM_OPC_DPC])tapdata;
    int           i,j;
    char         *str;
    float         avg;
    GtkListStore *list_store = NULL;
    GtkTreeIter   iter;

    if (!dlg.win || !tapdata)
    {
        return;
    }

    str=(char *)ep_alloc(256);
    i = 0;

    list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (dlg.table))); /* Get store */
    while (i < mtp3_num_used)
    {
        mtp3_addr_to_str_buf(&(*stat_p)[i].addr_opc, str, 256);
        dlg.entries[0] = g_strdup(str);

        mtp3_addr_to_str_buf(&(*stat_p)[i].addr_dpc, str, 256);
        dlg.entries[1] = g_strdup(str);

        for (j=0; j < MTP3_NUM_SI_CODE; j++){
            /* Creates a new row at position. iter will be changed to point to this new row.
             * If position is larger than the number of rows on the list, then the new row will be appended to the list.
             * The row will be filled with the values given to this function.
             * :
             * should generally be preferred when inserting rows in a sorted list store.
             */
             avg = 0.0f;
             if ((*stat_p)[i].si_code[j].num_msus !=0){
                 avg = (float)(*stat_p)[i].si_code[j].size/(float)(*stat_p)[i].si_code[j].num_msus;
             }


            gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
               OPC_COLUMN,       dlg.entries[0],
               DPC_COLUMN,       dlg.entries[1],
               SI_COLUMN,        mtp3_service_indicator_code_short_vals[j].strptr,
               NUM_MSUS_COLUMN,  (*stat_p)[i].si_code[j].num_msus,
               NUM_BYTES_COLUMN, (*stat_p)[i].si_code[j].size,
               AVG_BYTES_COLUMN, avg,
               -1);
        }
        i++;
    }
}




static void
mtp3_stat_gtk_win_destroy_cb(
    GtkWindow       *win _U_,
    gpointer        user_data)
{
    memset((void *) user_data, 0, sizeof(mtp3_stat_dlg_t));
}


static void
mtp3_stat_gtk_win_create(
    mtp3_stat_dlg_t *dlg_p,
    const char      *title)
{
    GtkWidget       *vbox;
    GtkWidget       *bt_close;
    GtkWidget       *bbox;


    dlg_p->win = dlg_window_new(title);  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(dlg_p->win), TRUE);

    gtk_window_set_default_size(GTK_WINDOW(dlg_p->win), 640, 390);

    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
    gtk_container_add(GTK_CONTAINER(dlg_p->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    dlg_p->scrolled_win = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), dlg_p->scrolled_win, TRUE, TRUE, 0);

    dlg_p->table = create_list();

    gtk_widget_show(dlg_p->table);

    gtk_container_add(GTK_CONTAINER(dlg_p->scrolled_win), dlg_p->table);

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    bt_close = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(dlg_p->win, bt_close, window_cancel_button_cb);

    g_signal_connect(dlg_p->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(dlg_p->win, "destroy", G_CALLBACK(mtp3_stat_gtk_win_destroy_cb), dlg_p);

    gtk_widget_show_all(dlg_p->win);
    window_present(dlg_p->win);
}


void mtp3_stat_gtk_cb(GtkAction *action _U_, gpointer user_data _U_)
{

    /*
     * if the window is already open, bring it to front
     */
    if (dlg.win)
    {
        gdk_window_raise(gtk_widget_get_window(dlg.win));
        return;
    }

    mtp3_stat_gtk_win_create(&dlg, "MTP3 Statistics");

    mtp3_stat_draw(&mtp3_stat);
}


static void
mtp3_stat_gtk_init( const char *opt_arg _U_, void* userdata _U_)
{
    mtp3_stat_gtk_cb(NULL, NULL);
}


void
register_tap_listener_gtkmtp3_stat(void)
{
    GString     *err_p;


    memset((void *) &mtp3_stat, 0, sizeof(mtp3_stat_t));

    err_p =
    register_tap_listener("mtp3", &mtp3_stat, NULL, 0,
        mtp3_stat_reset,
        mtp3_stat_packet,
        mtp3_stat_draw);

    if (err_p != NULL)
    {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "%s", err_p->str);
        g_string_free(err_p, TRUE);

        exit(1);
    }
    register_stat_cmd_arg("mtp3,msus", mtp3_stat_gtk_init,NULL);
}
