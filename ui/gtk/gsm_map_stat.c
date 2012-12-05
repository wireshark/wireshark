/* gsm_map_stat.c
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * MUCH code modified from service_response_time_table.c.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This TAP provides statistics for GSM MAP Operations:
 */

#include "config.h"
#include <string.h>

#include <gtk/gtk.h>

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/value_string.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-gsm_map.h>

#include "../stat_menu.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/gsm_map_stat.h"

#include "ui/gtk/old-gtk-compat.h"

enum
{
    ID_COLUMN,
    OP_CODE_COLUMN,
    INVOKES_COLUMN,
    NUM_BYTES_FWD_COLUMN,
    AVG_BYTES_FWD_COLUMN,
    RET_RES_COLUMN,
    NUM_BYTES_REV_COLUMN,
    AVG_BYTES_REV_COLUMN,
    TOT_BYTES_COLUMN,
    AVG_BYTES_COLUMN,
    N_COLUMN /* The number of columns */
};

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
                               G_TYPE_UINT,     /* ID               */
                               G_TYPE_STRING,   /* Operation Code   */
                               G_TYPE_INT,      /* Invokes          */
                               G_TYPE_INT,      /* Num Bytes        */
                               G_TYPE_FLOAT,    /* Avg Bytes        */
                               G_TYPE_INT,      /* RetResult        */
                               G_TYPE_INT,      /* Num Bytes        */
                               G_TYPE_FLOAT,    /* Avg Bytes        */
                               G_TYPE_INT,      /* Total Bytes      */
                               G_TYPE_FLOAT);   /* Avg Bytes        */

    /* Create a view */
    list = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));

    list_view = GTK_TREE_VIEW(list);
    sortable = GTK_TREE_SORTABLE(list_store);

    /* Speed up the list display */
    gtk_tree_view_set_fixed_height_mode(list_view, TRUE);

    /* Setup the sortable columns */
    gtk_tree_sortable_set_sort_column_id(sortable, ID_COLUMN, GTK_SORT_ASCENDING);
    gtk_tree_view_set_headers_clickable(list_view, FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (list_store));

    /*
     * Create the first column packet, associating the "text" attribute of the
     * cell_renderer to the first column of the model
     */
    /* 1:st column */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("ID", renderer,
        "text", ID_COLUMN,
        NULL);

    gtk_tree_view_column_set_sort_column_id(column, ID_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 40);

    /* Add the column to the view. */
    gtk_tree_view_append_column (list_view, column);

    /* 2:nd column..Operation Code. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Operation Code", renderer,
        "text", OP_CODE_COLUMN,
        NULL);
    gtk_tree_view_column_set_sort_column_id(column, OP_CODE_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 210);
    gtk_tree_view_append_column (list_view, column);

    /* 3:d column..Invokes. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Invokes", renderer,
        "text", INVOKES_COLUMN,
        NULL);
    gtk_tree_view_column_set_sort_column_id(column, INVOKES_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 60);
    gtk_tree_view_append_column (list_view, column);

    /* 4:th column.. Num Bytes. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Num Bytes", renderer,
        "text", NUM_BYTES_FWD_COLUMN,
        NULL);


    gtk_tree_view_column_set_sort_column_id(column, NUM_BYTES_FWD_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 5:th column.. Avg Bytes. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Avg Bytes", renderer,
        "text", AVG_BYTES_FWD_COLUMN,
        NULL);
    gtk_tree_view_column_set_cell_data_func(column, renderer, float_data_func,
        GINT_TO_POINTER(AVG_BYTES_FWD_COLUMN), NULL);

    gtk_tree_view_column_set_sort_column_id(column, AVG_BYTES_FWD_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (list_view, column);

    /* 6:d column..Invokes. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("ReturnResult", renderer,
        "text", RET_RES_COLUMN,
        NULL);
    gtk_tree_view_column_set_sort_column_id(column, RET_RES_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 60);
    gtk_tree_view_append_column (list_view, column);

    /* 7:th column.. Num Bytes. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Num Bytes", renderer,
        "text", NUM_BYTES_REV_COLUMN,
        NULL);


    gtk_tree_view_column_set_sort_column_id(column, NUM_BYTES_FWD_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 8:th column.. Avg Bytes. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Avg Bytes", renderer,
        "text", AVG_BYTES_REV_COLUMN,
        NULL);
    gtk_tree_view_column_set_cell_data_func(column, renderer, float_data_func,
        GINT_TO_POINTER(AVG_BYTES_REV_COLUMN), NULL);


    gtk_tree_view_column_set_sort_column_id(column, AVG_BYTES_REV_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (list_view, column);

    /* 9:th column.. Total Bytes. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Total Bytes", renderer,
        "text", TOT_BYTES_COLUMN,
        NULL);


    gtk_tree_view_column_set_sort_column_id(column, NUM_BYTES_FWD_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 10:th column.. Avg Bytes. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Avg Bytes", renderer,
        "text", AVG_BYTES_COLUMN,
        NULL);
    gtk_tree_view_column_set_cell_data_func(column, renderer, float_data_func,
        GINT_TO_POINTER(AVG_BYTES_COLUMN), NULL);

    gtk_tree_view_column_set_sort_column_id(column, AVG_BYTES_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 60);
    gtk_tree_view_append_column (list_view, column);

    /* Now enable the sorting of each column */
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(list_view), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(list_view), TRUE);

    /* Setup the selection handler */
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
    gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

    return list;

}

typedef struct _gsm_map_stat_dlg_t {
    GtkWidget       *win;
    GtkWidget       *scrolled_win;
    GtkWidget       *table;
} gsm_map_stat_dlg_t;

static gsm_map_stat_dlg_t   dlg;

/*
 * used by gsm_map_summary.c
 */
gsm_map_stat_t          gsm_map_stat;


static void
gsm_map_stat_reset(
    void        *tapdata)
{
    gsm_map_stat_t  *stat_p = tapdata;

    memset(stat_p, 0, sizeof(gsm_map_stat_t));
}


static gboolean
gsm_map_stat_packet(
    void            *tapdata,
    packet_info     *pinfo _U_,
    epan_dissect_t  *edt _U_,
    const void      *data)
{
    gsm_map_stat_t  *stat_p = tapdata;
    const gsm_map_tap_rec_t *data_p = data;

#if 0   /* always false because message_type is 8 bit value */
    if (data_p->opr_code_idx > sizeof(stat_p->opr_code))
    {
    /*
     * unknown message type !!!
     */
        return(FALSE);
    }
#endif

    if (data_p->invoke)
    {
        stat_p->opr_code[data_p->opr_code_idx]++;
        stat_p->size[data_p->opr_code_idx] += data_p->size;
    }
    else
    {
        stat_p->opr_code_rr[data_p->opr_code_idx]++;
        stat_p->size_rr[data_p->opr_code_idx] += data_p->size;
    }

    return(TRUE);
}


static void
gsm_map_stat_draw(
    void        *tapdata)
{
    gsm_map_stat_t  *stat_p = tapdata;
    int         i;
    GtkListStore *list_store;
    GtkTreeIter  iter;

    if (dlg.win && tapdata)
    {
        list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (dlg.table))); /* Get store */

        i = 0;
        while (gsm_map_opr_code_strings[i].strptr){
            float avrage_bytes_fwd;
            float avrage_bytes_rev;
            float avrage_bytes_tot;

            if (stat_p->opr_code[i] >0){
                avrage_bytes_fwd =(float)stat_p->size[i]/(float)stat_p->opr_code[i];
            }else{
                avrage_bytes_fwd = 0;
            }
            if (stat_p->opr_code_rr[i] >0){
                avrage_bytes_rev = (float)stat_p->size_rr[i]/(float)stat_p->opr_code_rr[i];
            }else{
                avrage_bytes_rev = 0;
            }
            if ((stat_p->opr_code[i] + stat_p->opr_code_rr[i])>0){
                avrage_bytes_tot = (float)(stat_p->size[i] +stat_p->size_rr[i])/(float)(stat_p->opr_code[i] + stat_p->opr_code_rr[i]);
            }else{
                avrage_bytes_tot = 0;
            }
            /* Creates a new row at position. iter will be changed to point to this new row.
             * If position is larger than the number of rows on the list, then the new row will be appended to the list.
             * The row will be filled with the values given to this function.
             * :
             * should generally be preferred when inserting rows in a sorted list store.
             */
            gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
                   ID_COLUMN,               gsm_map_opr_code_strings[i].value,
                   OP_CODE_COLUMN,          (char*)gsm_map_opr_code_strings[i].strptr,
                   INVOKES_COLUMN,          stat_p->opr_code[i],
                   NUM_BYTES_FWD_COLUMN,    (gint)stat_p->size[i],
                   AVG_BYTES_FWD_COLUMN,    avrage_bytes_fwd,
                   RET_RES_COLUMN,          stat_p->opr_code_rr[i],
                   NUM_BYTES_REV_COLUMN,    stat_p->size_rr[i],
                   AVG_BYTES_REV_COLUMN,    avrage_bytes_rev,
                   TOT_BYTES_COLUMN,        stat_p->size[i] + stat_p->size_rr[i],
                   AVG_BYTES_COLUMN,        avrage_bytes_tot,
                   -1);
            i++;
        }
    }
}

static void
gsm_map_stat_gtk_win_destroy_cb(
    GtkWindow       *win _U_,
    gpointer        user_data)
{
    memset((void *) user_data, 0, sizeof(gsm_map_stat_dlg_t));
}


static void
gsm_map_stat_gtk_win_create(
    gsm_map_stat_dlg_t  *dlg_p,
    const char          *title)
{
    GtkWidget       *vbox;
    GtkWidget       *bt_close;
    GtkWidget       *bbox;


    dlg_p->win = dlg_window_new(title);  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(dlg_p->win), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dlg_p->win), 560, 390);

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

    bt_close = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(dlg_p->win, bt_close, window_cancel_button_cb);

    g_signal_connect(dlg_p->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(dlg_p->win, "destroy", G_CALLBACK(gsm_map_stat_gtk_win_destroy_cb), dlg_p);

    gtk_widget_show_all(dlg_p->win);
    window_present(dlg_p->win);
}

void
gsm_map_stat_gtk_cb(GtkAction *action _U_, gpointer user_data _U_)
{


    /*
     * if the window is already open, bring it to front
     */
    if (dlg.win){
        gdk_window_raise(gtk_widget_get_window(dlg.win));
        return;
    }

    gsm_map_stat_gtk_win_create(&dlg, "GSM MAP Operation Statistics");

    gsm_map_stat_draw(&gsm_map_stat);
}


static void
gsm_map_stat_gtk_init(const char        *opt_arg _U_,
                      void* userdata _U_)
{
    gsm_map_stat_gtk_cb(NULL, NULL);
}


void
register_tap_listener_gtkgsm_map_stat(void)
{
    GString     *err_p;


    memset((void *) &gsm_map_stat, 0, sizeof(gsm_map_stat_t));

    err_p =
    register_tap_listener("gsm_map", &gsm_map_stat, NULL, 0,
        gsm_map_stat_reset,
        gsm_map_stat_packet,
        gsm_map_stat_draw);

    if (err_p != NULL)
    {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_p->str);
        g_string_free(err_p, TRUE);

        exit(1);
    }

    register_stat_cmd_arg("gsm_map", gsm_map_stat_gtk_init,NULL);
}
