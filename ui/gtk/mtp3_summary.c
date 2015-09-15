/* mtp3_summary.c
 * Routines for MTP3 Statictics summary window
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Modified from gsm_map_summary.c
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

#include "config.h"

#include <stdlib.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/stat_groups.h>
#include <epan/tap.h>
#include <epan/value_string.h>

#include <epan/dissectors/packet-mtp3.h>

#include "globals.h"
#include "summary.h"

#include "ui/simple_dialog.h"

#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"

void register_tap_listener_gtk_mtp3_summary(void);

#define SUM_STR_MAX 1024

typedef struct _mtp3_stat_si_code_t {
    int			num_msus;
    int			size;
} mtp3_stat_si_code_t;

typedef struct _mtp3_stat_t {
    mtp3_addr_pc_t		addr_opc;
    mtp3_addr_pc_t		addr_dpc;
    mtp3_stat_si_code_t		mtp3_si_code[MTP3_NUM_SI_CODE];
} mtp3_stat_t;

typedef struct _my_columns_t {
    guint32           value;
    const gchar      *strptr;
    GtkJustification  just;
} my_columns_t;

enum
{
    SI_COLUMN,
    NUM_MSUS_COLUMN,
    NUM_MSUS_SEC_COLUMN,
    NUM_BYTES_COLUMN,
    NUM_BYTES_MSU_COLUMN,
    NUM_BYTES_SEC_COLUMN,
    N_COLUMN /* The number of columns */
};

/*
 * I don't like it but I don't have time to create
 * the code for a dynamic size solution
 */
#define	MTP3_MAX_NUM_OPC_DPC	50

static mtp3_stat_t     mtp3_stat[MTP3_MAX_NUM_OPC_DPC];
static guint8          mtp3_num_used;

/* Create list */
static GtkWidget *
create_list(void)
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
                               G_TYPE_STRING,   /* SI               */
                               G_TYPE_INT,      /* Num MSUs         */
                               G_TYPE_STRING,   /* MSUs/sec         */
                               G_TYPE_INT,      /* Num Bytes        */
                               G_TYPE_STRING,   /* Bytes/MSU        */
                               G_TYPE_STRING);  /* Bytes/sec        */

    /* Create a view */
    list = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));

    list_view = GTK_TREE_VIEW(list);
    sortable = GTK_TREE_SORTABLE(list_store);

    /* Speed up the list display */
    gtk_tree_view_set_fixed_height_mode(list_view, TRUE);

    /* Setup the sortable columns */
    gtk_tree_sortable_set_sort_column_id(sortable, SI_COLUMN, GTK_SORT_ASCENDING);
    gtk_tree_view_set_headers_clickable(list_view, FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (list_store));

    /*
     * Create the first column packet, associating the "text" attribute of the
     * cell_renderer to the first column of the model
     */
    /* 1:st column */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("SI", renderer,
                "text", SI_COLUMN,
                NULL);

    gtk_tree_view_column_set_sort_column_id(column, SI_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 110);

    /* Add the column to the view. */
    gtk_tree_view_append_column (list_view, column);

    /* 2:nd column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Num MSUs", renderer,
                "text", NUM_MSUS_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, NUM_MSUS_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 3:d column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("MSUs/sec", renderer,
                "text", NUM_MSUS_SEC_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, NUM_MSUS_SEC_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 4:d column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Num Bytes", renderer,
                "text", NUM_BYTES_COLUMN,
                NULL);
    gtk_tree_view_column_set_sort_column_id(column, NUM_BYTES_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 5:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Bytes/MSU", renderer,
                "text", NUM_BYTES_MSU_COLUMN,
                NULL);


    gtk_tree_view_column_set_sort_column_id(column, NUM_BYTES_MSU_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column (list_view, column);

    /* 6:th column... */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Bytes/sec", renderer,
                "text", NUM_BYTES_SEC_COLUMN,
                NULL);

    gtk_tree_view_column_set_sort_column_id(column, NUM_BYTES_SEC_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
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
add_string_to_box(gchar *str, GtkWidget *box)
{
    GtkWidget *lb;
    lb = gtk_label_new(str);
    gtk_misc_set_alignment(GTK_MISC(lb), 0.0f, 0.5f);
    gtk_box_pack_start(GTK_BOX(box), lb,FALSE,FALSE, 0);
    gtk_widget_show(lb);
}



static void
mtp3_sum_draw(
    GtkWidget *table,
    double     seconds,
    int       *tot_num_msus_p,
    double    *tot_num_bytes_p)
{
    char         *entries[N_COLUMN];
    int           i, j;
    int           num_msus;
    int           num_bytes;
    GtkListStore *list_store;
    GtkTreeIter   iter;

    *tot_num_msus_p = 0;
    *tot_num_bytes_p = 0;

    list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (table))); /* Get store */

    for (i=0; i < MTP3_NUM_SI_CODE; i++)
    {
        j = 0;
        num_msus = 0;
        num_bytes = 0;

        while (j < mtp3_num_used)
        {
            num_msus += mtp3_stat[j].mtp3_si_code[i].num_msus;
            num_bytes += mtp3_stat[j].mtp3_si_code[i].size;

            j++;
        }

        *tot_num_msus_p += num_msus;
        *tot_num_bytes_p += num_bytes;

        entries[2] = (seconds) ? g_strdup_printf("%.2f", (double)num_msus/seconds) : g_strdup("N/A");
        entries[4] = (num_msus) ? g_strdup_printf("%.2f", (double)num_bytes/num_msus) : g_strdup("N/A");
        entries[5] = (seconds) ? g_strdup_printf("%.2f", (double)num_bytes/seconds) : g_strdup("N/A");

        gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
                                           SI_COLUMN, mtp3_service_indicator_code_short_vals[i].strptr,
                                           NUM_MSUS_COLUMN, num_msus,
                                           NUM_MSUS_SEC_COLUMN, entries[2],
                                           NUM_BYTES_COLUMN, num_bytes,
                                           NUM_BYTES_MSU_COLUMN, entries[4],
                                           NUM_BYTES_SEC_COLUMN, entries[5],
                                           -1);

        g_free(entries[2]);
        g_free(entries[4]);
        g_free(entries[5]);
    }
}


void
mtp3_sum_gtk_sum_cb(GtkAction *action _U_, gpointer user_data _U_)
{
    summary_tally  summary;
    GtkWidget     *sum_open_w;
    GtkWidget     *main_vb, *file_fr, *data_fr, *file_box;
    GtkWidget     *data_box, *bbox, *close_bt;
    GtkWidget     *tot_fr, *tot_box;
    GtkWidget     *table, *table_fr;

    gchar          string_buff[SUM_STR_MAX];
    const char    *file_type;
    double         seconds;
    int            tot_num_msus;
    double         tot_num_bytes;

    if (cfile.state == FILE_CLOSED) {
        return;
    }

    /* initialize the tally */
    summary_fill_in(&cfile, &summary);

    /* initial computations */
    seconds = summary.stop_time - summary.start_time;

    sum_open_w = dlg_window_new("MTP3 Statistics: Summary");  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(sum_open_w), TRUE);

    /* Container for each row of widgets */
    main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(sum_open_w), main_vb);
    gtk_widget_show(main_vb);

    /* File frame */
    file_fr = gtk_frame_new("File");
    gtk_box_pack_start(GTK_BOX(main_vb), file_fr, TRUE, TRUE, 0);
    gtk_widget_show(file_fr);

    file_box = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
    gtk_container_add(GTK_CONTAINER(file_fr), file_box);
    gtk_widget_show(file_box);

    /* filename */
    g_snprintf(string_buff, SUM_STR_MAX, "Name: %s", ((summary.filename) ? summary.filename : "None"));
    add_string_to_box(string_buff, file_box);

    /* length */
    g_snprintf(string_buff, SUM_STR_MAX, "Length: %" G_GINT64_MODIFIER "d", summary.file_length);
    add_string_to_box(string_buff, file_box);

    /* format */
    file_type = wtap_file_type_subtype_string(summary.file_type);
    g_snprintf(string_buff, SUM_STR_MAX, "Format: %s", (file_type ? file_type : "N/A"));
    add_string_to_box(string_buff, file_box);

    if (summary.has_snap) {
        /* snapshot length */
        g_snprintf(string_buff, SUM_STR_MAX, "Snapshot length: %u", summary.snap);
        add_string_to_box(string_buff, file_box);
    }

    /* Data frame */
    data_fr = gtk_frame_new("Data");
    gtk_box_pack_start(GTK_BOX(main_vb), data_fr, TRUE, TRUE, 0);
    gtk_widget_show(data_fr);

    data_box = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
    gtk_container_add(GTK_CONTAINER(data_fr), data_box);
    gtk_widget_show(data_box);

    /*
     * We must have no un-time-stamped packets (i.e., the number of
     * time-stamped packets must be the same as the number of packets),
     * and at least two time-stamped packets, in order for the elapsed
     * time to be valid.
     */
    if (summary.packet_count_ts == summary.packet_count &&
        summary.packet_count_ts >= 2) {
        /* seconds */
        g_snprintf(string_buff, SUM_STR_MAX, "Elapsed time: %.3f seconds", summary.elapsed_time);
        add_string_to_box(string_buff, data_box);

        g_snprintf(string_buff, SUM_STR_MAX, "Between first and last packet: %.3f seconds", seconds);
        add_string_to_box(string_buff, data_box);
    }

    /* Packet count */
    g_snprintf(string_buff, SUM_STR_MAX, "Packet count: %i", summary.packet_count);
    add_string_to_box(string_buff, data_box);

    /* MTP3 SPECIFIC */
    table_fr = gtk_frame_new("Service Indicator (SI) Totals");
    gtk_box_pack_start(GTK_BOX(main_vb), table_fr, TRUE, TRUE, 0);
    gtk_widget_show(table_fr);

    table = create_list();

    gtk_container_add(GTK_CONTAINER(table_fr), table);
    gtk_widget_show(table);


    mtp3_sum_draw(table, seconds, &tot_num_msus, &tot_num_bytes);

    /* Totals frame */
    tot_fr = gtk_frame_new("Totals");
    gtk_box_pack_start(GTK_BOX(main_vb), tot_fr, TRUE, TRUE, 0);
    gtk_widget_show(tot_fr);

    tot_box = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
    gtk_container_add(GTK_CONTAINER(tot_fr), tot_box);
    gtk_widget_show(tot_box);

    g_snprintf(string_buff, SUM_STR_MAX, "Total MSUs: %u", tot_num_msus);
    add_string_to_box(string_buff, tot_box);

    /*
     * We must have no un-time-stamped packets (i.e., the number of
     * time-stamped packets must be the same as the number of packets),
     * and at least two time-stamped packets, in order for the elapsed
     * time to be valid.
     */
    if (summary.packet_count_ts == summary.packet_count &&
        summary.packet_count_ts >= 2) {
        if (seconds) {
            g_snprintf(string_buff, SUM_STR_MAX, "MSUs/second: %.2f", tot_num_msus/seconds);
        }
        else {
            g_snprintf(string_buff, SUM_STR_MAX, "MSUs/second: N/A");
        }
        add_string_to_box(string_buff, tot_box);
    }

    g_snprintf(string_buff, SUM_STR_MAX, "Total Bytes: %.0f", tot_num_bytes);
    add_string_to_box(string_buff, tot_box);

    if (tot_num_msus) {
        g_snprintf(string_buff, SUM_STR_MAX, "Average Bytes/MSU: %.2f", tot_num_bytes/tot_num_msus);
    }
    else {
        g_snprintf(string_buff, SUM_STR_MAX, "Average Bytes/MSU: N/A");
    }
    add_string_to_box(string_buff, tot_box);

    /*
     * We must have no un-time-stamped packets (i.e., the number of
     * time-stamped packets must be the same as the number of packets),
     * and at least two time-stamped packets, in order for the elapsed
     * time to be valid.
     */
    if (summary.packet_count_ts == summary.packet_count &&
        summary.packet_count_ts >= 2) {
        if (seconds) {
            g_snprintf(string_buff, SUM_STR_MAX, "Bytes/second: %.2f", tot_num_bytes/seconds);
        }
        else {
            g_snprintf(string_buff, SUM_STR_MAX, "Bytes/second: N/A");
        }
        add_string_to_box(string_buff, tot_box);
    }

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(sum_open_w, close_bt, window_cancel_button_cb);

    g_signal_connect(sum_open_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

    gtk_widget_show_all(sum_open_w);
    window_present(sum_open_w);
}

static void
mtp3_summary_reset(
    void        *tapdata)
{
    mtp3_stat_t     (*stat_p)[MTP3_MAX_NUM_OPC_DPC] = (mtp3_stat_t(*)[MTP3_MAX_NUM_OPC_DPC])tapdata;

    mtp3_num_used = 0;
    memset(stat_p, 0, MTP3_MAX_NUM_OPC_DPC * sizeof(mtp3_stat_t));
}


static gboolean
mtp3_summary_packet(
    void            *tapdata,
    packet_info     *pinfo _U_,
    epan_dissect_t  *edt _U_,
    const void      *data)
{
    mtp3_stat_t           (*stat_p)[MTP3_MAX_NUM_OPC_DPC] = (mtp3_stat_t(*)[MTP3_MAX_NUM_OPC_DPC])tapdata;
    const mtp3_tap_rec_t  *data_p = (const mtp3_tap_rec_t *)data;
    int                    i;

    if (data_p->mtp3_si_code >= MTP3_NUM_SI_CODE)
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
    (*stat_p)[i].mtp3_si_code[data_p->mtp3_si_code].num_msus++;
    (*stat_p)[i].mtp3_si_code[data_p->mtp3_si_code].size += data_p->size;

    return(TRUE);
}

void
register_tap_listener_gtk_mtp3_summary(void)
{
    GString     *err_p;

    memset((void *) &mtp3_stat, 0, sizeof(mtp3_stat));

    err_p =
    register_tap_listener("mtp3", &mtp3_stat, NULL, 0,
        mtp3_summary_reset,
        mtp3_summary_packet,
        NULL);

    if (err_p != NULL)
    {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "%s", err_p->str);
        g_string_free(err_p, TRUE);

        exit(1);
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
