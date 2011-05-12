/* gsm_a_stat.c
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * This TAP provides statistics for the GSM A-Interface:
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <string.h>

#include <gtk/gtk.h>

#include "epan/packet_info.h"
#include "epan/epan.h"
#include "epan/value_string.h"
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-bssap.h>
#include <epan/dissectors/packet-gsm_a_common.h>

#include "../stat_menu.h"
#include "../simple_dialog.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/dlg_utils.h"
#include "gtk/filter_dlg.h"
#include "gtk/gui_utils.h"

enum
{
    IEI_COLUMN,
    MSG_NAME_COLUMN,
    COUNT_COLUMN,
    N_COLUMN /* The number of columns */
};

typedef struct _gsm_a_stat_dlg_t {
    GtkWidget       *win;
    GtkWidget       *scrolled_win;
    GtkWidget       *table;
} gsm_a_stat_dlg_t;

typedef struct _gsm_a_stat_t {
    int     bssmap_message_type[0xff];
    int     dtap_mm_message_type[0xff];
    int     dtap_rr_message_type[0xff];
    int     dtap_cc_message_type[0xff];
    int     dtap_gmm_message_type[0xff];
    int     dtap_sms_message_type[0xff];
    int     dtap_sm_message_type[0xff];
    int     dtap_ss_message_type[0xff];
    int     dtap_tp_message_type[0xff];
    int     sacch_rr_message_type[0xff];
} gsm_a_stat_t;


static gsm_a_stat_dlg_t     dlg_bssmap;
static gsm_a_stat_dlg_t     dlg_dtap_mm;
static gsm_a_stat_dlg_t     dlg_dtap_rr;
static gsm_a_stat_dlg_t     dlg_dtap_cc;
static gsm_a_stat_dlg_t     dlg_dtap_gmm;
static gsm_a_stat_dlg_t     dlg_dtap_sms;
static gsm_a_stat_dlg_t     dlg_dtap_sm;
static gsm_a_stat_dlg_t     dlg_dtap_ss;
static gsm_a_stat_dlg_t     dlg_dtap_tp;
static gsm_a_stat_dlg_t     dlg_sacch_rr;
static gsm_a_stat_t         gsm_a_stat;

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
    list_store = gtk_list_store_new(N_COLUMN,   /* Total number of columns XXX*/
                               G_TYPE_UINT,     /* IEI              */
                               G_TYPE_STRING,   /* Message Name     */
                               G_TYPE_UINT);    /* Count            */

    /* Create a view */
    list = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));

    list_view = GTK_TREE_VIEW(list);
    sortable = GTK_TREE_SORTABLE(list_store);

#if GTK_CHECK_VERSION(2,6,0)
    /* Speed up the list display */
    gtk_tree_view_set_fixed_height_mode(list_view, TRUE);
#endif

    /* Setup the sortable columns */
    gtk_tree_sortable_set_sort_column_id(sortable, IEI_COLUMN, GTK_SORT_ASCENDING);
    gtk_tree_view_set_headers_clickable(list_view, FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (list_store));

    /*
     * Create the first column packet, associating the "text" attribute of the
     * cell_renderer to the first column of the model
     */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("IEI", renderer,
        "text", IEI_COLUMN,
        NULL);

    /* gtk_tree_view_column_set_cell_data_func(column, renderer, present_as_hex_func,
        GINT_TO_POINTER(IEI_COLUMN), NULL);
        */

    gtk_tree_view_column_set_sort_column_id(column, IEI_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 50);

    /* Add the column to the view. */
    gtk_tree_view_append_column (list_view, column);

    /* Second column.. Message Name. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Message Name", renderer,
        "text", MSG_NAME_COLUMN,
        NULL);
    gtk_tree_view_column_set_sort_column_id(column, MSG_NAME_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 280);
    gtk_tree_view_append_column (list_view, column);

    /* Third column.. Count. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Count", renderer,
        "text", COUNT_COLUMN,
        NULL);


    gtk_tree_view_column_set_sort_column_id(column, COUNT_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 50);
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
gsm_a_stat_reset(
    void        *tapdata)
{
    gsm_a_stat_t    *stat_p = tapdata;

    memset(stat_p, 0, sizeof(gsm_a_stat_t));
}


static gboolean
gsm_a_stat_packet(
    void        *tapdata,
    packet_info     *pinfo _U_,
    epan_dissect_t  *edt _U_,
    const void      *data)
{
    gsm_a_stat_t    *stat_p = tapdata;
    const gsm_a_tap_rec_t   *data_p = data;

    switch (data_p->pdu_type)
    {
    case BSSAP_PDU_TYPE_BSSMAP:
        stat_p->bssmap_message_type[data_p->message_type]++;
        break;

    case BSSAP_PDU_TYPE_DTAP:
        switch (data_p->protocol_disc)
        {
        case PD_CC:
            stat_p->dtap_cc_message_type[data_p->message_type]++;
            break;
        case PD_MM:
            stat_p->dtap_mm_message_type[data_p->message_type]++;
            break;
        case PD_RR:
            stat_p->dtap_rr_message_type[data_p->message_type]++;
            break;
        case PD_GMM:
            stat_p->dtap_gmm_message_type[data_p->message_type]++;
            break;
        case PD_SMS:
            stat_p->dtap_sms_message_type[data_p->message_type]++;
            break;
        case PD_SM:
            stat_p->dtap_sm_message_type[data_p->message_type]++;
            break;
        case PD_SS:
            stat_p->dtap_ss_message_type[data_p->message_type]++;
            break;
        case PD_TP:
            stat_p->dtap_tp_message_type[data_p->message_type]++;
            break;
        default:
            /*
             * unsupported PD
             */
            return(FALSE);
    }
    break;

    case GSM_A_PDU_TYPE_SACCH:
        switch (data_p->protocol_disc)
        {
        case 0:
            stat_p->sacch_rr_message_type[data_p->message_type]++;
            break;
        default:
            /* unknown Short PD */
            break;
        }
        break;

    default:
    /*
     * unknown PDU type !!!
     */
    return(FALSE);
    }

    return(TRUE);
}


static void
gsm_a_stat_draw_aux(
    gsm_a_stat_dlg_t    *dlg_p,
    int                 *message_count,
    const value_string  *msg_strings)
{
    GtkListStore *list_store;
    GtkTreeIter  iter;
    int          i;


    if (dlg_p->win != NULL){
        i = 0;
        list_store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (dlg_p->table))); /* Get store */

        while (msg_strings[i].strptr){
            /* Creates a new row at position. iter will be changed to point to this new row.
             * If position is larger than the number of rows on the list, then the new row will be appended to the list.
             * The row will be filled with the values given to this function.
             * :
             * should generally be preferred when inserting rows in a sorted list store.
             */
#if GTK_CHECK_VERSION(2,6,0)
            gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
#else
            gtk_list_store_append  (list_store, &iter);
            gtk_list_store_set  (list_store, &iter,
#endif
                    IEI_COLUMN, msg_strings[i].value,
                    MSG_NAME_COLUMN, (char *)msg_strings[i].strptr,
                    COUNT_COLUMN, message_count[msg_strings[i].value],
                    -1);
            i++;
        }
    }
}

static void
gsm_a_stat_draw(
    void        *tapdata)
{
    gsm_a_stat_t    *stat_p = tapdata;

    if (!tapdata) return;

    if (dlg_bssmap.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_bssmap,
            stat_p->bssmap_message_type,
            gsm_a_bssmap_msg_strings);
    }

    if (dlg_dtap_mm.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_dtap_mm,
            stat_p->dtap_mm_message_type,
            gsm_a_dtap_msg_mm_strings);
    }

    if (dlg_dtap_rr.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_dtap_rr,
            stat_p->dtap_rr_message_type,
            gsm_a_dtap_msg_rr_strings);
    }

    if (dlg_dtap_cc.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_dtap_cc,
            stat_p->dtap_cc_message_type,
            gsm_a_dtap_msg_cc_strings);
    }

    if (dlg_dtap_gmm.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_dtap_gmm,
            stat_p->dtap_gmm_message_type,
            gsm_a_dtap_msg_gmm_strings);
    }

    if (dlg_dtap_sms.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_dtap_sms,
            stat_p->dtap_sms_message_type,
            gsm_a_dtap_msg_sms_strings);
    }

    if (dlg_dtap_sm.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_dtap_sm,
            stat_p->dtap_sm_message_type,
            gsm_a_dtap_msg_sm_strings);
    }

    if (dlg_dtap_ss.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_dtap_ss,
            stat_p->dtap_ss_message_type,
            gsm_a_dtap_msg_ss_strings);
    }

    if (dlg_dtap_tp.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_dtap_tp,
            stat_p->dtap_tp_message_type,
            gsm_a_dtap_msg_tp_strings);
    }

    if (dlg_sacch_rr.win != NULL)
    {
        gsm_a_stat_draw_aux(&dlg_sacch_rr,
            stat_p->sacch_rr_message_type,
            gsm_a_sacch_msg_rr_strings);
    }
}



static void
gsm_a_stat_gtk_win_destroy_cb(
    GtkWindow       *win _U_,
    gpointer        user_data)
{
    memset((void *) user_data, 0, sizeof(gsm_a_stat_dlg_t));
}


static void
gsm_a_stat_gtk_win_create(
    gsm_a_stat_dlg_t    *dlg_p,
    const char      *title)
{
    GtkWidget       *vbox;
    GtkWidget       *bt_close;
    GtkWidget       *bbox;


    dlg_p->win = dlg_window_new(title);  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(dlg_p->win), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dlg_p->win), 490, 500);

    vbox = gtk_vbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(dlg_p->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    dlg_p->scrolled_win = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), dlg_p->scrolled_win, TRUE, TRUE, 0);

    dlg_p->table = create_list();
    gtk_container_add(GTK_CONTAINER(dlg_p->scrolled_win), dlg_p->table);

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    bt_close = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(dlg_p->win, bt_close, window_cancel_button_cb);

    g_signal_connect(dlg_p->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(dlg_p->win, "destroy", G_CALLBACK(gsm_a_stat_gtk_win_destroy_cb), dlg_p);

    gtk_widget_show_all(dlg_p->win);
    window_present(dlg_p->win);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void gsm_a_stat_gtk_bssmap_cb(GtkAction *action, gpointer user_data )
#else
static void
gsm_a_stat_gtk_bssmap_cb(
    GtkWidget      *w _U_,
    gpointer        d _U_)
#endif
{
 /*   int           i;*/


    /*
     * if the window is already open, bring it to front
     */
    if (dlg_bssmap.win)
    {
    gdk_window_raise(dlg_bssmap.win->window);
    return;
    }

    gsm_a_stat_gtk_win_create(&dlg_bssmap, "GSM A-I/F BSSMAP Statistics");
    gsm_a_stat_draw(&gsm_a_stat);
}


static void
gsm_a_stat_gtk_bssmap_init(
    const char      *optarg _U_,
    void* userdata _U_)
{
    gsm_a_stat_gtk_bssmap_cb(NULL, NULL);
}

#ifdef MAIN_MENU_USE_UIMANAGER
static void
gsm_a_stat_gtk_dtap_cb(
    GtkAction *action _U_,
    gpointer user_data _U_,
    gsm_a_stat_dlg_t    *dlg_dtap_p,
    const char      *title,
    const value_string  *dtap_msg_strings _U_)
#else
static void
gsm_a_stat_gtk_dtap_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_,
    gsm_a_stat_dlg_t    *dlg_dtap_p,
    const char      *title,
    const value_string  *dtap_msg_strings _U_)
#endif
{

    /*
     * if the window is already open, bring it to front
     */
    if (dlg_dtap_p->win)
    {
    gdk_window_raise(dlg_dtap_p->win->window);
    return;
    }

    gsm_a_stat_gtk_win_create(dlg_dtap_p, title);

    gsm_a_stat_draw(&gsm_a_stat);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void 
gsm_a_stat_gtk_dtap_mm_cb(GtkAction *action, gpointer user_data )
{
    gsm_a_stat_gtk_dtap_cb(action, user_data, &dlg_dtap_mm,
    "GSM A-I/F DTAP Mobility Management Statistics",
    gsm_a_dtap_msg_mm_strings);
}
#else
static void
gsm_a_stat_gtk_dtap_mm_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_)
{
    gsm_a_stat_gtk_dtap_cb(action, user_data, &dlg_dtap_mm,
    "GSM A-I/F DTAP Mobility Management Statistics",
    gsm_a_dtap_msg_mm_strings);
}
#endif
static void
gsm_a_stat_gtk_dtap_mm_init(const char      *optarg _U_,
                            void* userdata _U_)
{
    gsm_a_stat_gtk_dtap_mm_cb(NULL, NULL);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
gsm_a_stat_gtk_dtap_rr_cb(GtkAction *action, gpointer user_data )
{
    gsm_a_stat_gtk_dtap_cb(action, user_data, &dlg_dtap_rr,
    "GSM A-I/F DTAP Radio Resource Management Statistics",
    gsm_a_dtap_msg_rr_strings);
}
#else
static void
gsm_a_stat_gtk_dtap_rr_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_rr,
    "GSM A-I/F DTAP Radio Resource Management Statistics",
    gsm_a_dtap_msg_rr_strings);
}
#endif


static void
gsm_a_stat_gtk_dtap_rr_init(const char      *optarg _U_,
                            void* userdata _U_)
{
    gsm_a_stat_gtk_dtap_rr_cb(NULL, NULL);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
gsm_a_stat_gtk_dtap_cc_cb(GtkAction *action, gpointer user_data )
{
    gsm_a_stat_gtk_dtap_cb(action, user_data, &dlg_dtap_cc,
    "GSM A-I/F DTAP Call Control Statistics",
    gsm_a_dtap_msg_cc_strings);
}
#else
static void
gsm_a_stat_gtk_dtap_cc_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_cc,
    "GSM A-I/F DTAP Call Control Statistics",
    gsm_a_dtap_msg_cc_strings);
}
#endif

static void
gsm_a_stat_gtk_dtap_cc_init(const char      *optarg _U_,
                            void* userdata _U_)
{
    gsm_a_stat_gtk_dtap_cc_cb(NULL, NULL);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
gsm_a_stat_gtk_dtap_gmm_cb(GtkAction *action, gpointer user_data )
{
    gsm_a_stat_gtk_dtap_cb(action, user_data, &dlg_dtap_gmm,
    "GSM A-I/F DTAP GPRS Mobility Management Statistics",
    gsm_a_dtap_msg_gmm_strings);
}

#else
static void
gsm_a_stat_gtk_dtap_gmm_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_gmm,
    "GSM A-I/F DTAP GPRS Mobility Management Statistics",
    gsm_a_dtap_msg_gmm_strings);
}
#endif

static void
gsm_a_stat_gtk_dtap_gmm_init(const char     *optarg _U_,
                             void* userdata _U_)
{
    gsm_a_stat_gtk_dtap_gmm_cb(NULL, NULL);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
gsm_a_stat_gtk_dtap_sms_cb(GtkAction *action, gpointer user_data )
{
    gsm_a_stat_gtk_dtap_cb(action, user_data, &dlg_dtap_sms,
    "GSM A-I/F DTAP Short Message Service Statistics",
    gsm_a_dtap_msg_sms_strings);
}
#else
static void
gsm_a_stat_gtk_dtap_sms_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_sms,
    "GSM A-I/F DTAP Short Message Service Statistics",
    gsm_a_dtap_msg_sms_strings);
}
#endif

static void
gsm_a_stat_gtk_dtap_sms_init(const char     *optarg _U_,
                             void* userdata _U_)
{
    gsm_a_stat_gtk_dtap_sms_cb(NULL, NULL);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
gsm_a_stat_gtk_dtap_sm_cb(GtkAction *action, gpointer user_data )
{
    gsm_a_stat_gtk_dtap_cb(action, user_data, &dlg_dtap_sm,
    "GSM A-I/F DTAP GPRS Session Management Statistics",
    gsm_a_dtap_msg_sm_strings);
}
#else
static void
gsm_a_stat_gtk_dtap_sm_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_sm,
    "GSM A-I/F DTAP GPRS Session Management Statistics",
    gsm_a_dtap_msg_sm_strings);
}
#endif

static void
gsm_a_stat_gtk_dtap_sm_init(const char      *optarg _U_,
                            void* userdata _U_)
{
    gsm_a_stat_gtk_dtap_sm_cb(NULL, NULL);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
gsm_a_stat_gtk_dtap_ss_cb(GtkAction *action, gpointer user_data )
{
    gsm_a_stat_gtk_dtap_cb(action, user_data, &dlg_dtap_ss,
    "GSM A-I/F DTAP Supplementary Services Statistics",
    gsm_a_dtap_msg_ss_strings);
}
#else
static void
gsm_a_stat_gtk_dtap_ss_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_ss,
    "GSM A-I/F DTAP Supplementary Services Statistics",
    gsm_a_dtap_msg_ss_strings);
}
#endif

static void
gsm_a_stat_gtk_dtap_ss_init(
    const char      *optarg _U_,
    void        *userdata _U_)
{
    gsm_a_stat_gtk_dtap_ss_cb(NULL, NULL);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
gsm_a_stat_gtk_dtap_tp_cb(GtkAction *action, gpointer user_data )
{
    gsm_a_stat_gtk_dtap_cb(action, user_data, &dlg_dtap_tp,
    "GSM A-I/F DTAP Special Conformance Testing Functions Statistics",
    gsm_a_dtap_msg_tp_strings);
}
#else
static void
gsm_a_stat_gtk_dtap_tp_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_tp,
    "GSM A-I/F DTAP Special Conformance Testing Functions Statistics",
    gsm_a_dtap_msg_tp_strings);
}
#endif

static void
gsm_a_stat_gtk_dtap_tp_init(
    const char      *optarg _U_,
    void        *userdata _U_)
{
    gsm_a_stat_gtk_dtap_tp_cb(NULL, NULL);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
gsm_a_stat_gtk_sacch_rr_cb(GtkAction *action _U_, gpointer user_data _U_ )
{

    /*
     * if the window is already open, bring it to front
     */
    if (dlg_sacch_rr.win)
    {
    gdk_window_raise(dlg_sacch_rr.win->window);
    return;
    }

    gsm_a_stat_gtk_win_create(&dlg_sacch_rr, "GSM A-I/F SACCH Statistics");
    gsm_a_stat_draw(&gsm_a_stat);
}
#else
static void
gsm_a_stat_gtk_sacch_rr_cb(
    GtkWidget       *w _U_,
    gpointer        d _U_)
{

    /*
     * if the window is already open, bring it to front
     */
    if (dlg_sacch_rr.win)
    {
    gdk_window_raise(dlg_sacch_rr.win->window);
    return;
    }

    gsm_a_stat_gtk_win_create(&dlg_sacch_rr, "GSM A-I/F SACCH Statistics");
    gsm_a_stat_draw(&gsm_a_stat);
}
#endif

static void
gsm_a_stat_gtk_sacch_rr_init(
    const char      *optarg _U_,
    void* userdata _U_)
{
    gsm_a_stat_gtk_sacch_rr_cb(NULL, NULL);
}

void
register_tap_listener_gtkgsm_a_stat(void)
{
    GString     *err_p;


    memset((void *) &gsm_a_stat, 0, sizeof(gsm_a_stat_t));

    err_p =
    register_tap_listener("gsm_a", &gsm_a_stat, NULL, 0,
        gsm_a_stat_reset,
        gsm_a_stat_packet,
        gsm_a_stat_draw);

    if (err_p != NULL)
    {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_p->str);
        g_string_free(err_p, TRUE);

        exit(1);
    }

#ifdef MAIN_MENU_USE_UIMANAGER
#else
    register_stat_menu_item("_GSM/A-Interface BSSMAP", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_bssmap_cb, NULL, NULL, NULL);
    register_stat_menu_item("_GSM/A-Interface DTAP/Mobility Management", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_dtap_mm_cb, NULL, NULL, NULL);
    register_stat_menu_item("_GSM/A-Interface DTAP/Radio Resource Management", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_dtap_rr_cb, NULL, NULL, NULL);
    register_stat_menu_item("_GSM/A-Interface DTAP/Call Control", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_dtap_cc_cb, NULL, NULL, NULL);
    register_stat_menu_item("_GSM/A-Interface DTAP/GPRS Mobility Management", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_dtap_gmm_cb, NULL, NULL, NULL);
    register_stat_menu_item("_GSM/A-Interface DTAP/Short Message Service", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_dtap_sms_cb, NULL, NULL, NULL);
    register_stat_menu_item("_GSM/A-Interface DTAP/GPRS Session Management", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_dtap_sm_cb, NULL, NULL, NULL);
    register_stat_menu_item("_GSM/A-Interface DTAP/Supplementary Services", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_dtap_ss_cb, NULL, NULL, NULL);
    register_stat_menu_item("_GSM/A-Interface DTAP/Special Conformance Testing Functions", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_dtap_tp_cb, NULL, NULL, NULL);
    register_stat_menu_item("_GSM/A-Interface SACCH", REGISTER_STAT_GROUP_TELEPHONY,
    gsm_a_stat_gtk_sacch_rr_cb, NULL, NULL, NULL);
#endif

    register_stat_cmd_arg("gsm_a,bssmap", gsm_a_stat_gtk_bssmap_init,NULL);

    register_stat_cmd_arg("gsm_a,dtap_mm", gsm_a_stat_gtk_dtap_mm_init,NULL);

    register_stat_cmd_arg("gsm_a,dtap_rr", gsm_a_stat_gtk_dtap_rr_init,NULL);

    register_stat_cmd_arg("gsm_a,dtap_cc", gsm_a_stat_gtk_dtap_cc_init,NULL);

    register_stat_cmd_arg("gsm_a,dtap_gmm", gsm_a_stat_gtk_dtap_gmm_init,NULL);

    register_stat_cmd_arg("gsm_a,dtap_sms", gsm_a_stat_gtk_dtap_sms_init,NULL);

    register_stat_cmd_arg("gsm_a,dtap_sm", gsm_a_stat_gtk_dtap_sm_init,NULL);

    register_stat_cmd_arg("gsm_a,dtap_ss", gsm_a_stat_gtk_dtap_ss_init,NULL);

    register_stat_cmd_arg("gsm_a,dtap_tp", gsm_a_stat_gtk_dtap_tp_init,NULL);

    register_stat_cmd_arg("gsm_a,sacch", gsm_a_stat_gtk_sacch_rr_init,NULL);
}
