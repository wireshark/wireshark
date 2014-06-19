/* lbm_stream_dlg.c
 * Routines for LBMC stream dialog
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
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
#include <glib.h>
#include <epan/to_str.h>
#include <stat_menu.h>
#include <epan/funnel.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/wmem/wmem.h>
#include <gtk/gtk.h>
#include <ui/gtk/gui_utils.h>
#include <ui/gtk/dlg_utils.h>
#include <cfile.h>
#include <globals.h>
#include <epan/dissectors/packet-lbm.h>
#include "lbm_stream_dlg.h"

/* Stream structures. */
typedef struct
{
    guint64 channel;
    gchar * endpoint_a;
    gchar * endpoint_b;
    guint32 first_frame;
    guint32 last_frame;
    guint32 messages;
    guint32 bytes;
    GtkTreeIter iter;
    GSequence * substreams;
} lbmc_stream_dlg_stream_entry_t;

typedef struct
{
    guint32 substream_id;
    gchar * endpoint_a;
    gchar * endpoint_b;
    guint32 first_frame;
    guint32 last_frame;
    guint32 messages;
    guint32 bytes;
    GtkTreeIter iter;
    lbmc_stream_dlg_stream_entry_t * parent;
} lbmc_stream_dlg_substream_entry_t;

/* Tree definitions. */
#define LBMC_STREAM_DLG_STORE_STREAM_DISPLAY_COLUMN 0
#define LBMC_STREAM_DLG_STORE_ENDPOINTA_COLUMN 1
#define LBMC_STREAM_DLG_STORE_ENDPOINTB_COLUMN 2
#define LBMC_STREAM_DLG_STORE_MESSAGES_COLUMN 3
#define LBMC_STREAM_DLG_STORE_BYTES_COLUMN 4
#define LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN 5
#define LBMC_STREAM_DLG_STORE_LAST_FRAME_COLUMN 6
#define LBMC_STREAM_DLG_STORE_CHANNEL_COLUMN 7
#define LBMC_STREAM_DLG_STORE_SUBSTREAM_COLUMN 8

static const gchar * global_stream_view_data = "stream-view";

typedef struct
{
    GtkWidget * dialog;
    GtkTreeModel * model;
    GSequence * stream_table;
} lbmc_stream_dlg_info_t;

static lbmc_stream_dlg_info_t * global_stream_dialog_info = NULL;

static gchar * lbmc_stream_dlg_format_endpoint_ep(const lbm_uim_stream_endpoint_t * endpoint)
{
    gchar * buf = NULL;

    if (endpoint->type == lbm_uim_instance_stream)
    {
        buf = bytes_to_ep_str(endpoint->stream_info.ctxinst.ctxinst, sizeof(endpoint->stream_info.ctxinst.ctxinst));
    }
    else
    {
        buf = wmem_strdup_printf(wmem_packet_scope(),
            "%" G_GUINT32_FORMAT ":%s:%" G_GUINT16_FORMAT,
            endpoint->stream_info.dest.domain,
            address_to_str(wmem_packet_scope(), &(endpoint->stream_info.dest.addr)),
            endpoint->stream_info.dest.port);
    }
    return (buf);
}

/**************************************************************/
/*  Common functions.                                         */
/**************************************************************/
static void lbmc_stream_dlg_stream_entry_destroy_cb(gpointer data)
{
    lbmc_stream_dlg_stream_entry_t * stream = (lbmc_stream_dlg_stream_entry_t *)data;

    if (stream->substreams != NULL)
    {
        g_sequence_free(stream->substreams);
        stream->substreams = NULL;
    }
    g_free(data);
}

static void lbmc_stream_dlg_substream_entry_destroy_cb(gpointer data)
{
    g_free(data);
}

static void lbmc_stream_dlg_reset_stream_table(lbmc_stream_dlg_info_t * info)
{
    if (info->stream_table != NULL)
    {
        g_sequence_free(info->stream_table);
        info->stream_table = NULL;
    }
    info->stream_table = g_sequence_new(lbmc_stream_dlg_stream_entry_destroy_cb);
}

static void lbmc_stream_dlg_window_destroy_event_cb(GtkWindow * window _U_, gpointer user_data)
{
    lbmc_stream_dlg_info_t * info = (lbmc_stream_dlg_info_t *)user_data;

    remove_tap_listener(info);
    if (info->stream_table != NULL)
    {
        g_sequence_free(info->stream_table);
        info->stream_table = NULL;
    }
    global_stream_dialog_info = NULL;
    g_free(info);
}

static GtkTreeModel * lbmc_stream_dlg_create_model(void)
{
    GtkTreeStore * store = NULL;

    store = gtk_tree_store_new(9, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT64, G_TYPE_UINT);
    return (GTK_TREE_MODEL(store));
}

static void lbmc_stream_dlg_stream_cell_data_function(GtkTreeViewColumn * column _U_, GtkCellRenderer * renderer, GtkTreeModel * model, GtkTreeIter * iter, gpointer user_data _U_)
{
    char stream_buf[64];
    guint64 channel;
    guint substream_id;

    gtk_tree_model_get(model, iter,
        LBMC_STREAM_DLG_STORE_CHANNEL_COLUMN, &channel,
        LBMC_STREAM_DLG_STORE_SUBSTREAM_COLUMN, &substream_id,
        -1);
    if (substream_id == 0)
    {
        g_snprintf(stream_buf, (gulong)sizeof(stream_buf), "%" G_GUINT64_FORMAT, channel);
        /* Left-align */
        g_object_set(renderer, "xalign", 0.0, NULL);
    }
    else
    {
        g_snprintf(stream_buf, (gulong)sizeof(stream_buf), "%" G_GUINT64_FORMAT ".%u", channel, substream_id);
        /* Right-align */
        g_object_set(renderer, "xalign", 1.0, NULL);
    }
    g_object_set(renderer, "text", stream_buf, NULL);
}

static void lbmc_stream_dlg_string_cell_data_function(GtkTreeViewColumn * column _U_, GtkCellRenderer * renderer, GtkTreeModel * model, GtkTreeIter * iter, gpointer user_data)
{
    gchar * value = NULL;
    gint data_column;

    data_column = GPOINTER_TO_INT(user_data);
    gtk_tree_model_get(model, iter, data_column, &value, -1);
    g_object_set(renderer, "text", value, NULL);
    /* Left-align */
    g_object_set(renderer, "xalign", 0.0, NULL);
}

static void lbmc_stream_dlg_guint_cell_data_function(GtkTreeViewColumn * column _U_, GtkCellRenderer * renderer, GtkTreeModel * model, GtkTreeIter * iter, gpointer user_data)
{
    guint uint_value;
    gint data_column;
    char value[64];

    data_column = GPOINTER_TO_INT(user_data);
    gtk_tree_model_get(model, iter, data_column, &uint_value, -1);
    g_snprintf(value, (gulong)sizeof(value), "%u", uint_value);
    g_object_set(renderer, "text", value, NULL);
    /* Right-align */
    g_object_set(renderer, "xalign", 1.0, NULL);
}

static gint lbmc_stream_dlg_guint_sort_func(GtkTreeModel * model, GtkTreeIter * a, GtkTreeIter * b, gpointer user_data)
{
    guint32 val_a;
    guint32 val_b;
    gint data_column;

    data_column = GPOINTER_TO_INT(user_data);
    gtk_tree_model_get(model, a, data_column, &val_a, -1);
    gtk_tree_model_get(model, b, data_column, &val_b, -1);
    if (val_a == val_b)
    {
        return (0);
    }
    else if (val_a < val_b)
    {
        return (-1);
    }
    else
    {
        return (1);
    }
}

static gint lbmc_stream_dlg_stream_sort_func(GtkTreeModel * model, GtkTreeIter * a, GtkTreeIter * b, gpointer user_data _U_)
{
    guint stream_a;
    guint substream_a;
    guint stream_b;
    guint substream_b;

    gtk_tree_model_get(model, a,
        LBMC_STREAM_DLG_STORE_CHANNEL_COLUMN, &stream_a,
        LBMC_STREAM_DLG_STORE_SUBSTREAM_COLUMN, &substream_a,
        -1);
    gtk_tree_model_get(model, b,
        LBMC_STREAM_DLG_STORE_CHANNEL_COLUMN, &stream_b,
        LBMC_STREAM_DLG_STORE_SUBSTREAM_COLUMN, &substream_b,
        -1);
    if (stream_a == stream_b)
    {
        if (substream_a == substream_b)
        {
            return (0);
        }
        else if (substream_a < substream_b)
        {
            return (-1);
        }
        else
        {
            return (1);
        }
    }
    else if (stream_a < stream_b)
    {
        return (-1);
    }
    else
    {
        return (1);
    }
}

static gint lbmc_stream_dlg_string_sort_func(GtkTreeModel * model, GtkTreeIter * a, GtkTreeIter * b, gpointer user_data)
{
    const gchar * str_a = NULL;
    const gchar * str_b = NULL;
    gint ret = 0;

    /* The col to get data from is in user_data */
    gint data_column = GPOINTER_TO_INT(user_data);

    gtk_tree_model_get(model, a, data_column, &str_a, -1);
    gtk_tree_model_get(model, b, data_column, &str_b, -1);

    if (str_a == str_b)
    {
        /* it's worth testing because a lot of rows point to the same data */
        return 0;
    }
    else if (str_a == NULL || str_b == NULL)
    {
        ret = (str_a == NULL) ? -1 : 1;
    }
    else
    {
        ret = g_ascii_strcasecmp(str_a, str_b);
    }
    return (ret);
}

static GtkWidget * lbmc_stream_dlg_create_view_and_model(lbmc_stream_dlg_info_t * info)
{
    GtkWidget * view = NULL;
    GtkTreeViewColumn * column;
    GtkCellRenderer * renderer;
    GtkTreeSortable * sortable;

    info->model = lbmc_stream_dlg_create_model();
    view = gtk_tree_view_new();
    sortable = GTK_TREE_SORTABLE(GTK_TREE_STORE(info->model));
#if GTK_CHECK_VERSION(2,6,0)
    gtk_tree_view_set_fixed_height_mode(GTK_TREE_VIEW(view), TRUE);
#endif
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(view), FALSE);

    /* Column 1 - Stream */
    renderer = gtk_cell_renderer_text_new();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes("Stream", renderer, NULL);
    gtk_tree_view_column_set_sort_column_id(column, LBMC_STREAM_DLG_STORE_STREAM_DISPLAY_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_cell_data_func(column, renderer, lbmc_stream_dlg_stream_cell_data_function, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_STREAM_DISPLAY_COLUMN), NULL);
    gtk_tree_sortable_set_sort_func(sortable, LBMC_STREAM_DLG_STORE_STREAM_DISPLAY_COLUMN, lbmc_stream_dlg_stream_sort_func, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_STREAM_DISPLAY_COLUMN), NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), column);

    /* Column 2 - EndpointA */
    renderer = gtk_cell_renderer_text_new();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes("Endpoint A", renderer, NULL);
    gtk_tree_view_column_set_sort_column_id(column, LBMC_STREAM_DLG_STORE_ENDPOINTA_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_cell_data_func(column, renderer, lbmc_stream_dlg_string_cell_data_function, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_ENDPOINTA_COLUMN), NULL);
    gtk_tree_sortable_set_sort_func(sortable, LBMC_STREAM_DLG_STORE_ENDPOINTA_COLUMN, lbmc_stream_dlg_string_sort_func, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_ENDPOINTA_COLUMN), NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 140);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), column);

    /* Column 3 - EndpointB */
    renderer = gtk_cell_renderer_text_new();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes("Endpoint B", renderer, NULL);
    gtk_tree_view_column_set_sort_column_id(column, LBMC_STREAM_DLG_STORE_ENDPOINTB_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_cell_data_func(column, renderer, lbmc_stream_dlg_string_cell_data_function, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_ENDPOINTB_COLUMN), NULL);
    gtk_tree_sortable_set_sort_func(sortable, LBMC_STREAM_DLG_STORE_ENDPOINTB_COLUMN, lbmc_stream_dlg_string_sort_func, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_ENDPOINTB_COLUMN), NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 140);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), column);

    /* Column 4 - Messages */
    renderer = gtk_cell_renderer_text_new();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes("Messages", renderer, NULL);
    gtk_tree_view_column_set_sort_column_id(column, LBMC_STREAM_DLG_STORE_MESSAGES_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_cell_data_func(column, renderer, lbmc_stream_dlg_guint_cell_data_function, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_MESSAGES_COLUMN), NULL);
    gtk_tree_sortable_set_sort_func(sortable, LBMC_STREAM_DLG_STORE_MESSAGES_COLUMN, lbmc_stream_dlg_guint_sort_func, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_MESSAGES_COLUMN), NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), column);

    /* Column 5 - Bytes */
    renderer = gtk_cell_renderer_text_new();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes("Bytes", renderer, NULL);
    gtk_tree_view_column_set_sort_column_id(column, LBMC_STREAM_DLG_STORE_BYTES_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_cell_data_func(column, renderer, lbmc_stream_dlg_guint_cell_data_function, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_BYTES_COLUMN), NULL);
    gtk_tree_sortable_set_sort_func(sortable, LBMC_STREAM_DLG_STORE_BYTES_COLUMN, lbmc_stream_dlg_guint_sort_func, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_BYTES_COLUMN), NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), column);

    /* Column 6 - First frame */
    renderer = gtk_cell_renderer_text_new();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes("First frame", renderer, NULL);
    gtk_tree_view_column_set_sort_column_id(column, LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_cell_data_func(column, renderer, lbmc_stream_dlg_guint_cell_data_function, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN), NULL);
    gtk_tree_sortable_set_sort_func(sortable, LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN, lbmc_stream_dlg_guint_sort_func, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN), NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), column);

    /* Column 6 - Last frame */
    renderer = gtk_cell_renderer_text_new();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes("Last frame", renderer, NULL);
    gtk_tree_view_column_set_sort_column_id(column, LBMC_STREAM_DLG_STORE_LAST_FRAME_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_cell_data_func(column, renderer, lbmc_stream_dlg_guint_cell_data_function, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_LAST_FRAME_COLUMN), NULL);
    gtk_tree_sortable_set_sort_func(sortable, LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN, lbmc_stream_dlg_guint_sort_func, GINT_TO_POINTER(LBMC_STREAM_DLG_STORE_LAST_FRAME_COLUMN), NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 100);
    gtk_tree_view_append_column(GTK_TREE_VIEW(view), column);

    gtk_tree_view_set_model(GTK_TREE_VIEW(view), info->model);
    g_object_unref(info->model);
    return (view);
}

static lbmc_stream_dlg_info_t * lbmc_stream_dlg_window_create(void)
{
    GtkWidget * vbox = NULL;
    GtkWidget * view = NULL;
    GtkWidget * button_row = NULL;
    GtkWidget * close_button = NULL;
    GtkWidget * scrolled_window = NULL;
    lbmc_stream_dlg_info_t * info = NULL;

    /* Setup the info structure. */
    info = (lbmc_stream_dlg_info_t *)g_malloc(sizeof(lbmc_stream_dlg_info_t));
    info->dialog = NULL;
    info->model = NULL;
    info->stream_table = NULL;
    lbmc_stream_dlg_reset_stream_table(info);

    /* Create the main window */
    info->dialog = dlg_window_new("29West LBMC Streams");
    g_signal_connect(info->dialog, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(info->dialog, "destroy", G_CALLBACK(lbmc_stream_dlg_window_destroy_event_cb), (gpointer)info);
    gtk_window_set_default_size(GTK_WINDOW(info->dialog), 800, 400);

    /* Build the vbox (to contain the tree view and buttons) */
    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
    gtk_container_add(GTK_CONTAINER(info->dialog), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    /* Build the tree view */
    view = lbmc_stream_dlg_create_view_and_model(info);
    g_object_set_data((GObject *)info->dialog, global_stream_view_data, (gpointer)view);

    /* Build a scrolling container for the tree view */
    scrolled_window = scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scrolled_window), view);

    /* Add the scrolling container to the vbox */
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);

    /* Build the button row */
    button_row = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);

    /* Add the button row to the vbox */
    gtk_box_pack_end(GTK_BOX(vbox), button_row, FALSE, FALSE, 0);

    /* Connect to the close button */
    close_button = (GtkWidget *)g_object_get_data(G_OBJECT(button_row), GTK_STOCK_CLOSE);
    window_set_cancel_button(info->dialog, close_button, window_cancel_button_cb);
    gtk_widget_show_all(info->dialog);
    return (info);
}

/**************************************************************/
/* Tap callbacks.                                             */
/**************************************************************/
static void lbmc_stream_dlg_tap_reset(void * tap_data)
{
    lbmc_stream_dlg_info_t * info = (lbmc_stream_dlg_info_t *)tap_data;

    gtk_tree_store_clear(GTK_TREE_STORE(info->model));
    lbmc_stream_dlg_reset_stream_table(info);
}

static gint lbmc_stream_dlg_stream_compare_cb(gconstpointer lhs, gconstpointer rhs, gpointer user_data _U_)
{
    const lbmc_stream_dlg_stream_entry_t * stream1 = (const lbmc_stream_dlg_stream_entry_t *)lhs;
    const lbmc_stream_dlg_stream_entry_t * stream2 = (const lbmc_stream_dlg_stream_entry_t *)rhs;

    if (stream1->channel == stream2->channel)
    {
        return (0);
    }
    else if (stream1->channel < stream2->channel)
    {
        return (-1);
    }
    return (1);
}

static gint lbmc_stream_dlg_substream_compare_cb(gconstpointer lhs, gconstpointer rhs, gpointer user_data _U_)
{
    const lbmc_stream_dlg_substream_entry_t * substream1 = (const lbmc_stream_dlg_substream_entry_t *)lhs;
    const lbmc_stream_dlg_substream_entry_t * substream2 = (const lbmc_stream_dlg_substream_entry_t *)rhs;

    if (substream1->substream_id == substream2->substream_id)
    {
        return (0);
    }
    else if (substream1->substream_id < substream2->substream_id)
    {
        return (-1);
    }
    return (1);
}

static gboolean lbmc_stream_dlg_tap_packet(void * tap_data, packet_info * pinfo, epan_dissect_t * edt _U_, const void * stream_info)
{
    const lbm_uim_stream_tap_info_t * tapinfo = (const lbm_uim_stream_tap_info_t *)stream_info;
    lbmc_stream_dlg_info_t * info = (lbmc_stream_dlg_info_t *)tap_data;
    GtkTreeIter stream_iter;
    GtkTreeIter stream_insert_before_iter;
    lbmc_stream_dlg_stream_entry_t * stream = NULL;
    GSequenceIter * stream_entry_it;
    lbmc_stream_dlg_stream_entry_t stream_key;
    gboolean add_stream = FALSE;
    gboolean add_stream_before = FALSE;
    GtkTreeIter substream_iter;
    GtkTreeIter substream_insert_before_iter;
    lbmc_stream_dlg_substream_entry_t * substream = NULL;
    GSequenceIter * substream_entry_it;
    lbmc_stream_dlg_substream_entry_t substream_key;
    gboolean add_substream = FALSE;
    gboolean add_substream_before = FALSE;
    GtkTreePath * stream_path = NULL;
    GtkTreePath * substream_path = NULL;

    memset((void *)&stream_key, 0, sizeof(lbmc_stream_dlg_stream_entry_t));
    stream_key.channel = tapinfo->channel;
    stream_entry_it = g_sequence_search(info->stream_table, (gpointer)&stream_key, lbmc_stream_dlg_stream_compare_cb, NULL);
    /* If the node exists, g_sequence_search() will return an iterator giving the NEXT node. */
    if (g_sequence_iter_is_begin(stream_entry_it))
    {
        /*
            The iterator marks the beginning of the sequence, so the node doesn't exist
            and the previous node doesn't exist.
        */
        add_stream = TRUE;
        if (g_sequence_iter_is_end(stream_entry_it))
        {
            /* Iterator is both beginning and end, so the list is empty - just append it. */
        }
        else
        {
            /* Not the end, so we'll insert before the next stream. */
            stream = (lbmc_stream_dlg_stream_entry_t *)g_sequence_get(stream_entry_it);
            add_stream_before = TRUE;
            stream_insert_before_iter = stream->iter;
        }
    }
    else
    {
        GSequenceIter * save_stream_entry_it = stream_entry_it;

        stream_entry_it = g_sequence_iter_prev(stream_entry_it);
        stream = (lbmc_stream_dlg_stream_entry_t *)g_sequence_get(stream_entry_it);
        if (stream->channel != tapinfo->channel)
        {
            /* Not the one we were looking for. */
            add_stream = TRUE;
            if (g_sequence_iter_is_end(save_stream_entry_it))
            {
                /* Insert after -> append  */
            }
            else
            {
                /* Insert before */
                stream = (lbmc_stream_dlg_stream_entry_t *)g_sequence_get(stream_entry_it);
                add_stream_before = TRUE;
                stream_insert_before_iter = stream->iter;
            }
        }
    }

    if (add_stream)
    {
        char valbuf[256];

        stream = (lbmc_stream_dlg_stream_entry_t *)g_malloc(sizeof(lbmc_stream_dlg_stream_entry_t));
        stream->channel = tapinfo->channel;
        stream->endpoint_a = wmem_strdup(wmem_file_scope(), lbmc_stream_dlg_format_endpoint_ep(&(tapinfo->endpoint_a)));
        stream->endpoint_b = wmem_strdup(wmem_file_scope(), lbmc_stream_dlg_format_endpoint_ep(&(tapinfo->endpoint_b)));
        stream->first_frame = (guint32)(~0);
        stream->last_frame = 0;
        stream->messages = 0;
        stream->bytes = 0;
        stream->substreams = g_sequence_new(lbmc_stream_dlg_substream_entry_destroy_cb);
        (void) g_sequence_insert_sorted(info->stream_table, (void *)stream, lbmc_stream_dlg_stream_compare_cb, NULL);
        if (add_stream_before)
        {
            gtk_tree_store_insert_before(GTK_TREE_STORE(info->model), &stream_iter, NULL, &stream_insert_before_iter);
        }
        else
        {
            gtk_tree_store_append(GTK_TREE_STORE(info->model), &stream_iter, NULL);
        }
        stream->iter = stream_iter;
        g_snprintf(valbuf, (gulong)sizeof(valbuf), "%" G_GUINT64_FORMAT, stream->channel);
        gtk_tree_store_set(GTK_TREE_STORE(info->model), &(stream->iter),
            LBMC_STREAM_DLG_STORE_STREAM_DISPLAY_COLUMN, valbuf,
            LBMC_STREAM_DLG_STORE_ENDPOINTA_COLUMN, stream->endpoint_a,
            LBMC_STREAM_DLG_STORE_ENDPOINTB_COLUMN, stream->endpoint_b,
            LBMC_STREAM_DLG_STORE_MESSAGES_COLUMN, (guint)0,
            LBMC_STREAM_DLG_STORE_BYTES_COLUMN, (guint)0,
            LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN, (guint)0,
            LBMC_STREAM_DLG_STORE_LAST_FRAME_COLUMN, (guint)0,
            LBMC_STREAM_DLG_STORE_CHANNEL_COLUMN, (guint64)stream->channel,
            LBMC_STREAM_DLG_STORE_SUBSTREAM_COLUMN, (guint)0,
            -1);
    }
    stream_iter = stream->iter;
    if (stream->first_frame > pinfo->fd->num)
    {
        stream->first_frame = pinfo->fd->num;
    }
    if (stream->last_frame < pinfo->fd->num)
    {
        stream->last_frame = pinfo->fd->num;
    }
    stream->bytes += tapinfo->bytes;
    stream->messages++;
    gtk_tree_store_set(GTK_TREE_STORE(info->model), &stream_iter,
        LBMC_STREAM_DLG_STORE_MESSAGES_COLUMN, (guint)stream->messages,
        LBMC_STREAM_DLG_STORE_BYTES_COLUMN, (guint)stream->bytes,
        LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN, (guint)stream->first_frame,
        LBMC_STREAM_DLG_STORE_LAST_FRAME_COLUMN, (guint)stream->last_frame,
        -1);

    memset((void *)&substream_key, 0, sizeof(lbmc_stream_dlg_substream_entry_t));
    substream_key.substream_id = tapinfo->substream_id;
    substream_entry_it = g_sequence_search(stream->substreams, (gpointer)&substream_key, lbmc_stream_dlg_substream_compare_cb, NULL);
    /* If the node exists, g_sequence_search() will return an iterator giving the NEXT node. */
    if (g_sequence_iter_is_begin(substream_entry_it))
    {
        /*
            The iterator marks the beginning of the sequence, so the node doesn't exist
            and the previous node doesn't exist.
        */
        add_substream = TRUE;
        if (g_sequence_iter_is_end(substream_entry_it))
        {
            /* Iterator is both beginning and end, so the list is empty - just append it. */
        }
        else
        {
            /* Not the end, so we'll insert before the next stream. */
            substream = (lbmc_stream_dlg_substream_entry_t *)g_sequence_get(substream_entry_it);
            add_substream_before = TRUE;
            substream_insert_before_iter = substream->iter;
        }
    }
    else
    {
        GSequenceIter * save_substream_entry_it = substream_entry_it;

        substream_entry_it = g_sequence_iter_prev(substream_entry_it);
        substream = (lbmc_stream_dlg_substream_entry_t *)g_sequence_get(substream_entry_it);
        if (substream->substream_id != tapinfo->substream_id)
        {
            /* Not the one we were looking for. */
            add_substream = TRUE;
            if (g_sequence_iter_is_end(save_substream_entry_it))
            {
                /* Insert after -> append  */
            }
            else
            {
                /* Insert before */
                substream = (lbmc_stream_dlg_substream_entry_t *)g_sequence_get(substream_entry_it);
                add_substream_before = TRUE;
                substream_insert_before_iter = substream->iter;
            }
        }
    }
    if (add_substream)
    {
        char valbuf[256];

        substream = (lbmc_stream_dlg_substream_entry_t *)g_malloc(sizeof(lbmc_stream_dlg_substream_entry_t));
        substream->substream_id = tapinfo->substream_id;
        substream->endpoint_a = wmem_strdup_printf(wmem_file_scope(), "%s:%" G_GUINT16_FORMAT, address_to_str(wmem_packet_scope(), &(pinfo->src)), (guint16)pinfo->srcport);
        substream->endpoint_b = wmem_strdup_printf(wmem_file_scope(), "%s:%" G_GUINT16_FORMAT, address_to_str(wmem_packet_scope(), &(pinfo->dst)), (guint16)pinfo->destport);
        substream->first_frame = (guint32)(~0);
        substream->last_frame = 0;
        substream->messages = 0;
        substream->bytes = 0;
        substream->parent = stream;
        (void) g_sequence_insert_sorted(stream->substreams, (void *)substream, lbmc_stream_dlg_substream_compare_cb, NULL);
        if (add_substream_before)
        {
            gtk_tree_store_insert_before(GTK_TREE_STORE(info->model), &substream_iter, &stream_iter, &substream_insert_before_iter);
        }
        else
        {
            gtk_tree_store_append(GTK_TREE_STORE(info->model), &substream_iter, &stream_iter);
        }
        substream->iter = substream_iter;
        g_snprintf(valbuf, (gulong)sizeof(valbuf), "%" G_GUINT64_FORMAT ":%" G_GUINT32_FORMAT, stream->channel, substream->substream_id);
        gtk_tree_store_set(GTK_TREE_STORE(info->model), &(substream->iter),
            LBMC_STREAM_DLG_STORE_STREAM_DISPLAY_COLUMN, valbuf,
            LBMC_STREAM_DLG_STORE_ENDPOINTA_COLUMN, substream->endpoint_a,
            LBMC_STREAM_DLG_STORE_ENDPOINTB_COLUMN, substream->endpoint_b,
            LBMC_STREAM_DLG_STORE_MESSAGES_COLUMN, (guint)0,
            LBMC_STREAM_DLG_STORE_BYTES_COLUMN, (guint)0,
            LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN, (guint)0,
            LBMC_STREAM_DLG_STORE_LAST_FRAME_COLUMN, (guint)0,
            LBMC_STREAM_DLG_STORE_CHANNEL_COLUMN, (guint)stream->channel,
            LBMC_STREAM_DLG_STORE_SUBSTREAM_COLUMN, (guint)substream->substream_id,
            -1);
    }
    substream_iter = substream->iter;
    if (substream->first_frame > pinfo->fd->num)
    {
        substream->first_frame = pinfo->fd->num;
    }
    if (substream->last_frame < pinfo->fd->num)
    {
        substream->last_frame = pinfo->fd->num;
    }
    substream->bytes += tapinfo->bytes;
    substream->messages++;
    gtk_tree_store_set(GTK_TREE_STORE(info->model), &substream_iter,
        LBMC_STREAM_DLG_STORE_MESSAGES_COLUMN, (guint)substream->messages,
        LBMC_STREAM_DLG_STORE_BYTES_COLUMN, (guint)substream->bytes,
        LBMC_STREAM_DLG_STORE_FIRST_FRAME_COLUMN, (guint)substream->first_frame,
        LBMC_STREAM_DLG_STORE_LAST_FRAME_COLUMN, (guint)substream->last_frame,
        -1);
    substream_path = gtk_tree_model_get_path(info->model, &(substream->iter));
    gtk_tree_model_row_changed(info->model, substream_path, &(substream->iter));
    gtk_tree_path_free(substream_path);
    substream_path = NULL;
    stream_path = gtk_tree_model_get_path(info->model, &(stream->iter));
    gtk_tree_model_row_changed(info->model, stream_path, &(stream->iter));
    gtk_tree_path_free(stream_path);
    stream_path = NULL;
    return (TRUE);
}

static void lbmc_stream_dlg_tap_draw(void * tap_data _U_)
{
    /* Nothing to do. */
}

/**************************************************************/
/* Stream table functions.                                    */
/**************************************************************/
void lbmc_stream_dlg_stream_menu_cb(gpointer arg _U_)
{
    GString * err_msg;

    if (global_stream_dialog_info != NULL)
    {
        gtk_widget_show(global_stream_dialog_info->dialog);
        return;
    }
    global_stream_dialog_info = lbmc_stream_dlg_window_create();
    err_msg = register_tap_listener("lbm_stream",
        (void *)global_stream_dialog_info,
        NULL,
        TL_REQUIRES_COLUMNS,
        lbmc_stream_dlg_tap_reset,
        lbmc_stream_dlg_tap_packet,
        lbmc_stream_dlg_tap_draw);
    if (err_msg != NULL)
    {
        fprintf(stderr, "register_tap_listener: %s\n", err_msg->str);
        g_string_free(err_msg, TRUE);
    }
    cf_retap_packets(&cfile);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
