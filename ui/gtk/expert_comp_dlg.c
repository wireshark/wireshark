/* expert_comp_dlg.c
 * expert_comp_dlg   2005 Greg Morris
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/prefs.h>

#include "../stat_menu.h"

#include "ui/simple_dialog.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/expert_comp_table.h"
#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/expert_comp_dlg.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/main.h"
#include "ui/gtk/expert_indicators.h"
#include "ui/gtk/main_proto_draw.h"
#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/edit_packet_comment_dlg.h"

enum
{
    NO_COLUMN_C_TABLE,
    SUMMARY_COLUMN_C_TABLE,
    FOREGROUND_COLOR_COL_C_TABLE,
    BACKGROUND_COLOR_COL_C_TABLE,
    N_COLUMNS_COMMENT_TBL
};

enum
{
    NO_COLUMN,
    SEVERITY_COLUMN,
    GROUP_COLUMN,
    PROTOCOL_COLUMN,
    SUMMARY_COLUMN,
    FOREGROUND_COLOR_COL,
    BACKGROUND_COLOR_COL,
    N_COLUMNS
};

/* used to keep track of the statistics for an entire program interface */
typedef struct _expert_comp_dlg_t {
    GtkWidget *win;
    GtkWidget *pkt_comments_label;
    GtkWidget *chat_label;
    GtkWidget *note_label;
    GtkWidget *warn_label;
    GtkWidget *error_label;
    GtkWidget *all_label;
    error_equiv_table chat_table;
    error_equiv_table note_table;
    error_equiv_table warn_table;
    error_equiv_table error_table;
    guint32 pkt_comments_events;
    guint32 disp_events;
    guint32 chat_events;
    guint32 note_events;
    guint32 warn_events;
    guint32 error_events;
} expert_comp_dlg_t;

struct expert_tapdata_s {
    GtkWidget   *win;
    GtkWidget   *scrolled_window;
    GtkTreeView *tree_view;
    GtkWidget   *scrolled_window_comments;
    GtkTreeView *tree_view_comments;
    GtkWidget   *label;
    guint32     pkt_comments_events;
    guint32     disp_events;
    guint32     chat_events;
    guint32     note_events;
    guint32     warn_events;
    guint32     error_events;
    int         severity_report_level;

    GArray      *ei_array;      /* expert info items */
    guint       first;
    guint       last;
    GStringChunk *text;  /* summary text */
};

static GtkWidget  *expert_comp_dlg_w = NULL;

static void
select_row_cb(GtkTreeSelection *selection, gpointer *user_data _U_)
{
    /*guint num = GPOINTER_TO_UINT(gtk_clist_get_row_data(clist, row));*/

    /*cf_goto_frame(&cfile, num);*/

    GtkTreeIter iter;
    GtkTreeModel *model;
    guint fnumber;

    if (selection==NULL)
        return;

    if (gtk_tree_selection_get_selected (selection, &model, &iter)){
        gtk_tree_model_get (model, &iter, NO_COLUMN, &fnumber, -1);
        cf_goto_frame(&cfile, fnumber);
    }

}

/* reset of display only, e.g. for filtering */
static void expert_dlg_display_reset(expert_tapdata_t * etd)
{
    etd->disp_events = 0;
    gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(etd->tree_view))));

    gtk_window_set_title(GTK_WINDOW(etd->win), "Wireshark: ? Expert Infos");
    if(etd->label) {
        gtk_label_set_text(GTK_LABEL(etd->label), "Please wait ...");
    }
}

/* complete reset, e.g. capture file closed */
static void
expert_dlg_reset(void *tapdata)
{
    expert_tapdata_t * etd = tapdata;

    etd->chat_events = 0;
    etd->note_events = 0;
    etd->warn_events = 0;
    etd->error_events = 0;
    etd->pkt_comments_events = 0;
    etd->last = 0;
    etd->first = 0;
    /* g_string_chunk_clear() is introduced in glib 2.14 */
    g_string_chunk_free(etd->text);
    etd->text = g_string_chunk_new(100);
    g_array_set_size(etd->ei_array, 0);

    expert_dlg_display_reset(etd);
}

static int
expert_dlg_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pointer)
{
    expert_info_t    *ei;
    expert_tapdata_t *etd = tapdata;

    g_array_append_val(etd->ei_array, *(expert_info_t *)pointer);
    etd->last = etd->ei_array->len;
    ei = &g_array_index(etd->ei_array, expert_info_t, etd->last -1); /* ugly */
    ei->protocol = g_string_chunk_insert_const(etd->text, ei->protocol);
    ei->summary = g_string_chunk_insert_const(etd->text, ei->summary);

    switch(ei->severity) {
    case(PI_COMMENT):
        etd->pkt_comments_events++;
        break;
    case(PI_CHAT):
        etd->chat_events++;
        break;
    case(PI_NOTE):
        etd->note_events++;
        break;
    case(PI_WARN):
        etd->warn_events++;
        break;
    case(PI_ERROR):
        etd->error_events++;
        break;
    default:
        g_assert_not_reached();
    }
    if(ei->severity < etd->severity_report_level) {
        return 0; /* draw not required */
    } else {
        return 1; /* draw required */
    }
}
static void
error_set_title(expert_comp_dlg_t *ss)
{
    char *title;

    title = g_strdup_printf("Expert Info: %s",
        cf_get_display_name(&cfile));
    gtk_window_set_title(GTK_WINDOW(ss->win), title);
    g_free(title);
}

static void
error_reset(void *pss)
{
    expert_comp_dlg_t *ss=(expert_comp_dlg_t *)pss;
    gchar *buf;

    ss->error_events = 0;
    ss->warn_events = 0;
    ss->note_events = 0;
    ss->chat_events = 0;
    ss->disp_events = 0;
    ss->pkt_comments_events = 0;

    reset_error_table_data(&ss->error_table);
    buf = g_strdup_printf("Errors: %u (0)", ss->error_table.num_procs);
    gtk_label_set_text( GTK_LABEL(ss->error_label), buf);
    g_free(buf);

    reset_error_table_data(&ss->warn_table);
    buf = g_strdup_printf("Warnings: %u (0)", ss->warn_table.num_procs);
    gtk_label_set_text( GTK_LABEL(ss->warn_label), buf);
    g_free(buf);

    reset_error_table_data(&ss->note_table);
    buf = g_strdup_printf("Notes: %u (0)", ss->note_table.num_procs);
    gtk_label_set_text( GTK_LABEL(ss->note_label), buf);
    g_free(buf);

    reset_error_table_data(&ss->chat_table);
    buf = g_strdup_printf("Chats: %u (0)", ss->chat_table.num_procs);
    gtk_label_set_text( GTK_LABEL(ss->chat_label), buf);
    g_free(buf);

    gtk_label_set_text( GTK_LABEL(ss->all_label), "Details: 0");

    gtk_label_set_text( GTK_LABEL(ss->pkt_comments_label), "Packet comments: 0");

    error_set_title(ss);
}

static gboolean
error_packet(void *pss, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *prv)
{
    expert_comp_dlg_t *ss=(expert_comp_dlg_t *)pss;
    const expert_info_t *error_pkt=prv;

    /* if return value is 0 then no error */
    if(error_pkt==NULL){
        return FALSE;
    }

    switch (error_pkt->severity) {
    case PI_ERROR:
        ss->disp_events++;
        ss->error_events++;
        init_error_table_row(&ss->error_table, error_pkt);
        break;
    case PI_WARN:
        ss->disp_events++;
        ss->warn_events++;
        init_error_table_row(&ss->warn_table, error_pkt);
        break;
    case PI_NOTE:
        ss->disp_events++;
        ss->note_events++;
        init_error_table_row(&ss->note_table, error_pkt);
        break;
    case PI_CHAT:
        ss->disp_events++;
        ss->chat_events++;
        init_error_table_row(&ss->chat_table, error_pkt);
        break;
    case PI_COMMENT:
        ss->disp_events++; /* Count ? */
        ss->pkt_comments_events++;
        break;
    default:
        return FALSE; /* Don't draw */
    }
    return TRUE; /* Draw */
}

static void
expert_comp_draw(void *data)
{
    gchar *buf = NULL;

    expert_comp_dlg_t *ss=(expert_comp_dlg_t *)data;

    buf = g_strdup_printf("Errors: %u (%u)", ss->error_table.num_procs, ss->error_events);
    gtk_label_set_text( GTK_LABEL(ss->error_label), buf);
    g_free(buf);

    buf = g_strdup_printf("Warnings: %u (%u)", ss->warn_table.num_procs, ss->warn_events);
    gtk_label_set_text( GTK_LABEL(ss->warn_label), buf);
    g_free(buf);

    buf = g_strdup_printf("Notes: %u (%u)", ss->note_table.num_procs, ss->note_events);
    gtk_label_set_text( GTK_LABEL(ss->note_label), buf);
    g_free(buf);

    buf = g_strdup_printf("Chats: %u (%u)", ss->chat_table.num_procs, ss->chat_events);
    gtk_label_set_text( GTK_LABEL(ss->chat_label), buf);
    g_free(buf);

    buf = g_strdup_printf("Details: %u", ss->disp_events);
    gtk_label_set_text( GTK_LABEL(ss->all_label), buf);
    g_free(buf);

    buf = g_strdup_printf("Packet Comments: %u", ss->pkt_comments_events);
    gtk_label_set_text( GTK_LABEL(ss->pkt_comments_label), buf);
    g_free(buf);

}

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
    expert_comp_dlg_t *ss=(expert_comp_dlg_t *)data;

    protect_thread_critical_region();
    remove_tap_listener(ss);
    unprotect_thread_critical_region();

    if (expert_comp_dlg_w != NULL) {
        window_destroy(expert_comp_dlg_w);
        expert_comp_dlg_w = NULL;
    }

    free_error_table_data(&ss->error_table);
    free_error_table_data(&ss->warn_table);
    free_error_table_data(&ss->note_table);
    free_error_table_data(&ss->chat_table);
    g_free(ss);

}

static void
expert_dlg_destroy_cb(GtkWindow *win _U_, gpointer data)
{
    expert_tapdata_t *etd=(expert_tapdata_t *)data;

    protect_thread_critical_region();
    remove_tap_listener(etd);
    unprotect_thread_critical_region();

    /*free_srt_table_data(&etd->afp_srt_table);*/
    g_array_free(etd->ei_array, TRUE);
    g_string_chunk_free(etd->text);
    g_free(etd);
}

static expert_tapdata_t * expert_dlg_new_table(void)
{
    expert_tapdata_t * etd;
    etd=g_malloc0(sizeof(expert_tapdata_t));

    etd->ei_array = g_array_sized_new(FALSE, FALSE, sizeof(expert_info_t), 1000);
    etd->text = g_string_chunk_new(100);
    etd->severity_report_level = PI_COMMENT;
    return etd;
}

static void
coments_row_double_click_cb(GtkTreeView *treeview _U_, GtkTreePath *path _U_,
                            GtkTreeViewColumn *col _U_, gpointer userdata _U_)
{
    edit_packet_comment_dlg(NULL, NULL);
}

static void
expert_dlg_init_comments_table(expert_tapdata_t * etd, GtkWidget *vbox)
{
    GtkListStore *store;
    GtkWidget *tree;
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;
    GtkTreeSortable *sortable;
    GtkTreeSelection  *selection;

    /* Create the store */
    store = gtk_list_store_new(N_COLUMNS_COMMENT_TBL,        /* Total number of columns */
                               G_TYPE_UINT,      /* No                      */
                               G_TYPE_POINTER,   /* Summary                 */
                               G_TYPE_STRING,    /* forground               */
                               G_TYPE_STRING);   /* Background              */

    /* Create a view */
    tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
    etd->tree_view_comments = GTK_TREE_VIEW(tree);
    sortable = GTK_TREE_SORTABLE(store);

    /* Speed up the list display */
    gtk_tree_view_set_fixed_height_mode(etd->tree_view_comments, TRUE);

    /* Setup the sortable columns */
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW (tree), FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (store));

    /* Let the font be the default one to have the same look as the rest of the tabs
     * Bug https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4388
     * gtk_widget_modify_font(GTK_WIDGET (etd->tree_view), user_font_get_regular());
     */

    /* Create a cell renderer */
    renderer = gtk_cell_renderer_text_new ();
    g_object_set(renderer, "ypad", 0, NULL);
    g_object_set(renderer, "xalign", 1.0, NULL);

    /* Create the first column, associating the "text" attribute of the
     * cell_renderer to the first column of the model */
    /* No */
    column = gtk_tree_view_column_new_with_attributes ("No", renderer,
        "text", NO_COLUMN_C_TABLE,
        "foreground", FOREGROUND_COLOR_COL_C_TABLE,
        "background", BACKGROUND_COLOR_COL_C_TABLE,
        NULL);
    gtk_tree_view_column_set_sort_column_id(column, NO_COLUMN_C_TABLE);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 40);
    gtk_tree_view_append_column (etd->tree_view_comments, column);


    /* Summary. */
    renderer = gtk_cell_renderer_text_new ();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes ("Summary", renderer,
        "foreground", FOREGROUND_COLOR_COL_C_TABLE,
        "background", BACKGROUND_COLOR_COL_C_TABLE,
        NULL);
    gtk_tree_view_column_set_cell_data_func(column, renderer, str_ptr_data_func,
        GINT_TO_POINTER(SUMMARY_COLUMN_C_TABLE), NULL);

    gtk_tree_sortable_set_sort_func(sortable, SUMMARY_COLUMN, str_ptr_sort_func,
        GINT_TO_POINTER(SUMMARY_COLUMN_C_TABLE), NULL);

    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 90);
    gtk_tree_view_column_set_sort_column_id(column, SUMMARY_COLUMN_C_TABLE);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column (etd->tree_view_comments, column);

    gtk_tree_view_set_search_column (etd->tree_view_comments, SUMMARY_COLUMN_C_TABLE); /* Allow searching the summary */
    gtk_tree_view_set_reorderable (etd->tree_view_comments, TRUE);   /* Allow user to reorder data with drag n drop */

    /* Now enable the sorting of each column */
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(etd->tree_view_comments), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(etd->tree_view_comments), TRUE);

    /* Setup the selection handler */
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(etd->tree_view_comments));
    gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

    g_signal_connect (G_OBJECT (selection), "changed", /* select_row */
                  G_CALLBACK (select_row_cb),
                  NULL);

    g_signal_connect(tree, "row-activated",
                     G_CALLBACK(coments_row_double_click_cb), NULL);

    etd->scrolled_window_comments=scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(etd->scrolled_window_comments), GTK_WIDGET (etd->tree_view_comments));

    gtk_box_pack_start(GTK_BOX(vbox), etd->scrolled_window_comments, TRUE, TRUE, 0);
}

static void
expert_dlg_init_table(expert_tapdata_t * etd, GtkWidget *vbox)
{
    GtkListStore *store;
    GtkWidget *tree;
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;
    GtkTreeSortable *sortable;
    GtkTreeSelection  *selection;

    /* Create the store */
    store = gtk_list_store_new(N_COLUMNS,        /* Total number of columns */
                               G_TYPE_UINT,      /* No                      */
                               G_TYPE_POINTER,   /* Severity                */
                               G_TYPE_POINTER,   /* Group                   */
                               G_TYPE_POINTER,   /* Protocol                */
                               G_TYPE_POINTER,   /* Summary                 */
                               G_TYPE_STRING,    /* forground               */
                               G_TYPE_STRING);   /* Background              */

    /* Create a view */
    tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
    etd->tree_view = GTK_TREE_VIEW(tree);
    sortable = GTK_TREE_SORTABLE(store);

    /* Speed up the list display */
    gtk_tree_view_set_fixed_height_mode(etd->tree_view, TRUE);

    /* Setup the sortable columns */
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW (tree), FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (store));

    /* Let the font be the default one to have the same look as the rest of the tabs
     * Bug https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4388
     * gtk_widget_modify_font(GTK_WIDGET (etd->tree_view), user_font_get_regular());
     */

    /* Create a cell renderer */
    renderer = gtk_cell_renderer_text_new ();
    g_object_set(renderer, "ypad", 0, NULL);
    g_object_set(renderer, "xalign", 1.0, NULL);

    /* Create the first column, associating the "text" attribute of the
     * cell_renderer to the first column of the model */
    /* No */
    column = gtk_tree_view_column_new_with_attributes ("No", renderer,
        "text", NO_COLUMN,
        "foreground", FOREGROUND_COLOR_COL,
        "background", BACKGROUND_COLOR_COL,
        NULL);
    gtk_tree_view_column_set_sort_column_id(column, NO_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 40);
    gtk_tree_view_append_column (etd->tree_view, column);

    /* Severity */
    renderer = gtk_cell_renderer_text_new ();
    g_object_set(renderer, "ypad", 0, NULL);

    column = gtk_tree_view_column_new_with_attributes ("Severity", renderer,
        "foreground", FOREGROUND_COLOR_COL,
        "background", BACKGROUND_COLOR_COL,
        NULL);

    gtk_tree_view_column_set_cell_data_func(column, renderer, str_ptr_data_func,
        GINT_TO_POINTER(SEVERITY_COLUMN), NULL);

    gtk_tree_sortable_set_sort_func(sortable, SEVERITY_COLUMN, str_ptr_sort_func,
        GINT_TO_POINTER(SEVERITY_COLUMN), NULL);

    gtk_tree_view_column_set_sort_column_id(column, SEVERITY_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    /* Add the column to the view. */
    gtk_tree_view_append_column (etd->tree_view, column);

    /* Group */
    renderer = gtk_cell_renderer_text_new ();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes ("Group", renderer,
        "foreground", FOREGROUND_COLOR_COL,
        "background", BACKGROUND_COLOR_COL,
        NULL);

    gtk_tree_view_column_set_cell_data_func(column, renderer, str_ptr_data_func,
        GINT_TO_POINTER(GROUP_COLUMN), NULL);

    gtk_tree_sortable_set_sort_func(sortable, GROUP_COLUMN, str_ptr_sort_func,
        GINT_TO_POINTER(GROUP_COLUMN), NULL);

    gtk_tree_view_column_set_sort_column_id(column, GROUP_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    /* Add the column to the view. */
    gtk_tree_view_append_column (etd->tree_view, column);

    /* Protocol. */
    renderer = gtk_cell_renderer_text_new ();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes ("Protocol", renderer,
        "foreground", FOREGROUND_COLOR_COL,
        "background", BACKGROUND_COLOR_COL,
        NULL);
    gtk_tree_view_column_set_cell_data_func(column, renderer, str_ptr_data_func,
        GINT_TO_POINTER(PROTOCOL_COLUMN), NULL);

    gtk_tree_sortable_set_sort_func(sortable, PROTOCOL_COLUMN, str_ptr_sort_func,
        GINT_TO_POINTER(PROTOCOL_COLUMN), NULL);

    gtk_tree_view_column_set_sort_column_id(column, PROTOCOL_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (etd->tree_view, column);

    /* Summary. */
    renderer = gtk_cell_renderer_text_new ();
    g_object_set(renderer, "ypad", 0, NULL);
    column = gtk_tree_view_column_new_with_attributes ("Summary", renderer,
        "foreground", FOREGROUND_COLOR_COL,
        "background", BACKGROUND_COLOR_COL,
        NULL);
    gtk_tree_view_column_set_cell_data_func(column, renderer, str_ptr_data_func,
        GINT_TO_POINTER(SUMMARY_COLUMN), NULL);

    gtk_tree_sortable_set_sort_func(sortable, SUMMARY_COLUMN, str_ptr_sort_func,
        GINT_TO_POINTER(SUMMARY_COLUMN), NULL);

    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 90);
    gtk_tree_view_column_set_sort_column_id(column, SUMMARY_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column (etd->tree_view, column);

    gtk_tree_view_set_search_column (etd->tree_view, SUMMARY_COLUMN); /* Allow searching the summary */
    gtk_tree_view_set_reorderable (etd->tree_view, TRUE);   /* Allow user to reorder data with drag n drop */

    /* Now enable the sorting of each column */
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(etd->tree_view), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(etd->tree_view), TRUE);

    /* Setup the selection handler */
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(etd->tree_view));
    gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

    g_signal_connect (G_OBJECT (selection), "changed", /* select_row */
                  G_CALLBACK (select_row_cb),
                  NULL);

    etd->scrolled_window=scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(etd->scrolled_window), GTK_WIDGET (etd->tree_view));

    gtk_box_pack_start(GTK_BOX(vbox), etd->scrolled_window, TRUE, TRUE, 0);
}

static void
expert_dlg_draw(void *data)
{
    expert_tapdata_t *etd = data;
    expert_info_t *ei;
    gchar *title;
    const char *entries[2];   /**< column entries */
    GtkListStore *list_store, *comments_list_store;
    GtkTreeIter iter;
    gchar *color_str = NULL;
    guint packet_no = 0;
    const gchar *group_str;
    const gchar *severity_str;


    if(etd->label) {
        if(etd->last - etd->first) {
            title = g_strdup_printf("Adding: %u new messages",etd->last - etd->first);
            gtk_label_set_text(GTK_LABEL(etd->label), title);
            g_free(title);
        }
    }

    list_store = GTK_LIST_STORE(gtk_tree_view_get_model(etd->tree_view)); /* Get store */
    comments_list_store = GTK_LIST_STORE(gtk_tree_view_get_model(etd->tree_view_comments)); 

    /* append new events (remove from new list, append to displayed list and clist) */
    while(etd->first < etd->last){
        ei = &g_array_index(etd->ei_array, expert_info_t, etd->first);
        etd->first++;

        if(ei->severity < etd->severity_report_level) {
            continue;
        }
        etd->disp_events++;

        /* packet number */
        if(ei->packet_num) {
            packet_no = ei->packet_num;
        }

        /*  match_strval return a static string or NULL
            severity */
        severity_str = match_strval(ei->severity, expert_severity_vals);
        /* group */
        group_str = match_strval(ei->group, expert_group_vals);

        /* protocol */
        if(ei->protocol) {
            entries[0] = ei->protocol;
        } else {
            entries[0] = "-";
        }

        /* summary */
        entries[1] = ei->summary;

        /* set rows background color depending on severity */
        switch(ei->severity) {
        case(PI_COMMENT):
            color_str = expert_color_comment_str;
            gtk_list_store_insert_with_values(comments_list_store , &iter, G_MAXINT,
                NO_COLUMN_C_TABLE, packet_no,
                SUMMARY_COLUMN_C_TABLE, entries[1],
                FOREGROUND_COLOR_COL_C_TABLE, expert_color_foreground_str,
                BACKGROUND_COLOR_COL_C_TABLE, color_str,
                -1);
            break;
        case(PI_CHAT):
            color_str = expert_color_chat_str;
            break;
        case(PI_NOTE):
            color_str = expert_color_note_str;
            break;
        case(PI_WARN):
            color_str = expert_color_warn_str;
            break;
        case(PI_ERROR):
            color_str = expert_color_error_str;
            break;
        default:
            g_assert_not_reached();
        }


        /* Creates a new row at position. iter will be changed to point to this new row.
         * If position is larger than the number of rows on the list, then the new row will be appended to the list.
         * The row will be filled with the values given to this function.
         * :
         * should generally be preferred when inserting rows in a sorted list store.
         */
        gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
                    NO_COLUMN, packet_no,
                    SEVERITY_COLUMN, severity_str,
                    GROUP_COLUMN, group_str,
                    PROTOCOL_COLUMN, entries[0],
                    SUMMARY_COLUMN, entries[1],
                    FOREGROUND_COLOR_COL, expert_color_foreground_str,
                    BACKGROUND_COLOR_COL, color_str,
                    -1);
    }

    if(etd->label) {
        title = g_strdup_printf("Errors: %u Warnings: %u Notes: %u Chats: %u, Packet comments: %u",
                                etd->error_events, etd->warn_events,
                                etd->note_events, etd->chat_events, etd->pkt_comments_events);
        gtk_label_set_text(GTK_LABEL(etd->label), title);
        g_free(title);
    }

    title = g_strdup_printf("Wireshark: %u Expert Info%s",
                            etd->disp_events,
                            plurality(etd->disp_events, "", "s"));
    gtk_window_set_title(GTK_WINDOW(etd->win), title);
    g_free(title);
}

static void
expert_comp_init(const char *optarg _U_, void* userdata _U_)
{
    expert_comp_dlg_t *ss;
    const char *filter=NULL;
    GString *error_string;
    GtkWidget *temp_page, *details_page, *comments_page;
    GtkWidget *main_nb;
    GtkWidget *vbox;
    GtkWidget *hbox;
    GtkWidget *image;
    GtkWidget *bbox;
    GtkWidget *close_bt;
    GtkWidget *help_bt;
    expert_tapdata_t *etd;

    ss=g_malloc(sizeof(expert_comp_dlg_t));

    ss->pkt_comments_events = 0;
    ss->disp_events = 0;
    ss->chat_events = 0;
    ss->note_events = 0;
    ss->warn_events = 0;
    ss->error_events = 0;

    expert_comp_dlg_w = ss->win=dlg_window_new("err");  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(ss->win), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(ss->win), 700, 300);

    error_set_title(ss);

    vbox=gtk_vbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(ss->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    main_nb = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), main_nb, TRUE, TRUE, 0);

    /* We must display TOP LEVEL Widget before calling init_table() */
    gtk_widget_show_all(ss->win);

    /* Errors */
    temp_page = gtk_vbox_new(FALSE, 6);
    ss->error_label = gtk_label_new("Errors: 0/y");
    gtk_widget_show(ss->error_label);
    hbox = gtk_hbox_new(FALSE, 3);
    if ( prefs.gui_expert_composite_eyecandy ) {
        image = pixbuf_to_widget(expert_error_pb_data);
        gtk_widget_show(image);
        gtk_container_add(GTK_CONTAINER(hbox), image);
    }
    gtk_container_add(GTK_CONTAINER(hbox), ss->error_label);
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, hbox);
    init_error_table(&ss->error_table, 0, temp_page);

    /* Warnings */
    temp_page = gtk_vbox_new(FALSE, 6);
    ss->warn_label = gtk_label_new("Warnings: 0/y");
    gtk_widget_show(ss->warn_label);
    hbox = gtk_hbox_new(FALSE, 3);
    if ( prefs.gui_expert_composite_eyecandy ) {
        image = pixbuf_to_widget(expert_warn_pb_data);
        gtk_widget_show(image);
        gtk_container_add(GTK_CONTAINER(hbox), image);
    }
    gtk_container_add(GTK_CONTAINER(hbox), ss->warn_label);
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, hbox);
    init_error_table(&ss->warn_table, 0, temp_page);

    /* Notes */
    temp_page = gtk_vbox_new(FALSE, 6);
    ss->note_label = gtk_label_new("Notes: 0/y");
    gtk_widget_show(ss->note_label);
    hbox = gtk_hbox_new(FALSE, 3);
    if ( prefs.gui_expert_composite_eyecandy ) {
        image = pixbuf_to_widget(expert_note_pb_data);
        gtk_widget_show(image);
        gtk_container_add(GTK_CONTAINER(hbox), image);
    }
    gtk_container_add(GTK_CONTAINER(hbox), ss->note_label);
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, hbox);
    init_error_table(&ss->note_table, 0, temp_page);

    /* Chat */
    temp_page = gtk_vbox_new(FALSE, 6);
    ss->chat_label = gtk_label_new("Chats: 0/y");
    gtk_widget_show(ss->chat_label);
    hbox = gtk_hbox_new(FALSE, 3);
    if ( prefs.gui_expert_composite_eyecandy ) {
        image = pixbuf_to_widget(expert_chat_pb_data);
        gtk_widget_show(image);
        gtk_container_add(GTK_CONTAINER(hbox), image);
    }
    gtk_container_add(GTK_CONTAINER(hbox), ss->chat_label);
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, hbox);
    init_error_table(&ss->chat_table, 0, temp_page);

    /* Details */
    details_page = gtk_vbox_new(FALSE, 6);
    ss->all_label = gtk_label_new("Details: 0");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), details_page, ss->all_label);

    /* Paket comments */
    comments_page = gtk_vbox_new(FALSE, 6);
    ss->pkt_comments_label = gtk_label_new("Packet Comments: 0/y");
    gtk_widget_show(ss->pkt_comments_label);
    hbox = gtk_hbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(hbox), ss->pkt_comments_label);
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), comments_page, hbox);

    etd = expert_dlg_new_table();
    etd->label=gtk_label_new("Please wait ...");
    gtk_misc_set_alignment(GTK_MISC(etd->label), 0.0f, 0.5f);

    etd->win=ss->win;
    expert_dlg_init_table(etd, details_page);
    expert_dlg_init_comments_table(etd, comments_page);

    /* Add tap listener functions for expert details, From expert_dlg.c*/
    error_string=register_tap_listener("expert", etd, NULL /* fstring */,
                                       TL_REQUIRES_PROTO_TREE,
                                       expert_dlg_reset,
                                       expert_dlg_packet,
                                       expert_dlg_draw);
    if(error_string){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        g_free(etd);
        return;
    }

    g_signal_connect(etd->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(etd->win, "destroy", G_CALLBACK(expert_dlg_destroy_cb), etd);

    /* Register the tap listener */

    error_string=register_tap_listener("expert", ss, filter, 0, error_reset, error_packet, expert_comp_draw);
    if(error_string){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        g_free(ss);
        return;
    }

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(ss->win, close_bt, window_cancel_button_cb);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_EXPERT_INFO_DIALOG);
    gtk_widget_set_tooltip_text (help_bt, "Show topic specific help");

    g_signal_connect(ss->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(ss->win, "destroy", G_CALLBACK(win_destroy_cb), ss);

    gtk_widget_show_all(ss->win);
    window_present(ss->win);

    /*
     * At least at present, the only information the tap listener appears
     * to care about is available regardless of whether the protocol tree
     * is being built, so we don't appear to need to have the protocol
     * tree built.
     *
     * This means we can use cf_retap_packets(), even though it will only
     * build the protocol tree if at least one tap has a filter in place.
     * cf_retap_packets() is faster than cf_redissect_packets(), as it
     * assumes we didn't change anything that would cause any packets to
     * dissect differently, and thus doesn't redo the packet display.
     */
    cf_retap_packets(&cfile);

    /* This will bring up the progress bar
     * Put our window back in front
     */
    gdk_window_raise(gtk_widget_get_window(ss->win));
    /* Set the lable text */
    expert_comp_draw(ss);
}

void
expert_comp_dlg_launch(void)
{
    if (expert_comp_dlg_w) {
        reactivate_window(expert_comp_dlg_w);
    } else {
        expert_comp_init("", NULL);
    }
}

void
register_tap_listener_expert_comp(void)
{
    register_stat_cmd_arg("expert_comp", expert_comp_init,NULL);
}

