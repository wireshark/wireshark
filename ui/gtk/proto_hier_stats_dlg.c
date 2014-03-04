/* proto_hier_stats_dlg.c
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

#include <stdio.h>
#include <string.h>

#include <gtk/gtk.h>

#include "../proto_hier_stats.h"
#include "ui/simple_dialog.h"
#include "ui/utf8_entities.h"

#include "ui/gtk/proto_hier_stats_dlg.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/filter_utils.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/help_dlg.h"


enum {
    PROTOCOL_COLUMN,
    PRCT_PKTS_COLUMN,
    PKTS_COLUMN,
    PRCT_BYTES_COLUMN,
    BYTES_COLUMN,
    BANDWIDTH_COLUMN,
    END_PKTS_COLUMN,
    END_BYTES_COLUMN,
    END_BANDWIDTH_COLUMN,
    FILTER_NAME,
    PRCT_PKTS_VALUE_COLUMN,
    PRCT_BYTES_VALUE_COLUMN,
    NUM_STAT_COLUMNS /* must be the last */
};

typedef struct {
    GtkTreeView  *tree_view;
    GtkTreeIter  *iter;
    ph_stats_t   *ps;
} draw_info_t;

static GtkWidget *tree;

#define PCT(x,y) (100.0 * (float)(x) / (float)(y))
#define BANDWIDTH(bytes,secs) ((bytes) * 8.0 / ((secs) * 1000.0 * 1000.0))

static void
proto_hier_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data _U_, guint callback_action)
{
    gchar *str = NULL;
    gchar *strtmp = NULL;
    const char *filter = NULL;
    GtkTreeSelection *sel;
    GtkTreeModel *model;
    GtkTreeIter iter;
    GtkTreePath *path;

    sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(tree));
    if (!gtk_tree_selection_get_selected(sel, &model, &iter))
        return;
    path = gtk_tree_model_get_path(model,&iter);

    gtk_tree_model_get (model, &iter, FILTER_NAME, &filter, -1);
    if (filter && strlen(filter) > 0) {
        str = g_strdup_printf("%s", filter);
    } else {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not acquire information to build a filter!\nTry expanding or choosing another item.");
        return;
    }

    while (gtk_tree_path_up(path) && gtk_tree_path_get_depth(path) > 0)
    {
        strtmp = g_strdup_printf("%s", str);
        g_free(str);

        gtk_tree_model_get_iter(model, &iter, path);
        gtk_tree_model_get(model, &iter, FILTER_NAME, &filter, -1);
        if (filter && strlen(filter) > 0) {
            str = g_strdup_printf("%s and %s", strtmp, filter);
        } else {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not acquire information to build a filter!\nTry expanding or choosing another item.");
            g_free(strtmp);
            return;
        }

        g_free(strtmp);
    }

    apply_selected_filter (callback_action, str);

    gtk_tree_path_free(path);
    g_free (str);
}


/* Action callbacks */
static void
apply_as_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_SELECTED, 0));
}
static void
apply_as_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_NOT_SELECTED, 0));
}
static void
apply_as_and_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_AND_SELECTED, 0));
}
static void
apply_as_or_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_OR_SELECTED, 0));
}
static void
apply_as_and_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, 0));
}
static void
apply_as_or_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, 0));
}

static void
prep_as_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_SELECTED, 0));
}
static void
prep_as_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, 0));
}
static void
prep_as_and_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_AND_SELECTED, 0));
}
static void
prep_as_or_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_OR_SELECTED, 0));
}
static void
prep_as_and_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, 0));
}
static void
prep_as_or_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, 0));
}

static void
find_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_FIND_FRAME(ACTYPE_SELECTED, 0));
}
static void
find_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_FIND_FRAME(ACTYPE_NOT_SELECTED, 0));
}
static void
find_prev_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, 0));
}
static void
find_prev_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_FIND_PREVIOUS(ACTYPE_NOT_SELECTED, 0));
}
static void
find_next_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_FIND_NEXT(ACTYPE_SELECTED, 0));
}
static void
find_next_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_FIND_NEXT(ACTYPE_NOT_SELECTED, 0));
}
static void
color_selected_cb(GtkWidget *widget, gpointer user_data)
{
    proto_hier_select_filter_cb( widget , user_data, CALLBACK_COLORIZE(ACTYPE_SELECTED, 0));
}


static const char *ui_desc_proto_hier_stats_filter_popup =
"<ui>\n"
"  <popup name='ProtoHierStatsFilterPopup'>\n"
"    <menu action='/Apply as Filter'>\n"
"      <menuitem action='/Apply as Filter/Selected'/>\n"
"      <menuitem action='/Apply as Filter/Not Selected'/>\n"
"      <menuitem action='/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " and Selected'/>\n"
"      <menuitem action='/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " or Selected'/>\n"
"      <menuitem action='/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " and not Selected'/>\n"
"      <menuitem action='/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " or not Selected'/>\n"
"    </menu>\n"
"    <menu action='/Prepare a Filter'>\n"
"      <menuitem action='/Prepare a Filter/Selected'/>\n"
"      <menuitem action='/Prepare a Filter/Not Selected'/>\n"
"      <menuitem action='/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " and Selected'/>\n"
"      <menuitem action='/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " or Selected'/>\n"
"      <menuitem action='/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " and not Selected'/>\n"
"      <menuitem action='/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " or not Selected'/>\n"
"    </menu>\n"
"    <menu action='/Find Frame'>\n"
"      <menu action='/Find Frame/Find Frame'>\n"
"        <menuitem action='/Find Frame/Selected'/>\n"
"        <menuitem action='/Find Frame/Not Selected'/>\n"
"      </menu>\n"
"      <menu action='/Find Frame/Find Next'>\n"
"        <menuitem action='/Find Next/Selected'/>\n"
"        <menuitem action='/Find Next/Not Selected'/>\n"
"      </menu>\n"
"      <menu action='/Find Frame/Find Previous'>\n"
"        <menuitem action='/Find Previous/Selected'/>\n"
"        <menuitem action='/Find Previous/Not Selected'/>\n"
"      </menu>\n"
"    </menu>\n"
"    <menu action='/Colorize Procedure'>\n"
"     <menuitem action='/Colorize Procedure/Colorize Protocol'/>\n"
"    </menu>\n"
"  </popup>\n"
"</ui>\n";

/*
 * GtkActionEntry
 * typedef struct {
 *   const gchar     *name;
 *   const gchar     *stock_id;
 *   const gchar     *label;
 *   const gchar     *accelerator;
 *   const gchar     *tooltip;
 *   GCallback  callback;
 * } GtkActionEntry;
 * const gchar *name;           The name of the action.
 * const gchar *stock_id;       The stock id for the action, or the name of an icon from the icon theme.
 * const gchar *label;          The label for the action. This field should typically be marked for translation,
 *                              see gtk_action_group_set_translation_domain().
 *                              If label is NULL, the label of the stock item with id stock_id is used.
 * const gchar *accelerator;    The accelerator for the action, in the format understood by gtk_accelerator_parse().
 * const gchar *tooltip;        The tooltip for the action. This field should typically be marked for translation,
 *                              see gtk_action_group_set_translation_domain().
 * GCallback callback;          The function to call when the action is activated.
 *
 */
static const GtkActionEntry proto_hier_stats_popup_entries[] = {
  { "/Apply as Filter",                         NULL, "Apply as Filter",                NULL, NULL,                             NULL },
  { "/Prepare a Filter",                        NULL, "Prepare a Filter",               NULL, NULL,                             NULL },
  { "/Find Frame",                              NULL, "Find Frame",                     NULL, NULL,                             NULL },
  { "/Find Frame/Find Frame",                   NULL, "Find Frame",                     NULL, NULL,                             NULL },
  { "/Find Frame/Find Next",                    NULL, "Find Next" ,                     NULL, NULL,                             NULL },
  { "/Find Frame/Find Previous",                NULL, "Find Previous",                  NULL, NULL,                             NULL },
  { "/Colorize Procedure",                      NULL, "Colorize Procedure",             NULL, NULL,                             NULL },
  { "/Apply as Filter/Selected",                NULL, "Selected",                       NULL, "Selected",                       G_CALLBACK(apply_as_selected_cb) },
  { "/Apply as Filter/Not Selected",        NULL, "Not Selected",               NULL, "Not Selected",               G_CALLBACK(apply_as_not_selected_cb) },
  { "/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " and Selected",       NULL, UTF8_HORIZONTAL_ELLIPSIS " and Selected",             NULL, UTF8_HORIZONTAL_ELLIPSIS " and Selected",             G_CALLBACK(apply_as_and_selected_cb) },
  { "/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " or Selected",            NULL, UTF8_HORIZONTAL_ELLIPSIS " or Selected",              NULL, UTF8_HORIZONTAL_ELLIPSIS " or Selected",              G_CALLBACK(apply_as_or_selected_cb) },
  { "/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " and not Selected",   NULL, UTF8_HORIZONTAL_ELLIPSIS " and not Selected",         NULL, UTF8_HORIZONTAL_ELLIPSIS " and not Selected",         G_CALLBACK(apply_as_and_not_selected_cb) },
  { "/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " or not Selected",        NULL, UTF8_HORIZONTAL_ELLIPSIS " or not Selected",          NULL, UTF8_HORIZONTAL_ELLIPSIS " or not Selected",          G_CALLBACK(apply_as_or_not_selected_cb) },
  { "/Prepare a Filter/Selected",               NULL, "Selected",                       NULL, "selcted",                        G_CALLBACK(prep_as_selected_cb) },
  { "/Prepare a Filter/Not Selected",       NULL, "Not Selected",               NULL, "Not Selected",               G_CALLBACK(prep_as_not_selected_cb) },
  { "/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " and Selected",      NULL, UTF8_HORIZONTAL_ELLIPSIS " and Selected",             NULL, UTF8_HORIZONTAL_ELLIPSIS " and Selected",             G_CALLBACK(prep_as_and_selected_cb) },
  { "/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " or Selected",       NULL, UTF8_HORIZONTAL_ELLIPSIS " or Selected",              NULL, UTF8_HORIZONTAL_ELLIPSIS " or Selected",              G_CALLBACK(prep_as_or_selected_cb) },
  { "/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " and not Selected",  NULL, UTF8_HORIZONTAL_ELLIPSIS " and not Selected",         NULL, UTF8_HORIZONTAL_ELLIPSIS " and not Selected",         G_CALLBACK(prep_as_and_not_selected_cb) },
  { "/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " or not Selected",   NULL, UTF8_HORIZONTAL_ELLIPSIS " or not Selected",          NULL, UTF8_HORIZONTAL_ELLIPSIS " or not Selected",          G_CALLBACK(prep_as_or_not_selected_cb) },
  { "/Find Frame/Selected",                     NULL, "Selected",                       NULL, "Selected",                       G_CALLBACK(find_selected_cb) },
  { "/Find Frame/Not Selected",                 NULL, "Not Selected",                   NULL, "Not Selected",                   G_CALLBACK(find_not_selected_cb) },
  { "/Find Previous/Selected",                  NULL, "Selected",                       NULL, "Selected",                       G_CALLBACK(find_prev_selected_cb) },
  { "/Find Previous/Not Selected",              NULL, "Not Selected",                   NULL, "Not Selected",                   G_CALLBACK(find_prev_not_selected_cb) },
  { "/Find Next/Selected",                      NULL, "Selected",                       NULL, "Selected",                       G_CALLBACK(find_next_selected_cb) },
  { "/Find Next/Not Selected",                  NULL, "Not Selected",                   NULL, "Not Selected",                   G_CALLBACK(find_next_not_selected_cb) },
  { "/Colorize Procedure/Colorize Protocol",    NULL, "Colorize Protocol",              NULL, "Colorize Protocol",              G_CALLBACK(color_selected_cb) },
};

static void
fill_in_tree_node(GNode *node, gpointer data)
{
    ph_stats_node_t *stats = (ph_stats_node_t *)node->data;
    draw_info_t     *di = (draw_info_t *)data;
    ph_stats_t      *ps = di->ps;
    draw_info_t     child_di;
    double          seconds;
    gchar          *text[NUM_STAT_COLUMNS];
    float           percent_packets, percent_bytes;
    GtkTreeView     *tree_view = di->tree_view;
    GtkTreeIter     *iter = di->iter;
    GtkTreeStore    *store;
    GtkTreeIter      new_iter;

    seconds = ps->last_time - ps->first_time;

    percent_packets = (float) PCT(stats->num_pkts_total, ps->tot_packets);
    percent_bytes = (float) PCT(stats->num_bytes_total, ps->tot_bytes);
    text[PROTOCOL_COLUMN] = (gchar *) (stats->hfinfo->name);
    text[PRCT_PKTS_COLUMN] = g_strdup_printf("%.2f %%", percent_packets);
    text[PKTS_COLUMN] = g_strdup_printf("%u", stats->num_pkts_total);
    text[PRCT_BYTES_COLUMN] = g_strdup_printf("%.2f %%", percent_bytes);
    text[BYTES_COLUMN] = g_strdup_printf("%u", stats->num_bytes_total);
    if (seconds > 0.0) {
        text[BANDWIDTH_COLUMN] = g_strdup_printf("%.3f",
            BANDWIDTH(stats->num_bytes_total, seconds));
    } else {
        text[BANDWIDTH_COLUMN] = g_strdup("n.c.");
    }
    text[END_PKTS_COLUMN] = g_strdup_printf("%u", stats->num_pkts_last);
    text[END_BYTES_COLUMN] = g_strdup_printf("%u", stats->num_bytes_last);
    if (seconds > 0.0) {
        text[END_BANDWIDTH_COLUMN] = g_strdup_printf("%.3f",
            BANDWIDTH(stats->num_bytes_last, seconds));
    } else {
        text[END_BANDWIDTH_COLUMN] = g_strdup("n.c.");
    }

    store = GTK_TREE_STORE(gtk_tree_view_get_model(tree_view));
    gtk_tree_store_append(store, &new_iter, iter);
    gtk_tree_store_set(store, &new_iter,
                       PROTOCOL_COLUMN, text[PROTOCOL_COLUMN],
                       PRCT_PKTS_COLUMN, text[PRCT_PKTS_COLUMN],
                       PKTS_COLUMN, text[PKTS_COLUMN],
                       PRCT_BYTES_COLUMN, text[PRCT_BYTES_COLUMN],
                       BYTES_COLUMN, text[BYTES_COLUMN],
                       BANDWIDTH_COLUMN, text[BANDWIDTH_COLUMN],
                       END_PKTS_COLUMN, text[END_PKTS_COLUMN],
                       END_BYTES_COLUMN, text[END_BYTES_COLUMN],
                       END_BANDWIDTH_COLUMN, text[END_BANDWIDTH_COLUMN],
                       FILTER_NAME, stats->hfinfo->abbrev,
                       PRCT_PKTS_VALUE_COLUMN, percent_packets,
                       PRCT_BYTES_VALUE_COLUMN, percent_bytes,
                       -1);

    g_free(text[PRCT_PKTS_COLUMN]);
    g_free(text[PKTS_COLUMN]);
    g_free(text[PRCT_BYTES_COLUMN]);
    g_free(text[BYTES_COLUMN]);
    if (seconds > 0.0) g_free(text[BANDWIDTH_COLUMN]);
    g_free(text[END_PKTS_COLUMN]);
    g_free(text[END_BYTES_COLUMN]);
    if (seconds > 0.0) g_free(text[END_BANDWIDTH_COLUMN]);

    child_di.tree_view = tree_view;
    child_di.iter = &new_iter;
    child_di.ps = ps;

    g_node_children_foreach(node, G_TRAVERSE_ALL,
                            fill_in_tree_node, &child_di);
}

static void
fill_in_tree(GtkWidget *tree_lcl, ph_stats_t *ps)
{
    draw_info_t di;

    di.tree_view = GTK_TREE_VIEW(tree_lcl);
    di.iter = NULL;
    di.ps = ps;

    g_node_children_foreach(ps->stats_tree, G_TRAVERSE_ALL,
                            fill_in_tree_node, &di);
}


static gboolean
proto_hier_show_popup_menu_cb(GtkWidget *widget _U_, GdkEvent *event, GtkWidget *popup_menu_object)
{
    GdkEventButton *bevent = (GdkEventButton *)event;

    if (event->type==GDK_BUTTON_PRESS && bevent->button==3) {
        /* If this is a right click on one of our columns, popup the context menu */
        gtk_menu_popup(GTK_MENU(popup_menu_object), NULL, NULL, NULL, NULL, bevent->button, bevent->time);
    }

    return FALSE;
}

static void
proto_hier_create_popup_menu(void)
{

    GtkUIManager *ui_manager;
    GtkActionGroup *action_group;
    GError *error = NULL;
    GtkWidget *popup_menu_object;

    action_group = gtk_action_group_new ("ProtoHierStatsTFilterPopupActionGroup");
    gtk_action_group_add_actions (action_group,                                 /* the action group */
                                (GtkActionEntry *)proto_hier_stats_popup_entries,       /* an array of action descriptions */
                                G_N_ELEMENTS(proto_hier_stats_popup_entries),   /* the number of entries */
                                NULL);                                          /* data to pass to the action callbacks */

    ui_manager = gtk_ui_manager_new ();
    gtk_ui_manager_insert_action_group (ui_manager,
        action_group,
        0); /* the position at which the group will be inserted */
    gtk_ui_manager_add_ui_from_string (ui_manager,ui_desc_proto_hier_stats_filter_popup, -1, &error);
    if (error != NULL)
    {
        fprintf (stderr, "Warning: building proto hier ststs filter popup failed: %s\n",
                error->message);
        g_error_free (error);
        error = NULL;
    }
    popup_menu_object = gtk_ui_manager_get_widget(ui_manager, "/ProtoHierStatsFilterPopup");
    g_signal_connect(tree, "button_press_event", G_CALLBACK(proto_hier_show_popup_menu_cb), popup_menu_object);

}

static void
create_tree(GtkWidget *container, ph_stats_t *ps)
{
    GtkWidget         *sw;
    GtkTreeView       *tree_view;
    GtkTreeStore      *store;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;

    /* Scrolled Window */
    sw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw),
                                        GTK_SHADOW_IN);
    gtk_box_pack_start(GTK_BOX(container), sw, TRUE, TRUE, 0);

    store = gtk_tree_store_new(NUM_STAT_COLUMNS, G_TYPE_STRING, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_POINTER, G_TYPE_FLOAT,
                               G_TYPE_FLOAT);
    tree = tree_view_new(GTK_TREE_MODEL(store));
    g_object_unref(G_OBJECT(store));
    tree_view = GTK_TREE_VIEW(tree);
    gtk_tree_view_set_headers_visible(tree_view, TRUE);
    gtk_tree_view_set_headers_clickable(tree_view, FALSE);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Protocol", renderer,
                                                      "text", PROTOCOL_COLUMN,
                                                      NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_progress_new();
    column = gtk_tree_view_column_new_with_attributes("% Packets", renderer,
                                                      "text", PRCT_PKTS_COLUMN,
                                                      "value", PRCT_PKTS_VALUE_COLUMN,
                                                      NULL);
    gtk_tree_view_column_set_expand(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Packets", renderer,
                                                      "text", PKTS_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_progress_new();
    column = gtk_tree_view_column_new_with_attributes("% Bytes", renderer,
                                                      "text", PRCT_BYTES_COLUMN,
                                                      "value", PRCT_BYTES_VALUE_COLUMN,
                                                      NULL);
    gtk_tree_view_column_set_expand(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Bytes", renderer,
                                                      "text", BYTES_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Mbit/s", renderer,
                                                      "text", BANDWIDTH_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("End Packets", renderer,
                                                      "text", END_PKTS_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("End Bytes", renderer,
                                                      "text", END_BYTES_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("End Mbit/s", renderer,
                                                      "text", END_BANDWIDTH_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);

    /* Fill in the data. */
    fill_in_tree(tree, ps);

    gtk_tree_view_expand_all(tree_view);

    proto_hier_create_popup_menu ();

    gtk_container_add(GTK_CONTAINER(sw), tree);
}

#define MAX_DLG_HEIGHT 450
#define DEF_DLG_WIDTH  920

void
proto_hier_stats_cb(GtkWidget *w _U_, gpointer d _U_)
{
    ph_stats_t *ps;
    GtkWidget  *dlg, *close_bt, *help_bt, *vbox, *bbox;
    GtkWidget  *label;
    char       title[256];
    const char *current_filter;

    /* Get the statistics. */
    ps = ph_stats_new();
    if (ps == NULL) {
        /* The user gave up before we finished; don't pop up
           a statistics window. */
        return;
    }

    dlg = window_new(GTK_WINDOW_TOPLEVEL, "Wireshark: Protocol Hierarchy Statistics");
    gtk_window_set_default_size(GTK_WINDOW(dlg), DEF_DLG_WIDTH, MAX_DLG_HEIGHT);

    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 5, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
    gtk_container_add(GTK_CONTAINER(dlg), vbox);

    current_filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));

    if (current_filter && strlen(current_filter) != 0) {
        g_snprintf(title, sizeof(title), "Display filter: %s", current_filter);
    } else {
        g_strlcpy(title, "Display filter: none", sizeof(title));
    }
    label = gtk_label_new(title);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    /* Data section */
    create_tree(vbox, ps);

    ph_stats_free(ps);

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(dlg, close_bt, window_cancel_button_cb);

    help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_PROTO_HIERARCHY_DIALOG);

    g_signal_connect(dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

    gtk_widget_show_all(dlg);
    window_present(dlg);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
