/* dissector_tables_dlg.c
 * dissector_tables_dlg   2010 Anders Broman
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

#include <glib.h>

#include <epan/packet.h>

#include <gtk/gtk.h>
#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/dissector_tables_dlg.h"

static GtkWidget  *dissector_tables_dlg_w = NULL;

/* The columns */
enum
{
    TABLE_UI_NAME_COL,
    TABLE_SHORT_NAME_COL,
    N_COLUMNS
};

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data _U_)
{

    if (dissector_tables_dlg_w != NULL) {
        window_destroy(dissector_tables_dlg_w);
        dissector_tables_dlg_w = NULL;
    }


}

/*
 * For a dissector table, put
 * its short name and its
 * descriptive name in the treeview.
 */

struct dissector_tables_tree_info {
    GtkWidget       *tree;
    GtkTreeIter     iter;
    GtkTreeIter     new_iter;
};

typedef struct dissector_tables_tree_info dissector_tables_tree_info_t;

static gint
ui_sort_func(GtkTreeModel *model,
             GtkTreeIter  *a,
             GtkTreeIter  *b,
             gpointer      user_data)
{
    gchar *stra, *strb;

    /* The col to get data from is in userdata */
    gint data_column = GPOINTER_TO_INT(user_data);

    gtk_tree_model_get(model, a, data_column, &stra, -1);
    gtk_tree_model_get(model, b, data_column, &strb, -1);

    return strcmp(stra, strb);
}


/*
 * Struct to hold the pointer to the trees
 * for dissector tables.
 */
struct dissector_tables_trees {
    GtkWidget       *str_tree_wgt;
    GtkWidget       *uint_tree_wgt;
    GtkWidget       *heuristic_tree_wgt;
};

typedef struct dissector_tables_trees dissector_tables_trees_t;

static void
proto_add_to_list(dissector_tables_tree_info_t *tree_info,
                  GtkTreeStore *store,
                  gchar        *str,
                  const gchar  *proto_name)
{
    gtk_tree_store_insert_with_values(store, &tree_info->new_iter, &tree_info->iter, G_MAXINT,
                                      TABLE_UI_NAME_COL,    str,
                                      TABLE_SHORT_NAME_COL, proto_name,
                                      -1);
}

static void
decode_proto_add_to_list (const gchar *table_name _U_, ftenum_t selector_type,
                          gpointer key, gpointer value _U_, gpointer user_data)
{
    GtkTreeStore       *store;
    const gchar        *proto_name;
    dtbl_entry_t       *dtbl_entry;
    dissector_handle_t  handle;
    guint32             port;
    gchar              *str;
    dissector_tables_tree_info_t *tree_info;

    tree_info = user_data;
    dtbl_entry = value;
    handle = dtbl_entry_get_handle(dtbl_entry);
    proto_name = dissector_handle_get_short_name(handle);

    store = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree_info->tree)));

    switch (selector_type) {

    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        port = GPOINTER_TO_UINT(key);
        /* Hack: Use fixed width rj str so alpha sort (strcmp) will sort field numerically */
        str = g_strdup_printf ("%10d", port);
        proto_add_to_list(tree_info, store, str, proto_name);
        g_free (str);
        break;

    case FT_STRING:
    case FT_STRINGZ:
        str = (gchar*) key;
        proto_add_to_list(tree_info, store, str, proto_name);
        break;

    default:
        g_assert_not_reached();
    }

}

static void
table_name_add_to_list(dissector_tables_tree_info_t  *tree_info,
                       GtkWidget  *tree_view,
                       const char *table_name,
                       const char *ui_name)
{
    GtkTreeStore *store;

    tree_info->tree = tree_view;
    store = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view))); /* Get store */

    gtk_tree_store_insert_with_values(store, &tree_info->iter, NULL, G_MAXINT,
                                      TABLE_UI_NAME_COL,    ui_name,
                                      TABLE_SHORT_NAME_COL, table_name,
                                      -1);
}

static void
display_heur_dissector_table_entries(gpointer data, gpointer user_data)
{
	heur_dtbl_entry_t *dtbl_entry = data;
	dissector_tables_tree_info_t  *tree_info = user_data;
	GtkTreeStore       *store;

	if(dtbl_entry->protocol){

		store = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree_info->tree))); /* Get store */
		proto_add_to_list(tree_info, store, 
			(gchar *)proto_get_protocol_long_name(dtbl_entry->protocol), 
			proto_get_protocol_short_name(dtbl_entry->protocol));
	}else{
		g_warning("no protocol info");
	}


}

static void
display_heur_dissector_table_names(const char *table_name, gpointer table, gpointer w)
{
    dissector_tables_trees_t      *dis_tbl_trees;
    dissector_tables_tree_info_t  *tree_info;
	heur_dissector_list_t *list;
	 
	tree_info = g_new(dissector_tables_tree_info_t, 1);
	dis_tbl_trees = w;
	list = table;

	table_name_add_to_list(tree_info, dis_tbl_trees->heuristic_tree_wgt, "", table_name);

	if(table){
		g_slist_foreach (*list, display_heur_dissector_table_entries, tree_info);
	}

}

static void
display_dissector_table_names(const char *table_name, const char *ui_name, gpointer w)
{
    dissector_tables_trees_t      *dis_tbl_trees;
    dissector_tables_tree_info_t  *tree_info;
    ftenum_t                       selector_type = get_dissector_table_selector_type(table_name);

    tree_info = g_new(dissector_tables_tree_info_t, 1);
    dis_tbl_trees = w;

    switch (selector_type) {
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
            table_name_add_to_list(tree_info, dis_tbl_trees->uint_tree_wgt, table_name, ui_name);
            break;
        case FT_STRING:
        case FT_STRINGZ:
            table_name_add_to_list(tree_info, dis_tbl_trees->str_tree_wgt, table_name, ui_name);
            break;
        default:
            break;
    }
    dissector_table_foreach(table_name, decode_proto_add_to_list, tree_info);

    g_free(tree_info);
}

static GtkWidget*
init_table(void)
{
    GtkTreeStore      *store;
    GtkWidget         *tree;
    GtkTreeView       *tree_view;
    GtkTreeViewColumn *column;
    GtkCellRenderer   *renderer;
    GtkTreeSortable   *sortable;

    /* Create the store */
    store = gtk_tree_store_new (N_COLUMNS,      /* Total number of columns */
                               G_TYPE_STRING,   /* Table              */
                               G_TYPE_STRING);  /* Table              */

    /* Create a view */
    tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
    tree_view = GTK_TREE_VIEW(tree);
    sortable = GTK_TREE_SORTABLE(store);

    /* Speed up the list display */
    gtk_tree_view_set_fixed_height_mode(tree_view, TRUE);

    /* Setup the sortable columns */
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW (tree), FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (store));

    /* Create the first column, associating the "text" attribute of the
     * cell_renderer to the first column of the model */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("UI name", renderer, "text", TABLE_UI_NAME_COL, NULL);
    gtk_tree_sortable_set_sort_func(sortable, TABLE_UI_NAME_COL,
                                    ui_sort_func, GINT_TO_POINTER(TABLE_UI_NAME_COL), NULL);
    gtk_tree_view_column_set_sort_column_id(column, TABLE_UI_NAME_COL);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_column_set_fixed_width(column, 330);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree_view), column);

    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Short name", renderer, "text", TABLE_SHORT_NAME_COL, NULL);
    gtk_tree_sortable_set_sort_func(sortable, TABLE_SHORT_NAME_COL,
                                    ui_sort_func, GINT_TO_POINTER(TABLE_SHORT_NAME_COL), NULL);
    gtk_tree_view_column_set_sort_column_id(column, TABLE_SHORT_NAME_COL);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_column_set_fixed_width(column, 100);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree_view), column);

    return tree;

}

static void
dissector_tables_dlg_init(void)
{
    dissector_tables_trees_t dis_tbl_trees;
    GtkWidget       *vbox;
    GtkWidget       *hbox;
    GtkWidget       *main_nb;
    GtkWidget       *scrolled_window;
    GtkTreeSortable *sortable;
    GtkWidget       *temp_page, *tmp;

    dissector_tables_dlg_w = dlg_window_new("Dissector tables");  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(dissector_tables_dlg_w), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dissector_tables_dlg_w), 700, 300);

    vbox=gtk_vbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(dissector_tables_dlg_w), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    main_nb = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), main_nb, TRUE, TRUE, 0);

    /* String tables */
    temp_page = gtk_vbox_new(FALSE, 6);
    tmp = gtk_label_new("String tables");
    gtk_widget_show(tmp);
    hbox = gtk_hbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(hbox), tmp);
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, hbox);

    scrolled_window = scrolled_window_new(NULL, NULL);
    dis_tbl_trees.str_tree_wgt = init_table();
    gtk_widget_show(dis_tbl_trees.str_tree_wgt);
    gtk_container_add(GTK_CONTAINER(scrolled_window), dis_tbl_trees.str_tree_wgt);
    gtk_box_pack_start(GTK_BOX(temp_page), scrolled_window, TRUE, TRUE, 0);
    gtk_widget_show(scrolled_window);

    /* uint tables */
    temp_page = gtk_vbox_new(FALSE, 6);
    tmp = gtk_label_new("Integer tables");
    gtk_widget_show(tmp);
    hbox = gtk_hbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(hbox), tmp);
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, hbox);

    scrolled_window = scrolled_window_new(NULL, NULL);
    dis_tbl_trees.uint_tree_wgt = init_table();
    gtk_widget_show(dis_tbl_trees.uint_tree_wgt);
    gtk_container_add(GTK_CONTAINER(scrolled_window), dis_tbl_trees.uint_tree_wgt);
    gtk_box_pack_start(GTK_BOX(temp_page), scrolled_window, TRUE, TRUE, 0);
    gtk_widget_show(scrolled_window);

    /* heuristic tables */
    temp_page = gtk_vbox_new(FALSE, 6);
    tmp = gtk_label_new("Heuristic tables");
    gtk_widget_show(tmp);
    hbox = gtk_hbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(hbox), tmp);
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, hbox);

    scrolled_window = scrolled_window_new(NULL, NULL);
    dis_tbl_trees.heuristic_tree_wgt = init_table();
    gtk_widget_show(dis_tbl_trees.heuristic_tree_wgt);
    gtk_container_add(GTK_CONTAINER(scrolled_window), dis_tbl_trees.heuristic_tree_wgt);
    gtk_box_pack_start(GTK_BOX(temp_page), scrolled_window, TRUE, TRUE, 0);
    gtk_widget_show(scrolled_window);

	/* We must display TOP LEVEL Widget before calling init_table() */
    gtk_widget_show_all(dissector_tables_dlg_w);
    g_signal_connect(dissector_tables_dlg_w, "destroy", G_CALLBACK(win_destroy_cb), NULL);

    /* Fill the table with data */
    dissector_all_tables_foreach_table(display_dissector_table_names, (gpointer)&dis_tbl_trees);

    dissector_all_heur_tables_foreach_table(display_heur_dissector_table_names, (gpointer)&dis_tbl_trees);

	sortable = GTK_TREE_SORTABLE(gtk_tree_view_get_model(GTK_TREE_VIEW(dis_tbl_trees.str_tree_wgt)));
    gtk_tree_sortable_set_sort_column_id(sortable, TABLE_UI_NAME_COL, GTK_SORT_ASCENDING);

    sortable = GTK_TREE_SORTABLE(gtk_tree_view_get_model(GTK_TREE_VIEW(dis_tbl_trees.uint_tree_wgt)));
    gtk_tree_sortable_set_sort_column_id(sortable, TABLE_UI_NAME_COL, GTK_SORT_ASCENDING);

    sortable = GTK_TREE_SORTABLE(gtk_tree_view_get_model(GTK_TREE_VIEW(dis_tbl_trees.heuristic_tree_wgt)));
    gtk_tree_sortable_set_sort_column_id(sortable, TABLE_UI_NAME_COL, GTK_SORT_ASCENDING);

}

void
dissector_tables_dlg_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (dissector_tables_dlg_w) {
          reactivate_window(dissector_tables_dlg_w);
    } else {
          dissector_tables_dlg_init();
    }
}
