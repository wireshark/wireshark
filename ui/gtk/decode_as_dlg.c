/* decode_as_dlg.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include <epan/decode_as.h>
#include <epan/dissectors/packet-dcerpc.h>

#include "ui/decode_as_utils.h"
#include "ui/simple_dialog.h"
#include "ui/utf8_entities.h"

#include "ui/gtk/main.h"
#include "ui/gtk/decode_as_dlg.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/packet_win.h"
#include "ui/gtk/stock_icons.h"

#undef DEBUG

/**************************************************/
/*                Typedefs & Enums                */
/**************************************************/

#define E_DECODE_MIN_HEIGHT 300
#define E_NOTEBOOK "notebook"

#define E_COMBO_BOX_MULTIVALUE "combo_box_multivalue"

#define E_PAGE_DECODE_AS_DATA  "decode_as_data"

/*
 * Columns for a "Display" list
 */
#define E_LIST_D_TABLE      0
#define E_LIST_D_SELECTOR   1
#define E_LIST_D_INITIAL    2
#define E_LIST_D_CURRENT    3
#define E_LIST_D_MAX        E_LIST_D_CURRENT
#define E_LIST_D_COLUMNS   (E_LIST_D_MAX + 1)

/*
 * Columns for a "Select" list.
 * Note that most of these columns aren't displayed; they're attached
 * to the row of the table as additional information.
 */
#define E_LIST_S_PROTO_NAME 0
#define E_LIST_S_TABLE	    1
/* The following is for debugging in decode_add_to_list */
#define E_LIST_S_MAX	    E_LIST_S_TABLE
#define E_LIST_S_COLUMNS   (E_LIST_S_MAX + 1)

#define E_PAGE_LIST   "notebook_page_list"
#define E_PAGE_TABLE  "notebook_page_table_name"
#define E_PAGE_TITLE  "notebook_page_title"
#define E_PAGE_VALUE  "notebook_page_value"

#define E_PAGE_ACTION "notebook_page_action"

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
 * button or select the "Display:User Specified Decodes" menu item
 * while there's already a "Decode As:Show" window up, we just pop up
 * the existing one, rather than creating a new one.
 */
static GtkWidget *decode_show_w = NULL;

/*
 * A list of the dialog items that only have meaning when the user has
 * selected the "Decode" radio button.  When the "Do not decode"
 * button is selected these items should be dimmed.
 */
GSList *decode_dimmable = NULL;

/*
 * Remember the "action" radio button that is currently selected in
 * the dialog.  This value is initialized when the dialog is created,
 * modified in a callback routine, and read in the routine that
 * handles a click in the "OK" button for the dialog.
 */
enum action_type  requested_action = (enum action_type)-1;


/**************************************************/
/*            Global Functions                    */
/**************************************************/

/**************************************************/
/*             Saving "Decode As"                 */
/**************************************************/

/*
 * Data structure to hold information of the "Decode As" entry.
 */
struct da_entry {
  gchar *table;
  guint selector;
  gchar *initial;
  gchar *current;
};

/*
 * A typedef for the "Decode As" entry.
 */
typedef struct da_entry da_entry_t;

/*
 * Container that holds the entries of the "Decode As"
 */
GSList *da_entries = NULL;

/*
 * Save entries into preferences.
 */
static void
write_da_entry(gpointer item, gpointer user_data)
{
  da_entry_t *entry = (da_entry_t *)item;
  FILE *daf = (FILE *)user_data;
  gchar *selector_str = g_strdup_printf("%d", entry->selector);

  decode_as_write_entry(daf, entry->table, selector_str, entry->initial, entry->current);
  g_free(selector_str);
}

/*
 * Free memory used by the da_entry
 */
static void
free_da_entry(gpointer item, gpointer user_data _U_)
{
  da_entry_t *entry = (da_entry_t *)item;
  g_free(entry->table);
  g_free(entry->initial);
  g_free(entry->current);
}


/**************************************************/
/*             Show Changed Dissectors            */
/**************************************************/

#define SORT_ALPHABETICAL 0

static gint
sort_iter_compare_func (GtkTreeModel *model,
                        GtkTreeIter *a,
                        GtkTreeIter *b,
                        gpointer user_data)
{
    gint sortcol = GPOINTER_TO_INT(user_data);
    gint ret = 0;
    switch (sortcol)
    {
        case SORT_ALPHABETICAL:
        {
        gchar *name1, *name2;
        gtk_tree_model_get(model, a, 0, &name1, -1);
        gtk_tree_model_get(model, b, 0, &name2, -1);
        if (name1 == NULL || name2 == NULL)
        {
            if (name1 == NULL && name2 == NULL)
                break; /* both equal => ret = 0 */
            ret = (name1 == NULL) ? -1 : 1;
        }
        else
        {
            ret = g_ascii_strcasecmp(name1,name2);
        }
        g_free(name1);
        g_free(name2);
        }
        break;
        default:
        g_return_val_if_reached(0);
    }
    return ret;
}


static void
decode_add_to_show_list (gpointer list_data,
                         const gchar *table_name,
                         gchar *selector_name,
                         const gchar *initial_proto_name,
                         const gchar *current_proto_name)
{
    const gchar     *text[E_LIST_D_COLUMNS];
    GtkListStore *store;
    GtkTreeIter   iter;

    store = (GtkListStore *)list_data;

    text[E_LIST_D_TABLE] = table_name;
    text[E_LIST_D_SELECTOR] = selector_name;
    text[E_LIST_D_INITIAL] = initial_proto_name;
    text[E_LIST_D_CURRENT] = current_proto_name;
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, E_LIST_D_TABLE, text[E_LIST_D_TABLE],
                       E_LIST_D_SELECTOR, text[E_LIST_D_SELECTOR],
                       E_LIST_D_INITIAL, text[E_LIST_D_INITIAL],
                       E_LIST_D_CURRENT, text[E_LIST_D_CURRENT], -1);
}


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
 * @param user_data A pointer to the list in which this information
 * should be stored.
 */
static void
decode_build_show_list (const gchar *table_name, ftenum_t selector_type,
                        gpointer key, gpointer value, gpointer user_data)
{
    dissector_handle_t current, initial;
    const gchar *current_proto_name, *initial_proto_name;
    gchar       *selector_name;
    gchar        string1[20];
    da_entry_t *entry;

    entry = g_new(da_entry_t,1);

    g_assert(user_data);
    g_assert(value);

    current = dtbl_entry_get_handle((dtbl_entry_t *)value);
    if (current == NULL)
        current_proto_name = DECODE_AS_NONE;
    else
        current_proto_name = dissector_handle_get_short_name(current);
    initial = dtbl_entry_get_initial_handle((dtbl_entry_t *)value);
    if (initial == NULL)
        initial_proto_name = DECODE_AS_NONE;
    else
        initial_proto_name = dissector_handle_get_short_name(initial);

    switch (selector_type) {

    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        switch (get_dissector_table_base(table_name)) {

        case BASE_DEC:
            g_snprintf(string1, sizeof(string1), "%u", GPOINTER_TO_UINT(key));
            break;

        case BASE_HEX:
            switch (get_dissector_table_selector_type(table_name)) {

            case FT_UINT8:
                g_snprintf(string1, sizeof(string1), "0x%02x", GPOINTER_TO_UINT(key));
                break;

            case FT_UINT16:
                g_snprintf(string1, sizeof(string1), "0x%04x", GPOINTER_TO_UINT(key));
                break;

            case FT_UINT24:
                g_snprintf(string1, sizeof(string1), "0x%06x", GPOINTER_TO_UINT(key));
                break;

            case FT_UINT32:
                g_snprintf(string1, sizeof(string1), "0x%08x", GPOINTER_TO_UINT(key));
                break;

            default:
                g_assert_not_reached();
                break;
            }
            break;

        case BASE_OCT:
            g_snprintf(string1, sizeof(string1), "%#o", GPOINTER_TO_UINT(key));
            break;
        }
        selector_name = string1;
        break;

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        selector_name = (gchar *)key;
        break;

    default:
        g_assert_not_reached();
        selector_name = NULL;
        break;
    }

    decode_add_to_show_list (
        user_data,
        get_dissector_table_ui_name(table_name),
        selector_name,
        initial_proto_name,
        current_proto_name);

    entry->table    = g_strdup(table_name);
    entry->selector = GPOINTER_TO_UINT(key);
    entry->initial  = g_strdup(initial_proto_name);
    entry->current  = g_strdup(current_proto_name);
    da_entries = g_slist_append(da_entries, entry);
}


/*
 * This routine is called when the user clicks the "OK" button in
 * the "Decode As:Show..." dialog window.  This routine destroys the
 * dialog box and performs other housekeeping functions.
 *
 * @param ok_bt A pointer to the "OK" button.
 *
 * @param parent_w A pointer to the dialog window.
 */
static void
decode_show_ok_cb (GtkWidget *ok_bt _U_, gpointer parent_w)
{
    window_destroy(GTK_WIDGET(parent_w));
}


/*
 * This routine is called when the user clicks the "Clear" button in
 * the "Decode As:Show..." dialog window.  This routine resets all the
 * dissector values and then destroys the dialog box and performs
 * other housekeeping functions.
 *
 * @param clear_bt A pointer to the "Clear" button.
 *
 * @param parent_w A pointer to the dialog window.
 */
static void
decode_show_clear_cb (GtkWidget *clear_bt _U_, gpointer parent_w)
{
    decode_clear_all();
    redissect_packets();
    redissect_all_packet_windows();

    window_destroy(GTK_WIDGET(parent_w));

    decode_show_cb(NULL, NULL);
}


/*
 * This routine is called when the user clicks the X at the top right end in
 * the "Decode As:Show..." dialog window.  This routine simply calls the
 * ok routine as if the user had clicked the ok button.
 *
 * @param win       A pointer to the dialog box.
 *
 * @param event     A pointer to the event struct
 *
 * @param user_data Unused
 */
static gboolean
decode_show_delete_cb (GtkWidget *win _U_, GdkEvent *event _U_, gpointer user_data _U_)
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
 * @param win A pointer to the dialog box.
 *
 * @param user_data Unused
 */
static void
decode_show_destroy_cb (GtkWidget *win _U_, gpointer user_data _U_)
{
    /* Note that we no longer have a "Decode As:Show" dialog box. */
    decode_show_w = NULL;

    /* Clear saved "Decode As" entries. */
    g_slist_foreach(da_entries, free_da_entry, NULL);
    g_slist_free(da_entries);
    da_entries = NULL;
}


/*
 * This routine saves the current "Decode As"-entries into the
 * preferences file
 *
 * @param win Unused
 *
 * @param user_data Unused
 */
static void
decode_show_save_cb (GtkWidget *win _U_, gpointer user_data _U_)
{
  FILE        *daf = decode_as_open();

  if (!daf) return;

  g_slist_foreach(da_entries, write_da_entry, daf);

  fclose(daf);
}

/* add a single binding to the Show list */
static void
decode_dcerpc_add_show_list_single(gpointer data, gpointer user_data)
{
    gchar      string1[20];


    decode_dcerpc_bind_values_t *binding = (decode_dcerpc_bind_values_t *)data;

    g_snprintf(string1, sizeof(string1), "ctx_id: %u", binding->ctx_id);

    decode_add_to_show_list (
        user_data,
        "DCE-RPC",
        string1,
        "-",
        binding->ifname->str);
}

/*
 * This routine creates the "Decode As:Show" dialog box. This dialog box
 * shows the user which protocols have had their dissectors changed.
 *
 * @param w Unused
 *
 * @param user_data Unused
 */
void
decode_show_cb (GtkWidget *w _U_, gpointer user_data _U_)
{
    GtkWidget         *main_vb, *bbox, *ok_bt, *clear_bt, *save_bt, *help_bt, *scrolled_window;
    const gchar       *titles[E_LIST_D_COLUMNS] = {
        "Table", "Value", "Initial", "Current"
    };
    gint               column;
    GtkListStore      *store;
    GtkTreeView       *list;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *tc;
    GtkTreeIter        iter;

    if (decode_show_w != NULL) {
        /* There's already a "Decode As" dialog box; reactivate it. */
        reactivate_window(decode_show_w);
        return;
    }

    decode_show_w = dlg_window_new("Wireshark: Decode As: Show");
    /* Provide a minimum of a couple of rows worth of data */
    gtk_window_set_default_size(GTK_WINDOW(decode_show_w), -1, E_DECODE_MIN_HEIGHT);

    /* Container for each row of widgets */
    main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 2, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(decode_show_w), main_vb);

    /* Initialize list */
    store = gtk_list_store_new(E_LIST_D_COLUMNS, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    list = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(list), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(list), FALSE);
    gtk_tree_selection_set_mode(gtk_tree_view_get_selection(list),
                                GTK_SELECTION_NONE);

    for (column = 0; column < E_LIST_D_COLUMNS; column++) {
        renderer = gtk_cell_renderer_text_new();
        tc = gtk_tree_view_column_new_with_attributes(titles[column],
                                                      renderer, "text",
                                                      column, NULL);
        gtk_tree_view_column_set_sizing(tc, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
        gtk_tree_view_column_set_resizable(tc, TRUE);
        gtk_tree_view_append_column(list, tc);
    }

    /* Add data */
    dissector_all_tables_foreach_changed(decode_build_show_list, store);
    g_object_unref(G_OBJECT(store));
    decode_dcerpc_add_show_list(decode_dcerpc_add_show_list_single, store);

    /* Put list into a scrolled window */
    scrolled_window = scrolled_window_new(NULL, NULL);
    /* this will result to set the width of the dialog to the required size */
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_window),
                                        GTK_SHADOW_IN);
    gtk_container_add(GTK_CONTAINER(scrolled_window),
                      GTK_WIDGET(list));
    gtk_box_pack_start(GTK_BOX(main_vb), scrolled_window, TRUE, TRUE, 0);

    /* Button row */
    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CLEAR, GTK_STOCK_SAVE, GTK_STOCK_HELP, NULL);
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    ok_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
    g_signal_connect(ok_bt, "clicked", G_CALLBACK(decode_show_ok_cb), decode_show_w);

    clear_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLEAR);
    g_signal_connect(clear_bt, "clicked", G_CALLBACK(decode_show_clear_cb), decode_show_w);

    save_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_SAVE);
    g_signal_connect(save_bt, "clicked", G_CALLBACK(decode_show_save_cb), decode_show_w);

    help_bt =(GtkWidget *) g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_DECODE_AS_SHOW_DIALOG);

    /* set ok as default, this button won't change anything */
    window_set_cancel_button(decode_show_w, ok_bt, NULL);

    g_signal_connect(decode_show_w, "delete_event", G_CALLBACK(decode_show_delete_cb), NULL);
    g_signal_connect(decode_show_w, "destroy", G_CALLBACK(decode_show_destroy_cb), NULL);

    gtk_widget_set_sensitive(clear_bt,
                             gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter));

    gtk_widget_show_all(decode_show_w);
    window_present(decode_show_w);
}


/**************************************************/
/*         Modify the dissector routines          */
/**************************************************/


/**************************************************/
/* Action routines for the "Decode As..." dialog  */
/*   - called when the OK button pressed          */
/*   - one per notebook page                      */
/**************************************************/


#ifdef DEBUG
/*
 * Print debugging information about tree view selection.  Extract all
 * information from the tree view entry that was selected and print it to
 * a dialog window.
 *
 * @param tree_view The tree view to dump.
 *
 * @param leadin A string to print at the start of each line.
 */
static void
decode_debug (GtkTreeView *tree_view, gchar *leadin)
{
    GtkListStore *store;
    GtkTreeSelection *selection;
    GtkTreeIter iter;
    char *string, *text[E_LIST_S_COLUMNS];
    dissector_handle_t handle;

    selection = gtk_tree_view_get_selection(tree_view);

    if (gtk_tree_selection_get_selected(selection, NULL, &iter)){
        store = GTK_LIST_STORE(gtk_tree_view_get_model(tree_view));
        gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
                           E_LIST_S_PROTO_NAME, &text[E_LIST_S_PROTO_NAME],
                           E_LIST_S_TABLE, &text[E_LIST_S_TABLE],
                           E_LIST_S_TABLE+1, &handle,
                           -1);
        string = g_strdup_printf("%s list: <put handle here>, name %s, table %s",
                                 leadin, text[E_LIST_S_PROTO_NAME],
                                 text[E_LIST_S_TABLE]);
    } else {
        string = g_strdup_printf("%s list row (none), aka do not decode", leadin);
    }
    simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, string);
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
    GtkWidget *list, *combo_box;
    GtkTreeSelection  *selection;
    GtkTreeModel      *model;
    GtkTreeIter        iter;
    decode_as_t *entry;
    gchar *table_name, *abbrev;
    dissector_handle_t handle;
    guint value_loop, *selector_type;
    gpointer ptr, value_ptr;
    gint requested_index = 0;
    gboolean add_reset_list = FALSE;

    list = (GtkWidget *)g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_LIST);
    if (requested_action == E_DECODE_NO)
        gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(list)));

    entry = (decode_as_t *)g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_DECODE_AS_DATA);
    table_name = (gchar *)g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_TABLE);

    /* (sub)dissector selection */
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
    if (gtk_tree_selection_get_selected(selection, &model, &iter) == FALSE)
    {
        abbrev = NULL;
        handle = NULL;
    } else {
        gtk_tree_model_get(model, &iter, E_LIST_S_PROTO_NAME, &abbrev,
                           E_LIST_S_TABLE+1, &handle, -1);
    }

    if (entry->num_items > 1)
    {
        combo_box = (GtkWidget *)g_object_get_data(G_OBJECT(notebook_pg), E_COMBO_BOX_MULTIVALUE);
        if (!ws_combo_box_get_active_pointer(GTK_COMBO_BOX(combo_box), &ptr))
            g_assert_not_reached();  /* Programming error if no active item in combo_box */
        requested_index = GPOINTER_TO_INT(ptr);
    }

    /* Apply values to dissector table (stored in entry) */
    for (value_loop = 0; value_loop < entry->values[requested_index].num_values; value_loop++)
    {
        value_ptr = entry->values[requested_index].build_values[value_loop](&cfile.edt->pi);
        if (abbrev != NULL && strcmp(abbrev, "(default)") == 0) {
            add_reset_list = entry->reset_value(table_name, value_ptr);
        } else {
            add_reset_list = entry->change_value(table_name, value_ptr, &handle, abbrev);
        }

        if (add_reset_list) {
            selector_type = g_new(guint,1);
            *selector_type = GPOINTER_TO_UINT(value_ptr);
            decode_build_reset_list(g_strdup(table_name), FT_UINT32, selector_type, NULL, NULL);
        }
    }

    g_free(abbrev);
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
decode_ok_cb (GtkWidget *ok_bt _U_, gpointer parent_w)
{
    GtkWidget *notebook, *notebook_pg;
    void (* func)(GtkWidget *);
    gint page_num;
    decode_as_t *entry;

    /* Call the right routine for the page that was currently in front. */
    notebook =  (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_NOTEBOOK);
    page_num = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));
    notebook_pg = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), page_num);

    func = (void (*)(GtkWidget *))g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_ACTION);
    func(notebook_pg);

    /* Free any values that used dynamic memory */
    entry = (decode_as_t *)g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_DECODE_AS_DATA);
    if ((entry->num_items == 1) && (entry->free_func != NULL))
        entry->free_func(g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_VALUE));

    window_destroy(GTK_WIDGET(parent_w));
    g_slist_free(decode_dimmable);
    decode_dimmable = NULL;

    redissect_packets();
    redissect_all_packet_windows();
}

/*
 * This routine is called when the user clicks the "Apply" button in the
 * "Decode As..." dialog window.  This routine calls various helper
 * routines to set/clear dissector values as requested by the user.
 * These routines accumulate information on what actions they have
 * taken, and this summary information is printed by this routine.
 *
 * @param apply_bt A pointer to the "Apply" button.
 *
 * @param parent_w A pointer to the dialog window.
 */
static void
decode_apply_cb (GtkWidget *apply_bt _U_, gpointer parent_w)
{
    GtkWidget *notebook, *notebook_pg;
    void (* func)(GtkWidget *);
    gint page_num;

    /* Call the right routine for the page that was currently in front. */
    notebook =  (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_NOTEBOOK);
    page_num = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));
    notebook_pg = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), page_num);

    func = (void (*)(GtkWidget *))g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_ACTION);
    func(notebook_pg);

    redissect_packets();
    redissect_all_packet_windows();
}

/*
 * This routine is called when the user clicks the "Close" button in
 * the "Decode As..." dialog window.  This routine then destroys the
 * dialog box and performs other housekeeping functions.
 *
 * @param close_bt A pointer to the "Close" button.
 *
 * @param parent_w A pointer to the dialog window.
 */
static void
decode_close_cb (GtkWidget *close_bt _U_, gpointer parent_w)
{
    GtkWidget *notebook, *notebook_pg;
    gint page_num;
    decode_as_t *entry;

    /* Call the right routine for the page that was currently in front. */
    notebook =  (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_NOTEBOOK);
    page_num = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));
    notebook_pg = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), page_num);

    /* Free any values that used dynamic memory */
    entry = (decode_as_t *)g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_DECODE_AS_DATA);
    if ((entry->num_items == 1) && (entry->free_func != NULL))
        entry->free_func(g_object_get_data(G_OBJECT(notebook_pg), E_PAGE_VALUE));

    window_destroy(GTK_WIDGET(parent_w));
    g_slist_free(decode_dimmable);
    decode_dimmable = NULL;
}


/*
 * This routine is called when the user clicks the "Close" button in
 * the "Decode As..." dialog window.  This routine simply calls the
 * close routine as if the user had clicked the close button instead
 * of the close button.
 *
 * @param decode_w_lcl A pointer to the dialog box.
 *
 * @param event    A pointer to the GdkEvent struct
 *
 * @param user_data Unused
 */
static gboolean
decode_delete_cb (GtkWidget *decode_w_lcl, GdkEvent *event _U_, gpointer user_data _U_)
{
    decode_close_cb(NULL, decode_w_lcl);
    return FALSE;
}


/*
 * This routine is called at the destruction of the "Decode As..."
 * dialog box.  It clears the pointer maintained by this file, so that
 * the next time the user selects the "Decode As..." menu item a new
 * dialog box will be created.
 *
 * @param win A pointer to the dialog box.
 *
 * @param user_data Unused
 *
 * @return void
 */
static void
decode_destroy_cb (GtkWidget *win _U_, gpointer user_data _U_)
{
    /* Note that we no longer have a "Decode As" dialog box. */
    decode_w = NULL;
}


/*
 * This routine is called when the user clicks the "Clear" button in
 * the "Decode As..." dialog window.  This routine resets all the
 * dissector values and performs other housekeeping functions.
 *
 * @param clear_bt A pointer to the "Clear" button.
 *
 * @param user_data Unused
 */
static void
decode_clear_cb(GtkWidget *clear_bt _U_, gpointer user_data _U_)
{
    decode_clear_all();
    redissect_packets();
    redissect_all_packet_windows();
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
 * @param user_data The enum value assigned to this radio button.  This
 * will be either E_DECODE_YES or E_DECODE_NO
 */
static void
decode_update_action (GtkWidget *w _U_, gpointer user_data)
{
    GSList *tmp;
    gboolean enable;

    requested_action = (enum action_type)GPOINTER_TO_INT(user_data);
    enable = (requested_action == E_DECODE_YES);
    for (tmp = decode_dimmable; tmp; tmp = g_slist_next(tmp)) {
        gtk_widget_set_sensitive((GtkWidget *)tmp->data, enable);
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
    GtkWidget   *format_vb, *radio_button;
    GSList      *format_grp;

    format_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 2, FALSE);

    radio_button = gtk_radio_button_new_with_label(NULL, "Decode");
    format_grp = gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio_button));
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_button), TRUE);
    g_signal_connect(radio_button, "clicked", G_CALLBACK(decode_update_action),
                   GINT_TO_POINTER(E_DECODE_YES));
    gtk_box_pack_start(GTK_BOX(format_vb), radio_button, FALSE, FALSE, 0);

    radio_button = gtk_radio_button_new_with_label(format_grp, "Do not decode");
    g_signal_connect(radio_button, "clicked", G_CALLBACK(decode_update_action),
                   GINT_TO_POINTER(E_DECODE_NO));
    gtk_box_pack_start(GTK_BOX(format_vb), radio_button, FALSE, FALSE, 0);

    return(format_vb);
}

/**************************************************/
/*          Dialog setup - simple combo_boxes     */
/**************************************************/

/*
 * This routine is called to pack an combo_box into an aligment, so
 * that it doesn't expand vertically to fill up the space available to
 * it.
 *
 * @param combo_box A pointer to the option menu to be so packed.
 *
 * @return GtkWidget * A pointer to the newly created alignment.
 */
static GtkWidget *
decode_add_pack_combo_box (GtkWidget *combo_box)
{
    GtkWidget *alignment;

    alignment = gtk_alignment_new(0.0f, 0.5f, 0.0f, 0.0f);
    gtk_container_add(GTK_CONTAINER(alignment), combo_box);

    return(alignment);
}


/*
 * This routine is called to add a selection combo_box to
 * the dialog box.  The combo_box choices are determined by the dissector.
 * The default choice for the combo_box is also determined by the dissector.
 *
 * @param page A pointer notebook page that will contain all
 * widgets created by this routine.
 * @param entry Decode As structure used to setup combo_box
 *
 * @return GtkWidget * A pointer to the newly created alignment into
 * which we've packed the newly created combo_box.
 */
static GtkWidget *
decode_add_multivalue_combo_box (GtkWidget *page, decode_as_t *entry)
{
    GtkWidget *combo_box, *alignment;
    guint value;
    gchar prompt[MAX_DECODE_AS_PROMPT_LEN];

    combo_box = ws_combo_box_new_text_and_pointer();

    for (value = 0; value < entry->num_items; value++)
    {
        entry->values[value].label_func(&cfile.edt->pi, prompt);
        ws_combo_box_append_text_and_pointer(GTK_COMBO_BOX(combo_box), prompt, GINT_TO_POINTER(value));
    }

    ws_combo_box_set_active(GTK_COMBO_BOX(combo_box), entry->default_index_value);
    g_object_set_data(G_OBJECT(page), E_COMBO_BOX_MULTIVALUE, combo_box);

    alignment = decode_add_pack_combo_box(combo_box);
    return(alignment);
}

/*************************************************/
/*        Dialog setup - list based menus        */
/*************************************************/

struct handle_lookup_info {
    dissector_handle_t handle;
    gboolean           found;
};

static gboolean
lookup_handle(GtkTreeModel *model, GtkTreePath *path _U_, GtkTreeIter *iter,
              gpointer user_data)
{
    dissector_handle_t handle;
    struct handle_lookup_info *hli = (struct handle_lookup_info *)user_data;

    gtk_tree_model_get(model, iter, E_LIST_S_TABLE+1, &handle, -1);
    if (hli->handle == handle) {
        hli->found = TRUE;
        return TRUE;
    }
    return FALSE;
}

/*
 * This routine creates one entry in the list of protocol dissector
 * that can be used.  It is called by the dissector_table_foreach_handle
 * routine once for each entry in a dissector table's list of handles
 * for dissectors that could be used in that table.  It guarantees unique
 * entries by iterating over the list of entries build up to this point,
 * looking for a duplicate name.  If there is no duplicate, then this
 * entry is added to the list of possible dissectors.
 *
 * @param table_name The name of the dissector table currently
 * being walked.
 *
 * @param proto_name The protocol name
 *
 * @param value The dissector handle for this entry.  This is an opaque
 * pointer that can only be handed back to routines in the file packet.c
 *
 * @param user_data A data block passed into each instance of this
 * routine.  It contains information from the caller of the foreach
 * routine, specifying information about the dissector table and where
 * to store any information generated by this routine.
 */
static void
decode_add_to_list (const gchar *table_name, const gchar *proto_name, gpointer value, gpointer user_data)
{
    const gchar     *text[E_LIST_S_COLUMNS];
    GtkTreeView  *list;
    GtkListStore *store;
    GtkTreeIter   iter;
    struct handle_lookup_info hli;

    g_assert(user_data);
    g_assert(value);

    list = (GtkTreeView *)user_data;

    hli.handle = (dissector_handle_t)value;
    hli.found = FALSE;
    store = GTK_LIST_STORE(gtk_tree_view_get_model(list));
    gtk_tree_model_foreach(GTK_TREE_MODEL(store), lookup_handle, &hli);
    /* We already have an entry for this handle.
     * XXX - will this ever happen? */
    if (hli.found) return;

    text[E_LIST_S_PROTO_NAME] = proto_name;
    text[E_LIST_S_TABLE] = table_name;
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter,
                       E_LIST_S_PROTO_NAME, text[E_LIST_S_PROTO_NAME],
                       E_LIST_S_TABLE, text[E_LIST_S_TABLE],
                       E_LIST_S_TABLE+1, value, -1);
}

static gboolean
decode_list_button_press_cb(GtkWidget *list, GdkEventButton *event, gpointer user_data _U_)
{
  if (event->type == GDK_2BUTTON_PRESS) {
    GtkWidget *main_w = gtk_widget_get_toplevel(list);

    decode_ok_cb (NULL, main_w);
  }

  return FALSE;
}

static gboolean
decode_list_key_release_cb(GtkWidget *list, GdkEventKey *event, gpointer user_data _U_)
{
  if (event->keyval == GDK_Return || event->keyval == GDK_KP_Enter) {
    GtkWidget    *main_w = gtk_widget_get_toplevel(list);

    decode_ok_cb (NULL, main_w);
  }

  return FALSE;
}

/*
 * This routine starts the creation of a List on a notebook page.  It
 * creates both a scrolled window and a list, adds the list to the
 * window, and attaches the list as a data object on the page.
 *
 * @param page A pointer to the notebook page being created.
 *
 * @param list_p Will be filled in with the address of a newly
 * created List.
 *
 * @param scrolled_win_p Will be filled in with the address of a newly
 * created GtkScrolledWindow.
 */
static void
decode_list_menu_start(GtkWidget *page, GtkWidget **list_p,
                       GtkWidget **scrolled_win_p)
{
    GtkTreeView       *list;
    GtkListStore      *store;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *tc;
    GtkTreeSortable   *sortable;

    store = gtk_list_store_new(E_LIST_S_COLUMNS+1, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_POINTER);
    g_object_set_data(G_OBJECT(decode_w), "sctp_data", store);
    list = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
    g_object_unref(G_OBJECT(store));
    sortable = GTK_TREE_SORTABLE(store);
    gtk_tree_sortable_set_sort_func(sortable, SORT_ALPHABETICAL, sort_iter_compare_func, GINT_TO_POINTER(SORT_ALPHABETICAL), NULL);
    gtk_tree_sortable_set_sort_column_id(sortable, SORT_ALPHABETICAL, GTK_SORT_ASCENDING);
    gtk_tree_view_set_headers_clickable(list, FALSE);
#ifndef DEBUG
    gtk_tree_view_set_headers_visible(list, FALSE);
#endif
    renderer = gtk_cell_renderer_text_new();
    tc = gtk_tree_view_column_new_with_attributes("Short Name", renderer,
                                                  "text", E_LIST_S_PROTO_NAME,
                                                  NULL);
    gtk_tree_view_column_set_sizing(tc, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(list, tc);
    g_object_set_data(G_OBJECT(page), E_PAGE_LIST, list);

    *scrolled_win_p = scrolled_window_new(NULL, NULL);
    /* this will result to set the width of the dialog to the required size */
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(*scrolled_win_p),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(*scrolled_win_p),
                                   GTK_SHADOW_IN);
    gtk_container_add(GTK_CONTAINER(*scrolled_win_p), GTK_WIDGET(list));

    *list_p = GTK_WIDGET(list);
}

/*
 * This routine finishes the creation of a List on a notebook page.
 * It adds the default entry, sets the default entry as the
 * highlighted entry, and sorts the List.
 *
 * @param list A pointer the the List to finish.
 */
static void
decode_list_menu_finish(GtkWidget *list)
{
    const gchar *text[E_LIST_S_COLUMNS];
    GtkListStore *store;
    GtkTreeIter   iter;

    text[E_LIST_S_PROTO_NAME] = "(default)";
    text[E_LIST_S_TABLE] = DECODE_AS_NONE;
    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
    gtk_list_store_prepend(store, &iter);
    gtk_list_store_set(store, &iter,
                       E_LIST_S_PROTO_NAME, text[E_LIST_S_PROTO_NAME],
                       E_LIST_S_TABLE, text[E_LIST_S_TABLE],
                       E_LIST_S_TABLE+1, NULL, -1);

    gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(list)), &iter);
    g_signal_connect(list, "button_press_event", G_CALLBACK(decode_list_button_press_cb), NULL);
    g_signal_connect(list, "key_release_event", G_CALLBACK(decode_list_key_release_cb), NULL);
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
 * @param entry Decode As structure used to build this (list) menu.
 *
 * @return GtkWidget * A pointer to the newly created list within a
 * scrolled window.
 */
static GtkWidget *
decode_add_simple_menu (GtkWidget *page, decode_as_t *entry)
{
    GtkWidget *scrolled_window;
    GtkWidget *list;

    decode_list_menu_start(page, &list, &scrolled_window);
    entry->populate_list(entry->table_name, decode_add_to_list, list);
    decode_list_menu_finish(list);
    return(scrolled_window);
}


/**************************************************/
/*                  Dialog setup                  */
/**************************************************/

/*
 * This routine creates a sample notebook page in the dialog box.
 * This notebook page provides a prompt specifying what is being
 * changed and its current value (e.g. "IP Protocol number (17)"), and
 * a list specifying all the available choices.  The list of choices
 * is conditionally enabled, based upon the setting of the
 * "decode"/"do not decode" radio buttons.
 *
 * @param entry Decode As structure used to build this page
 *
 * @return GtkWidget * A pointer to the notebook page created by this
 * routine.
 */
static GtkWidget *
decode_add_simple_page (decode_as_t *entry)
{
    GtkWidget  *page, *label, *scrolled_window, *combo_box;
    gchar prompt[MAX_DECODE_AS_PROMPT_LEN];

    page = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5, FALSE);
    g_object_set_data(G_OBJECT(page), E_PAGE_ACTION, decode_simple);
    g_object_set_data(G_OBJECT(page), E_PAGE_TABLE, (gchar *) entry->table_name);
    g_object_set_data(G_OBJECT(page), E_PAGE_DECODE_AS_DATA, (gchar *)entry);

    if (entry->num_items == 1)
    {
        g_object_set_data(G_OBJECT(page), E_PAGE_VALUE, entry->values[0].build_values[0](&cfile.edt->pi));

        /* Always enabled */
        entry->values->label_func(&cfile.edt->pi, prompt);
        label = gtk_label_new(prompt);
        gtk_box_pack_start(GTK_BOX(page), label, FALSE, FALSE, 0);
    }
    else
    {
        /* Always enabled */
        if (entry->pre_value_str)
        {
            label = gtk_label_new(entry->pre_value_str);
            gtk_box_pack_start(GTK_BOX(page), label, FALSE, FALSE, 0);
        }
        combo_box = decode_add_multivalue_combo_box(page, entry);
        gtk_box_pack_start(GTK_BOX(page), combo_box, FALSE, FALSE, 0);

        if (entry->post_value_str)
        {
            label = gtk_label_new(entry->post_value_str);
            gtk_box_pack_start(GTK_BOX(page), label, FALSE, FALSE, 0);
        }
    }

    /* Conditionally enabled - only when decoding packets */
    scrolled_window = decode_add_simple_menu(page, entry);
    gtk_box_pack_start(GTK_BOX(page), scrolled_window, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, scrolled_window);

    return(page);
}

/*
 * This routine indicates whether we'd actually have any pages in the
 * notebook in a "Decode As" dialog box; if there wouldn't be, we
 * inactivate the menu item for "Decode As".
 */
gboolean
decode_as_ok(void)
{
    wmem_list_frame_t * protos = wmem_list_head(cfile.edt->pi.layers);
    int proto_id;
    const char* proto_name;
    GList *list_entry;
    decode_as_t *entry;
    dissector_table_t sub_dissectors;

    while (protos != NULL)
    {
        proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
        proto_name = proto_get_protocol_filter_name(proto_id);

        list_entry = decode_as_list;
        while (list_entry != NULL) {
            entry = (decode_as_t *)list_entry->data;
            if (!strcmp(proto_name, entry->name))
            {
                sub_dissectors = find_dissector_table(entry->table_name);
                if (sub_dissectors != NULL)
                    return TRUE;
            }

            list_entry = g_list_next(list_entry);
        }

        protos = wmem_list_frame_next(protos);
    }

    return FALSE;
}


/*
 * This routine creates the bulk of the "Decode As" dialog box.  All
 * items created by this routine are packed as pages into a notebook.
 * There will be a page for each protocol layer that can be changed.
 *
 * @param format_hb A pointer to the widget in which the notebook
 * should be installed.
 */
static void
decode_add_notebook (GtkWidget *format_hb)
{
    GtkWidget *notebook, *page, *label;
    wmem_list_frame_t * protos = wmem_list_head(cfile.edt->pi.layers);
    int proto_id;
    const char* proto_name;
    GList *list_entry;
    decode_as_t *entry;
    dissector_table_t sub_dissectors;

    /* Start a nootbook for flipping between sets of changes */
    notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(format_hb), notebook, TRUE, TRUE, 0);
    g_object_set_data(G_OBJECT(decode_w), E_NOTEBOOK, notebook);

    while (protos != NULL)
    {
        proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
        proto_name = proto_get_protocol_filter_name(proto_id);

        list_entry = decode_as_list;
        while (list_entry != NULL) {
            entry = (decode_as_t *)list_entry->data;
            if (!strcmp(proto_name, entry->name))
            {
                sub_dissectors = find_dissector_table(entry->table_name);
                if (sub_dissectors != NULL)
                {
                    page = decode_add_simple_page(entry);
                    label = gtk_label_new(entry->title);
                    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page, label);
                }
            }

            list_entry = g_list_next(list_entry);
        }

        protos = wmem_list_frame_next(protos);
    }

    /* Select the last added page (selects first by default) */
    /* Notebook must be visible for set_page to work. */
    gtk_widget_show_all(notebook);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), -1);
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
 * @param w Unused
 *
 * @param user_data Unused
 */
void
decode_as_cb (GtkWidget * w _U_, gpointer user_data _U_)
{
    GtkWidget   *main_vb, *format_hb, *bbox, *ok_bt, *close_bt, *help_bt, *button;
    GtkWidget   *button_vb, *apply_bt;

    if (decode_w != NULL) {
        /* There's already a "Decode As" dialog box; reactivate it. */
        reactivate_window(decode_w);
        return;
    }

    requested_action = E_DECODE_YES;
    decode_w = dlg_window_new("Wireshark: Decode As");
    /* Provide a minimum of a couple of rows worth of data */
    gtk_window_set_default_size(GTK_WINDOW(decode_w), -1, E_DECODE_MIN_HEIGHT);

    /* Container for each row of widgets */
    main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 2, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(decode_w), main_vb);

    /* First row - Buttons and Notebook */
    format_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5, FALSE);
    gtk_box_pack_start(GTK_BOX(main_vb), format_hb, TRUE, TRUE, 10);

    button_vb = decode_add_yes_no();
    gtk_box_pack_start(GTK_BOX(format_hb), button_vb, FALSE, FALSE, 10);

    button = gtk_button_new_with_label("Show Current");
    g_signal_connect(button, "clicked", G_CALLBACK(decode_show_cb), NULL);
    gtk_widget_set_can_default(button, TRUE);
    gtk_box_pack_end(GTK_BOX(button_vb), button, FALSE, FALSE, 0);
	gtk_widget_set_tooltip_text(button, "Open a dialog showing the current settings.\n"
		"Note you need to select and press apply first to be able to save the current setting");

    button = ws_gtk_button_new_from_stock(GTK_STOCK_CLEAR);
    g_signal_connect(button, "clicked", G_CALLBACK(decode_clear_cb), NULL);
    gtk_widget_set_can_default(button, TRUE);
    gtk_box_pack_end(GTK_BOX(button_vb), button, FALSE, FALSE, 0);
	gtk_widget_set_tooltip_text(button, "Clear ALL settings.");

    decode_add_notebook(format_hb);

    /* Button row */
    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    ok_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
    g_signal_connect(ok_bt, "clicked", G_CALLBACK(decode_ok_cb), decode_w);
	gtk_widget_set_tooltip_text(ok_bt, "Apply current setting, close dialog and redissect packets.");

    apply_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_APPLY);
    g_signal_connect(apply_bt, "clicked", G_CALLBACK(decode_apply_cb), decode_w);
	gtk_widget_set_tooltip_text(apply_bt, "Apply current setting, redissect packets and keep dialog open.");

    close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(decode_w, close_bt, NULL);
    g_signal_connect(close_bt, "clicked", G_CALLBACK(decode_close_cb), decode_w);
	gtk_widget_set_tooltip_text(close_bt, "Close the dialog, don't redissect packets.");

    help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_DECODE_AS_DIALOG);

    gtk_widget_grab_default(ok_bt);

    g_signal_connect(decode_w, "delete_event", G_CALLBACK(decode_delete_cb), NULL);
    g_signal_connect(decode_w, "destroy", G_CALLBACK(decode_destroy_cb), NULL);

    gtk_widget_show_all(decode_w);
    window_present(decode_w);
}
