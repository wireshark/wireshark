/* hostlist_table.c   2004 Ian Schorr
 * modified from endpoint_talkers_table.c   2003 Ronnie Sahlberg
 * Helper routines common to all host list taps.
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

#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <locale.h>

#include <gtk/gtk.h>

#include <epan/addr_resolv.h>
#ifdef HAVE_GEOIP
#include <GeoIP.h>
#include "epan/geoip_db.h"
#include "wsutil/pint.h"
#endif

#include "ui/simple_dialog.h"
#include "ui/alert_box.h"
#include <wsutil/utf8_entities.h>

#include "ui/gtk/hostlist_table.h"
#include "ui/gtk/filter_utils.h"
#include "ui/gtk/gtkglobals.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/main.h"
#ifdef HAVE_GEOIP
#include "ui/gtk/webbrowser.h"
#include "ui/gtk/stock_icons.h"
#endif

#include "ui/gtk/old-gtk-compat.h"

#define HOST_PTR_KEY "hostlist-pointer"
#define NB_PAGES_KEY "notebook-pages"
#define HL_DLG_HEIGHT 550

#define CMP_INT(i1, i2)         \
    if ((i1) > (i2))            \
        return 1;               \
    else if ((i1) < (i2))       \
        return -1;              \
    else                        \
        return 0;

#define COL_STR_LEN 32

static void
reset_host_table_data(hostlist_table *hosts)
{
    char *display_name;
    char title[256];
    GString *error_string;
    const char *filter;
    GtkListStore *store;

    if (hosts->use_dfilter) {
        filter = gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
    } else {
        filter = hosts->filter;
    }
    error_string = set_tap_dfilter (&hosts->hash, filter);
    if (error_string) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        return;
    }


    if(hosts->page_lb) {
        display_name = cf_get_display_name(&cfile);
        g_snprintf(title, sizeof(title), "Endpoints: %s", display_name);
        g_free(display_name);
        gtk_window_set_title(GTK_WINDOW(hosts->win), title);
        g_snprintf(title, sizeof(title), "%s", hosts->name);
        gtk_label_set_text(GTK_LABEL(hosts->page_lb), title);
        gtk_widget_set_sensitive(hosts->page_lb, FALSE);

        if (hosts->use_dfilter) {
            if (filter && strlen(filter)) {
                g_snprintf(title, sizeof(title), "%s Endpoints - Filter: %s", hosts->name, filter);
            } else {
                g_snprintf(title, sizeof(title), "%s Endpoints - No Filter", hosts->name);
            }
        } else {
            g_snprintf(title, sizeof(title), "%s Endpoints", hosts->name);
        }
        gtk_label_set_text(GTK_LABEL(hosts->name_lb), title);
    } else {
        display_name = cf_get_display_name(&cfile);
        g_snprintf(title, sizeof(title), "%s Endpoints: %s", hosts->name, display_name);
        g_free(display_name);
        gtk_window_set_title(GTK_WINDOW(hosts->win), title);
    }

    /* remove all entries from the list */
    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(hosts->table)));
    gtk_list_store_clear(store);

    /* delete all hosts */
    reset_hostlist_table_data(&hosts->hash);
}

static void
reset_hostlist_table_data_cb(void *arg)
{
    conv_hash_t *hash = (conv_hash_t*)arg;

    reset_host_table_data((hostlist_table *)hash->user_data);
}

static void
hostlist_win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
    hostlist_table *hosts=(hostlist_table *)data;

    remove_tap_listener(&hosts->hash);

    reset_host_table_data(hosts);
    g_free(hosts);
}

static gint
hostlist_sort_column(GtkTreeModel *model,
                     GtkTreeIter *a,
                     GtkTreeIter *b,
                     gpointer user_data)

{
    guint32 idx1, idx2;
    gint data_column = GPOINTER_TO_INT(user_data);
    hostlist_table *hl = (hostlist_table *)g_object_get_data(G_OBJECT(model), HOST_PTR_KEY);
    hostlist_talker_t *host1 = NULL;
    hostlist_talker_t *host2 = NULL;

    gtk_tree_model_get(model, a, ENDP_INDEX_COLUMN, &idx1, -1);
    gtk_tree_model_get(model, b, ENDP_INDEX_COLUMN, &idx2, -1);

    if (!hl || idx1 >= hl->hash.conv_array->len || idx2 >= hl->hash.conv_array->len)
        return 0;

    host1 = &g_array_index(hl->hash.conv_array, hostlist_talker_t, idx1);
    host2 = &g_array_index(hl->hash.conv_array, hostlist_talker_t, idx2);

    switch(data_column){
    case ENDP_COLUMN_ADDR: /* Address */
        return(cmp_address(&host1->myaddress, &host2->myaddress));
    case ENDP_COLUMN_PORT: /* (Port) */
        CMP_INT(host1->port, host2->port);
#ifdef HAVE_GEOIP
    default:
        {
            gchar *text1, *text2;
            double loc1 = 0, loc2 = 0;

            gtk_tree_model_get(model, a, data_column, &text1, -1);
            gtk_tree_model_get(model, b, data_column, &text2, -1);

            if (text1) {
                loc1 = g_ascii_strtod(text1, NULL);
                g_free(text1);
            }

            if (text2) {
                loc2 = g_ascii_strtod(text2, NULL);
                g_free(text2);
            }
            CMP_INT(loc1, loc2);
        }
        break;
#endif
    }
    g_assert_not_reached();
    return 0;
}

static void
hostlist_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
    guint idx;
    hostlist_table *hl=(hostlist_table *)callback_data;
    char *str;
    GtkTreeIter iter;
    GtkTreeModel *model;
    GtkTreeSelection  *sel;
    hostlist_talker_t *host;

    sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(hl->table));
    if (!gtk_tree_selection_get_selected(sel, &model, &iter))
        return;

    gtk_tree_model_get (model, &iter,
                            ENDP_INDEX_COLUMN, &idx,
                            -1);

    if(idx>= hl->hash.conv_array->len){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No hostlist selected");
        return;
    }
    host = &g_array_index(hl->hash.conv_array, hostlist_talker_t, idx);

    str = get_hostlist_filter(host);

    apply_selected_filter (callback_action, str);

    g_free (str);
}
static gboolean
hostlist_show_popup_menu_cb(void *widg _U_, GdkEvent *event, hostlist_table *et)
{
    GdkEventButton *bevent = (GdkEventButton *)event;

    if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
            gtk_menu_popup(GTK_MENU(et->menu), NULL, NULL, NULL, NULL,
                           bevent->button, bevent->time);
    }

    return FALSE;
}

/* Action callbacks */
static void
apply_as_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_SELECTED, 0));
}
static void
apply_as_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_NOT_SELECTED, 0));
}
static void
apply_as_and_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_AND_SELECTED, 0));
}
static void
apply_as_or_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_OR_SELECTED, 0));
}
static void
apply_as_and_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, 0));
}
static void
apply_as_or_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, 0));
}

static void
prep_as_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_SELECTED, 0));
}
static void
prep_as_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, 0));
}
static void
prep_as_and_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_AND_SELECTED, 0));
}
static void
prep_as_or_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_OR_SELECTED, 0));
}
static void
prep_as_and_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, 0));
}
static void
prep_as_or_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, 0));
}

static void
find_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_FIND_FRAME(ACTYPE_SELECTED, 0));
}
static void
find_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_FIND_FRAME(ACTYPE_NOT_SELECTED, 0));
}
static void
find_prev_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, 0));
}
static void
find_prev_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_FIND_PREVIOUS(ACTYPE_NOT_SELECTED, 0));
}
static void
find_next_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_FIND_NEXT(ACTYPE_SELECTED, 0));
}
static void
find_next_not_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_FIND_NEXT(ACTYPE_NOT_SELECTED, 0));
}
static void
color_selected_cb(GtkWidget *widget, gpointer user_data)
{
    hostlist_select_filter_cb( widget , user_data, CALLBACK_COLORIZE(ACTYPE_SELECTED, 0));
}

static const char *ui_desc_hostlist_table_popup =
"<ui>\n"
"  <popup name='HostlistTableFilterPopup'>\n"
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
"     <menuitem action='/Colorize Procedure/Colorize Host Traffic'/>\n"
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
static const GtkActionEntry service_resp_t_popup_entries[] = {
  { "/Apply as Filter",                         NULL, "Apply as Filter",                NULL, NULL,                             NULL },
  { "/Prepare a Filter",                        NULL, "Prepare a Filter",               NULL, NULL,                             NULL },
  { "/Find Frame",                              NULL, "Find Frame",                     NULL, NULL,                             NULL },
  { "/Find Frame/Find Frame",                   NULL, "Find Frame",                     NULL, NULL,                             NULL },
  { "/Find Frame/Find Next",                    NULL, "Find Next" ,                     NULL, NULL,                             NULL },
  { "/Find Frame/Find Previous",                NULL, "Find Previous",                  NULL, NULL,                             NULL },
  { "/Colorize Procedure",                      NULL, "Colorize Procedure",             NULL, NULL,                             NULL },
  { "/Apply as Filter/Selected",                NULL, "Selected",                       NULL, "Selected",                       G_CALLBACK(apply_as_selected_cb) },
  { "/Apply as Filter/Not Selected",            NULL, "Not Selected",                   NULL, "Not Selected",               G_CALLBACK(apply_as_not_selected_cb) },
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
  { "/Colorize Procedure/Colorize Host Traffic",NULL, "Colorize Host Traffic",          NULL, "Colorize Host Traffic",          G_CALLBACK(color_selected_cb) },
};

static void
hostlist_create_popup_menu(hostlist_table *hl)
{
    GtkUIManager *ui_manager;
    GtkActionGroup *action_group;
    GError *error = NULL;

    action_group = gtk_action_group_new ("HostlistTablePopupActionGroup");
    gtk_action_group_add_actions (action_group,                             /* the action group */
                                service_resp_t_popup_entries,              /* an array of action descriptions */
                                G_N_ELEMENTS(service_resp_t_popup_entries),/* the number of entries */
                                hl);                                        /* data to pass to the action callbacks */

    ui_manager = gtk_ui_manager_new ();
    gtk_ui_manager_insert_action_group (ui_manager,
        action_group,
        0); /* the position at which the group will be inserted */
    gtk_ui_manager_add_ui_from_string (ui_manager,ui_desc_hostlist_table_popup, -1, &error);
    if (error != NULL)
    {
        fprintf (stderr, "Warning: building hostlist table filter popup failed: %s\n",
                error->message);
        g_error_free (error);
        error = NULL;
    }
    hl->menu = gtk_ui_manager_get_widget(ui_manager, "/HostlistTableFilterPopup");
    g_signal_connect(hl->table, "button_press_event", G_CALLBACK(hostlist_show_popup_menu_cb), hl);
}

/* Refresh the address fields of all entries in the list */
static void
draw_hostlist_table_addresses(hostlist_table *hl)
{
    guint idx;
    GtkListStore *store;
    GtkTreeIter iter;
    gboolean iter_valid;

    store = GTK_LIST_STORE(gtk_tree_view_get_model(hl->table));
    g_object_ref(store);
    gtk_tree_view_set_model(GTK_TREE_VIEW(hl->table), NULL);
    iter_valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

    while (iter_valid) {
        hostlist_talker_t *host;
        char *addr_str, *port_str;

        gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, ENDP_INDEX_COLUMN, &idx, -1);
        host = &g_array_index(hl->hash.conv_array, hostlist_talker_t, idx);

        addr_str = get_conversation_address(NULL, &host->myaddress, hl->resolve_names);
        port_str = get_conversation_port(NULL, host->port, host->ptype, hl->resolve_names);
        gtk_list_store_set (store, &iter,
                  ENDP_COLUMN_ADDR, addr_str,
                  ENDP_COLUMN_PORT, port_str,
                    -1);

        iter_valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
        wmem_free(NULL, addr_str);
        wmem_free(NULL, port_str);
    }
    gtk_tree_view_set_model(GTK_TREE_VIEW(hl->table), GTK_TREE_MODEL(store));
    g_object_unref(store);
}


static void
draw_hostlist_table_data(hostlist_table *hl)
{
    guint idx, new_idx;
    char title[256];
    GtkListStore *store;
    GtkTreeIter iter;
    gboolean iter_valid;
    gboolean first = TRUE;

    if (hl->page_lb) {
        if(hl->hash.conv_array && hl->hash.conv_array->len) {
            g_snprintf(title, sizeof(title), "%s: %u", hl->name, hl->hash.conv_array->len);
        } else {
            g_snprintf(title, sizeof(title), "%s", hl->name);
        }
        gtk_label_set_text(GTK_LABEL(hl->page_lb), title);
        gtk_widget_set_sensitive(hl->page_lb, hl->hash.conv_array && hl->hash.conv_array->len);
    } else {
        if(hl->hash.conv_array && hl->hash.conv_array->len) {
            g_snprintf(title, sizeof(title), "%s Endpoints: %u", hl->name, hl->hash.conv_array->len);
        } else {
            g_snprintf(title, sizeof(title), "%s Endpoints", hl->name);
        }
        gtk_label_set_text(GTK_LABEL(hl->name_lb), title);
    }

    store = GTK_LIST_STORE(gtk_tree_view_get_model(hl->table));
    iter_valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);
    new_idx = gtk_tree_model_iter_n_children(GTK_TREE_MODEL(store), NULL);

    while (iter_valid || (hl->hash.conv_array && new_idx < hl->hash.conv_array->len)) {
        hostlist_talker_t *host;

        if (iter_valid) {
            gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, ENDP_INDEX_COLUMN, &idx, -1);
        } else {
            idx = new_idx;
            new_idx++;
        }
        if(!hl->hash.conv_array){ /* Already check on while loop but for avoid Clang Analyzer warnings */
            continue;
        }

        host = &g_array_index(hl->hash.conv_array, hostlist_talker_t, idx);

        if (!host->modified) {
            iter_valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
            continue;
        }

        if (first) {
            g_object_ref(store);
            gtk_tree_view_set_model(GTK_TREE_VIEW(hl->table), NULL);

            first = FALSE;
        }
        host->modified = FALSE;
        if (!iter_valid) {
            char *addr_str, *port_str;
#ifdef HAVE_GEOIP
            char *geoip[ENDP_NUM_GEOIP_COLUMNS];
            guint j;

            if ((host->myaddress.type == AT_IPv4 || host->myaddress.type == AT_IPv6) && !hl->geoip_visible) {
                GList             *columns, *list;
                GtkTreeViewColumn *column;
                columns = gtk_tree_view_get_columns(GTK_TREE_VIEW(hl->table));
                list = columns;
                while(columns) {
                    const gchar *title_p;
                    gint  id;

                    column = (GtkTreeViewColumn *)columns->data;
                    title_p = gtk_tree_view_column_get_title(column);
                    id = gtk_tree_view_column_get_sort_column_id(column);
                    if (title_p[0] != 0 && id >= ENDP_COLUMN_GEOIP1) {
                        gtk_tree_view_column_set_visible(column, TRUE);
                    }
                    columns = g_list_next(columns);
                }
                g_list_free(list);
                hl->geoip_visible = TRUE;
            }

            /* Filled in from the GeoIP config, if any */
            for (j = 0; j < ENDP_NUM_GEOIP_COLUMNS; j++) {
                if (host->myaddress.type == AT_IPv4 && j < geoip_db_num_dbs()) {
                    guchar *name = geoip_db_lookup_ipv4(j, pntoh32(host->myaddress.data), "-");
                    geoip[j] = g_strdup(name);
                    wmem_free(NULL, name);
                } else if (host->myaddress.type == AT_IPv6 && j < geoip_db_num_dbs()) {
                    guchar *name;
                    const struct e_in6_addr *addr = (const struct e_in6_addr *) host->myaddress.data;

                    name = geoip_db_lookup_ipv6(j, *addr, "-");
                    geoip[j] = g_strdup(name);
                    wmem_free(NULL, name);
                } else {
                  geoip[j] = NULL;
                }
            }
#endif /* HAVE_GEOIP */

            addr_str = get_conversation_address(NULL, &host->myaddress, hl->resolve_names);
            port_str = get_conversation_port(NULL, host->port, host->ptype, hl->resolve_names);
            gtk_list_store_insert_with_values( store, &iter, G_MAXINT,
                  ENDP_COLUMN_ADDR, addr_str,
                  ENDP_COLUMN_PORT, port_str,
                  ENDP_COLUMN_PACKETS,  host->tx_frames+host->rx_frames,
                  ENDP_COLUMN_BYTES,    host->tx_bytes+host->rx_bytes,
                  ENDP_COLUMN_PKT_AB,   host->tx_frames,
                  ENDP_COLUMN_BYTES_AB, host->tx_bytes,
                  ENDP_COLUMN_PKT_BA,   host->rx_frames,
                  ENDP_COLUMN_BYTES_BA, host->rx_bytes,
#ifdef HAVE_GEOIP
                  ENDP_COLUMN_GEOIP1,   geoip[0],
                  ENDP_COLUMN_GEOIP2,   geoip[1],
                  ENDP_COLUMN_GEOIP3,   geoip[2],
                  ENDP_COLUMN_GEOIP4,   geoip[3],
                  ENDP_COLUMN_GEOIP5,   geoip[4],
                  ENDP_COLUMN_GEOIP6,   geoip[5],
                  ENDP_COLUMN_GEOIP7,   geoip[6],
                  ENDP_COLUMN_GEOIP8,   geoip[7],
                  ENDP_COLUMN_GEOIP9,   geoip[8],
                  ENDP_COLUMN_GEOIP10,  geoip[9],
                  ENDP_COLUMN_GEOIP11,  geoip[10],
                  ENDP_COLUMN_GEOIP12,  geoip[11],
                  ENDP_COLUMN_GEOIP13,  geoip[12],
#endif
                  ENDP_INDEX_COLUMN,    idx,
                    -1);
            wmem_free(NULL, addr_str);
            wmem_free(NULL, port_str);
#ifdef HAVE_GEOIP
            for (j = 0; j < ENDP_NUM_GEOIP_COLUMNS; j++)
                g_free(geoip[j]);
#endif /* HAVE_GEOIP */
        }
        else {
            gtk_list_store_set (store, &iter,
                  ENDP_COLUMN_PACKETS,  host->tx_frames+host->rx_frames,
                  ENDP_COLUMN_BYTES,    host->tx_bytes+host->rx_bytes,
                  ENDP_COLUMN_PKT_AB,   host->tx_frames,
                  ENDP_COLUMN_BYTES_AB, host->tx_bytes,
                  ENDP_COLUMN_PKT_BA,   host->rx_frames,
                  ENDP_COLUMN_BYTES_BA, host->rx_bytes,
                    -1);
        }

        iter_valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
    }
    if (!first) {
            if (!hl->fixed_col && hl->hash.conv_array && hl->hash.conv_array->len >= 1000) {
                /* finding the right size for a column isn't easy
                 * let it run in autosize a little (1000 is arbitrary)
                 * and then switch to fixed width.
                */
                hl->fixed_col = TRUE;
                switch_to_fixed_col(hl->table);
            }

            gtk_tree_view_set_model(GTK_TREE_VIEW(hl->table), GTK_TREE_MODEL(store));
            g_object_unref(store);
    }
}

static void
draw_hostlist_table_data_cb(void *arg)
{
    conv_hash_t *hash = (conv_hash_t*)arg;

    draw_hostlist_table_data((hostlist_table *)hash->user_data);
}

typedef struct {
    int             nb_cols;
    gint            columns_order[ENDP_NUM_COLUMNS+ENDP_NUM_GEOIP_COLUMNS];
    GString        *CSV_str;
    hostlist_table *talkers;
} csv_t;

/* output in C locale */
static gboolean
csv_handle(GtkTreeModel *model, GtkTreePath *path _U_, GtkTreeIter *iter,
              gpointer data)
{
    csv_t   *csv = (csv_t *)data;
    gchar   *table_text;
    int      i;
    guint idx;
    guint64  value;

    gtk_tree_model_get(model, iter, ENDP_INDEX_COLUMN, &idx, -1);

    for (i=0; i< csv->nb_cols; i++) {
        if (i)
            g_string_append(csv->CSV_str, ",");

        switch(csv->columns_order[i]) {
        case ENDP_COLUMN_ADDR:
        case ENDP_COLUMN_PORT:
            gtk_tree_model_get(model, iter, csv->columns_order[i], &table_text, -1);
            if (table_text) {
                g_string_append_printf(csv->CSV_str, "\"%s\"", table_text);
                g_free(table_text);
            }
            break;
        case ENDP_COLUMN_PACKETS:
        case ENDP_COLUMN_BYTES:
        case ENDP_COLUMN_PKT_AB:
        case ENDP_COLUMN_BYTES_AB:
        case ENDP_COLUMN_PKT_BA:
        case ENDP_COLUMN_BYTES_BA:
            gtk_tree_model_get(model, iter, csv->columns_order[i], &value, -1);
            g_string_append_printf(csv->CSV_str, "\"%" G_GINT64_MODIFIER "u\"", value);
            break;
        default:
            gtk_tree_model_get(model, iter, csv->columns_order[i], &table_text, -1);
            if (table_text) {
                g_string_append_printf(csv->CSV_str, "\"%s\"", table_text);
                g_free(table_text);
            }
            break;
        }
    }
    g_string_append(csv->CSV_str,"\n");

    return FALSE;
}

static void
copy_as_csv_cb(GtkWindow *copy_bt, gpointer data _U_)
{
    GtkClipboard      *cb;
    char              *savelocale;
    GList             *columns, *list;
    GtkTreeViewColumn *column;
    GtkListStore      *store;
    csv_t              csv;

    csv.talkers=(hostlist_table *)g_object_get_data(G_OBJECT(copy_bt), HOST_PTR_KEY);
    if (!csv.talkers)
        return;

    savelocale = g_strdup(setlocale(LC_NUMERIC, NULL));
    setlocale(LC_NUMERIC, "C");
    csv.CSV_str = g_string_new("");

    columns = gtk_tree_view_get_columns(GTK_TREE_VIEW(csv.talkers->table));
    list = columns;
    csv.nb_cols = 0;
    while(columns) {
        column = (GtkTreeViewColumn *)columns->data;
        if (gtk_tree_view_column_get_visible(column)) {
            csv.columns_order[csv.nb_cols] = gtk_tree_view_column_get_sort_column_id(column);
            if (csv.nb_cols)
                g_string_append(csv.CSV_str, ",");
            g_string_append_printf(csv.CSV_str, "\"%s\"", gtk_tree_view_column_get_title(column));
            csv.nb_cols++;
        }
        columns = g_list_next(columns);
    }
    g_list_free(list);

    g_string_append(csv.CSV_str,"\n");
    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(csv.talkers->table)));
    gtk_tree_model_foreach(GTK_TREE_MODEL(store), csv_handle, &csv);

    /* Now that we have the CSV data, copy it into the default clipboard */
    cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);      /* Get the default clipboard */
    gtk_clipboard_set_text(cb, csv.CSV_str->str, -1);    /* Copy the CSV data into the clipboard */
    setlocale(LC_NUMERIC, savelocale);
    g_free(savelocale);
    g_string_free(csv.CSV_str, TRUE);                    /* Free the memory */
}

#ifdef HAVE_GEOIP

static void
open_as_map_cb(GtkWindow *copy_bt, gpointer data _U_)
{
    gchar          *err_str;
    gchar          *file_uri;
    gboolean        uri_open;
    hostlist_table *talkers;
    gchar          *map_filename;


    talkers = (hostlist_table *)g_object_get_data(G_OBJECT(copy_bt), HOST_PTR_KEY);
    if (!talkers) {
        return;
    }

    map_filename = create_endpoint_geoip_map(talkers->hash.conv_array, &err_str);

    if (!map_filename) {
        simple_error_message_box("%s", err_str);
        g_free(err_str);
        return;
    }

    /* open the webbrowser */
    file_uri = g_filename_to_uri(map_filename, NULL, NULL);
    g_free(map_filename);
    uri_open = browser_open_url (file_uri);
    if(!uri_open) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Couldn't open the file: \"%s\" in your web browser", file_uri);
        g_free(file_uri);
        return;
    }

    g_free(file_uri);
}
#endif /* HAVE_GEOIP */

static gint default_col_size[ENDP_NUM_COLUMNS+ENDP_NUM_GEOIP_COLUMNS];

static void
init_default_col_size(GtkWidget *view)
{

    default_col_size[ENDP_COLUMN_ADDR] = get_default_col_size(view, "00000000.000000000000");
    default_col_size[ENDP_COLUMN_PORT] = get_default_col_size(view, "000000");
    default_col_size[ENDP_COLUMN_PACKETS] = get_default_col_size(view, "00 000 000");
    default_col_size[ENDP_COLUMN_BYTES] = get_default_col_size(view, "0 000 000 000");
    default_col_size[ENDP_COLUMN_PKT_AB] = default_col_size[ENDP_COLUMN_PACKETS];
    default_col_size[ENDP_COLUMN_PKT_BA] = default_col_size[ENDP_COLUMN_PACKETS];
    default_col_size[ENDP_COLUMN_BYTES_AB] = default_col_size[ENDP_COLUMN_BYTES];
    default_col_size[ENDP_COLUMN_BYTES_BA] = default_col_size[ENDP_COLUMN_BYTES];
#ifdef HAVE_GEOIP
    default_col_size[ENDP_COLUMN_GEOIP1] = default_col_size[ENDP_COLUMN_ADDR];
    default_col_size[ENDP_COLUMN_GEOIP2] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP3] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP4] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP5] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP6] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP7] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP8] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP9] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP10] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP11] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP12] = default_col_size[ENDP_COLUMN_GEOIP1];
    default_col_size[ENDP_COLUMN_GEOIP13] = default_col_size[ENDP_COLUMN_GEOIP1];

#endif
}

static gboolean
init_hostlist_table_page(hostlist_table *hosttable, GtkWidget *vbox, gboolean hide_ports, const char *table_name, const char *tap_name,
  const char *filter, tap_packet_cb packet_func)
{
    guint i;
    GString *error_string;
    char title[256];
    GtkListStore *store;
    GtkWidget *tree;
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;
    GtkTreeSortable *sortable;
    GtkTreeSelection  *sel;
    static gboolean col_size = FALSE;

    hosttable->default_titles[0]  = "Address";
    hosttable->default_titles[1]  = "Port";
    hosttable->default_titles[2]  = "Packets";
    hosttable->default_titles[3]  = "Bytes";
    hosttable->default_titles[4]  = "Tx Packets";
    hosttable->default_titles[5]  = "Tx Bytes";
    hosttable->default_titles[6]  = "Rx Packets";
    hosttable->default_titles[7]  = "Rx Bytes";

#ifdef HAVE_GEOIP
    for (i = 0; i < ENDP_NUM_GEOIP_COLUMNS; i++) {
        if (i < geoip_db_num_dbs()) {
            hosttable->default_titles[ENDP_NUM_COLUMNS + i]  = geoip_db_name(i);
        } else {
            hosttable->default_titles[ENDP_NUM_COLUMNS + i]  = "";
        }
    }
#endif /* HAVE_GEOIP */

    if (strcmp(table_name, "NCP")==0) {
        hosttable->default_titles[1] = endp_conn_title;
    }

    hosttable->has_ports=!hide_ports;
    hosttable->resolve_names=TRUE;
    hosttable->page_lb = NULL;
    hosttable->fixed_col = FALSE;
    hosttable->geoip_visible = FALSE;

    g_snprintf(title, sizeof(title), "%s Endpoints", table_name);
    hosttable->name_lb = gtk_label_new(title);
    gtk_box_pack_start(GTK_BOX(vbox), hosttable->name_lb, FALSE, FALSE, 0);

    /* Create the store */

    store = gtk_list_store_new (ENDP_INDEX_COLUMN + 1,      /* Total number of columns */
                               G_TYPE_STRING,   /* Address  */
                               G_TYPE_STRING,   /* Port     */
                               G_TYPE_UINT64,   /* Packets   */
                               G_TYPE_UINT64,   /* Bytes     */
                               G_TYPE_UINT64,   /* Packets A->B */
                               G_TYPE_UINT64,   /* Bytes  A->B  */
                               G_TYPE_UINT64,   /* Packets A<-B */
                               G_TYPE_UINT64,   /* Bytes  A<-B */
#ifdef HAVE_GEOIP
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
#endif
                               G_TYPE_UINT);    /* Index */

    hosttable->scrolled_window=scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), hosttable->scrolled_window, TRUE, TRUE, 0);

    tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
    hosttable->table = GTK_TREE_VIEW(tree);
    sortable = GTK_TREE_SORTABLE(store);
    g_object_unref (G_OBJECT (store));

    if (!col_size) {
        col_size = TRUE;
        init_default_col_size(GTK_WIDGET(hosttable->table));
    }

    g_object_set_data(G_OBJECT(store), HOST_PTR_KEY, hosttable);
    g_object_set_data(G_OBJECT(hosttable->table), HOST_PTR_KEY, hosttable);

    for (i = 0; i < ENDP_NUM_COLUMNS+ENDP_NUM_GEOIP_COLUMNS; i++) {
        renderer = gtk_cell_renderer_text_new ();
        g_object_set(renderer, "ypad", 0, NULL);
        switch(i) {
        case ENDP_COLUMN_ADDR: /* address and port */
        case ENDP_COLUMN_PORT:
            column = gtk_tree_view_column_new_with_attributes (hosttable->default_titles[i], renderer, "text",
                                                               i, NULL);
            if(hide_ports && i == ENDP_COLUMN_PORT){
                /* hide srcport and dstport if we don't use ports */
                gtk_tree_view_column_set_visible(column, FALSE);
            }
            gtk_tree_sortable_set_sort_func(sortable, i, hostlist_sort_column, GINT_TO_POINTER(i), NULL);
            break;
        case ENDP_COLUMN_PACKETS: /* counts */
        case ENDP_COLUMN_BYTES:
        case ENDP_COLUMN_PKT_AB:
        case ENDP_COLUMN_BYTES_AB:
        case ENDP_COLUMN_PKT_BA:
        case ENDP_COLUMN_BYTES_BA: /* right align numbers */
            g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
            column = gtk_tree_view_column_new_with_attributes (hosttable->default_titles[i], renderer, NULL);
            gtk_tree_view_column_set_cell_data_func(column, renderer, u64_data_func,  GINT_TO_POINTER(i), NULL);
            break;
        default: /* GEOIP */
            column = gtk_tree_view_column_new_with_attributes (hosttable->default_titles[i], renderer, "text",
                                                               i, NULL);
            gtk_tree_view_column_set_visible(column, FALSE);
#ifdef HAVE_GEOIP
            if (i >= ENDP_NUM_COLUMNS && i - ENDP_NUM_COLUMNS < geoip_db_num_dbs()) {
                int goip_type = geoip_db_type(i - ENDP_NUM_COLUMNS);
                if (goip_type == WS_LON_FAKE_EDITION || goip_type == WS_LAT_FAKE_EDITION) {
                    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
                    gtk_tree_sortable_set_sort_func(sortable, i, hostlist_sort_column, GINT_TO_POINTER(i), NULL);
                }
            }
#endif
            break;
        }
        gtk_tree_view_column_set_sort_column_id(column, i);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_column_set_reorderable(column, TRUE);
        gtk_tree_view_column_set_min_width(column, 40);
        gtk_tree_view_column_set_fixed_width(column, default_col_size[i]);
        gtk_tree_view_append_column (hosttable->table, column);

#if 0
        /* make total frames be the default sort order, too slow */
        if (i == PACKETS_COLUMN) {
              gtk_tree_view_column_clicked(column);
        }
#endif
    }

    gtk_container_add(GTK_CONTAINER(hosttable->scrolled_window), (GtkWidget *)hosttable->table);
    gtk_tree_view_set_rules_hint(hosttable->table, TRUE);
    gtk_tree_view_set_headers_clickable(hosttable->table, TRUE);
    gtk_tree_view_set_reorderable (hosttable->table, TRUE);

    hosttable->hash.conv_array = NULL;
    hosttable->hash.hashtable = NULL;
    hosttable->hash.user_data = hosttable;

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hosttable->table));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);

    /* create popup menu for this table */
    hostlist_create_popup_menu(hosttable);

    /* register the tap and rerun the taps on the packet list */
    error_string=register_tap_listener(tap_name, &hosttable->hash, filter, 0, reset_hostlist_table_data_cb, packet_func, draw_hostlist_table_data_cb);
    if(error_string){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        g_free(hosttable);
        return FALSE;
    }
    return TRUE;
}


void
init_hostlist_table(struct register_ct* ct, const char *filter)
{
    hostlist_table *hosttable;
    char *display_name;
    char title[256];
    GtkWidget *vbox;
    GtkWidget *bbox;
    GtkWidget *close_bt, *help_bt;
    gboolean ret;
    GtkWidget *copy_bt;
#ifdef HAVE_GEOIP
    GtkWidget *map_bt;
#endif
    window_geometry_t tl_geom;

    hosttable=g_new0(hostlist_table,1);

    hosttable->name=proto_get_protocol_short_name(find_protocol_by_id(get_conversation_proto_id(ct)));
    hosttable->filter=filter;
    hosttable->use_dfilter=FALSE;
    display_name = cf_get_display_name(&cfile);
    g_snprintf(title, sizeof(title), "%s Endpoints: %s", hosttable->name, display_name);
    g_free(display_name);
    hosttable->win = dlg_window_new(title);  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(hosttable->win), TRUE);

    window_get_geometry(top_level, &tl_geom);
    gtk_window_set_default_size(GTK_WINDOW(hosttable->win), tl_geom.width * 8 / 10, HL_DLG_HEIGHT);

    vbox=ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_LABEL_SPACING, FALSE);
    gtk_container_add(GTK_CONTAINER(hosttable->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), DLG_OUTER_MARGIN);

    ret = init_hostlist_table_page(hosttable, vbox, get_conversation_hide_ports(ct), hosttable->name,
                    proto_get_protocol_filter_name(get_conversation_proto_id(ct)), filter, get_hostlist_packet_func(ct));
    if(ret == FALSE) {
        g_free(hosttable);
        return;
    }

    /* Button row. */
    /* XXX - maybe we want to have a "Copy as CSV" stock button here? */
    /*copy_bt = gtk_button_new_with_label ("Copy content to clipboard as CSV");*/
#ifdef HAVE_GEOIP
    if( strstr(hosttable->name, "IPv4") || strstr(hosttable->name, "IPv6") ) {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, WIRESHARK_STOCK_MAP, GTK_STOCK_HELP, NULL);
    } else {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
    }
#else
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
#endif

    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(hosttable->win, close_bt, window_cancel_button_cb);

    copy_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
    gtk_widget_set_tooltip_text(copy_bt, "Copy all statistical values of this page to the clipboard in CSV (Comma Separated Values) format.");
    g_object_set_data(G_OBJECT(copy_bt), HOST_PTR_KEY, hosttable);
    g_signal_connect(copy_bt, "clicked", G_CALLBACK(copy_as_csv_cb), NULL);

#ifdef HAVE_GEOIP
    map_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_MAP);
    if(map_bt != NULL) {
        gtk_widget_set_tooltip_text(map_bt, "Show a map of the IP addresses (internet connection required).");
        g_object_set_data(G_OBJECT(map_bt), HOST_PTR_KEY, hosttable);
        g_signal_connect(map_bt, "clicked", G_CALLBACK(open_as_map_cb), NULL);
    }
#endif /* HAVE_GEOIP */

    help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_ENDPOINTS_DIALOG);

    g_signal_connect(hosttable->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(hosttable->win, "destroy", G_CALLBACK(hostlist_win_destroy_cb), hosttable);

    gtk_widget_show_all(hosttable->win);
    window_present(hosttable->win);

    cf_retap_packets(&cfile);
    gdk_window_raise(gtk_widget_get_window(hosttable->win));
}


static void
ct_nb_switch_page_cb(GtkNotebook *nb, gpointer *pg _U_, guint page, gpointer data)
{
    GtkWidget *copy_bt = (GtkWidget *) data;
    void ** pages = (void **)g_object_get_data(G_OBJECT(nb), NB_PAGES_KEY);

    page++;

    if (pages && page > 0 && (int) page <= GPOINTER_TO_INT(pages[0]) && copy_bt) {
        g_object_set_data(G_OBJECT(copy_bt), HOST_PTR_KEY, pages[page]);
    }
}

#ifdef HAVE_GEOIP
static void
ct_nb_map_switch_page_cb(GtkNotebook *nb, gpointer *pg _U_, guint page, gpointer data)
{
    GtkWidget *map_bt = (GtkWidget *) data;
    void ** pages = (void **)g_object_get_data(G_OBJECT(nb), NB_PAGES_KEY);

    page++;

    if (pages && page > 0 && (int) page <= GPOINTER_TO_INT(pages[0]) && map_bt) {
        g_object_set_data(G_OBJECT(map_bt), HOST_PTR_KEY, pages[page]);
        if( strstr(((hostlist_table *)pages[page])->name, "IPv4") ||
            strstr(((hostlist_table *)pages[page])->name, "IPv6") ) {
            gtk_widget_set_sensitive(map_bt, TRUE);
        } else {
            gtk_widget_set_sensitive(map_bt, FALSE);
        }
    }
}
#endif /* HAVE_GEOIP */


static void
hostlist_win_destroy_notebook_cb(GtkWindow *win _U_, gpointer data)
{
    void ** pages = (void **)data;
    int page;

    /* first "page" contains the number of pages */
    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        hostlist_win_destroy_cb(NULL, pages[page]);
    }
    g_free(pages);
}




static hostlist_table *
init_hostlist_notebook_page_cb(register_ct_t *table, const char *filter)
{
    gboolean ret;
    GtkWidget *page_vbox;
    hostlist_table *hosttable;

    hosttable=g_new0(hostlist_table,1);
    hosttable->name=proto_get_protocol_short_name(find_protocol_by_id(get_conversation_proto_id(table)));
    hosttable->filter=filter;
    hosttable->use_dfilter=FALSE;

    page_vbox=ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 6, FALSE);
    hosttable->win = page_vbox;
    gtk_container_set_border_width(GTK_CONTAINER(page_vbox), 6);

    ret = init_hostlist_table_page(hosttable, page_vbox, get_conversation_hide_ports(table), hosttable->name,
                proto_get_protocol_filter_name(get_conversation_proto_id(table)), filter, get_hostlist_packet_func(table));
    if(ret == FALSE) {
        g_free(hosttable);
        return NULL;
    }

    return hosttable;
}

static void
hostlist_resolve_toggle_dest(GtkWidget *widget, gpointer data)
{
    int page;
    void ** pages = (void **)data;
    gboolean resolve_names;
    hostlist_table *hosttable;


    resolve_names = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        hosttable = (hostlist_table *)pages[page];
        hosttable->resolve_names = resolve_names;
        draw_hostlist_table_addresses(hosttable);
    }
}


static void
hostlist_filter_toggle_dest(GtkWidget *widget, gpointer data)
{
    int page;
    void ** pages = (void **)data;
    gboolean use_filter;
    hostlist_table *hosttable = NULL;

    use_filter = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        hosttable = (hostlist_table *)pages[page];
        hosttable->use_dfilter = use_filter;
        reset_host_table_data(hosttable);
    }

    cf_retap_packets(&cfile);
    if (hosttable) {
        gdk_window_raise(gtk_widget_get_window(hosttable->win));
    }
}

typedef struct _init_host_page_data {
    int page;
    void ** pages;
    GtkWidget *nb;
    GtkWidget *win;
} init_host_page_data;

static void
init_host_page(gpointer data, gpointer user_data)
{
    register_ct_t *table = (register_ct_t*)data;
    init_host_page_data* host_page_data = (init_host_page_data*)user_data;

    hostlist_table *hosttable;
    GtkWidget *page_lb;

    hosttable = init_hostlist_notebook_page_cb(table, NULL /*filter*/);
    if (hosttable) {
        g_object_set_data(G_OBJECT(hosttable->win), HOST_PTR_KEY, hosttable);
        page_lb = gtk_label_new("");
        gtk_notebook_append_page(GTK_NOTEBOOK(host_page_data->nb), hosttable->win, page_lb);
        hosttable->win = host_page_data->win;
        hosttable->page_lb = page_lb;
        host_page_data->pages[++host_page_data->page] = hosttable;
    }
}

void
init_hostlist_notebook_cb(GtkWidget *w _U_, gpointer d _U_)
{
    char *display_name;
    char title[256];
    GtkWidget *vbox;
    GtkWidget *hbox;
    GtkWidget *bbox;
    GtkWidget *close_bt, *help_bt;
    GtkWidget *win;
    GtkWidget *resolv_cb;
    GtkWidget *filter_cb;
    void ** pages;
    GtkWidget *nb;
    GtkWidget *copy_bt;
#ifdef HAVE_GEOIP
    GtkWidget *map_bt;
#endif
    window_geometry_t tl_geom;
    init_host_page_data host_page_iter_data;

    pages = (void **)g_malloc(sizeof(void *) * (conversation_table_get_num() + 1));

    win = dlg_window_new("hostlist");  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(win), TRUE);

    display_name = cf_get_display_name(&cfile);
    g_snprintf(title, sizeof(title), "Endpoints: %s", display_name);
    g_free(display_name);
    gtk_window_set_title(GTK_WINDOW(win), title);

    window_get_geometry(top_level, &tl_geom);
    gtk_window_set_default_size(GTK_WINDOW(win), tl_geom.width * 8 / 10, HL_DLG_HEIGHT);

    vbox=ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_LABEL_SPACING, FALSE);
    gtk_container_add(GTK_CONTAINER(win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), DLG_OUTER_MARGIN);

    nb = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), nb, TRUE, TRUE, 0);
    g_object_set_data(G_OBJECT(nb), NB_PAGES_KEY, pages);

    host_page_iter_data.page = 0;
    host_page_iter_data.pages = pages;
    host_page_iter_data.nb = nb;
    host_page_iter_data.win = win;

    conversation_table_iterate_tables(init_host_page, &host_page_iter_data);

    pages[0] = GINT_TO_POINTER(host_page_iter_data.page);
    hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_UNRELATED_SPACING, FALSE);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    resolv_cb = gtk_check_button_new_with_mnemonic("Name resolution");
    gtk_box_pack_start(GTK_BOX(hbox), resolv_cb, FALSE, FALSE, 0);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(resolv_cb), TRUE);
    gtk_widget_set_tooltip_text(resolv_cb,
        "Show results of name resolutions rather than the \"raw\" values. Please note: The corresponding name resolution must be enabled.");

    g_signal_connect(resolv_cb, "toggled", G_CALLBACK(hostlist_resolve_toggle_dest), pages);

    filter_cb = gtk_check_button_new_with_mnemonic("Limit to display filter");
    gtk_box_pack_start(GTK_BOX(hbox), filter_cb, FALSE, FALSE, 0);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(filter_cb), FALSE);
    gtk_widget_set_tooltip_text(filter_cb, "Limit the list to endpoints matching the current display filter.");

    g_signal_connect(filter_cb, "toggled", G_CALLBACK(hostlist_filter_toggle_dest), pages);

    /* Button row. */
#ifdef HAVE_GEOIP
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, WIRESHARK_STOCK_MAP, GTK_STOCK_HELP, NULL);
#else
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
#endif
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    /* Close */
    close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(win, close_bt, window_cancel_button_cb);

    /* Copy */
    copy_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
    gtk_widget_set_tooltip_text(copy_bt, "Copy all statistical values of this page to the clipboard in CSV (Comma Separated Values) format.");
    g_signal_connect(copy_bt, "clicked", G_CALLBACK(copy_as_csv_cb), NULL);
    g_object_set_data(G_OBJECT(copy_bt), HOST_PTR_KEY, pages[host_page_iter_data.page]);

#ifdef HAVE_GEOIP
    map_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_MAP);
    gtk_widget_set_tooltip_text(map_bt, "Show a map of the IP addresses (internet connection required).");
    g_object_set_data(G_OBJECT(map_bt), HOST_PTR_KEY, pages[host_page_iter_data.page]);
    g_signal_connect(map_bt, "clicked", G_CALLBACK(open_as_map_cb), NULL);
    g_signal_connect(nb, "switch-page", G_CALLBACK(ct_nb_map_switch_page_cb), map_bt);
    gtk_widget_set_sensitive(map_bt, FALSE);
#endif /* HAVE_GEOIP */

    g_signal_connect(nb, "switch-page", G_CALLBACK(ct_nb_switch_page_cb), copy_bt);

    help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_ENDPOINTS_DIALOG);

    g_signal_connect(win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(win, "destroy", G_CALLBACK(hostlist_win_destroy_notebook_cb), pages);

    gtk_widget_show_all(win);
    window_present(win);

    cf_retap_packets(&cfile);
    gdk_window_raise(gtk_widget_get_window(win));
}

void hostlist_endpoint_cb(register_ct_t* table)
{
    char cmd_str[50];

    g_snprintf(cmd_str, 50, "%s,%s", HOSTLIST_TAP_PREFIX, proto_get_protocol_filter_name(get_conversation_proto_id(table)));

    dissector_hostlist_init(cmd_str, table);
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
