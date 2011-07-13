/* hostlist_table.c   2004 Ian Schorr
 * modified from endpoint_talkers_table.c   2003 Ronnie Sahlberg
 * Helper routines common to all host list taps.
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <locale.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/to_str.h>
#include <epan/addr_resolv.h>
#include <epan/tap.h>
#include <epan/strutil.h>
#ifdef HAVE_GEOIP
#include <epan/geoip_db.h>
#include <epan/pint.h>
#include <epan/filesystem.h>
#endif

#include <wsutil/file_util.h>

#include "../simple_dialog.h"
#include "../alert_box.h"
#include "../tempfile.h"

#include "gtk/hostlist_table.h"
#include "gtk/filter_utils.h"
#include "gtk/gtkglobals.h"

#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/help_dlg.h"
#include "gtk/main.h"
#include "gtk/utf8_entities.h"
#ifdef HAVE_GEOIP
#include "gtk/webbrowser.h"
#include "gtk/stock_icons.h"
#endif

#define HOST_PTR_KEY "hostlist-pointer"
#define NB_PAGES_KEY "notebook-pages"

#define CMP_INT(i1, i2)         \
    if ((i1) > (i2))            \
        return 1;               \
    else if ((i1) < (i2))       \
        return -1;              \
    else                        \
        return 0;

#define COL_STR_LEN 32

/* convert a port number into a string */
static char *
hostlist_port_to_str(int port_type_val, guint32 port)
{
    static int i=0;
    static gchar *strp, str[4][12];
    gchar *bp;

    switch(port_type_val){
    case PT_TCP:
    case PT_UDP:
    case PT_SCTP:
        i = (i+1)%4;
        strp=str[i];
        bp = &strp[11];

        *bp = 0;
        do {
            *--bp = (port % 10) +'0';
        } while ((port /= 10) != 0 && bp > strp);
        return bp;
    }
    return NULL;
}


#define FN_ANY_ADDRESS          0
#define FN_ANY_PORT             1

/* Given an address (to distinguish between ipv4 and ipv6 for tcp/udp,
   a port_type and a name_type (FN_...)
   return a string for the filter name.

   Some addresses, like AT_ETHER may actually be any of multiple types
   of protocols,   either ethernet, tokenring, fddi etc so we must be more
   specific there;  that's why we need specific_addr_type.
*/
static const char *
hostlist_get_filter_name(address *addr, int specific_addr_type_val, int port_type_val, int name_type_val)
{
    switch(name_type_val){
    case FN_ANY_ADDRESS:
        switch(addr->type){
        case AT_ETHER:
            switch(specific_addr_type_val){
            case SAT_ETHER:
                return "eth.addr";
            case SAT_WLAN:
                return "wlan.addr";
            case SAT_FDDI:
                return "fddi.addr";
            case SAT_TOKENRING:
                return "tr.addr";
            default:
                break;
            }
            break;
        case AT_IPv4:
            return "ip.addr";
        case AT_IPv6:
            return "ipv6.addr";
        case AT_IPX:
            return "ipx.addr";
        case AT_FC:
            return "fc.id";
        case AT_URI:
            switch(specific_addr_type_val){
            case SAT_JXTA:
                return "jxta.message.address";
            default:
                break;
            }
            break;
        case AT_USB:
            return "usb.addr";
        default:
            break;
        }
        break;
    case FN_ANY_PORT:
        switch(port_type_val){
        case PT_TCP:
            return "tcp.port";
        case PT_UDP:
            return "udp.port";
        case PT_SCTP:
            return "sctp.port";
        }
        break;
    }

    g_assert_not_reached();
    return NULL;
}

static void
reset_hostlist_table_data(hostlist_table *hosts)
{
    guint32 i;
    char title[256];
    GString *error_string;
    const char *filter;
    GtkListStore *store;

    if (hosts->use_dfilter) {
        filter = gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
    } else {
        filter = hosts->filter;
    }
    error_string = set_tap_dfilter (hosts, filter);
    if (error_string) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        return;
    }


    if(hosts->page_lb) {
        g_snprintf(title, sizeof(title), "Endpoints: %s", cf_get_display_name(&cfile));
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
        g_snprintf(title, sizeof(title), "%s Endpoints: %s", hosts->name, cf_get_display_name(&cfile));
        gtk_window_set_title(GTK_WINDOW(hosts->win), title);
    }

    /* remove all entries from the list */
    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(hosts->table)));
    gtk_list_store_clear(store);

    /* delete all hosts */
    for(i=0;i<hosts->num_hosts;i++){
        hostlist_talker_t *host = &g_array_index(hosts->hosts, hostlist_talker_t, i);
        g_free((gpointer)host->address.data);
    }

    if (hosts->hosts)
        g_array_free(hosts->hosts, TRUE);

    if (hosts->hashtable != NULL)
        g_hash_table_destroy(hosts->hashtable);

    hosts->hosts=NULL;
    hosts->hashtable=NULL;
    hosts->num_hosts=0;
}

static void
reset_hostlist_table_data_cb(void *arg)
{
    reset_hostlist_table_data(arg);
}

static void
hostlist_win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
    hostlist_table *hosts=(hostlist_table *)data;

    protect_thread_critical_region();
    remove_tap_listener(hosts);
    unprotect_thread_critical_region();

    reset_hostlist_table_data(hosts);
    g_free(hosts);
}

enum
{
    ADR_COLUMN,
    PORT_COLUMN,
    PACKETS_COLUMN,
    BYTES_COLUMN,
    PKT_AB_COLUMN,
    BYTES_AB_COLUMN,
    PKT_BA_COLUMN,
    BYTES_BA_COLUMN,
#ifdef HAVE_GEOIP
    GEOIP1_COLUMN,
    GEOIP2_COLUMN,
    GEOIP3_COLUMN,
    GEOIP4_COLUMN,
    GEOIP5_COLUMN,
    GEOIP6_COLUMN,
    GEOIP7_COLUMN,
    GEOIP8_COLUMN,
    GEOIP9_COLUMN,
    GEOIP10_COLUMN,
    GEOIP11_COLUMN,
    GEOIP12_COLUMN,
    GEOIP13_COLUMN,
#endif
    INDEX_COLUMN,
    N_COLUMNS
};

static gint
hostlist_sort_column(GtkTreeModel *model,
                     GtkTreeIter *a,
                     GtkTreeIter *b,
                     gpointer user_data)

{
    guint32 idx1, idx2;
    gint data_column = GPOINTER_TO_INT(user_data);
    hostlist_table *hl = g_object_get_data(G_OBJECT(model), HOST_PTR_KEY);
    hostlist_talker_t *host1 = NULL;
    hostlist_talker_t *host2 = NULL;

    gtk_tree_model_get(model, a, INDEX_COLUMN, &idx1, -1);
    gtk_tree_model_get(model, b, INDEX_COLUMN, &idx2, -1);

    if (!hl || idx1 >= hl->num_hosts || idx2 >= hl->num_hosts)
        return 0;

    host1 = &g_array_index(hl->hosts, hostlist_talker_t, idx1);
    host2 = &g_array_index(hl->hosts, hostlist_talker_t, idx2);

    switch(data_column){
    case 0: /* Address */
        return(CMP_ADDRESS(&host1->address, &host2->address));
    case 1: /* (Port) */
        CMP_INT(host1->port, host2->port);
#ifdef HAVE_GEOIP
    default:
        {
            gchar *text1, *text2;
            double loc1 = 0, loc2 = 0;

            gtk_tree_model_get(model, a, data_column, &text1, -1);
            gtk_tree_model_get(model, b, data_column, &text2, -1);

            if (text1) {
                loc1 = atof(text1);
                g_free(text1);
            }

            if (text2) {
                loc2 = atof(text2);
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
    char *str = NULL;
    char *sport;
    GtkTreeIter iter;
    GtkTreeModel *model;
    GtkTreeSelection  *sel;
    hostlist_talker_t *host = NULL;

    sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(hl->table));
    if (!gtk_tree_selection_get_selected(sel, &model, &iter))
        return;

    gtk_tree_model_get (model, &iter,
                            INDEX_COLUMN, &idx,
                            -1);

    if(idx>= hl->num_hosts){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No hostlist selected");
        return;
    }
    host = &g_array_index(hl->hosts, hostlist_talker_t, idx);

    sport=hostlist_port_to_str(host->port_type, host->port);

    str = g_strdup_printf("%s==%s%s%s%s%s",
                          hostlist_get_filter_name(&host->address, host->sat, host->port_type,  FN_ANY_ADDRESS),
                          ep_address_to_str(&host->address),
                          sport?" && ":"",
                          sport?hostlist_get_filter_name(&host->address, host->sat, host->port_type,  FN_ANY_PORT):"",
                          sport?"==":"",
                          sport?sport:"");

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
 * const gchar *name;			The name of the action.
 * const gchar *stock_id;		The stock id for the action, or the name of an icon from the icon theme.
 * const gchar *label;			The label for the action. This field should typically be marked for translation,
 *								see gtk_action_group_set_translation_domain().
 *								If label is NULL, the label of the stock item with id stock_id is used.
 * const gchar *accelerator;	The accelerator for the action, in the format understood by gtk_accelerator_parse().
 * const gchar *tooltip;		The tooltip for the action. This field should typically be marked for translation,
 *                              see gtk_action_group_set_translation_domain().
 * GCallback callback;			The function to call when the action is activated.
 *
 */
static const GtkActionEntry service_resp_t__popup_entries[] = {
  { "/Apply as Filter",							NULL, "Apply as Filter",				NULL, NULL,								NULL },
  { "/Prepare a Filter",						NULL, "Prepare a Filter",				NULL, NULL,								NULL },
  { "/Find Frame",								NULL, "Find Frame",						NULL, NULL,								NULL },
  { "/Find Frame/Find Frame",					NULL, "Find Frame",						NULL, NULL,								NULL },
  { "/Find Frame/Find Next",					NULL, "Find Next" ,						NULL, NULL,								NULL },
  { "/Find Frame/Find Previous",				NULL, "Find Previous",					NULL, NULL,								NULL },
  { "/Colorize Procedure",						NULL, "Colorize Procedure",				NULL, NULL,								NULL },
  { "/Apply as Filter/Selected",				NULL, "Selected",						NULL, "Selected",						G_CALLBACK(apply_as_selected_cb) },
  { "/Apply as Filter/Not Selected",		NULL, "Not Selected",				NULL, "Not Selected",				G_CALLBACK(apply_as_not_selected_cb) },
  { "/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " and Selected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " and Selected",				NULL, UTF8_HORIZONTAL_ELLIPSIS " and Selected",				G_CALLBACK(apply_as_and_selected_cb) },
  { "/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " or Selected",			NULL, UTF8_HORIZONTAL_ELLIPSIS " or Selected",				NULL, UTF8_HORIZONTAL_ELLIPSIS " or Selected",				G_CALLBACK(apply_as_or_selected_cb) },
  { "/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " and not Selected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " and not Selected",			NULL, UTF8_HORIZONTAL_ELLIPSIS " and not Selected",			G_CALLBACK(apply_as_and_not_selected_cb) },
  { "/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " or not Selected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " or not Selected",			NULL, UTF8_HORIZONTAL_ELLIPSIS " or not Selected",			G_CALLBACK(apply_as_or_not_selected_cb) },
  { "/Prepare a Filter/Selected",				NULL, "Selected",						NULL, "selcted",						G_CALLBACK(prep_as_selected_cb) },
  { "/Prepare a Filter/Not Selected",		NULL, "Not Selected",				NULL, "Not Selected",				G_CALLBACK(prep_as_not_selected_cb) },
  { "/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " and Selected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " and Selected",				NULL, UTF8_HORIZONTAL_ELLIPSIS " and Selected",				G_CALLBACK(prep_as_and_selected_cb) },
  { "/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " or Selected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " or Selected",				NULL, UTF8_HORIZONTAL_ELLIPSIS " or Selected",				G_CALLBACK(prep_as_or_selected_cb) },
  { "/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " and not Selected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " and not Selected",			NULL, UTF8_HORIZONTAL_ELLIPSIS " and not Selected",			G_CALLBACK(prep_as_and_not_selected_cb) },
  { "/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " or not Selected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " or not Selected",			NULL, UTF8_HORIZONTAL_ELLIPSIS " or not Selected",			G_CALLBACK(prep_as_or_not_selected_cb) },
  { "/Find Frame/Selected",						NULL, "Selected",						NULL, "Selected",						G_CALLBACK(find_selected_cb) },
  { "/Find Frame/Not Selected",					NULL, "Not Selected",					NULL, "Not Selected",					G_CALLBACK(find_not_selected_cb) },
  { "/Find Previous/Selected",					NULL, "Selected",						NULL, "Selected",						G_CALLBACK(find_prev_selected_cb) },
  { "/Find Previous/Not Selected",				NULL, "Not Selected",					NULL, "Not Selected",					G_CALLBACK(find_prev_not_selected_cb) },
  { "/Find Next/Selected",						NULL, "Selected",						NULL, "Selected",						G_CALLBACK(find_next_selected_cb) },
  { "/Find Next/Not Selected",					NULL, "Not Selected",					NULL, "Not Selected",					G_CALLBACK(find_next_not_selected_cb) },
  { "/Colorize Procedure/Colorize Host Traffic",NULL, "Colorize Host Traffic",			NULL, "Colorize Host Traffic",			G_CALLBACK(color_selected_cb) },
};

static void
hostlist_create_popup_menu(hostlist_table *hl)
{
	GtkUIManager *ui_manager;
	GtkActionGroup *action_group;
	GError *error = NULL;

	action_group = gtk_action_group_new ("HostlistTablePopupActionGroup");
	gtk_action_group_add_actions (action_group,								/* the action group */
								(gpointer)service_resp_t__popup_entries,	/* an array of action descriptions */
								G_N_ELEMENTS(service_resp_t__popup_entries),/* the number of entries */
								hl);										/* data to pass to the action callbacks */

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


/* Draw/refresh the address field of a single entry at the specified index */
static void
get_hostlist_table_address(hostlist_table *hl, hostlist_talker_t *host, char **entries)
{
    char *port;
    guint32 pt;

    if (!hl->resolve_names)
        entries[0] = ep_address_to_str(&host->address);
    else
        entries[0] = (char *)get_addr_name(&host->address);

    pt = host->port_type;
    if(!hl->resolve_names) pt = PT_NONE;
    switch(pt) {
    case(PT_TCP):
        entries[1] = get_tcp_port(host->port);
        break;
    case(PT_UDP):
        entries[1] = get_udp_port(host->port);
        break;
    case(PT_SCTP):
        entries[1] = get_sctp_port(host->port);
        break;
    default:
        port=hostlist_port_to_str(host->port_type, host->port);
        entries[1] = port?port:"";
    }
}

/* Refresh the address fields of all entries in the list */
static void
draw_hostlist_table_addresses(hostlist_table *hl)
{
    guint32 i;
    char *entries[2];
    GtkListStore *store;

    store = GTK_LIST_STORE(gtk_tree_view_get_model(hl->table));
    g_object_ref(store);
    gtk_tree_view_set_model(GTK_TREE_VIEW(hl->table), NULL);

    for(i=0;i<hl->num_hosts;i++){
        hostlist_talker_t *host = &g_array_index(hl->hosts, hostlist_talker_t, i);
        get_hostlist_table_address(hl, host, entries);
        gtk_list_store_set (store, &host->iter,
                  ADR_COLUMN, entries[0],
                  PORT_COLUMN, entries[1],
                    -1);
    }
    gtk_tree_view_set_model(GTK_TREE_VIEW(hl->table), GTK_TREE_MODEL(store));
    g_object_unref(store);
}


static void
draw_hostlist_table_data(hostlist_table *hl)
{
    guint32 i;
    char title[256];
    GtkListStore *store;
    gboolean first = TRUE;

    if (hl->page_lb) {
        if(hl->num_hosts) {
            g_snprintf(title, sizeof(title), "%s: %u", hl->name, hl->num_hosts);
        } else {
            g_snprintf(title, sizeof(title), "%s", hl->name);
        }
        gtk_label_set_text(GTK_LABEL(hl->page_lb), title);
        gtk_widget_set_sensitive(hl->page_lb, hl->num_hosts);
    } else {
        if(hl->num_hosts) {
            g_snprintf(title, sizeof(title), "%s Endpoints: %u", hl->name, hl->num_hosts);
        } else {
            g_snprintf(title, sizeof(title), "%s Endpoints", hl->name);
        }
        gtk_label_set_text(GTK_LABEL(hl->name_lb), title);
    }

    store = GTK_LIST_STORE(gtk_tree_view_get_model(hl->table));
    for(i=0;i<hl->num_hosts;i++){
        hostlist_talker_t *host = &g_array_index(hl->hosts, hostlist_talker_t, i);

        if (!host->modified)
            continue;

        if (first) {
            g_object_ref(store);
            gtk_tree_view_set_model(GTK_TREE_VIEW(hl->table), NULL);

            first = FALSE;
        }
        host->modified = FALSE;
        if (!host->iter_valid) {
            char *entries[2];
#ifdef HAVE_GEOIP
            char geoip[NUM_GEOIP_COLS][COL_STR_LEN];
            guint j;

            if (host->address.type == AT_IPv4 && !hl->geoip_visible) {
                GList             *columns, *list;
                GtkTreeViewColumn *column;
                columns = gtk_tree_view_get_columns(GTK_TREE_VIEW(hl->table));
                list = columns;
                while(columns) {
                    const gchar *title_p;
                    gint  id;

                    column = columns->data;
                    title_p = gtk_tree_view_column_get_title(column);
                    id = gtk_tree_view_column_get_sort_column_id(column);
                    if (title_p[0] != 0 && id >= GEOIP1_COLUMN) {
                        gtk_tree_view_column_set_visible(column, TRUE);
                    }
                    columns = g_list_next(columns);
                }
                g_list_free(list);
                hl->geoip_visible = TRUE;
            }

            /* Filled in from the GeoIP config, if any */
            for (j = 0; j < NUM_GEOIP_COLS; j++) {
                if (host->address.type == AT_IPv4 && j < geoip_db_num_dbs()) {
                    const guchar *name = geoip_db_lookup_ipv4(j, pntohl(host->address.data), "-");
                    g_strlcpy(geoip[j], format_text (name, strlen(name)), COL_STR_LEN);
                } else {
                  geoip[j][0] = 0;
                }
            }
#endif /* HAVE_GEOIP */

            get_hostlist_table_address(hl, host, entries);
            host->iter_valid = TRUE;
            gtk_list_store_insert_with_values( store , &host->iter, G_MAXINT,
                  ADR_COLUMN,      entries[0],
                  PORT_COLUMN,     entries[1],
                  PACKETS_COLUMN,  host->tx_frames+host->rx_frames,
                  BYTES_COLUMN,    host->tx_bytes+host->rx_bytes,
                  PKT_AB_COLUMN,   host->tx_frames,
                  BYTES_AB_COLUMN, host->tx_bytes,
                  PKT_BA_COLUMN,   host->rx_frames,
                  BYTES_BA_COLUMN, host->rx_bytes,
#ifdef HAVE_GEOIP
                  GEOIP1_COLUMN,   geoip[0],
                  GEOIP2_COLUMN,   geoip[1],
                  GEOIP3_COLUMN,   geoip[2],
                  GEOIP4_COLUMN,   geoip[3],
                  GEOIP5_COLUMN,   geoip[4],
                  GEOIP6_COLUMN,   geoip[5],
                  GEOIP7_COLUMN,   geoip[6],
                  GEOIP8_COLUMN,   geoip[7],
                  GEOIP9_COLUMN,   geoip[8],
                  GEOIP10_COLUMN,  geoip[9],
                  GEOIP11_COLUMN,  geoip[10],
                  GEOIP12_COLUMN,  geoip[11],
                  GEOIP13_COLUMN,  geoip[12],
#endif
                  INDEX_COLUMN,    i,
                    -1);
        }
        else {
            gtk_list_store_set (store, &host->iter,
                  PACKETS_COLUMN,  host->tx_frames+host->rx_frames,
                  BYTES_COLUMN,    host->tx_bytes+host->rx_bytes,
                  PKT_AB_COLUMN,   host->tx_frames,
                  BYTES_AB_COLUMN, host->tx_bytes,
                  PKT_BA_COLUMN,   host->rx_frames,
                  BYTES_BA_COLUMN, host->rx_bytes,
                    -1);
        }
    }
    if (!first) {
            if (!hl->fixed_col && hl->num_hosts >= 1000) {
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
    draw_hostlist_table_data(arg);
}

typedef struct {
    int             nb_cols;
    gint            columns_order[N_COLUMNS];
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
    unsigned idx;
    guint64  value;

    gtk_tree_model_get(model, iter, INDEX_COLUMN, &idx, -1);

    for (i=0; i< csv->nb_cols; i++) {
        if (i)
            g_string_append(csv->CSV_str, ",");

        switch(csv->columns_order[i]) {
        case ADR_COLUMN:
        case PORT_COLUMN:
            gtk_tree_model_get(model, iter, csv->columns_order[i], &table_text, -1);
            if (table_text) {
                g_string_append_printf(csv->CSV_str, "\"%s\"", table_text);
                g_free(table_text);
            }
            break;
        case PACKETS_COLUMN:
        case BYTES_COLUMN:
        case PKT_AB_COLUMN:
        case BYTES_AB_COLUMN:
        case PKT_BA_COLUMN:
        case BYTES_BA_COLUMN:
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

    csv.talkers=g_object_get_data(G_OBJECT(copy_bt), HOST_PTR_KEY);
    if (!csv.talkers)
        return;

    savelocale = setlocale(LC_NUMERIC, NULL);
    setlocale(LC_NUMERIC, "C");
    csv.CSV_str = g_string_new("");

    columns = gtk_tree_view_get_columns(GTK_TREE_VIEW(csv.talkers->table));
    list = columns;
    csv.nb_cols = 0;
    while(columns) {
        column = columns->data;
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
    g_string_free(csv.CSV_str, TRUE);                    /* Free the memory */
}

#ifdef HAVE_GEOIP
typedef struct {
    int                nb_cols;
    gint32             col_lat, col_lon, col_country, col_city, col_as_num, col_ip, col_packets, col_bytes;
    FILE              *out_file;
    gboolean           hosts_written;
    hostlist_table    *talkers;
} map_t;

/* XXX output in C locale */
static gboolean
map_handle(GtkTreeModel *model, GtkTreePath *path _U_, GtkTreeIter *iter,
              gpointer data)
{
    map_t   *map = (map_t *)data;
    gchar   *table_entry;
    guint64  value;
    /* Add the column values to the TSV data */

    /* check, if we have a geolocation available for this host */
    gtk_tree_model_get(model, iter, map->col_lat, &table_entry, -1);
    if (strcmp(table_entry, "-") == 0) {
        g_free(table_entry);
        return FALSE;
    }

    gtk_tree_model_get(model, iter, map->col_lon, &table_entry, -1);
    if (strcmp(table_entry, "-") == 0) {
        g_free(table_entry);
        return FALSE;
    }

    /* Latitude */
    gtk_tree_model_get(model, iter, map->col_lat, &table_entry, -1);
    fputs(table_entry, map->out_file);
    g_free(table_entry);
    fputs("\t", map->out_file);

    /* Longitude */
    gtk_tree_model_get(model, iter, map->col_lon, &table_entry, -1);
    fputs(table_entry, map->out_file);
    g_free(table_entry);
    fputs("\t", map->out_file);

    /* Title */
    gtk_tree_model_get(model, iter, map->col_ip, &table_entry, -1);
    fputs(table_entry, map->out_file);
    g_free(table_entry);
    fputs("\t", map->out_file);

    /* Description */
    if (map->col_as_num >= 0) {
        gtk_tree_model_get(model, iter, map->col_as_num, &table_entry, -1);
        fputs("AS: ", map->out_file);
        fputs(table_entry, map->out_file);
        g_free(table_entry);
        fputs("<br/>", map->out_file);
    }

    if (map->col_country >= 0) {
        gtk_tree_model_get(model, iter, map->col_country, &table_entry, -1);
        fputs("Country: ", map->out_file);
        fputs(table_entry, map->out_file);
        g_free(table_entry);
        fputs("<br/>", map->out_file);
    }

    if (map->col_country >= 0) {
        gtk_tree_model_get(model, iter, map->col_city, &table_entry, -1);
        fputs("City: ", map->out_file);
        fputs(table_entry, map->out_file);
        g_free(table_entry);
        fputs("<br/>", map->out_file);
    }

    gtk_tree_model_get(model, iter, map->col_packets, &value, -1);
    fprintf(map->out_file, "Packets: %" G_GINT64_MODIFIER "u<br/>", value);

    gtk_tree_model_get(model, iter, map->col_bytes, &value, -1);
    fprintf(map->out_file, "Bytes: %" G_GINT64_MODIFIER "u\t", value);

    /* XXX - we could add specific icons, e.g. depending on the amount of packets or bytes */

    fputs("\n", map->out_file);                     /* new row */
    map->hosts_written = TRUE;

    return FALSE;
}

static void
open_as_map_cb(GtkWindow *copy_bt, gpointer data _U_)
{
    guint32         i;
    gchar             *file_uri;
    gboolean           uri_open;
    char              *map_path, *map_data_filename;
    char              *src_file_path;
    char              *dst_file_path;
    GList             *columns, *list;
    GtkTreeViewColumn *column;
    GtkListStore      *store;
    map_t              map;

    map.talkers =g_object_get_data(G_OBJECT(copy_bt), HOST_PTR_KEY);
    if (!map.talkers)
        return;

    map.col_lat = map.col_lon = map.col_country = map.col_city = map.col_as_num = map.col_ip = map.col_packets = map.col_bytes = -1;
    map.hosts_written = FALSE;
    /* Find the interesting columns */
    columns = gtk_tree_view_get_columns(GTK_TREE_VIEW(map.talkers->table));
    list = columns;
    map.nb_cols = 0;
    while(columns) {
        column = columns->data;
        i = gtk_tree_view_column_get_sort_column_id(column);
        if(strcmp(map.talkers->default_titles[i], "Latitude") == 0) {
            map.col_lat = i;
            map.nb_cols++;
        }
        if(strcmp(map.talkers->default_titles[i], "Longitude") == 0) {
            map.col_lon = i;
            map.nb_cols++;
        }
        if(strcmp(map.talkers->default_titles[i], "Country") == 0) {
            map.col_country = i;
            map.nb_cols++;
        }
        if(strcmp(map.talkers->default_titles[i], "City") == 0) {
            map.col_city = i;
            map.nb_cols++;
        }
        if(strcmp(map.talkers->default_titles[i], "AS Number") == 0) {
            map.col_as_num = i;
        }
        if(strcmp(map.talkers->default_titles[i], "Address") == 0) {
            map.col_ip = i;
            map.nb_cols++;
        }
        if(strcmp(map.talkers->default_titles[i], "Packets") == 0) {
            map.col_packets = i;
            map.nb_cols++;
        }
        if(strcmp(map.talkers->default_titles[i], "Bytes") == 0) {
            map.col_bytes = i;
            map.nb_cols++;
        }
        columns = g_list_next(columns);
    }
    g_list_free(list);

    /* check for the minimum required data */
    if(map.col_lat == -1 || map.col_lon == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Latitude/Longitude data not available (GeoIP installed?)");
        return;
    }

    /* open the TSV output file */
    /* XXX - add error handling */
    if (! create_tempdir(&map_path, "Wireshark IP Map ")) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Could not create temporary directory\n%s",
                map_path);
        return;
    }
    map_data_filename = g_strdup_printf("%s%cipmap.txt", map_path, G_DIR_SEPARATOR);
    map.out_file = ws_fopen(map_data_filename, "w");
    if(map.out_file == NULL) {
        open_failure_alert_box(map_data_filename, errno, TRUE);
        return;
    }

    fputs("lat\tlon\ttitle\tdescription\t\n", map.out_file);
    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(map.talkers->table)));
    gtk_tree_model_foreach(GTK_TREE_MODEL(store), map_handle, &map);


    fclose(map.out_file);

    if(!map.hosts_written) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No latitude/longitude data found");
        return;
    }

    /* copy ipmap.html to temp dir */
    src_file_path = get_datafile_path("ipmap.html");
    dst_file_path = g_strdup_printf("%s%cipmap.html", map_path, G_DIR_SEPARATOR);

    if (!copy_file_binary_mode(src_file_path, dst_file_path)) {
        g_free(src_file_path);
        g_free(dst_file_path);
        return;
    }
    g_free(src_file_path);

    /* open the webbrowser */
    file_uri = filename2uri(dst_file_path);
    g_free(dst_file_path);
    uri_open = browser_open_url (file_uri);
    if(!uri_open) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Couldn't open the file: \"%s\" in your web browser", file_uri);
        g_free(file_uri);
        return;
    }

    g_free(file_uri);
}
#endif /* HAVE_GEOIP */

static gint default_col_size[N_COLUMNS];

static void
init_default_col_size(GtkWidget *view)
{

    default_col_size[ADR_COLUMN] = get_default_col_size(view, "00000000.000000000000");
    default_col_size[PORT_COLUMN] = get_default_col_size(view, "000000");
    default_col_size[PACKETS_COLUMN] = get_default_col_size(view, "00 000 000");
    default_col_size[BYTES_COLUMN] = get_default_col_size(view, "0 000 000 000");
    default_col_size[PKT_AB_COLUMN] = default_col_size[PACKETS_COLUMN];
    default_col_size[PKT_BA_COLUMN] = default_col_size[PACKETS_COLUMN];
    default_col_size[BYTES_AB_COLUMN] = default_col_size[BYTES_COLUMN];
    default_col_size[BYTES_BA_COLUMN] = default_col_size[BYTES_COLUMN];
#ifdef HAVE_GEOIP
    default_col_size[GEOIP1_COLUMN] = default_col_size[ADR_COLUMN];
    default_col_size[GEOIP2_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP3_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP4_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP5_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP6_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP7_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP8_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP9_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP10_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP11_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP12_COLUMN] = default_col_size[GEOIP1_COLUMN];
    default_col_size[GEOIP13_COLUMN] = default_col_size[GEOIP1_COLUMN];

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
    for (i = 0; i < NUM_GEOIP_COLS; i++) {
        if (i < geoip_db_num_dbs()) {
            hosttable->default_titles[NUM_BUILTIN_COLS + i]  = geoip_db_name(i);
        } else {
            hosttable->default_titles[NUM_BUILTIN_COLS + i]  = "";
        }
    }
#endif /* HAVE_GEOIP */

    if (strcmp(table_name, "NCP")==0) {
        hosttable->default_titles[1] = "Connection";
    }

    hosttable->has_ports=!hide_ports;
    hosttable->num_hosts = 0;
    hosttable->resolve_names=TRUE;
    hosttable->page_lb = NULL;
    hosttable->fixed_col = FALSE;
    hosttable->geoip_visible = FALSE;

    g_snprintf(title, sizeof(title), "%s Endpoints", table_name);
    hosttable->name_lb = gtk_label_new(title);
    gtk_box_pack_start(GTK_BOX(vbox), hosttable->name_lb, FALSE, FALSE, 0);

    /* Create the store */
    store = gtk_list_store_new (N_COLUMNS,      /* Total number of columns */
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

    for (i = 0; i < N_COLUMNS -1; i++) {
        renderer = gtk_cell_renderer_text_new ();
        g_object_set(renderer, "ypad", 0, NULL);
        switch(i) {
        case 0: /* address and port */
        case 1:
            column = gtk_tree_view_column_new_with_attributes (hosttable->default_titles[i], renderer, "text",
                                                               i, NULL);
            if(hide_ports && i == 1){
                /* hide srcport and dstport if we don't use ports */
                gtk_tree_view_column_set_visible(column, FALSE);
            }
            gtk_tree_sortable_set_sort_func(sortable, i, hostlist_sort_column, GINT_TO_POINTER(i), NULL);
            break;
        case 2: /* counts */
        case 3:
        case 4:
        case 5:
        case 6:
        case 7: /* right align numbers */
            g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
            column = gtk_tree_view_column_new_with_attributes (hosttable->default_titles[i], renderer, NULL);
            gtk_tree_view_column_set_cell_data_func(column, renderer, u64_data_func,  GINT_TO_POINTER(i), NULL);
            break;
        default: /* GEOIP */
            column = gtk_tree_view_column_new_with_attributes (hosttable->default_titles[i], renderer, "text",
                                                               i, NULL);
            gtk_tree_view_column_set_visible(column, FALSE);
#ifdef HAVE_GEOIP
            if (i >= NUM_BUILTIN_COLS && i - NUM_BUILTIN_COLS < geoip_db_num_dbs()) {
                int goip_type = geoip_db_type(i - NUM_BUILTIN_COLS);
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

    hosttable->num_hosts=0;
    hosttable->hosts=NULL;
    hosttable->hashtable=NULL;

    gtk_tree_view_set_rules_hint(hosttable->table, TRUE);
    gtk_tree_view_set_headers_clickable(hosttable->table, TRUE);
    gtk_tree_view_set_reorderable (hosttable->table, TRUE);

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hosttable->table));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);

    /* create popup menu for this table */
    hostlist_create_popup_menu(hosttable);

    /* register the tap and rerun the taps on the packet list */
    error_string=register_tap_listener(tap_name, hosttable, filter, 0, reset_hostlist_table_data_cb, packet_func, draw_hostlist_table_data_cb);
    if(error_string){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        g_free(hosttable);
        return FALSE;
    }
    return TRUE;
}


void
init_hostlist_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    hostlist_table *hosttable;
    char title[256];
    GtkWidget *vbox;
    GtkWidget *bbox;
    GtkWidget *close_bt, *help_bt;
    gboolean ret;
    GtkWidget *copy_bt;
#ifdef HAVE_GEOIP
    GtkWidget *map_bt;
#endif

    hosttable=g_malloc(sizeof(hostlist_table));

    hosttable->name=table_name;
    hosttable->filter=filter;
    hosttable->use_dfilter=FALSE;
    g_snprintf(title, sizeof(title), "%s Endpoints: %s", table_name, cf_get_display_name(&cfile));
    hosttable->win = dlg_window_new(title);  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(hosttable->win), TRUE);

    gtk_window_set_default_size(GTK_WINDOW(hosttable->win), 750, 400);

    vbox=gtk_vbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(hosttable->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    ret = init_hostlist_table_page(hosttable, vbox, hide_ports, table_name, tap_name, filter, packet_func);
    if(ret == FALSE) {
        g_free(hosttable);
        return;
    }

    /* Button row. */
    /* XXX - maybe we want to have a "Copy as CSV" stock button here? */
    /*copy_bt = gtk_button_new_with_label ("Copy content to clipboard as CSV");*/
#ifdef HAVE_GEOIP
    if( strstr(table_name, "IPv4") != NULL) {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, WIRESHARK_STOCK_MAP, GTK_STOCK_HELP, NULL);
    } else {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
    }
#else
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
#endif

    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(hosttable->win, close_bt, window_cancel_button_cb);

    copy_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
	gtk_widget_set_tooltip_text(copy_bt, "Copy all statistical values of this page to the clipboard in CSV (Comma Separated Values) format.");
    g_object_set_data(G_OBJECT(copy_bt), HOST_PTR_KEY, hosttable);
    g_signal_connect(copy_bt, "clicked", G_CALLBACK(copy_as_csv_cb), NULL);

#ifdef HAVE_GEOIP
    map_bt = g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_MAP);
    if(map_bt != NULL) {
        gtk_widget_set_tooltip_text(map_bt, "Show a map of the IP addresses (internet connection required).");
        g_object_set_data(G_OBJECT(map_bt), HOST_PTR_KEY, hosttable);
        g_signal_connect(map_bt, "clicked", G_CALLBACK(open_as_map_cb), NULL);
    }
#endif /* HAVE_GEOIP */

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_ENDPOINTS_DIALOG);

    g_signal_connect(hosttable->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(hosttable->win, "destroy", G_CALLBACK(hostlist_win_destroy_cb), hosttable);

    gtk_widget_show_all(hosttable->win);
    window_present(hosttable->win);

    cf_retap_packets(&cfile);
#if GTK_CHECK_VERSION(2,14,0)
    gdk_window_raise(gtk_widget_get_window(hosttable->win));
#else
    gdk_window_raise(hosttable->win->window);
#endif
}


static void
ct_nb_switch_page_cb(GtkNotebook *nb, gpointer *pg _U_, guint page, gpointer data)
{
    GtkWidget *copy_bt = (GtkWidget *) data;
    void ** pages = g_object_get_data(G_OBJECT(nb), NB_PAGES_KEY);

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
    void ** pages = g_object_get_data(G_OBJECT(nb), NB_PAGES_KEY);

    page++;

    if (pages && page > 0 && (int) page <= GPOINTER_TO_INT(pages[0]) && map_bt) {
        g_object_set_data(G_OBJECT(map_bt), HOST_PTR_KEY, pages[page]);
        if(strstr( ((hostlist_table *)pages[page])->name, "IPv4") != NULL) {
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
    void ** pages = data;
    int page;

    /* first "page" contains the number of pages */
    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        hostlist_win_destroy_cb(NULL, pages[page]);
    }
    g_free(pages);
}




static hostlist_table *
init_hostlist_notebook_page_cb(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter,
  tap_packet_cb packet_func)
{
    gboolean ret;
    GtkWidget *page_vbox;
    hostlist_table *hosttable;

    hosttable=g_malloc(sizeof(hostlist_table));
    hosttable->name=table_name;
    hosttable->filter=filter;
    hosttable->use_dfilter=FALSE;

    page_vbox=gtk_vbox_new(FALSE, 6);
    hosttable->win = page_vbox;
    gtk_container_set_border_width(GTK_CONTAINER(page_vbox), 6);

    ret = init_hostlist_table_page(hosttable, page_vbox, hide_ports, table_name, tap_name, filter, packet_func);
    if(ret == FALSE) {
        g_free(hosttable);
        return NULL;
    }

    return hosttable;
}


typedef struct {
    gboolean hide_ports;       /* hide TCP / UDP port columns */
    const char *table_name;    /* GUI output name */
    const char *tap_name;      /* internal name */
    const char *filter;        /* display filter string (unused) */
    tap_packet_cb packet_func; /* function to be called for new incoming packets */
} register_hostlist_t;


static GSList *registered_hostlist_tables = NULL;

void
register_hostlist_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    register_hostlist_t *table;

    table = g_malloc(sizeof(register_hostlist_t));

    table->hide_ports   = hide_ports;
    table->table_name   = table_name;
    table->tap_name     = tap_name;
    table->filter       = filter;
    table->packet_func  = packet_func;

    registered_hostlist_tables = g_slist_append(registered_hostlist_tables, table);
}


static void
hostlist_resolve_toggle_dest(GtkWidget *widget, gpointer data)
{
    int page;
    void ** pages = data;
    gboolean resolve_names;
    hostlist_table *hosttable;


    resolve_names = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        hosttable = pages[page];
        hosttable->resolve_names = resolve_names;
        draw_hostlist_table_addresses(hosttable);
    }
}


static void
hostlist_filter_toggle_dest(GtkWidget *widget, gpointer data)
{
    int page;
    void ** pages = data;
    gboolean use_filter;
    hostlist_table *hosttable = NULL;

    use_filter = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        hosttable = pages[page];
        hosttable->use_dfilter = use_filter;
        reset_hostlist_table_data(hosttable);
    }

    cf_retap_packets(&cfile);
    if (hosttable) {
#if GTK_CHECK_VERSION(2,14,0)
        gdk_window_raise(gtk_widget_get_window(hosttable->win));
#else
        gdk_window_raise(hosttable->win->window);
#endif
    }
}


void
init_hostlist_notebook_cb(GtkWidget *w _U_, gpointer d _U_)
{
    hostlist_table *hosttable;
    char title[256];
    GtkWidget *vbox;
    GtkWidget *hbox;
    GtkWidget *bbox;
    GtkWidget *close_bt, *help_bt;
    GtkWidget *win;
    GtkWidget *resolv_cb;
    GtkWidget *filter_cb;
    int page;
    void ** pages;
    GtkWidget *nb;
    GtkWidget *page_lb;
    GSList  *current_table;
    register_hostlist_t *registered;
    GtkWidget *copy_bt;
#ifdef HAVE_GEOIP
    GtkWidget *map_bt;
#endif


    pages = g_malloc(sizeof(void *) * (g_slist_length(registered_hostlist_tables) + 1));

    win = dlg_window_new("hostlist");  /* transient_for top_level */
    gtk_window_set_destroy_with_parent (GTK_WINDOW(win), TRUE);

    g_snprintf(title, sizeof(title), "Endpoints: %s", cf_get_display_name(&cfile));
    gtk_window_set_title(GTK_WINDOW(win), title);
    gtk_window_set_default_size(GTK_WINDOW(win), 750, 400);

    vbox=gtk_vbox_new(FALSE, 6);
    gtk_container_add(GTK_CONTAINER(win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    nb = gtk_notebook_new();
    gtk_container_add(GTK_CONTAINER(vbox), nb);
    g_object_set_data(G_OBJECT(nb), NB_PAGES_KEY, pages);

    page = 0;

    current_table = registered_hostlist_tables;
    while(current_table) {
        registered = current_table->data;
        page_lb = gtk_label_new("");
        hosttable = init_hostlist_notebook_page_cb(registered->hide_ports, registered->table_name, registered->tap_name,
            registered->filter, registered->packet_func);
        g_object_set_data(G_OBJECT(hosttable->win), HOST_PTR_KEY, hosttable);
        gtk_notebook_append_page(GTK_NOTEBOOK(nb), hosttable->win, page_lb);
        hosttable->win = win;
        hosttable->page_lb = page_lb;
        pages[++page] = hosttable;

        current_table = g_slist_next(current_table);
    }

    pages[0] = GINT_TO_POINTER(page);

    hbox = gtk_hbox_new(FALSE, 3);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    resolv_cb = gtk_check_button_new_with_mnemonic("Name resolution");
    gtk_container_add(GTK_CONTAINER(hbox), resolv_cb);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(resolv_cb), TRUE);
	gtk_widget_set_tooltip_text(resolv_cb, 
		"Show results of name resolutions rather than the \"raw\" values. Please note: The corresponding name resolution must be enabled.");

    g_signal_connect(resolv_cb, "toggled", G_CALLBACK(hostlist_resolve_toggle_dest), pages);

    filter_cb = gtk_check_button_new_with_mnemonic("Limit to display filter");
    gtk_container_add(GTK_CONTAINER(hbox), filter_cb);
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

    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(win, close_bt, window_cancel_button_cb);

    copy_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
    gtk_widget_set_tooltip_text(copy_bt, "Copy all statistical values of this page to the clipboard in CSV (Comma Separated Values) format.");
    g_signal_connect(copy_bt, "clicked", G_CALLBACK(copy_as_csv_cb), NULL);
    g_object_set_data(G_OBJECT(copy_bt), HOST_PTR_KEY, pages[page]);

#ifdef HAVE_GEOIP
    map_bt = g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_MAP);
    gtk_widget_set_tooltip_text(map_bt, "Show a map of the IP addresses (internet connection required).");
    g_object_set_data(G_OBJECT(map_bt), HOST_PTR_KEY, pages[page]);
    g_signal_connect(map_bt, "clicked", G_CALLBACK(open_as_map_cb), NULL);
    g_signal_connect(nb, "switch-page", G_CALLBACK(ct_nb_map_switch_page_cb), map_bt);
    gtk_widget_set_sensitive(map_bt, FALSE);
#endif /* HAVE_GEOIP */

    g_signal_connect(nb, "switch-page", G_CALLBACK(ct_nb_switch_page_cb), copy_bt);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_ENDPOINTS_DIALOG);

    g_signal_connect(win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(win, "destroy", G_CALLBACK(hostlist_win_destroy_notebook_cb), pages);

    gtk_widget_show_all(win);
    window_present(win);

    cf_retap_packets(&cfile);
#if GTK_CHECK_VERSION(2,14,0)
    gdk_window_raise(gtk_widget_get_window(win));
#else
    gdk_window_raise(win->window);
#endif
}

/*
 * Compute the hash value for a given address/port pairs if the match
 * is to be exact.
 */
typedef struct {
    address  address;
    guint32  port;
} host_key_t;

static guint
host_hash(gconstpointer v)
{
    const host_key_t *key = (const host_key_t *)v;
    guint hash_val;

    hash_val = 0;
    ADD_ADDRESS_TO_HASH(hash_val, &key->address);
    hash_val += key->port;
    return hash_val;
}

/*
 * Compare two host keys for an exact match.
 */
static gint
host_match(gconstpointer v, gconstpointer w)
{
    const host_key_t *v1 = (const host_key_t *)v;
    const host_key_t *v2 = (const host_key_t *)w;

    if (v1->port == v2->port &&
        ADDRESSES_EQUAL(&v1->address, &v2->address)) {
        return 1;
    }
    /*
     * The addresses or the ports don't match.
     */
    return 0;
}

void
add_hostlist_table_data(hostlist_table *hl, const address *addr, guint32 port, gboolean sender, int num_frames, int num_bytes, SAT_E sat, int port_type_val)
{
    hostlist_talker_t *talker=NULL;
    int talker_idx=0;

    /* XXX should be optimized to allocate n extra entries at a time
       instead of just one */
    /* if we dont have any entries at all yet */
    if(hl->hosts==NULL){
        hl->hosts=g_array_sized_new(FALSE, FALSE, sizeof(hostlist_talker_t), 10000);
        hl->hashtable = g_hash_table_new_full(host_hash,
                                              host_match, /* key_equal_func */
                                              g_free,     /* key_destroy_func */
                                              NULL);      /* value_destroy_func */
    }
    else {
        /* try to find it among the existing known conversations */
        host_key_t existing_key;

        existing_key.address = *addr;
        existing_key.port = port;
        talker_idx = GPOINTER_TO_UINT(g_hash_table_lookup(hl->hashtable, &existing_key));
        if (talker_idx) {
            talker_idx--;
            talker=&g_array_index(hl->hosts, hostlist_talker_t, talker_idx);
        }
    }

    /* if we still dont know what talker this is it has to be a new one
       and we have to allocate it and append it to the end of the list */
    if(talker==NULL){
        host_key_t *new_key;
        hostlist_talker_t host;

        COPY_ADDRESS(&host.address, addr);
        host.sat=sat;
        host.port_type=port_type_val;
        host.port=port;
        host.rx_frames=0;
        host.tx_frames=0;
        host.rx_bytes=0;
        host.tx_bytes=0;
        host.iter_valid = FALSE;
        host.modified = TRUE;

        g_array_append_val(hl->hosts, host);
        talker_idx= hl->num_hosts;
        talker=&g_array_index(hl->hosts, hostlist_talker_t, talker_idx);

        /* hl->hosts address is not a constant but address.data is */
        new_key = g_malloc(sizeof (host_key_t));
        SET_ADDRESS(&new_key->address, talker->address.type, talker->address.len, talker->address.data);
        new_key->port = port;
        g_hash_table_insert(hl->hashtable, new_key, GUINT_TO_POINTER(talker_idx +1));
        hl->num_hosts++;
    }

    /* if this is a new talker we need to initialize the struct */
    talker->modified = TRUE;

    /* update the talker struct */
    if( sender ){
        talker->tx_frames+=num_frames;
        talker->tx_bytes+=num_bytes;
    } else {
        talker->rx_frames+=num_frames;
        talker->rx_bytes+=num_bytes;
    }
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
 * ex: set shiftwidth=4 tabstop=8 expandtab
 * :indentSize=4:tabSize=8:noTabs=true:
 */
