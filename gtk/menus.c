/* menus.c
 * Menu routines
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

#include <gtk/gtk.h>

#include <stdio.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/tap.h>
#include <epan/timestamp.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/dissector_filters.h>
#include <epan/strutil.h>
#include <epan/plugins.h>
#include <epan/epan_dissect.h>
#include <epan/column.h>

#include "../print.h"
#include "../ui_util.h"
#include "../simple_dialog.h"
#include "../main_statusbar.h"
#include "../color_filters.h"
#include "../stat_menu.h"
#include "../u3.h"

#include "gtk/about_dlg.h"
#include "gtk/capture_dlg.h"
#include "gtk/capture_if_dlg.h"
#include "gtk/color_dlg.h"
#include "gtk/filter_dlg.h"
#include "gtk/profile_dlg.h"
#include "gtk/dlg_utils.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/fileset_dlg.h"
#include "gtk/file_import_dlg.h"
#include "gtk/find_dlg.h"
#include "gtk/goto_dlg.h"
#include "gtk/summary_dlg.h"
#include "gtk/prefs_dlg.h"
#include "gtk/packet_win.h"
#include "gtk/follow_tcp.h"
#include "gtk/follow_udp.h"
#include "gtk/follow_ssl.h"
#include "gtk/decode_as_dlg.h"
#include "gtk/help_dlg.h"
#include "gtk/supported_protos_dlg.h"
#include "gtk/proto_dlg.h"
#include "gtk/proto_hier_stats_dlg.h"
#include "gtk/keys.h"
#include "gtk/stock_icons.h"
#include "gtk/gtkglobals.h"
#include "gtk/recent.h"
#include "gtk/main_proto_draw.h"
#include "gtk/conversations_table.h"
#include "gtk/hostlist_table.h"
#include "gtk/packet_history.h"
#include "gtk/sctp_stat.h"
#include "gtk/firewall_dlg.h"
#include "gtk/macros_dlg.h"
#include "gtk/export_object.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/main.h"
#include "gtk/menus.h"
#include "gtk/main_toolbar.h"
#include "gtk/main_welcome.h"
#include "gtk/uat_gui.h"
#include "gtk/gui_utils.h"
#include "gtk/manual_addr_resolv.h"
#include "gtk/proto_help.h"
#include "gtk/dissector_tables_dlg.h"
#include "gtk/utf8_entities.h"
#include "gtk/expert_comp_dlg.h"

#include "gtk/new_packet_list.h"

#ifdef HAVE_IGE_MAC_INTEGRATION
#include <ige-mac-menu.h>
#endif

#ifdef HAVE_GTKOSXAPPLICATION
#include <igemacintegration/gtkosxapplication.h>
#endif

static int initialize = TRUE;
#ifdef MAIN_MENU_USE_UIMANAGER
    GtkActionGroup    *main_menu_bar_action_group;
#else
static GtkItemFactory *main_menu_factory = NULL;
#endif /* MAIN_MENU_USE_UIMANAGER */
static GtkUIManager *ui_manager_main_menubar = NULL;
static GtkUIManager *ui_manager_packet_list_heading = NULL;
static GtkUIManager *ui_manager_packet_list_menu = NULL;
static GtkUIManager *ui_manager_tree_view_menu = NULL;
static GtkUIManager *ui_manager_bytes_menu = NULL;
static GtkUIManager *ui_manager_statusbar_profiles_menu = NULL;
static GSList *popup_menu_list = NULL;

static GtkAccelGroup *grp;

typedef struct _menu_item {
    gint          group;
    const char   *gui_path;
    const char   *name;
    const char   *stock_id;
    const char   *label;
    const char   *accelerator;
    const gchar  *tooltip;
#ifdef MAIN_MENU_USE_UIMANAGER
    GCallback    callback;
#else
    GtkItemFactoryCallback callback;
#endif
    gboolean enabled;
    gpointer callback_data;
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *, gpointer callback_data);
    gboolean (*selected_tree_row_enabled)(field_info *, gpointer callback_data);
    GList *children;
} menu_item_t;

static GList *tap_menu_tree_root = NULL;

GtkWidget *popup_menu_object;


#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

static void merge_all_tap_menus(GList *node);
#ifdef MAIN_MENU_USE_UIMANAGER
static void menu_open_recent_file_cmd_cb(GtkAction *action, gpointer data _U_ );
static void add_recent_items (guint merge_id, GtkUIManager *ui_manager);
#endif /* MAIN_MENU_USE_UIMANAGER */

static void menus_init(void);
static void set_menu_sensitivity (GtkUIManager *ui_manager, const gchar *, gint);
#ifndef MAIN_MENU_USE_UIMANAGER
static void clear_menu_recent_capture_file_cmd_cb(GtkWidget *w, gpointer unused _U_);
static void set_menu_sensitivity_old (const gchar *, gint);
#endif /* MAIN_MENU_USE_UIMANAGER */
static void show_hide_cb(GtkWidget *w, gpointer data, gint action);
#ifndef MAIN_MENU_USE_UIMANAGER
static void timestamp_format_cb(GtkWidget *w, gpointer d, gint action);
static void timestamp_precision_cb(GtkWidget *w, gpointer d, gint action);
#endif
static void timestamp_seconds_time_cb(GtkWidget *w, gpointer d, gint action);
static void name_resolution_cb(GtkWidget *w, gpointer d, gint action);
#ifdef HAVE_LIBPCAP
#ifndef MAIN_MENU_USE_UIMANAGER
static void auto_scroll_live_cb(GtkWidget *w, gpointer d);
#endif
#endif
static void colorize_cb(GtkWidget *w, gpointer d);


/*  As a general GUI guideline, we try to follow the Gnome Human Interface Guidelines, which can be found at:
    http://developer.gnome.org/projects/gup/hig/1.0/index.html

Please note: there are some differences between the Gnome HIG menu suggestions and our implementation:

File/Open Recent:   the Gnome HIG suggests putting the list of recently used files as elements into the File menuitem.
                    As this is ok for only a few items, this will become unhandy for 10 or even more list entries.
                    For this reason, we use a submenu for this.

File/Close:         the Gnome HIG suggests putting this item just above the Quit item.
                    This results in unintuitive behaviour as both Close and Quit items are very near together.
                    By putting the Close item near the open item(s), it better suggests that it will close the
                    currently opened/captured file only.
*/

typedef enum {
    SHOW_HIDE_MAIN_TOOLBAR = 1,
    SHOW_HIDE_FILTER_TOOLBAR,
    SHOW_HIDE_AIRPCAP_TOOLBAR,
    SHOW_HIDE_STATUSBAR,
    SHOW_HIDE_PACKET_LIST,
    SHOW_HIDE_TREE_VIEW,
    SHOW_HIDE_BYTE_VIEW
} show_hide_values_e;

typedef enum {
    CONV_ETHER = 1,
    CONV_IP,
    CONV_TCP,
    CONV_UDP,
    CONV_CBA
} conv_values_e;

static char *
build_conversation_filter(int action, gboolean show_dialog)
{
    packet_info *pi = &cfile.edt->pi;
    char        *buf;


    switch(action) {
    case(CONV_CBA):
        if (pi->profinet_type == 0) {
            if (show_dialog) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Error filtering conversation.  Please make\n"
                    "sure you have a PROFINET CBA packet selected.");
            }
            return NULL;
        }

        if( pi->net_src.type == AT_IPv4 && pi->net_dst.type == AT_IPv4
        && pi->ipproto == IP_PROTO_TCP ) {
            /* IPv4 */
            switch(pi->profinet_type) {
            case(1):
                buf = g_strdup_printf("(ip.src eq %s and ip.dst eq %s and cba.acco.dcom == 1) || (ip.src eq %s and ip.dst eq %s and cba.acco.dcom == 0)",
                    ip_to_str( pi->net_dst.data),
                    ip_to_str( pi->net_src.data),
                    ip_to_str( pi->net_src.data),
                    ip_to_str( pi->net_dst.data));
                break;
            case(2):
                buf = g_strdup_printf("(ip.src eq %s and ip.dst eq %s and cba.acco.dcom == 1) || (ip.src eq %s and ip.dst eq %s and cba.acco.dcom == 0)",
                    ip_to_str( pi->net_src.data),
                    ip_to_str( pi->net_dst.data),
                    ip_to_str( pi->net_dst.data),
                    ip_to_str( pi->net_src.data));
                break;
            case(3):
                buf = g_strdup_printf("(ip.src eq %s and ip.dst eq %s and cba.acco.srt == 1) || (ip.src eq %s and ip.dst eq %s and cba.acco.srt == 0)",
                    ip_to_str( pi->net_dst.data),
                    ip_to_str( pi->net_src.data),
                    ip_to_str( pi->net_src.data),
                    ip_to_str( pi->net_dst.data));
                break;
            case(4):
                buf = g_strdup_printf("(ip.src eq %s and ip.dst eq %s and cba.acco.srt == 1) || (ip.src eq %s and ip.dst eq %s and cba.acco.srt == 0)",
                    ip_to_str( pi->net_src.data),
                    ip_to_str( pi->net_dst.data),
                    ip_to_str( pi->net_dst.data),
                    ip_to_str( pi->net_src.data));
                break;
            default:
                return NULL;
            }
        } else {
            return NULL;
        }
        break;
    case(CONV_TCP):
        if (pi->ipproto != IP_PROTO_TCP) {
            if (show_dialog) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Error filtering conversation.  Please make\n"
                    "sure you have a TCP packet selected.");
            }
            return NULL;
        }

        if( pi->net_src.type == AT_IPv4 && pi->net_dst.type == AT_IPv4 ) {
            /* TCP over IPv4 */
            buf = g_strdup_printf("(ip.addr eq %s and ip.addr eq %s) and (tcp.port eq %d and tcp.port eq %d)",
                ip_to_str( pi->net_src.data),
                ip_to_str( pi->net_dst.data),
                pi->srcport, pi->destport );
        } else if( pi->net_src.type == AT_IPv6 && pi->net_dst.type == AT_IPv6 ) {
            /* TCP over IPv6 */
            buf = g_strdup_printf("(ipv6.addr eq %s and ipv6.addr eq %s) and (tcp.port eq %d and tcp.port eq %d)",
                ip6_to_str((const struct e_in6_addr *)pi->net_src.data),
                ip6_to_str((const struct e_in6_addr *)pi->net_dst.data),
                pi->srcport, pi->destport );
        } else {
            return NULL;
        }
        break;
    case(CONV_UDP):
        if (pi->ipproto != IP_PROTO_UDP) {
            if (show_dialog) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Error filtering conversation.  Please make\n"
                    "sure you have a UDP packet selected.");
            }
            return NULL;
        }

        if( pi->net_src.type == AT_IPv4 && pi->net_dst.type == AT_IPv4 ) {
            /* UDP over IPv4 */
            buf = g_strdup_printf("(ip.addr eq %s and ip.addr eq %s) and (udp.port eq %d and udp.port eq %d)",
                ip_to_str( pi->net_src.data),
                ip_to_str( pi->net_dst.data),
                pi->srcport, pi->destport );
        } else if( pi->net_src.type == AT_IPv6 && pi->net_dst.type == AT_IPv6 ) {
            /* UDP over IPv6 */
            buf = g_strdup_printf("(ipv6.addr eq %s and ipv6.addr eq %s) and (udp.port eq %d and udp.port eq %d)",
                ip6_to_str((const struct e_in6_addr *)pi->net_src.data),
                ip6_to_str((const struct e_in6_addr *)pi->net_dst.data),
                pi->srcport, pi->destport );
        } else {
            return NULL;
        }
        break;
    case(CONV_IP):
        if ((pi->ethertype != ETHERTYPE_IP) && (pi->ethertype != ETHERTYPE_IPv6)) {
            if (show_dialog) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Error filtering conversation.  Please make\n"
                    "sure you have a IP packet selected.");
            }
            return NULL;
        }

        if( pi->net_src.type == AT_IPv4 && pi->net_dst.type == AT_IPv4 ) {
            /* IPv4 */
            buf = g_strdup_printf("ip.addr eq %s and ip.addr eq %s",
                ip_to_str( pi->net_src.data),
                ip_to_str( pi->net_dst.data));
        } else if( pi->net_src.type == AT_IPv6 && pi->net_dst.type == AT_IPv6 ) {
            /* IPv6 */
            buf = g_strdup_printf("ipv6.addr eq %s and ipv6.addr eq %s",
                ip6_to_str((const struct e_in6_addr *)pi->net_src.data),
                ip6_to_str((const struct e_in6_addr *)pi->net_dst.data));
        } else {
            return NULL;
        }
        break;
    case(CONV_ETHER):
        /* XXX - is this the right way to check for Ethernet? */
        /* check for the data link address type */
        /* (ethertype will be 0 when used as length field) */
        if (pi->dl_src.type != AT_ETHER) {
            if (show_dialog) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Error filtering conversation.  Please make\n"
                    "sure you have a Ethernet packet selected.");
            }
            return NULL;
        }

        if( pi->dl_src.type == AT_ETHER && pi->dl_dst.type == AT_ETHER ) {
            /* Ethernet */
            buf = g_strdup_printf("eth.addr eq %s and eth.addr eq %s",
                ether_to_str( pi->dl_src.data),
                ether_to_str( pi->dl_dst.data));
        } else {
            return NULL;
        }
        break;
    default:
        return NULL;
    }

    return buf;
}

static void 
new_window_cb(GtkWidget *widget)
{
	new_packet_window(widget, FALSE);
}

static void 
edit_window_cb(GtkWidget *widget)
{
	new_packet_window(widget, TRUE);
}

static void
conversation_cb(GtkAction *a _U_, gpointer data _U_, int action)
{
    gchar       *filter;
    GtkWidget   *filter_te;

    if (cfile.current_frame) {
        /* create a filter-string based on the selected packet and action */
        filter = build_conversation_filter(action, TRUE);

        /* Run the display filter so it goes in effect - even if it's the
        same as the previous display filter. */
        filter_te = gtk_bin_get_child(GTK_BIN(g_object_get_data(G_OBJECT(top_level), E_DFILTER_CM_KEY)));

        gtk_entry_set_text(GTK_ENTRY(filter_te), filter);
        main_filter_packets(&cfile, filter, TRUE);

        g_free(filter);
    }
}

static void
colorize_conversation_cb(GtkWidget * w _U_, gpointer data _U_, int action)
{
    gchar        *filter = NULL;

    if( (action>>8) == 255 ) {
        color_filters_reset_tmp();
        new_packet_list_colorize_packets();
    } else if (cfile.current_frame) {
        if( (action&0xff) == 0 ) {
            /* colorize_conversation_cb was called from the window-menu
             * or through an accelerator key. Try to build a conversation
             * filter in the order TCP, UDP, IP, Ethernet and apply the
             * coloring */
            filter = build_conversation_filter(CONV_TCP,FALSE);
            if( filter == NULL )
                filter = build_conversation_filter(CONV_UDP,FALSE);
            if( filter == NULL )
                filter = build_conversation_filter(CONV_IP,FALSE);
            if( filter == NULL )
                filter = build_conversation_filter(CONV_ETHER,FALSE);
            if( filter == NULL ) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Unable to build conversation filter.");
                return;
            }
        } else {
            /* create a filter-string based on the selected packet and action */
            filter = build_conversation_filter(action&0xff, TRUE);
        }

        if( (action>>8) == 0) {
            /* Open the "new coloring filter" dialog with the filter */
            color_display_with_filter(filter);
        } else {
            /* Set one of the temporary coloring filters */
            color_filters_set_tmp((guint8)(action>>8),filter,FALSE);
            new_packet_list_colorize_packets();
        }

        g_free(filter);
    }
}

static void
goto_conversation_frame(gboolean dir)
{
        gchar *filter;
        dfilter_t *dfcode = NULL;
        gboolean found_packet=FALSE;

        filter = build_conversation_filter(CONV_TCP,FALSE);
        if( filter == NULL )
            filter = build_conversation_filter(CONV_UDP,FALSE);
        if( filter == NULL )
            filter = build_conversation_filter(CONV_IP,FALSE);
        if( filter == NULL ) {
            statusbar_push_temporary_msg("Unable to build conversation filter.");
            g_free(filter);
            return;
        }

        if (!dfilter_compile(filter, &dfcode)) {
            /* The attempt failed; report an error. */
            statusbar_push_temporary_msg("Error compiling filter for this conversation.");
            g_free(filter);
            return;
        }

        found_packet = cf_find_packet_dfilter(&cfile, dfcode, dir);

        if (!found_packet) {
            /* We didn't find a packet */
            statusbar_push_temporary_msg("No previous/next packet in conversation.");
        }

        dfilter_free(dfcode);
        g_free(filter);
}

#ifdef MAIN_MENU_USE_UIMANAGER
static void
goto_next_frame_conversation_cb(GtkAction *action _U_, gpointer user_data _U_)
{
    goto_conversation_frame(FALSE);
}

static void
goto_previous_frame_conversation_cb(GtkAction *action _U_, gpointer user_data _U_)
{
    goto_conversation_frame(TRUE);
}
#else
static void
goto_next_frame_conversation_cb(GtkWidget *w _U_, gpointer d _U_)
{
    goto_conversation_frame(FALSE);
}

static void
goto_previous_frame_conversation_cb(GtkWidget *w _U_, gpointer d _U_)
{
    goto_conversation_frame(TRUE);
}
#endif /* MAIN_MENU_USE_UIMANAGER */



/*Apply a filter */

static void
tree_view_menu_apply_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyAsFilter/Selected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW);
}

static void
tree_view_menu_apply_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyAsFilter/NotSelected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW);
}

static void
tree_view_menu_apply_and_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyAsFilter/AndSelected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW);
}

static void
tree_view_menu_apply_or_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyAsFilter/OrSelected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW);
}

static void
tree_view_menu_apply_and_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyAsFilter/AndNotSelected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW);
}

static void
tree_view_menu_apply_or_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyAsFilter/OrNotSelected");
	match_selected_ptree_cb( widget , user_data,MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW);
}
/* Prepare a filter */
static void
tree_view_menu_prepare_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/PrepareaFilter/Selected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_REPLACE);
}

static void
tree_view_menu_prepare_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/PrepareaFilter/NotSelected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_NOT);
}

static void
tree_view_menu_prepare_and_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/PrepareaFilter/AndSelected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_AND);
}

static void
tree_view_menu_prepare_or_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/PrepareaFilter/OrSelected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_OR);
}

static void
tree_view_menu_prepare_and_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/PrepareaFilter/AndNotSelected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_AND_NOT);
}

static void
tree_view_menu_prepare_or_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/PrepareaFilter/OrNotSelected");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_OR_NOT);
}

/* Prepare for use of GTKUImanager */
#ifdef MAIN_MENU_USE_UIMANAGER 

static void
copy_description_cb(GtkAction *action _U_, gpointer user_data)
{
	copy_selected_plist_cb( NULL /* widget _U_ */ , user_data, COPY_SELECTED_DESCRIPTION);
}

static void
copy_fieldname_cb(GtkAction *action _U_, gpointer user_data)
{
	copy_selected_plist_cb( NULL /* widget _U_ */ , user_data, COPY_SELECTED_FIELDNAME);
}

static void
copy_value_cb(GtkAction *action _U_, gpointer user_data)
{
	copy_selected_plist_cb( NULL /* widget _U_ */ , user_data, COPY_SELECTED_VALUE);
}

static void
copy_as_filter_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_ptree_cb( NULL /* widget _U_ */ , user_data, MATCH_SELECTED_REPLACE|MATCH_SELECTED_COPY_ONLY);
}

static void
set_reftime_cb(GtkAction *action _U_, gpointer user_data)
{
	reftime_frame_cb( NULL /* widget _U_ */ , user_data, REFTIME_TOGGLE);
}

static void
find_next_ref_time_cb(GtkAction *action _U_, gpointer user_data)
{
	reftime_frame_cb( NULL /* widget _U_ */ , user_data, REFTIME_FIND_NEXT);
}

static void
find_previous_ref_time_cb(GtkAction *action _U_, gpointer user_data)
{
	reftime_frame_cb( NULL /* widget _U_ */ , user_data, REFTIME_FIND_PREV);
}

static void
menus_prefs_cb(GtkAction *action _U_, gpointer user_data)
{
	prefs_page_cb( NULL /* widget _U_ */ , user_data, PREFS_PAGE_USER_INTERFACE);
}

static void
main_toolbar_show_hide_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/MainToolbar");

	if (!widget){
		g_warning("main_toolbar_show_hide_cb: No widget found");
	}else{
		show_hide_cb( widget, user_data, SHOW_HIDE_MAIN_TOOLBAR);
	}
}

static void
filter_toolbar_show_hide_cb(GtkAction * action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/FilterToolbar");
	if (!widget){
		g_warning("filter_toolbar_show_hide_cb: No widget found");
	}else{
		show_hide_cb( widget, user_data, SHOW_HIDE_FILTER_TOOLBAR);
	}
}

#ifdef HAVE_AIRPCAP
static void
wireless_toolbar_show_hide_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/WirelessToolbar");
	if (!widget){
		g_warning("wireless_toolbar_show_hide_cb: No widget found");
	}else{
		show_hide_cb( widget, user_data, SHOW_HIDE_AIRPCAP_TOOLBAR);
	}
}
#endif /* HAVE_AIRPCAP */

static void
status_bar_show_hide_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/Statusbar");
	if (!widget){
		g_warning("status_bar_show_hide_cb: No widget found");
	}else{
		show_hide_cb( widget, user_data, SHOW_HIDE_STATUSBAR);
	}
}
static void
packet_list_show_hide_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/PacketList");
	if (!widget){
		g_warning("packet_list_show_hide_cb: No widget found");
	}else{
		show_hide_cb( widget, user_data, SHOW_HIDE_PACKET_LIST);
	}
}
static void
packet_details_show_hide_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/PacketDetails");
	if (!widget){
		g_warning("packet_details_show_hide_cb: No widget found");
	}else{
		show_hide_cb( widget, user_data, SHOW_HIDE_TREE_VIEW);
	}
}
static void
packet_bytes_show_hide_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/PacketBytes");
	if (!widget){
		g_warning("packet_bytes_show_hide_cb: No widget found");
	}else{
		show_hide_cb( widget, user_data, SHOW_HIDE_BYTE_VIEW);
	}
}

static void
timestamp_format_new_cb (GtkRadioAction *action, GtkRadioAction *current _U_, gpointer user_data  _U_)
{
    gint value;

    value = gtk_radio_action_get_current_value (action);
    g_warning("timestamp_format_new_cb, value %u, recent.gui_time_format %u",value, recent.gui_time_format);
    if (recent.gui_time_format != value) {
        timestamp_set_type(value);
        recent.gui_time_format = value;
        /* This call adjusts column width */
        cf_timestamp_auto_precision(&cfile);
        new_packet_list_queue_draw();
    }

}

static void
timestamp_precision_new_cb (GtkRadioAction *action, GtkRadioAction *current _U_, gpointer user_data _U_)
{
    gint value;

    value = gtk_radio_action_get_current_value (action);
    g_warning("timestamp_precision_new_cb, value %u, recent.gui_time_precision %u",value, recent.gui_time_precision);
    if (recent.gui_time_precision != value) {
        /* the actual precision will be set in new_packet_list_queue_draw() below */
        if (value == TS_PREC_AUTO) {
            timestamp_set_precision(TS_PREC_AUTO_SEC);
        } else {
            timestamp_set_precision(value);
        }
        recent.gui_time_precision  = value;
        /* This call adjusts column width */
        cf_timestamp_auto_precision(&cfile);
        new_packet_list_queue_draw();
    }
}


static void
view_menu_seconds_time_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/TimeDisplayFormat/DisplaySecondsWithHoursAndMinutes");
	if (!widget){
		g_warning("view_menu_seconds_time_cb: No widget found");
	}else{
		timestamp_seconds_time_cb(widget, user_data, 0);
	}
}

static void
view_menu_en_for_MAC_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/NameResolution/EnableforMACLayer");
	if (!widget){
		g_warning("view_menu_en_for_MAC_cb: No widget found");
	}else{
		name_resolution_cb( widget , user_data, RESOLV_MAC);
	}
}

static void
view_menu_en_for_network_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/NameResolution/EnableforNetworkLayer");
	if (!widget){
		g_warning("view_menu_en_for_network_cb: No widget found");
	}else{
		name_resolution_cb( widget , user_data, RESOLV_NETWORK);
	}
}

static void
view_menu_en_for_transport_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/NameResolution/EnableforTransportLayer");
	if (!widget){
		g_warning("view_menu_en_for_transport_cb: No widget found");
	}else{
		name_resolution_cb( widget , user_data, RESOLV_TRANSPORT);
	}
}

static void
view_menu_colorize_pkt_lst_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/ColorizePacketList");
	if (!widget){
		g_warning("view_menu_colorize_pkt_lst_cb: No widget found");
	}else{
		colorize_cb( widget , user_data);
	}

}

#ifdef HAVE_LIBPCAP
static void
view_menu_auto_scroll_live_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/AutoScrollinLiveCapture");

	if (!widget){
		g_warning("view_menu_auto_scroll_live_cb: No widget found");
	}else{
		menu_auto_scroll_live_changed(GTK_CHECK_MENU_ITEM(widget)->active);
	}
}
#endif

static void
view_menu_color_conv_color1_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_*/ , user_data, 1*256);
}

static void
view_menu_color_conv_color2_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 2*256);
}

static void
view_menu_color_conv_color3_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 3*256);
}

static void
view_menu_color_conv_color4_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 4*256);
}

static void
view_menu_color_conv_color5_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 5*256);
}

static void
view_menu_color_conv_color6_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 6*256);
}

static void
view_menu_color_conv_color7_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 7*256);
}

static void
view_menu_color_conv_color8_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 8*256);
}

static void
view_menu_color_conv_color9_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 9*256);
}

static void
view_menu_color_conv_color10_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 10*256);
}

static void
view_menu_color_conv_new_rule_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 0);
}

static void
view_menu_reset_coloring_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb(  NULL /* widget _U_*/ , user_data, 255*256);
}

static void
help_menu_cont_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	topic_menu_cb(NULL/*widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(HELP_CONTENT));
}

static void
help_menu_faq_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	topic_menu_cb(NULL/*widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(ONLINEPAGE_FAQ));
}

static void
help_menu_wireshark_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/*widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(LOCALPAGE_MAN_WIRESHARK));
}

static void
help_menu_wireshark_flt_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/*widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(LOCALPAGE_MAN_WIRESHARK_FILTER)); 
}

static void
help_menu_Tshark_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/*widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(LOCALPAGE_MAN_TSHARK)); 
}

static void
help_menu_RawShark_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/*widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(LOCALPAGE_MAN_RAWSHARK));  
}

static void
help_menu_Dumpcap_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/*widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(LOCALPAGE_MAN_DUMPCAP));   
}

static void
help_menu_Mergecap_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/*widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(LOCALPAGE_MAN_MERGECAP));   
}

static void
help_menu_Editcap_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/* widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(LOCALPAGE_MAN_EDITCAP));   
}

static void
help_menu_Text2pcap_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/* widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(LOCALPAGE_MAN_TEXT2PCAP));   
}

static void
help_menu_Website_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/* widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(ONLINEPAGE_HOME));   
}

static void
help_menu_Wiki_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/* widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(ONLINEPAGE_WIKI));   
}

static void
help_menu_Downloads_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb(NULL/* widget _U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(ONLINEPAGE_DOWNLOAD)); 
}

static void
help_menu_SampleCaptures_cb(GtkAction *action _U_, gpointer user_data _U_)
{
 	topic_menu_cb( NULL/* widget_U_ */, NULL /*GdkEventButton *event _U_*/, GINT_TO_POINTER(ONLINEPAGE_SAMPLE_FILES));   
}

static const char *ui_desc_menubar =
"<ui>\n"
"  <menubar name ='Menubar'>\n"
"    <menu name= 'FileMenu' action='/File'>\n"
"      <menuitem name='Open' action='/File/Open'/>\n"
"      <menu name='OpenRecent' action='/File/OpenRecent'>\n"
"         <placeholder name='RecentFiles'/>\n"
"      </menu>\n"
"      <menuitem name='Merge' action='/File/Merge'/>\n"
"      <menuitem name='Import' action='/File/Import'/>\n"
"      <menuitem name='Close' action='/File/Close'/>\n"
"      <separator/>\n"
"      <menuitem name='Save' action='/File/Save'/>\n"
"      <menuitem name='SaveAs' action='/File/SaveAs'/>\n"
"      <separator/>\n"
"      <menu name= 'Set' action='/File/Set'>\n"
"        <menuitem name='ListFiles' action='/File/Set/ListFiles'/>\n"
"        <menuitem name='NextFile' action='/File/Set/NextFile'/>\n"
"        <menuitem name='PreviousFile' action='/File/Set/PreviousFile'/>\n"
"      </menu>\n"
"      <separator/>\n"
"      <menu name= 'Export' action='/File/Export'>\n"
#if _WIN32
"        <menuitem name='File' action='/File/Export/File'/>\n"
#else
"        <menu name= 'File' action='/File/Export/File'>\n"
"          <menuitem name='AsTxt' action='/File/Export/File/Text'/>\n"
"          <menuitem name='AsPostScript' action='/File/Export/File/PostScript'/>\n"
"          <menuitem name='AsCSV' action='/File/Export/File/CSV'/>\n"
"          <menuitem name='AsCArrays' action='/File/Export/File/CArrays'/>\n"
"          <separator/>\n"
"          <menuitem name='AsPSML' action='/File/Export/File/PSML'/>\n"
"          <menuitem name='AsPDML' action='/File/Export/File/PDML'/>\n"
"          <separator/>\n"
"        </menu>\n"
#endif /* _WIN32 */
"      <menuitem name='SelectedPacketBytes' action='/File/Export/SelectedPacketBytes'/>\n"
"        <menu name= 'Objects' action='/File/Export/Objects'>\n"
"          <menuitem name='HTTP' action='/File/Export/Objects/HTTP'/>\n"
"          <menuitem name='DICOM' action='/File/Export/Objects/DICOM'/>\n"
"          <menuitem name='SMB' action='/File/Export/Objects/SMB'/>\n"
"        </menu>\n"
"      </menu>\n"
"      <separator/>\n"
"      <menuitem name='Print' action='/File/Print'/>\n"
"      <separator/>\n"
"        <menuitem name='Quit' action='/File/Quit'/>\n"
"    </menu>\n"
"    <menu name= 'EditMenu' action='/Edit'>\n"
"        <menu name= 'Copy' action='/Edit/Copy'>\n"
"          <menuitem name='Description' action='/Edit/Copy/Description'/>\n"
"          <menuitem name='Fieldname' action='/Edit/Copy/Fieldname'/>\n"
"          <menuitem name='Value' action='/Edit/Copy/Value'/>\n"
"          <separator/>\n"
"          <menuitem name='AsFilter' action='/Edit/Copy/AsFilter'/>\n"
"        </menu>\n"
"        <menuitem name='FindPacket' action='/Edit/FindPacket'/>\n"
"        <menuitem name='FindNext' action='/Edit/FindNext'/>\n"
"        <menuitem name='FindPrevious' action='/Edit/FindPrevious'/>\n"
"        <separator/>\n"
"        <menuitem name='MarkPacket' action='/Edit/MarkPacket'/>\n"
"        <menuitem name='MarkAllDisplayedPackets' action='/Edit/MarkAllDisplayedPackets'/>\n"
"        <menuitem name='UnmarkAllDisplayedPackets' action='/Edit/UnmarkAllDisplayedPackets'/>\n"
"        <menuitem name='FindNextMark' action='/Edit/FindNextMark'/>\n"
"        <menuitem name='FindPreviousMark' action='/Edit/FindPreviousMark'/>\n"
"        <separator/>\n"
"        <menuitem name='IgnorePacket' action='/Edit/IgnorePacket'/>\n"
"        <menuitem name='IgnoreAllDisplayedPackets' action='/Edit/IgnoreAllDisplayedPackets'/>\n"
"        <menuitem name='Un-IgnoreAllPackets' action='/Edit/Un-IgnoreAllPackets'/>\n"
"        <separator/>\n"
"        <menuitem name='SetTimeReference' action='/Edit/SetTimeReference'/>\n"
"        <menuitem name='Un-TimeReferenceAllPackets' action='/Edit/Un-TimeReferenceAllPackets'/>\n"
"        <menuitem name='FindNextTimeReference' action='/Edit/FindNextTimeReference'/>\n"
"        <menuitem name='FindPreviousTimeReference' action='/Edit/FindPreviousTimeReference'/>\n"
"        <separator/>\n"
"        <menuitem name='EditPacket' action='/Edit/EditPacket'/>\n"
"        <separator/>\n"
"        <menuitem name='ConfigurationProfiles' action='/Edit/ConfigurationProfiles'/>\n"
"        <menuitem name='Preferences' action='/Edit/Preferences'/>\n"
"    </menu>\n"
"    <menu name= 'ViewMenu' action='/View'>\n"
"      <menuitem name='MainToolbar' action='/View/MainToolbar'/>\n"
"      <menuitem name='FilterToolbar' action='/View/FilterToolbar'/>\n"
#ifdef HAVE_AIRPCAP
"      <menuitem name='WirelessToolbar' action='/View/WirelessToolbar'/>\n"
#endif
"      <menuitem name='Statusbar' action='/View/Statusbar'/>\n"
"      <separator/>\n"
"      <menuitem name='PacketList' action='/View/PacketList'/>\n"
"      <menuitem name='PacketDetails' action='/View/PacketDetails'/>\n"
"      <menuitem name='PacketBytes' action='/View/PacketBytes'/>\n"
"      <separator/>\n"
"      <menu name= 'TimeDisplayFormat' action='/View/TimeDisplayFormat'>\n"
"        <menuitem name='DateandTimeofDay' action='/View/TimeDisplayFormat/DateandTimeofDay'/>\n"
"        <menuitem name='TimeofDay' action='/View/TimeDisplayFormat/TimeofDay'/>\n"
"        <menuitem name='SecondsSinceEpoch' action='/View/TimeDisplayFormat/SecondsSinceEpoch'/>\n"
"        <menuitem name='SecondsSinceBeginningofCapture' action='/View/TimeDisplayFormat/SecondsSinceBeginningofCapture'/>\n"
"        <menuitem name='SecondsSincePreviousCapturedPacket' action='/View/TimeDisplayFormat/SecondsSincePreviousCapturedPacket'/>\n"
"        <menuitem name='SecondsSincePreviousDisplayedPacket' action='/View/TimeDisplayFormat/SecondsSincePreviousDisplayedPacket'/>\n"
"        <separator/>\n"
"        <menuitem name='FileFormatPrecision-Automatic' action='/View/TimeDisplayFormat/FileFormatPrecision-Automatic'/>\n"
"        <menuitem name='FileFormatPrecision-Seconds' action='/View/TimeDisplayFormat/FileFormatPrecision-Seconds'/>\n"
"        <menuitem name='FileFormatPrecision-Deciseconds' action='/View/TimeDisplayFormat/FileFormatPrecision-Deciseconds'/>\n"
"        <menuitem name='FileFormatPrecision-Centiseconds' action='/View/TimeDisplayFormat/FileFormatPrecision-Centiseconds'/>\n"
"        <menuitem name='FileFormatPrecision-Milliseconds' action='/View/TimeDisplayFormat/FileFormatPrecision-Milliseconds'/>\n"
"        <menuitem name='FileFormatPrecision-Microseconds' action='/View/TimeDisplayFormat/FileFormatPrecision-Microseconds'/>\n"
"        <menuitem name='FileFormatPrecision-Nanoseconds' action='/View/TimeDisplayFormat/FileFormatPrecision-Nanoseconds'/>\n"
"        <separator/>\n"
"        <menuitem name='DisplaySecondsWithHoursAndMinutes' action='/View/TimeDisplayFormat/DisplaySecondsWithHoursAndMinutes'/>\n"
"      </menu>\n"
"      <menu name= 'NameResolution' action='/View/NameResolution'>\n"
"         <menuitem name='ResolveName' action='/View/NameResolution/ResolveName'/>\n"
"         <separator/>\n"
"         <menuitem name='EnableforMACLayer' action='/View/NameResolution/EnableforMACLayer'/>\n"
"         <menuitem name='EnableforNetworkLayer' action='/View/NameResolution/EnableforNetworkLayer'/>\n"
"         <menuitem name='EnableforTransportLayer' action='/View/NameResolution/EnableforTransportLayer'/>\n"
"      </menu>\n"
"      <menuitem name='ColorizePacketList' action='/View/ColorizePacketList'/>\n"
"      <menuitem name='AutoScrollinLiveCapture' action='/View/AutoScrollinLiveCapture'/>\n"
"      <separator/>\n"
"      <menuitem name='ZoomIn' action='/View/ZoomIn'/>\n"
"      <menuitem name='ZoomOut' action='/View/ZoomOut'/>\n"
"      <menuitem name='NormalSize' action='/View/NormalSize'/>\n"
"      <separator/>\n"
"      <menuitem name='ResizeAllColumns' action='/View/ResizeAllColumns'/>\n"
"      <menuitem name='DisplayedColumns' action='/View/DisplayedColumns'/>\n"
"      <separator/>\n"
"      <menuitem name='ExpandSubtrees' action='/View/ExpandSubtrees'/>\n"
"      <menuitem name='ExpandAll' action='/View/ExpandAll'/>\n"
"      <menuitem name='CollapseAll' action='/View/CollapseAll'/>\n"
"      <separator/>\n"
"      <menu name= 'ColorizeConversation' action='/View/ColorizeConversation'>\n"
"         <menuitem name='Color1' action='/View/ColorizeConversation/Color 1'/>\n"
"         <menuitem name='Color2' action='/View/ColorizeConversation/Color 2'/>\n"
"         <menuitem name='Color3' action='/View/ColorizeConversation/Color 3'/>\n"
"         <menuitem name='Color4' action='/View/ColorizeConversation/Color 4'/>\n"
"         <menuitem name='Color5' action='/View/ColorizeConversation/Color 5'/>\n"
"         <menuitem name='Color6' action='/View/ColorizeConversation/Color 6'/>\n"
"         <menuitem name='Color7' action='/View/ColorizeConversation/Color 7'/>\n"
"         <menuitem name='Color8' action='/View/ColorizeConversation/Color 8'/>\n"
"         <menuitem name='Color9' action='/View/ColorizeConversation/Color 9'/>\n"
"         <menuitem name='Color10' action='/View/ColorizeConversation/Color 10'/>\n"
"         <menuitem name='NewColoringRule' action='/View/ColorizeConversation/NewColoringRule'/>\n"
"      </menu>\n"
"      <separator/>\n"
"      <menuitem name='ResetColoring1-10' action='/View/ResetColoring1-10'/>\n"
"      <menuitem name='ColoringRules' action='/View/ColoringRules'/>\n"
"      <separator/>\n"
"      <menuitem name='ShowPacketinNewWindow' action='/View/ShowPacketinNewWindow'/>\n"
"      <menuitem name='Reload' action='/View/Reload'/>\n"
"    </menu>\n"
"    <menu name= 'GoMenu' action='/Go'>\n"
"      <menuitem name='Back' action='/Go/Back'/>\n"
"      <menuitem name='Forward' action='/Go/Forward'/>\n"
"      <menuitem name='Goto' action='/Go/Goto'/>\n"
"      <menuitem name='GotoCorrespondingPacket' action='/Go/GotoCorrespondingPacket'/>\n"
"      <separator/>\n"
"      <menuitem name='PreviousPacket' action='/Go/PreviousPacket'/>\n"
"      <menuitem name='NextPacket' action='/Go/NextPacket'/>\n"
"      <menuitem name='FirstPacket' action='/Go/FirstPacket'/>\n"
"      <menuitem name='LastPacket' action='/Go/LastPacket'/>\n"
"      <menuitem name='PreviousPacketInConversation' action='/Go/PreviousPacketInConversation'/>\n"
"      <menuitem name='NextPacketInConversation' action='/Go/NextPacketInConversation'/>\n"
"    </menu>\n"
#ifdef HAVE_LIBPCAP
"    <menu name= 'CaptureMenu' action='/Capture'>\n"
"      <menuitem name='Interfaces' action='/Capture/Interfaces'/>\n"
"      <menuitem name='Options' action='/Capture/Options'/>\n"
"      <menuitem name='Start' action='/Capture/Start'/>\n"
"      <menuitem name='Stop' action='/Capture/Stop'/>\n"
"      <menuitem name='Restart' action='/Capture/Restart'/>\n"
"      <menuitem name='CaptureFilters' action='/Capture/CaptureFilters'/>\n"
"    </menu>\n"
#endif /* HAVE_LIBPCAP */
"    <menu name= 'AnalyzeMenu' action='/Analyze'>\n"
"      <menuitem name='DisplayFilters' action='/Analyze/DisplayFilters'/>\n"
"      <menuitem name='DisplayFilterMacros' action='/Analyze/DisplayFilterMacros'/>\n"
"      <separator/>\n"
"      <menuitem name='ApplyasColumn' action='/Analyze/ApplyasColumn'/>\n"
"      <menu name= 'ApplyAsFilter' action='/Analyze/ApplyasFilter'>\n"
"        <menuitem name='Selected' action='/Analyze/ApplyasFilter/Selected'/>\n"
"        <menuitem name='NotSelected' action='/Analyze/ApplyasFilter/NotSelected'/>\n"
"        <menuitem name='AndSelected' action='/Analyze/ApplyasFilter/AndSelected'/>\n"
"        <menuitem name='OrSelected' action='/Analyze/ApplyasFilter/OrSelected'/>\n"
"        <menuitem name='AndNotSelected' action='/Analyze/ApplyasFilter/AndNotSelected'/>\n"
"        <menuitem name='OrNotSelected' action='/Analyze/ApplyasFilter/OrNotSelected'/>\n"
"      </menu>\n"
"      <menu name= 'PrepareaFilter' action='/Analyze/PrepareaFilter'>\n"
"        <menuitem name='Selected' action='/Analyze/PrepareaFilter/Selected'/>\n"
"        <menuitem name='NotSelected' action='/Analyze/PrepareaFilter/NotSelected'/>\n"
"        <menuitem name='AndSelected' action='/Analyze/PrepareaFilter/AndSelected'/>\n"
"        <menuitem name='OrSelected' action='/Analyze/PrepareaFilter/OrSelected'/>\n"
"        <menuitem name='AndNotSelected' action='/Analyze/PrepareaFilter/AndNotSelected'/>\n"
"        <menuitem name='OrNotSelected' action='/Analyze/PrepareaFilter/OrNotSelected'/>\n"
"      </menu>\n"
"      <separator/>\n"
"      <menuitem name='EnabledProtocols' action='/Analyze/EnabledProtocols'/>\n"
"      <menuitem name='DecodeAs' action='/Analyze/DecodeAs'/>\n"
"      <menuitem name='UserSpecifiedDecodes' action='/Analyze/UserSpecifiedDecodes'/>\n"
"      <separator/>\n"
"      <menuitem name='FollowTCPStream' action='/Analyze/FollowTCPStream'/>\n"
"      <menuitem name='FollowUDPStream' action='/Analyze/FollowUDPStream'/>\n"
"      <menuitem name='FollowSSLStream' action='/Analyze/FollowSSLStream'/>\n"
"      <menuitem name='ExpertInfoComposite' action='/Analyze/ExpertInfoComposite'/>\n"
"      <menu name= 'ConversationFilterMenu' action='/Analyze/ConversationFilter'>\n"
"        <placeholder name='Filters'/>\n"
"      </menu>\n"
"    </menu>\n"
"    <menu name= 'StatisticsMenu' action='/Statistics'>\n"
"      <menuitem name='Summary' action='/Statistics/Summary'/>\n"
"      <menuitem name='ProtocolHierarchy' action='/Statistics/ProtocolHierarchy'/>\n"
"      <menuitem name='Conversations' action='/Statistics/Conversations'/>\n"
"      <menuitem name='Endpoints' action='/Statistics/Endpoints'/>\n"
"      <menuitem name='IOGraphs' action='/Statistics/IOGraphs'/>\n"
"      <separator/>\n"
"      <menu name= 'ConversationListMenu' action='/Analyze/ConversationList'>\n"
"        <menuitem name='Ethernet' action='/Analyze/ConversationList/Ethernet'/>\n"
"        <menuitem name='FibreChannel' action='/Analyze/ConversationList/FibreChannel'/>\n"
"        <menuitem name='FDDI' action='/Analyze/ConversationList/FDDI'/>\n"
"        <menuitem name='IP' action='/Analyze/ConversationList/IP'/>\n"
"        <menuitem name='IPv6' action='/Analyze/ConversationList/IPv6'/>\n"
"        <menuitem name='JXTA' action='/Analyze/ConversationList/JXTA'/>\n"
"        <menuitem name='NCP' action='/Analyze/ConversationList/NCP'/>\n"
"        <menuitem name='RSVP' action='/Analyze/ConversationList/RSVP'/>\n"
"        <menuitem name='SCTP' action='/Analyze/ConversationList/SCTP'/>\n"
"        <menuitem name='TCPIP' action='/Analyze/ConversationList/TCPIP'/>\n"
"        <menuitem name='TR' action='/Analyze/ConversationList/TR'/>\n"
"        <menuitem name='UDPIP' action='/Analyze/ConversationList/UDPIP'/>\n"
"        <menuitem name='USB' action='/Analyze/ConversationList/USB'/>\n"
"        <menuitem name='WLAN' action='/Analyze/ConversationList/WLAN'/>\n"
"      </menu>\n"
"      <menu name= 'EndpointListMenu' action='/Analyze/EndpointList'>\n"
"        <menuitem name='Ethernet' action='/Analyze/EndpointList/Ethernet'/>\n"
"        <menuitem name='FibreChannel' action='/Analyze/EndpointList/FibreChannel'/>\n"
"        <menuitem name='FDDI' action='/Analyze/EndpointList/FDDI'/>\n"
"        <menuitem name='IP' action='/Analyze/EndpointList/IP'/>\n"
"        <menuitem name='IPv6' action='/Analyze/EndpointList/IPv6'/>\n"
"        <menuitem name='JXTA' action='/Analyze/EndpointList/JXTA'/>\n"
"        <menuitem name='RSVP' action='/Analyze/EndpointList/RSVP'/>\n"
"        <menuitem name='SCTP' action='/Analyze/ConversationList/SCTP'/>\n"
"        <menuitem name='TCPIP' action='/Analyze/ConversationList/TCPIP'/>\n"
"        <menuitem name='TR' action='/Analyze/ConversationList/TR'/>\n"
"        <menuitem name='UDPIP' action='/Analyze/ConversationList/UDPIP'/>\n"
"        <menuitem name='USB' action='/Analyze/ConversationList/USB'/>\n"
"        <menuitem name='WLAN' action='/Analyze/ConversationList/WLAN'/>\n"
"      </menu>\n"
"      <menu name= 'ServiceResponseTimeMenu' action='/Analyze/ServiceResponseTime'>\n"
"        <placeholder name='SRT-List-item'/>\n"
"      </menu>\n"
"      <separator/>\n"
"      <placeholder name='ANCP'/>\n"
"      <menu name= 'BACnetMenu' action='/Analyze/BACnet'>\n"
"        <placeholder name='BACnet-List-item'/>\n"
"      </menu>\n"
"      <menuitem name='FlowGraph' action='/Analyze/StatisticsMenu/FlowGraph'/>\n"
"      <menu name= 'HTTPMenu' action='/Analyze/HTTP'>\n"
"        <placeholder name='HTTP-List-item'/>\n"
"      </menu>\n"
"    </menu>\n"
"    <menu name= 'TelephonyMenu' action='/Telephony'>\n"
"      <menu name= 'IAX2menu' action='/Telephony/IAX2'>\n"
"        <menuitem name='StreamAnalysis' action='/Telephony/IAX2/StreamAnalysis'/>\n"
"      </menu>\n"
"       <menuitem name='VoIPCalls' action='/Telephony/VoIPCalls'/>\n"
"    </menu>\n"
"    <menu name= 'ToolsMenu' action='/Tools'>\n"
"      <menuitem name='FirewallACLRules' action='/Tools/FirewallACLRules'/>\n"
"    </menu>\n"
"    <menu name= 'InternalsMenu' action='/Internals'>\n"
"      <menuitem name='Dissectortables' action='/Internals/Dissectortables'/>\n"
"      <menuitem name='SupportedProtocols' action='/Internals/SupportedProtocols'/>\n"
"    </menu>\n"
"    <menu name= 'HelpMenu' action='/Help'>\n"
"      <menuitem name='Contents' action='/Help/Contents'/>\n"
"      <menu name= 'ManualPages' action='/Help/ManualPages'>\n"
"        <menuitem name='Wireshark' action='/Help/ManualPages/Wireshark'/>\n"
"        <menuitem name='WiresharkFilter' action='/Help/ManualPages/WiresharkFilter'/>\n"
"        <separator/>\n"
"        <menuitem name='TShark' action='/Help/ManualPages/TShark'/>\n"
"        <menuitem name='RawShark' action='/Help/ManualPages/RawShark'/>\n"
"        <menuitem name='Dumpcap' action='/Help/ManualPages/Dumpcap'/>\n"
"        <menuitem name='Mergecap' action='/Help/ManualPages/Mergecap'/>\n"
"        <menuitem name='Editcap' action='/Help/ManualPages/Editcap'/>\n"
"        <menuitem name='Text2pcap' action='/Help/ManualPages/Text2pcap'/>\n"
"      </menu>\n"
"      <separator/>\n"
"      <menuitem name='Website' action='/Help/Website'/>\n"
"      <menuitem name='FAQs' action='/Help/FAQs'/>\n"
"      <menuitem name='Downloads' action='/Help/Downloads'/>\n"
"      <separator/>\n"
"      <menuitem name='Wiki' action='/Help/Wiki'/>\n"
"      <menuitem name='SampleCaptures' action='/Help/SampleCaptures'/>\n"
"      <separator/>\n"
"      <menuitem name='AboutWireshark' action='/Help/AboutWireshark'/>\n"
"    </menu>\n"
"  </menubar>\n"
"</ui>\n";


/*
 * Main menu.
 *
 * Please do not use keystrokes that are used as "universal" shortcuts in
 * various desktop environments:
 *
 *   Windows:
 *	http://support.microsoft.com/kb/126449
 *
 *   GNOME:
 *	http://library.gnome.org/users/user-guide/nightly/keyboard-skills.html.en
 *
 *   KDE:
 *	http://developer.kde.org/documentation/standards/kde/style/keys/shortcuts.html
 *
 * In particular, do not use the following <control> sequences for anything
 * other than their standard purposes:
 *
 *	<control>O	File->Open
 *	<control>S	File->Save
 *	<control>P	File->Print
 *	<control>W	File->Close
 *	<control>Q	File->Quit
 *	<control>Z	Edit->Undo (which we don't currently have)
 *	<control>X	Edit->Cut (which we don't currently have)
 *	<control>C	Edit->Copy (which we don't currently have)
 *	<control>V	Edit->Paste (which we don't currently have)
 *	<control>A	Edit->Select All (which we don't currently have)
 *
 * Note that some if not all of the Edit keys above already perform those
 * functions in text boxes, such as the Filter box.  Do no, under any
 * circumstances, make a change that keeps them from doing so.
 */

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
static const GtkActionEntry main_menu_bar_entries[] = {
  /* Top level */ 
  { "/File",					NULL,							"_File",			NULL,					NULL,			NULL },
  { "/Edit",					NULL,							"_Edit",			NULL,					NULL,			NULL },
  { "/View",					NULL,							"_View",			NULL,					NULL,			NULL },
  { "/Go",						NULL,							"_Go",				NULL,					NULL,			NULL },
#ifdef HAVE_LIBPCAP
  { "/Capture",					NULL,							"_Capture",			NULL,					NULL,			NULL },
#endif
  { "/Analyze",					NULL,							"_Analyze",			NULL,					NULL,			NULL },
  { "/Statistics",				NULL,							"_Statistics",		NULL,					NULL,			NULL },
  { "/Telephony",				NULL,							"Telephon_y",		NULL,					NULL,			NULL },
  { "/Tools",					NULL,							"_Tools",			NULL,					NULL,			NULL },
  { "/Internals",				NULL,							"_Internals",		NULL,					NULL,			NULL },
  { "/Help",					NULL,							"_Help",			NULL,					NULL,			NULL },

  { "/File/Open",				GTK_STOCK_OPEN,					"_Open...",			"<control>O",			"Open a file",	G_CALLBACK(file_open_cmd_cb) },
  { "/File/OpenRecent",			NULL,							"Open _Recent",		NULL,					NULL,			NULL },
  { "/File/Merge",				NULL,							"_Merge...",		NULL,					NULL,			G_CALLBACK(file_merge_cmd_cb) },
  { "/File/Import",				NULL,							"_Import...",		NULL,					NULL,			G_CALLBACK(file_import_cmd_cb) },
  { "/File/Close",				GTK_STOCK_CLOSE,				"_Close",			"<control>W",			NULL,			G_CALLBACK(file_close_cmd_cb) },

  { "/File/Save",				GTK_STOCK_SAVE,					"_Save",			"<control>S",			NULL,			G_CALLBACK(file_save_cmd_cb) },
  { "/File/SaveAs",				GTK_STOCK_SAVE_AS,				"Save _As...",		"<shift><control>S",	NULL,			G_CALLBACK(file_save_as_cmd_cb) },

  { "/File/Set",				NULL,							"File Set",			NULL,					NULL,			NULL },
  { "/File/Export",				NULL,							"Export",			NULL,					NULL,			NULL },
  { "/File/Print",				GTK_STOCK_PRINT,				"_Print...",		"<control>P",			NULL,			G_CALLBACK(file_print_cmd_cb) },
  { "/File/Quit",				GTK_STOCK_QUIT,					"_Quit",			"<control>Q",			NULL,			G_CALLBACK(file_quit_cmd_cb) },

  { "/File/Set/ListFiles",	WIRESHARK_STOCK_FILE_SET_LIST,	"List Files",		NULL,					NULL,			G_CALLBACK(fileset_cb) },
  { "/File/Set/NextFile",	WIRESHARK_STOCK_FILE_SET_NEXT,	"Next File",		NULL,					NULL,			G_CALLBACK(fileset_next_cb) },
  { "/File/Set/PreviousFile",WIRESHARK_STOCK_FILE_SET_PREVIOUS,	"Previous File",	NULL,				NULL,			G_CALLBACK(fileset_previous_cb) },

#if _WIN32
  { "/File/Export/File",				NULL,		"File...",						NULL,					NULL,			G_CALLBACK(export_text_cmd_cb) },
#else
  { "/File/Export/File",				NULL,		"File...",						NULL,					NULL,			NULL },
  { "/File/Export/File/Text",			NULL,		"as \"Plain _Text\" file...",	NULL,					NULL,			G_CALLBACK(export_text_cmd_cb) },
  { "/File/Export/File/PostScript",		NULL,		"as \"_PostScript\" file...",	NULL,					NULL,			G_CALLBACK(export_ps_cmd_cb) },
  { "/File/Export/File/CSV",			NULL,		"as \"_CSV\" (Comma Separated Values packet summary) file...",
																					NULL,					NULL,			G_CALLBACK(export_csv_cmd_cb) },
  { "/File/Export/File/CArrays",		NULL,		"as \"C _Arrays\" (packet bytes) file...",
																					NULL,					NULL,			G_CALLBACK(export_carrays_cmd_cb) },
  { "/File/Export/File/PSML",			NULL,		"as XML - \"P_SML\" (packet summary) file...",
																					NULL,					NULL,			G_CALLBACK(export_psml_cmd_cb) },
  { "/File/Export/File/PDML",			NULL,		"as XML - \"P_DML\" (packet details) file...",	
																					NULL,					NULL,			G_CALLBACK(export_pdml_cmd_cb) },
#endif /* _WIN32 */
  { "/File/Export/SelectedPacketBytes",	NULL,		"Selected Packet _Bytes...",	"<control>H",			NULL,			G_CALLBACK(savehex_cb) },
  { "/File/Export/Objects",				NULL,		"Objects",						NULL,					NULL,			NULL },
  { "/File/Export/Objects/HTTP",		NULL,		"_HTTP",						NULL,					NULL,			G_CALLBACK(eo_http_cb) },
  { "/File/Export/Objects/DICOM",		NULL,		"_DICOM",						NULL,					NULL,			G_CALLBACK(eo_dicom_cb) },
  { "/File/Export/Objects/SMB",			NULL,		"_SMB",							NULL,					NULL,			G_CALLBACK(eo_smb_cb) },


  { "/Edit/Copy",						NULL,		"Copy",							NULL,					NULL,			NULL },

  { "/Edit/Copy/Description",			NULL,		"Description",					"<shift><control>D",	NULL,			G_CALLBACK(copy_description_cb) },
  { "/Edit/Copy/Fieldname",				NULL,		"Fieldname",					"<shift><control>F",	NULL,			G_CALLBACK(copy_fieldname_cb) },
  { "/Edit/Copy/Value",					NULL,		"Value",						"<shift><control>V",	NULL,			G_CALLBACK(copy_value_cb) },
  { "/Edit/Copy/AsFilter",				NULL,		"As Filter",					"<shift><control>C",	NULL,			G_CALLBACK(copy_as_filter_cb) },

#if 0
    /*
     * Un-#if this when we actually implement Cut/Copy/Paste for the
     * packet list and packet detail windows.
     *
     * Note: when we implement Cut/Copy/Paste in those windows, we
     * will almost certainly want to allow multiple packets to be
     * selected in the packet list pane and multiple packet detail
     * items to be selected in the packet detail pane, so that
     * the user can, for example, copy the summaries of multiple
     * packets to the clipboard from the packet list pane and multiple
     * packet detail items - perhaps *all* packet detail items - from
     * the packet detail pane.  Given that, we'll also want to
     * implement Select All.
     *
     * If multiple packets are selected, we would probably display nothing
     * in the packet detail pane, just as we do if no packet is selected,
     * and any menu items etc. that would pertain only to a single packet
     * would be disabled.
     *
     * If multiple packet detail items are selected, we would probably
     * disable all items that pertain only to a single packet detail
     * item, such as some items in the status bar.
     *
     * XXX - the actions for these will be different depending on what
     * widget we're in; ^C should copy from the filter text widget if
     * we're in that widget, the packet list if we're in that widget
     * (presumably copying the summaries of selected packets to the
     * clipboard, e.g. the text copy would be the text of the columns),
     * the packet detail if we're in that widget (presumably copying
     * the contents of selected protocol tree items to the clipboard,
     * e.g. the text copy would be the text displayed for those items),
     * etc..
     *
     * Given that those menu items should also affect text widgets
     * such as the filter box, we would again want Select All, and,
     * at least for the filter box, we would also want Undo and Redo.
     * We would only want Cut, Paste, Undo, and Redo for the packet
     * list and packet detail panes if we support modifying them.
     */
    {"/Edit/_Undo", "<control>Z", NULL,
                             0, "<StockItem>", GTK_STOCK_UNDO,},
    {"/Edit/_Redo", "<shift><control>Z", NULL,
                             0, "<StockItem>", GTK_STOCK_REDO,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/Cu_t", "<control>X", NULL,
                             0, "<StockItem>", GTK_STOCK_CUT,},
    {"/Edit/_Copy", "<control>C", NULL,
                             0, "<StockItem>", GTK_STOCK_COPY,},
    {"/Edit/_Paste", "<control>V", NULL,
                             0, "<StockItem>", GTK_STOCK_PASTE,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/Select _All", "<control>A", NULL, 0,
#ifdef GTK_STOCK_SELECT_ALL	/* first appeared in 2.10 */
                             "<StockItem>", GTK_STOCK_SELECT_ALL,
#else
                             NULL, NULL,
#endif /* GTK_STOCK_SELECT_ALL */
#endif /* 0 */
   { "/Edit/FindPacket",				GTK_STOCK_FIND,		"_Find Packet...",						"<control>F",			NULL,			G_CALLBACK(find_frame_cb) },
   { "/Edit/FindNext",					NULL,				"Find Ne_xt",							"<control>N",			NULL,			G_CALLBACK(find_next_cb) },
   { "/Edit/FindPrevious",				NULL,				"Find Pre_vious",						"<control>B",			NULL,			G_CALLBACK(find_previous_cb) },

   { "/Edit/MarkPacket",				NULL,				"_Mark Packet (toggle)",				"<control>M",			NULL,			G_CALLBACK(new_packet_list_mark_frame_cb) },
   { "/Edit/ToggleMarkingOfAllDisplayedPackets",	NULL,	"Toggle Marking Of All Displayed Packets",	"<shift><alt><control>M",			NULL,			G_CALLBACK(new_packet_list_toggle_mark_all_displayed_frames_cb) },
   { "/Edit/MarkAllDisplayedPackets",	NULL,				"Mark All Displayed Packets",			"<shift><control>M",	NULL,			G_CALLBACK(new_packet_list_mark_all_displayed_frames_cb) },
   { "/Edit/UnmarkAllDisplayedPackets",	NULL,				"_Unmark All Displayed Packets",		"<alt><control>M",		NULL,			G_CALLBACK(new_packet_list_unmark_all_displayed_frames_cb) },
   { "/Edit/FindNextMark",				NULL,				"Find Next Mark",						"<shift><control>N",	NULL,			G_CALLBACK(find_next_mark_cb) },
   { "/Edit/FindPreviousMark",			NULL,				"Find Next Mark",						"<shift><control>B",	NULL,			G_CALLBACK(find_prev_mark_cb) },

   { "/Edit/IgnorePacket",				NULL,				"_Ignore Packet (toggle)",				"<control>X",			NULL,			G_CALLBACK(new_packet_list_ignore_frame_cb) },
    /*
     * XXX - this next one overrides /Edit/Copy/Description
     */
   { "/Edit/IgnoreAllDisplayedPackets",	NULL,				"_Ignore All Displayed Packets (toggle)","<alt><shift><control>X",	NULL,			G_CALLBACK(new_packet_list_ignore_all_displayed_frames_cb) },
   { "/Edit/Un-IgnoreAllPackets",		NULL,				"U_n-Ignore All Packets",				"<shift><control>X",		NULL,			G_CALLBACK(new_packet_list_unignore_all_frames_cb) },
   { "/Edit/SetTimeReference",			WIRESHARK_STOCK_TIME,	"Set Time Reference (toggle)",			"<control>T",			NULL,			G_CALLBACK(set_reftime_cb) },
   { "/Edit/Un-TimeReferenceAllPackets",NULL,				"Un-Time Reference All Packets",		"<alt><control>T",			NULL,			G_CALLBACK(new_packet_list_untime_reference_all_frames_cb) },
   { "/Edit/FindNextTimeReference",		NULL,				"Find Next Time Reference",				"<alt><control>N",			NULL,			G_CALLBACK(find_next_ref_time_cb) },
   { "/Edit/FindPreviousTimeReference",	NULL,				"Find Previous Time Reference",			"<alt><control>B",			NULL,			G_CALLBACK(find_previous_ref_time_cb) },

   { "/Edit/ConfigurationProfiles",	NULL,					"_Configuration Profiles...",			"<shift><control>A",		NULL,			G_CALLBACK(profile_dialog_cb) },
   { "/Edit/Preferences",			GTK_STOCK_PREFERENCES,	"_Preferences...",						"<shift><control>P",		NULL,			G_CALLBACK(menus_prefs_cb) },
   { "/Edit/EditPacket",				NULL,				"_Edit Packet",							NULL,						NULL,			G_CALLBACK(edit_window_cb) },


   { "/View/TimeDisplayFormat",		NULL,					"_Time Display Format",					NULL,						NULL,			NULL },

   { "/View/NameResolution",			NULL,					"Name Resol_ution",						NULL,						NULL,			NULL },
   { "/View/ZoomIn",				GTK_STOCK_ZOOM_IN,		"_Zoom In",								"<control>plus",			NULL,			G_CALLBACK(view_zoom_in_cb) },
   { "/View/ZoomOut",				GTK_STOCK_ZOOM_OUT,		"Zoom _Out",							"<control>minus",			NULL,			G_CALLBACK(view_zoom_out_cb) },
   { "/View/NormalSize",			GTK_STOCK_ZOOM_100,		"_Normal Size",							"<control>equal",			NULL,			G_CALLBACK(view_zoom_100_cb) },
   { "/View/ResizeAllColumns",		WIRESHARK_STOCK_RESIZE_COLUMNS,	"Resize All Columns",			"<shift><control>R",		NULL,			G_CALLBACK(new_packet_list_resize_columns_cb) },
   { "/View/DisplayedColumns",		NULL,					"Displayed Columns",			NULL,		NULL,			NULL },
   { "/View/ExpandSubtrees",		NULL,					"Expand Subtrees",		NULL,					NULL,			G_CALLBACK(expand_tree_cb) },
   { "/View/ExpandAll",				NULL,					"Expand All",			NULL,					NULL,			G_CALLBACK(expand_all_cb) },
   { "/View/CollapseAll",			NULL,					"Collapse All",			NULL,					NULL,			G_CALLBACK(collapse_all_cb) },
   { "/View/ColorizeConversation",	NULL,					"Colorize Conversation",NULL,					NULL,			NULL },

   { "/View/ColorizeConversation/Color 1",	WIRESHARK_STOCK_COLOR1, "Color 1",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color1_cb) },
   { "/View/ColorizeConversation/Color 2",	WIRESHARK_STOCK_COLOR2, "Color 2",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color2_cb) },
   { "/View/ColorizeConversation/Color 3",	WIRESHARK_STOCK_COLOR3, "Color 3",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color3_cb) },
   { "/View/ColorizeConversation/Color 4",	WIRESHARK_STOCK_COLOR4, "Color 4",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color4_cb) },
   { "/View/ColorizeConversation/Color 5",	WIRESHARK_STOCK_COLOR5, "Color 5",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color5_cb) },
   { "/View/ColorizeConversation/Color 6",	WIRESHARK_STOCK_COLOR6, "Color 6",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color6_cb) },
   { "/View/ColorizeConversation/Color 7",	WIRESHARK_STOCK_COLOR7, "Color 7",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color7_cb) },
   { "/View/ColorizeConversation/Color 8",	WIRESHARK_STOCK_COLOR8, "Color 8",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color8_cb) },
   { "/View/ColorizeConversation/Color 9",	WIRESHARK_STOCK_COLOR9, "Color 9",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color9_cb) },
   { "/View/ColorizeConversation/Color 10",	WIRESHARK_STOCK_COLOR0, "Color 10",					NULL, NULL, G_CALLBACK(view_menu_color_conv_color10_cb) },
   { "/View/ColorizeConversation/NewColoringRule",	NULL,			"New Coloring Rule...",		NULL, NULL, G_CALLBACK(view_menu_color_conv_new_rule_cb) },

   { "/View/ResetColoring1-10",		NULL,					"Reset Coloring 1-10",				"<control>space",				NULL,				G_CALLBACK(view_menu_reset_coloring_cb) },
   { "/View/ColoringRules",			GTK_STOCK_SELECT_COLOR,	"_Coloring Rules...",				NULL,							NULL,				G_CALLBACK(color_display_cb) },
   { "/View/ShowPacketinNewWindow",	NULL,					"Show Packet in New _Window",		NULL,							NULL,				G_CALLBACK(new_window_cb) },
   { "/View/Reload",				GTK_STOCK_REFRESH,		"_Reload",							"<control>R",					NULL,				G_CALLBACK(file_reload_cmd_cb) },


   { "/Go/Back",					GTK_STOCK_GO_BACK,		"_Back",							"<alt>Left",					NULL,				G_CALLBACK(history_back_cb) },
   { "/Go/Forward",					GTK_STOCK_GO_FORWARD,	"_Forward",							"<alt>Right",					NULL,				G_CALLBACK(history_forward_cb) },
   { "/Go/Goto",					GTK_STOCK_JUMP_TO,		"_Go to Packet...",					"<control>G",					NULL,				G_CALLBACK(goto_frame_cb) },
   { "/Go/GotoCorrespondingPacket",	NULL,					"Go to _Corresponding Packet",		NULL,							NULL,				G_CALLBACK(goto_framenum_cb) },
   { "/Go/PreviousPacket",			GTK_STOCK_GO_UP,		"Previous Packet",					"<control>Up",					NULL,				G_CALLBACK(goto_previous_frame_cb) },
   { "/Go/NextPacket",				GTK_STOCK_GO_DOWN,		"Next Packet",						"<control>Down",				NULL,				G_CALLBACK(goto_next_frame_cb) },
   { "/Go/FirstPacket",				GTK_STOCK_GOTO_TOP,		"F_irst Packet",					"<control>Home",				NULL,				G_CALLBACK(goto_top_frame_cb) },
   { "/Go/LastPacket",				GTK_STOCK_GOTO_BOTTOM,	"_Last Packet",						"<control>End",					NULL,				G_CALLBACK(goto_bottom_frame_cb) },
   { "/Go/PreviousPacketInConversation",			GTK_STOCK_GO_UP,		"Previous Packet In Conversation",					"<control>comma",					NULL,				G_CALLBACK(goto_previous_frame_conversation_cb) },
   { "/Go/NextPacketInConversation",				GTK_STOCK_GO_DOWN,		"Next Packet In Conversation",						"<control>period",				NULL,				G_CALLBACK(goto_next_frame_conversation_cb) },

#ifdef HAVE_LIBPCAP
   { "/Capture/Interfaces",			WIRESHARK_STOCK_CAPTURE_INTERFACES,	"_Interfaces...",		"<control>I",					NULL,				G_CALLBACK(capture_if_cb) },
   { "/Capture/Options",			WIRESHARK_STOCK_CAPTURE_OPTIONS,	"_Options...",			"<control>K",					NULL,				G_CALLBACK(capture_prep_cb) },
   { "/Capture/Start",				WIRESHARK_STOCK_CAPTURE_START,		"_Start",				"<control>E",					NULL,				G_CALLBACK(capture_start_cb) },
   { "/Capture/Stop",				WIRESHARK_STOCK_CAPTURE_STOP,		"S_top",				"<control>E",					NULL,				G_CALLBACK(capture_stop_cb) },
   { "/Capture/Restart",			WIRESHARK_STOCK_CAPTURE_RESTART,	"_Restart",				"<control>R",					NULL,				G_CALLBACK(capture_restart_cb) },
   { "/Capture/CaptureFilters",		WIRESHARK_STOCK_CAPTURE_FILTER,		"Capture _Filters...",	NULL,							NULL,				G_CALLBACK(cfilter_dialog_cb) },

#endif /* HAVE_LIBPCAP */
   { "/Analyze/DisplayFilters",		WIRESHARK_STOCK_DISPLAY_FILTER,		"_Display Filters...",	NULL,							NULL,				G_CALLBACK(dfilter_dialog_cb) },

   { "/Analyze/DisplayFilterMacros",			NULL,					"Display Filter _Macros...",	NULL,					NULL,				G_CALLBACK(macros_dialog_cb) },
   { "/Analyze/ApplyasColumn",					NULL,							"Apply as Column",		NULL,					NULL,				G_CALLBACK(apply_as_custom_column_cb) },
   { "/Analyze/ApplyasFilter",					NULL,							"Apply as Filter",		NULL,					NULL,				NULL },

   { "/Analyze/ApplyasFilter/Selected",			NULL, "_Selected" ,				NULL, NULL, G_CALLBACK(tree_view_menu_apply_selected_cb) },
   { "/Analyze/ApplyasFilter/NotSelected",		NULL, "_Not Selected",			NULL, NULL, G_CALLBACK(tree_view_menu_apply_not_selected_cb) },
   { "/Analyze/ApplyasFilter/AndSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _and Selected",		NULL, NULL, G_CALLBACK(tree_view_menu_apply_and_selected_cb) },
   { "/Analyze/ApplyasFilter/OrSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _or Selected",		NULL, NULL, G_CALLBACK(tree_view_menu_apply_or_selected_cb) },
   { "/Analyze/ApplyasFilter/AndNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " a_nd not Selected",	NULL, NULL, G_CALLBACK(tree_view_menu_apply_and_not_selected_cb) },
   { "/Analyze/ApplyasFilter/OrNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " o_r not Selected",	NULL, NULL, G_CALLBACK(tree_view_menu_apply_or_not_selected_cb) },

   { "/Analyze/PrepareaFilter",					NULL, "Prepare a Filter",		NULL, NULL, NULL },
   { "/Analyze/PrepareaFilter/Selected",		NULL, "_Selected" ,				NULL, NULL, G_CALLBACK(tree_view_menu_prepare_selected_cb) },
   { "/Analyze/PrepareaFilter/NotSelected",		NULL, "_Not Selected",			NULL, NULL, G_CALLBACK(tree_view_menu_prepare_not_selected_cb) },
   { "/Analyze/PrepareaFilter/AndSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _and Selected",		NULL, NULL, G_CALLBACK(tree_view_menu_prepare_and_selected_cb) },
   { "/Analyze/PrepareaFilter/OrSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _or Selected",		NULL, NULL, G_CALLBACK(tree_view_menu_prepare_or_selected_cb) },
   { "/Analyze/PrepareaFilter/AndNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " a_nd not Selected",	NULL, NULL, G_CALLBACK(tree_view_menu_prepare_and_not_selected_cb) },
   { "/Analyze/PrepareaFilter/OrNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " o_r not Selected",	NULL, NULL, G_CALLBACK(tree_view_menu_prepare_or_not_selected_cb) },

   { "/Analyze/EnabledProtocols",	WIRESHARK_STOCK_CHECKBOX, "_Enabled Protocols...",	"<shift><control>E", NULL, G_CALLBACK(proto_cb) },
   { "/Analyze/DecodeAs",	WIRESHARK_STOCK_DECODE_AS, "Decode _As...",			NULL, NULL, G_CALLBACK(decode_as_cb) },
   { "/Analyze/UserSpecifiedDecodes",	WIRESHARK_STOCK_DECODE_AS, "_User Specified Decodes...",			NULL, NULL, G_CALLBACK(decode_show_cb) },

   { "/Analyze/FollowTCPStream",							NULL,		"Follow TCP Stream",					NULL, NULL, G_CALLBACK(follow_tcp_stream_cb) },
   { "/Analyze/FollowUDPStream",							NULL,		"Follow UDP Stream",					NULL, NULL, G_CALLBACK(follow_udp_stream_cb) },
   { "/Analyze/FollowSSLStream",							NULL,		"Follow SSL Stream",					NULL, NULL, G_CALLBACK(follow_ssl_stream_cb) },

   { "/Analyze/ExpertInfoComposite",WIRESHARK_STOCK_EXPERT_INFO,		"Expert Info _Composite",				NULL, NULL, G_CALLBACK(expert_comp_dlg_launch) },

   { "/Analyze/ConversationFilter",							NULL,		"Conversation Filter",					NULL, NULL, NULL },
   { "/Analyze/ConversationList",							NULL,		"_Conversation List",					NULL, NULL, NULL },
   { "/Analyze/ConversationList/Ethernet",		WIRESHARK_STOCK_CONVERSATIONS,	"Ethernet",						NULL, NULL,	G_CALLBACK(eth_endpoints_cb) },
   { "/Analyze/ConversationList/FibreChannel",	WIRESHARK_STOCK_CONVERSATIONS,	"Fibre Channel",				NULL, NULL,	G_CALLBACK(fc_endpoints_cb) },
   { "/Analyze/ConversationList/FDDI",			WIRESHARK_STOCK_CONVERSATIONS,	"FDDI",							NULL, NULL,	G_CALLBACK(fddi_endpoints_cb) },
   { "/Analyze/ConversationList/IP",			WIRESHARK_STOCK_CONVERSATIONS,	"IPv4",							NULL, NULL,	G_CALLBACK(ip_endpoints_cb) },
   { "/Analyze/ConversationList/IPv6",			WIRESHARK_STOCK_CONVERSATIONS,	"IPv6",							NULL, NULL,	G_CALLBACK(ipv6_endpoints_cb) },
   { "/Analyze/ConversationList/IPX",			WIRESHARK_STOCK_CONVERSATIONS,	"IPX",							NULL, NULL,	G_CALLBACK(ipx_endpoints_cb) },
   { "/Analyze/ConversationList/JXTA",			WIRESHARK_STOCK_CONVERSATIONS,	"JXTA",							NULL, NULL,	G_CALLBACK(jxta_conversation_cb) },
   { "/Analyze/ConversationList/NCP",			WIRESHARK_STOCK_CONVERSATIONS,	"NCP",							NULL, NULL,	G_CALLBACK(ncp_endpoints_cb) },
   { "/Analyze/ConversationList/RSVP",			WIRESHARK_STOCK_CONVERSATIONS,	"RSVP",							NULL, NULL,	G_CALLBACK(rsvp_endpoints_cb) },
   { "/Analyze/ConversationList/SCTP",			WIRESHARK_STOCK_CONVERSATIONS,	"SCTP",							NULL, NULL,	G_CALLBACK(sctp_conversation_cb) },
   { "/Analyze/ConversationList/TCPIP",			WIRESHARK_STOCK_CONVERSATIONS,	"TCP (IPv4 & IPv6)",			NULL, NULL,	G_CALLBACK(tcpip_conversation_cb) },
   { "/Analyze/ConversationList/TR",			WIRESHARK_STOCK_CONVERSATIONS,	"Token Ring",					NULL, NULL,	G_CALLBACK(tr_conversation_cb) },
   { "/Analyze/ConversationList/UDPIP",			WIRESHARK_STOCK_CONVERSATIONS,	"UDP (IPv4 & IPv6)",			NULL, NULL,	G_CALLBACK(udpip_conversation_cb) },
   { "/Analyze/ConversationList/USB",			WIRESHARK_STOCK_CONVERSATIONS,	"USB",							NULL, NULL,	G_CALLBACK(usb_endpoints_cb) },
   { "/Analyze/ConversationList/WLAN",			WIRESHARK_STOCK_CONVERSATIONS,	"WLAN",							NULL, NULL,	G_CALLBACK(wlan_endpoints_cb) },

   { "/Analyze/EndpointList",								NULL,				"_Endpoint List",				NULL, NULL, NULL },
   { "/Analyze/EndpointList/Ethernet",			WIRESHARK_STOCK_ENDPOINTS,		"Ethernet",						NULL, NULL,	G_CALLBACK(gtk_eth_hostlist_cb) },
   { "/Analyze/EndpointList/FibreChannel",		WIRESHARK_STOCK_ENDPOINTS,		"Fibre Channel",				NULL, NULL,	G_CALLBACK(gtk_fc_hostlist_cb) },
   { "/Analyze/EndpointList/FDDI",				WIRESHARK_STOCK_ENDPOINTS,		"FDDI",							NULL, NULL,	G_CALLBACK(gtk_fddi_hostlist_cb) },
   { "/Analyze/EndpointList/IP",				WIRESHARK_STOCK_ENDPOINTS,		"IPv4",							NULL, NULL,	G_CALLBACK(gtk_ip_hostlist_cb) },
   { "/Analyze/EndpointList/IPv6",				WIRESHARK_STOCK_ENDPOINTS,		"IPv6",							NULL, NULL,	G_CALLBACK(gtk_ipv6_hostlist_cb) },
   { "/Analyze/EndpointList/IPX",				WIRESHARK_STOCK_ENDPOINTS,		"IPX",							NULL, NULL,	G_CALLBACK(gtk_ipx_hostlist_cb) },
   { "/Analyze/EndpointList/JXTA",				WIRESHARK_STOCK_ENDPOINTS,		"JXTA",							NULL, NULL,	G_CALLBACK(gtk_jxta_hostlist_cb) },
   { "/Analyze/EndpointList/NCP",				WIRESHARK_STOCK_ENDPOINTS,		"NCP",							NULL, NULL,	G_CALLBACK(gtk_ncp_hostlist_cb) },
   { "/Analyze/EndpointList/RSVP",				WIRESHARK_STOCK_ENDPOINTS,		"RSVP",							NULL, NULL,	G_CALLBACK(gtk_rsvp_hostlist_cb) },
   { "/Analyze/EndpointList/SCTP",				WIRESHARK_STOCK_ENDPOINTS,		"SCTP",							NULL, NULL,	G_CALLBACK(gtk_sctp_hostlist_cb) },
   { "/Analyze/EndpointList/TCPIP",				WIRESHARK_STOCK_ENDPOINTS,		"TCP (IPv4 & IPv6)",			NULL, NULL,	G_CALLBACK(gtk_tcpip_hostlist_cb) },
   { "/Analyze/EndpointList/TR",				WIRESHARK_STOCK_ENDPOINTS,		"Token Ring",					NULL, NULL,	G_CALLBACK(gtk_tr_hostlist_cb) },
   { "/Analyze/EndpointList/UDPIP",				WIRESHARK_STOCK_ENDPOINTS,		"UDP (IPv4 & IPv6)",			NULL, NULL,	G_CALLBACK(gtk_udpip_hostlist_cb) },
   { "/Analyze/EndpointList/USB",				WIRESHARK_STOCK_ENDPOINTS,		"USB",							NULL, NULL,	G_CALLBACK(gtk_usb_hostlist_cb) },
   { "/Analyze/EndpointList/WLAN",				WIRESHARK_STOCK_ENDPOINTS,		"WLAN",							NULL, NULL,	G_CALLBACK(gtk_wlan_hostlist_cb) },

   { "/Analyze/ServiceResponseTime",						NULL,				"Service _Response Time",		NULL, NULL, NULL },

   { "/Analyze/BACnet",										NULL,				"BACnet",						NULL, NULL, NULL },
   
   { "/Analyze/StatisticsMenu/FlowGraph",		WIRESHARK_STOCK_FLOW_GRAPH,		"Flo_w Graph...",				NULL, NULL,	G_CALLBACK(flow_graph_launch) },
   { "/Analyze/HTTP",										NULL,				"HTTP",							NULL, NULL, NULL },

   { "/Statistics/Summary",						GTK_STOCK_PROPERTIES,			"_Summary",						NULL, NULL,	G_CALLBACK(summary_open_cb) },
   { "/Statistics/ProtocolHierarchy",			NULL,							"_Protocol Hierarchy",			NULL, NULL, G_CALLBACK(proto_hier_stats_cb) },
   { "/Statistics/Conversations",	WIRESHARK_STOCK_CONVERSATIONS,	"Conversations",		NULL,							NULL,				G_CALLBACK(init_conversation_notebook_cb) },
   { "/Statistics/Endpoints",		WIRESHARK_STOCK_ENDPOINTS,		"Endpoints",			NULL,							NULL,				G_CALLBACK(init_hostlist_notebook_cb) },
   { "/Statistics/IOGraphs",			WIRESHARK_STOCK_GRAPHS,		"_IO Graph",			NULL,							NULL,				G_CALLBACK(gui_iostat_cb) },

   { "/Telephony/IAX2",					NULL,						"IA_X2",				NULL, NULL, NULL },
   { "/Telephony/IAX2/StreamAnalysis",	NULL,						"Stream Analysis...",	NULL,							NULL,				G_CALLBACK(iax2_analysis_cb) },
   { "/Telephony/VoIPCalls",			WIRESHARK_STOCK_TELEPHONE,	"_VoIP Calls",			NULL,							NULL,				G_CALLBACK(voip_calls_launch) },

   { "/Tools/FirewallACLRules",		NULL,							"Firewall ACL Rules",	NULL,							NULL,				G_CALLBACK(firewall_rule_cb) },

   { "/Internals/Dissectortables",	NULL,							"_Dissector tables",	NULL,							NULL,				G_CALLBACK(dissector_tables_dlg_cb) },
   { "/Internals/SupportedProtocols", NULL,					"_Supported Protocols (slow!)",	NULL,							NULL,				G_CALLBACK(supported_cb) },
   
   { "/Help/Contents",				GTK_STOCK_HELP,					"_Contents",			"F1",							NULL,				G_CALLBACK(help_menu_cont_cb) },
   { "/Help/ManualPages",			NULL,							"ManualPages",			NULL,							NULL,				NULL },
   { "/Help/ManualPages/Wireshark", NULL,							"Wireshark",			NULL,							NULL,				G_CALLBACK(help_menu_wireshark_cb) },
   { "/Help/ManualPages/WiresharkFilter", NULL,						"Wireshark Filter",		NULL,							NULL,				G_CALLBACK(help_menu_wireshark_flt_cb) },
   { "/Help/ManualPages/TShark",	NULL,							"Wireshark",			NULL,							NULL,				G_CALLBACK(help_menu_Tshark_cb) },
   { "/Help/ManualPages/RawShark",	NULL,							"RawShark",				NULL,							NULL,				G_CALLBACK(help_menu_RawShark_cb) },
   { "/Help/ManualPages/Dumpcap",	NULL,							"Dumpcap",				NULL,							NULL,				G_CALLBACK(help_menu_Dumpcap_cb) },
   { "/Help/ManualPages/Mergecap",	NULL,							"Mergecap",				NULL,							NULL,				G_CALLBACK(help_menu_Mergecap_cb) },
   { "/Help/ManualPages/Editcap",	NULL,							"Editcap",				NULL,							NULL,				G_CALLBACK(help_menu_Editcap_cb) },
   { "/Help/ManualPages/Text2pcap",	NULL,							"Text2pcap",			NULL,							NULL,				G_CALLBACK(help_menu_Text2pcap_cb) },

   { "/Help/Website",				GTK_STOCK_HOME,					"Website",				NULL,							NULL,				G_CALLBACK(help_menu_Website_cb) },
   { "/Help/FAQs",					NULL,							"FAQ's",				NULL,							NULL,				G_CALLBACK(help_menu_faq_cb) },
   { "/Help/Downloads",				NULL,							"Downloads",			NULL,							NULL,				G_CALLBACK(help_menu_Downloads_cb) },
   { "/Help/Wiki",					WIRESHARK_STOCK_WIKI,			"Wiki",					NULL,							NULL,				G_CALLBACK(help_menu_Wiki_cb) },
   { "/Help/SampleCaptures",		NULL,							"Sample Captures",		NULL,							NULL,				G_CALLBACK(help_menu_SampleCaptures_cb) },
   { "/Help/AboutWireshark",		WIRESHARK_STOCK_ABOUT,			"_About Wireshark",		NULL,							NULL,				G_CALLBACK(about_wireshark_cb) },
};

static const GtkToggleActionEntry main_menu_bar_toggle_action_entries[] = 
{
	/* name, stock id, label, accel, tooltip, callback, is_active */
	{"/View/MainToolbar",	NULL, "_Main Toolbar",	NULL, NULL,	G_CALLBACK(main_toolbar_show_hide_cb), TRUE}, 
	{"/View/FilterToolbar", NULL, "_FilterToolbar", NULL, NULL,	G_CALLBACK(filter_toolbar_show_hide_cb), TRUE}, 
#ifdef HAVE_AIRPCAP
	{"/View/WirelessToolbar", NULL, "_WirelessToolbar", NULL, NULL,	G_CALLBACK(wireless_toolbar_show_hide_cb), TRUE}, 
#endif /* HAVE_AIRPCAP */
	{"/View/Statusbar",		NULL, "_Statusbar", NULL, NULL,	G_CALLBACK(status_bar_show_hide_cb), TRUE}, 
	{"/View/PacketList",	NULL, "Packet _List", NULL, NULL,	G_CALLBACK(packet_list_show_hide_cb), TRUE}, 
	{"/View/PacketDetails",	NULL, "Packet _Details", NULL, NULL,	G_CALLBACK(packet_details_show_hide_cb), TRUE}, 
	{"/View/PacketBytes",	NULL, "Packet _Bytes", NULL, NULL,	G_CALLBACK(packet_bytes_show_hide_cb), TRUE}, 
	{"/View/TimeDisplayFormat/DisplaySecondsWithHoursAndMinutes",	NULL, "Display Seconds with hours and minutes", NULL, NULL,	G_CALLBACK(view_menu_seconds_time_cb), FALSE}, 
	{"/View/NameResolution/ResolveName",							NULL, "_Resolve Name",							NULL, NULL,	G_CALLBACK(resolve_name_cb), FALSE},
	{"/View/NameResolution/EnableforMACLayer",						NULL, "Enable for _MAC Layer",					NULL, NULL, G_CALLBACK(view_menu_en_for_MAC_cb), TRUE},
	{"/View/NameResolution/EnableforNetworkLayer",					NULL, "Enable for _Network Layer",				NULL, NULL, G_CALLBACK(view_menu_en_for_network_cb), TRUE },
	{"/View/NameResolution/EnableforTransportLayer",				NULL, "Enable for _Transport Layer",			NULL, NULL, G_CALLBACK(view_menu_en_for_transport_cb), TRUE },
	{"/View/ColorizePacketList",									NULL, "Colorize Packet List",					NULL, NULL, G_CALLBACK(view_menu_colorize_pkt_lst_cb), TRUE },
#ifdef HAVE_LIBPCAP
	{"/View/AutoScrollinLiveCapture",								NULL, "Auto Scroll in Li_ve Capture",			NULL, NULL, G_CALLBACK(view_menu_auto_scroll_live_cb), TRUE },
#endif
};



static const GtkRadioActionEntry main_menu_bar_radio_view_time_entries [] =
{
	/* name, stock id, label, accel, tooltip,  value */
	{ "/View/TimeDisplayFormat/DateandTimeofDay",					NULL, "Date and Time of Day:   1970-01-01 01:02:03.123456", "<alt><control>1", NULL, TS_ABSOLUTE_WITH_DATE },
	{ "/View/TimeDisplayFormat/TimeofDay",							NULL, "Time of Day:   01:02:03.123456", "<alt><control>2", NULL, TS_ABSOLUTE },
	{ "/View/TimeDisplayFormat/SecondsSinceEpoch",					NULL, "Seconds Since Epoch (1970-01-01):   1234567890.123456", "<alt><control>3", NULL, TS_EPOCH },
	{ "/View/TimeDisplayFormat/SecondsSinceBeginningofCapture",		NULL, "Seconds Since Beginning of Capture:   123.123456", "<alt><control>4", NULL, TS_RELATIVE },
	{ "/View/TimeDisplayFormat/SecondsSincePreviousCapturedPacket", NULL, "Seconds Since Previous Captured Packet:   1.123456", "<alt><control>5", NULL, TS_DELTA },
	{ "/View/TimeDisplayFormat/SecondsSincePreviousDisplayedPacket",NULL, "Seconds Since Previous Displayed Packet:   1.123456", "<alt><control>6", NULL, TS_DELTA_DIS },
};

static const GtkRadioActionEntry main_menu_bar_radio_view_time_fileformat_prec_entries [] =
{
	/* name, stock id, label, accel, tooltip,  value */
	{ "/View/TimeDisplayFormat/FileFormatPrecision-Automatic",		NULL, "Automatic (File Format Precision)",	NULL, NULL, TS_PREC_AUTO },
	{ "/View/TimeDisplayFormat/FileFormatPrecision-Seconds",		NULL, "Seconds:   0",					    NULL, NULL, TS_PREC_FIXED_SEC },
	{ "/View/TimeDisplayFormat/FileFormatPrecision-Deciseconds",	NULL, "Deciseconds:   0.1",					NULL, NULL, TS_PREC_FIXED_DSEC },
	{ "/View/TimeDisplayFormat/FileFormatPrecision-Centiseconds",	NULL, "Centiseconds:  0.12",				NULL, NULL, TS_PREC_FIXED_CSEC },
	{ "/View/TimeDisplayFormat/FileFormatPrecision-Milliseconds",	NULL, "Milliseconds:  0.123",				NULL, NULL, TS_PREC_FIXED_MSEC },
	{ "/View/TimeDisplayFormat/FileFormatPrecision-Microseconds",	NULL, "Microseconds:  0.123456",			NULL, NULL, TS_PREC_FIXED_USEC },
	{ "/View/TimeDisplayFormat/FileFormatPrecision-Nanoseconds",	NULL, "Nanoseconds:   0.123456789",			NULL, NULL, TS_PREC_FIXED_NSEC },
};
#else /* MAIN_MENU_USE_UIMANAGER */
/*
 * Main menu.
 *
 * Please do not use keystrokes that are used as "universal" shortcuts in
 * various desktop environments:
 *
 *   Windows:
 *	http://support.microsoft.com/kb/126449
 *
 *   GNOME:
 *	http://library.gnome.org/users/user-guide/nightly/keyboard-skills.html.en
 *
 *   KDE:
 *	http://developer.kde.org/documentation/standards/kde/style/keys/shortcuts.html
 *
 * In particular, do not use the following <control> sequences for anything
 * other than their standard purposes:
 *
 *	<control>O	File->Open
 *	<control>S	File->Save
 *	<control>P	File->Print
 *	<control>W	File->Close
 *	<control>Q	File->Quit
 *	<control>Z	Edit->Undo (which we don't currently have)
 *	<control>X	Edit->Cut (which we don't currently have)
 *	<control>C	Edit->Copy (which we don't currently have)
 *	<control>V	Edit->Paste (which we don't currently have)
 *	<control>A	Edit->Select All (which we don't currently have)
 *
 * Note that some if not all of the Edit keys above already perform those
 * functions in text boxes, such as the Filter box.  Do no, under any
 * circumstances, make a change that keeps them from doing so.
 */

/* This is the GtkItemFactoryEntry structure used to generate new menus.
       Item 1: The menu path. The letter after the underscore indicates an
               accelerator key once the menu is open.
       Item 2: The accelerator key for the entry
       Item 3: The callback function.
       Item 4: The callback action.  This changes the parameters with
               which the function is called.  The default is 0.
       Item 5: The item type, used to define what kind of an item it is.
               Here are the possible values:

               NULL               -> "<Item>"
               ""                 -> "<Item>"
               "<Title>"          -> create a title item
               "<Item>"           -> create a simple item
               "<ImageItem>"      -> create an item holding an image
               "<StockItem>"      -> create an item holding a stock image
               "<CheckItem>"      -> create a check item
               "<ToggleItem>"     -> create a toggle item
               "<RadioItem>"      -> create a radio item
               <path>             -> path of a radio item to link against
               "<Separator>"      -> create a separator
               "<Tearoff>"        -> create a tearoff separator
               "<Branch>"         -> create an item to hold sub items (optional)
               "<LastBranch>"     -> create a right justified branch
       Item 6: extra data needed for ImageItem and StockItem
    */
static GtkItemFactoryEntry menu_items[] =
{
    {"/_File", NULL, NULL, 0, "<Branch>", NULL,},
    {"/File/_Open...", "<control>O", GTK_MENU_FUNC(file_open_cmd_cb),
                             0, "<StockItem>", GTK_STOCK_OPEN,},
    {"/File/Open _Recent", NULL, NULL, 0, "<Branch>", NULL,},
    {"/File/_Merge...", NULL, GTK_MENU_FUNC(file_merge_cmd_cb), 0, NULL, NULL,},
    {"/File/_Import...", NULL, GTK_MENU_FUNC(file_import_cmd_cb), 0, NULL, NULL,},
    {"/File/_Close", "<control>W", GTK_MENU_FUNC(file_close_cmd_cb),
                             0, "<StockItem>", GTK_STOCK_CLOSE,},
    {"/File/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/File/_Save", "<control>S", GTK_MENU_FUNC(file_save_cmd_cb),
                             0, "<StockItem>", GTK_STOCK_SAVE,},
    {"/File/Save _As...", "<shift><control>S", GTK_MENU_FUNC(file_save_as_cmd_cb),
                             0, "<StockItem>", GTK_STOCK_SAVE_AS,},
    {"/File/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/File/File Set", NULL, NULL, 0, "<Branch>", NULL,},
    {"/File/File Set/List Files", NULL, GTK_MENU_FUNC(fileset_cb), 0, "<StockItem>", WIRESHARK_STOCK_FILE_SET_LIST,},
    {"/File/File Set/Next File", NULL, GTK_MENU_FUNC(fileset_next_cb), 0, "<StockItem>", WIRESHARK_STOCK_FILE_SET_NEXT,},
    {"/File/File Set/Previous File", NULL, GTK_MENU_FUNC(fileset_previous_cb), 0, "<StockItem>", WIRESHARK_STOCK_FILE_SET_PREVIOUS,},
    {"/File/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/File/_Export", NULL, NULL, 0, "<Branch>", NULL,},
#if _WIN32
    {"/File/Export/File...", NULL, GTK_MENU_FUNC(export_text_cmd_cb),
                         0, NULL, NULL,},
#else
    {"/File/Export/as \"Plain _Text\" file...", NULL, GTK_MENU_FUNC(export_text_cmd_cb),
                             0, NULL, NULL,},
    {"/File/Export/as \"_PostScript\" file...", NULL, GTK_MENU_FUNC(export_ps_cmd_cb),
                             0, NULL, NULL,},
    {"/File/Export/as \"_CSV\" (Comma Separated Values packet summary) file...",
                             NULL, GTK_MENU_FUNC(export_csv_cmd_cb), 0, NULL, NULL,},
    {"/File/Export/as \"C _Arrays\" (packet bytes) file...", NULL, GTK_MENU_FUNC(export_carrays_cmd_cb),
                             0, NULL, NULL,},
    {"/File/Export/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/File/Export/as XML - \"P_SML\" (packet summary) file...", NULL, GTK_MENU_FUNC(export_psml_cmd_cb),
                             0, NULL, NULL,},
    {"/File/Export/as XML - \"P_DML\" (packet details) file...", NULL, GTK_MENU_FUNC(export_pdml_cmd_cb),
                             0, NULL, NULL,},
    {"/File/Export/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
#endif
    {"/File/Export/Selected Packet _Bytes...", "<control>H", GTK_MENU_FUNC(savehex_cb),
                             0, NULL, NULL,},
    {"/File/Export/_Objects/_HTTP", NULL, GTK_MENU_FUNC(eo_http_cb), 0, NULL, NULL,},
    {"/File/Export/_Objects/_DICOM", NULL, GTK_MENU_FUNC(eo_dicom_cb), 0, NULL, NULL,},
    {"/File/Export/_Objects/_SMB", NULL, GTK_MENU_FUNC(eo_smb_cb), 0, NULL, NULL,},
    {"/File/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/File/_Print...", "<control>P", GTK_MENU_FUNC(file_print_cmd_cb),
                             0, "<StockItem>", GTK_STOCK_PRINT,},
    {"/File/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/File/_Quit", "<control>Q", GTK_MENU_FUNC(file_quit_cmd_cb),
                             0, "<StockItem>", GTK_STOCK_QUIT,},
    {"/_Edit", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Edit/Copy", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Edit/Copy/Description", "<shift><control>D", GTK_MENU_FUNC(copy_selected_plist_cb), COPY_SELECTED_DESCRIPTION, NULL, NULL,},
    {"/Edit/Copy/Fieldname", "<shift><control>F", GTK_MENU_FUNC(copy_selected_plist_cb), COPY_SELECTED_FIELDNAME, NULL, NULL,},
    {"/Edit/Copy/Value", "<shift><control>V", GTK_MENU_FUNC(copy_selected_plist_cb), COPY_SELECTED_VALUE, NULL, NULL,},
    {"/Edit/Copy/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/Copy/As Filter", "<shift><control>C", GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_REPLACE|MATCH_SELECTED_COPY_ONLY, NULL, NULL,},
#if 0
    /*
     * Un-#if this when we actually implement Cut/Copy/Paste for the
     * packet list and packet detail windows.
     *
     * Note: when we implement Cut/Copy/Paste in those windows, we
     * will almost certainly want to allow multiple packets to be
     * selected in the packet list pane and multiple packet detail
     * items to be selected in the packet detail pane, so that
     * the user can, for example, copy the summaries of multiple
     * packets to the clipboard from the packet list pane and multiple
     * packet detail items - perhaps *all* packet detail items - from
     * the packet detail pane.  Given that, we'll also want to
     * implement Select All.
     *
     * If multiple packets are selected, we would probably display nothing
     * in the packet detail pane, just as we do if no packet is selected,
     * and any menu items etc. that would pertain only to a single packet
     * would be disabled.
     *
     * If multiple packet detail items are selected, we would probably
     * disable all items that pertain only to a single packet detail
     * item, such as some items in the status bar.
     *
     * XXX - the actions for these will be different depending on what
     * widget we're in; ^C should copy from the filter text widget if
     * we're in that widget, the packet list if we're in that widget
     * (presumably copying the summaries of selected packets to the
     * clipboard, e.g. the text copy would be the text of the columns),
     * the packet detail if we're in that widget (presumably copying
     * the contents of selected protocol tree items to the clipboard,
     * e.g. the text copy would be the text displayed for those items),
     * etc..
     *
     * Given that those menu items should also affect text widgets
     * such as the filter box, we would again want Select All, and,
     * at least for the filter box, we would also want Undo and Redo.
     * We would only want Cut, Paste, Undo, and Redo for the packet
     * list and packet detail panes if we support modifying them.
     */
    {"/Edit/_Undo", "<control>Z", NULL,
                             0, "<StockItem>", GTK_STOCK_UNDO,},
    {"/Edit/_Redo", "<shift><control>Z", NULL,
                             0, "<StockItem>", GTK_STOCK_REDO,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/Cu_t", "<control>X", NULL,
                             0, "<StockItem>", GTK_STOCK_CUT,},
    {"/Edit/_Copy", "<control>C", NULL,
                             0, "<StockItem>", GTK_STOCK_COPY,},
    {"/Edit/_Paste", "<control>V", NULL,
                             0, "<StockItem>", GTK_STOCK_PASTE,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/Select _All", "<control>A", NULL, 0,
#ifdef GTK_STOCK_SELECT_ALL	/* first appeared in 2.10 */
                             "<StockItem>", GTK_STOCK_SELECT_ALL,
#else
                             NULL, NULL,
#endif /* GTK_STOCK_SELECT_ALL */
    },
#endif /* 0 */
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/_Find Packet...",                             "<control>F", GTK_MENU_FUNC(find_frame_cb), 0, "<StockItem>", GTK_STOCK_FIND,},
    {"/Edit/Find Ne_xt",                                  "<control>N", GTK_MENU_FUNC(find_next_cb), 0, NULL, NULL,},
    {"/Edit/Find Pre_vious",                              "<control>B", GTK_MENU_FUNC(find_previous_cb), 0, NULL, NULL,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/_Mark Packet (toggle)",                       "<control>M", GTK_MENU_FUNC(new_packet_list_mark_frame_cb),0, NULL, NULL,},
    {"/Edit/Toggle Marking Of All Displayed Packets",        "<shift><alt><control>M", GTK_MENU_FUNC(new_packet_list_toggle_mark_all_displayed_frames_cb), 0, NULL, NULL,},
    {"/Edit/Mark All Displayed Packets",                  "<shift><control>M", GTK_MENU_FUNC(new_packet_list_mark_all_displayed_frames_cb), 0, NULL, NULL,},
    {"/Edit/Unmark All Displayed Packets",                "<alt><control>M", GTK_MENU_FUNC(new_packet_list_unmark_all_displayed_frames_cb), 0, NULL, NULL,},
    {"/Edit/Find Next Mark",                       "<shift><control>N", GTK_MENU_FUNC(find_next_mark_cb), 0, NULL, NULL,},
    {"/Edit/Find Previous Mark",                   "<shift><control>B", GTK_MENU_FUNC(find_prev_mark_cb), 0, NULL, NULL,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/_Ignore Packet (toggle)",                     "<control>D", GTK_MENU_FUNC(new_packet_list_ignore_frame_cb), 0, NULL, NULL,},
    /*
     * XXX - this next one overrides /Edit/Copy/Description
     */
    {"/Edit/Ignore All Displayed Packets (toggle)","<shift><control>D", GTK_MENU_FUNC(new_packet_list_ignore_all_displayed_frames_cb), 0, NULL, NULL,},
    {"/Edit/U_n-Ignore All Packets",                 "<alt><control>D", GTK_MENU_FUNC(new_packet_list_unignore_all_frames_cb), 0, NULL, NULL,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/Set Time Reference (toggle)",                 "<control>T", GTK_MENU_FUNC(reftime_frame_cb), REFTIME_TOGGLE, "<StockItem>", WIRESHARK_STOCK_TIME,},
    {"/Edit/Un-Time Reference All Packets",          "<alt><control>T", GTK_MENU_FUNC(new_packet_list_untime_reference_all_frames_cb), 0, NULL, NULL,},
    {"/Edit/Find Next Time Reference",               "<alt><control>N", GTK_MENU_FUNC(reftime_frame_cb), REFTIME_FIND_NEXT, NULL, NULL,},
    {"/Edit/Find Previous Time Reference",           "<alt><control>B", GTK_MENU_FUNC(reftime_frame_cb), REFTIME_FIND_PREV, NULL, NULL,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/Edit packet",							NULL,				GTK_MENU_FUNC(edit_window_cb), 0, NULL, NULL, },
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/_Configuration Profiles...", "<shift><control>A", GTK_MENU_FUNC(profile_dialog_cb), 0, NULL, NULL,},
    {"/Edit/_Preferences...", "<shift><control>P", GTK_MENU_FUNC(prefs_page_cb),
                             PREFS_PAGE_USER_INTERFACE, "<StockItem>", GTK_STOCK_PREFERENCES,},
    {"/_View", NULL, NULL, 0, "<Branch>", NULL,},
    {"/View/_Main Toolbar", NULL, GTK_MENU_FUNC(show_hide_cb), SHOW_HIDE_MAIN_TOOLBAR, "<CheckItem>", NULL,},
    {"/View/_Filter Toolbar", NULL, GTK_MENU_FUNC(show_hide_cb), SHOW_HIDE_FILTER_TOOLBAR, "<CheckItem>", NULL,},
#ifdef HAVE_AIRPCAP
    {"/View/_Wireless Toolbar", NULL, GTK_MENU_FUNC(show_hide_cb), SHOW_HIDE_AIRPCAP_TOOLBAR, "<CheckItem>", NULL,},
#endif
    {"/View/_Statusbar", NULL, GTK_MENU_FUNC(show_hide_cb), SHOW_HIDE_STATUSBAR, "<CheckItem>", NULL,},
    {"/View/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/View/Packet _List", NULL, GTK_MENU_FUNC(show_hide_cb), SHOW_HIDE_PACKET_LIST, "<CheckItem>", NULL,},
    {"/View/Packet _Details", NULL, GTK_MENU_FUNC(show_hide_cb), SHOW_HIDE_TREE_VIEW, "<CheckItem>", NULL,},
    {"/View/Packet _Bytes", NULL, GTK_MENU_FUNC(show_hide_cb), SHOW_HIDE_BYTE_VIEW, "<CheckItem>", NULL,},
    {"/View/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/View/_Time Display Format", NULL, NULL, 0, "<Branch>", NULL,},
    {"/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", "<alt><control>1", GTK_MENU_FUNC(timestamp_format_cb),
                        TS_ABSOLUTE_WITH_DATE, "<RadioItem>", NULL,},
    {"/View/Time Display Format/Time of Day:   01:02:03.123456", "<alt><control>2", GTK_MENU_FUNC(timestamp_format_cb),
                        TS_ABSOLUTE, "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", NULL,},
    {"/View/Time Display Format/Seconds Since Epoch (1970-01-01):   1234567890.123456", "<alt><control>3", GTK_MENU_FUNC(timestamp_format_cb),
                        TS_EPOCH, "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", NULL,},
    {"/View/Time Display Format/Seconds Since Beginning of Capture:   123.123456", "<alt><control>4", GTK_MENU_FUNC(timestamp_format_cb),
                        TS_RELATIVE, "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", NULL,},
    {"/View/Time Display Format/Seconds Since Previous Captured Packet:   1.123456", "<alt><control>5", GTK_MENU_FUNC(timestamp_format_cb),
                        TS_DELTA, "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", NULL,},
    {"/View/Time Display Format/Seconds Since Previous Displayed Packet:   1.123456", "<alt><control>6", GTK_MENU_FUNC(timestamp_format_cb),
                        TS_DELTA_DIS, "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", NULL,},
    {"/View/Time Display Format/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/View/Time Display Format/Automatic (File Format Precision)", NULL, GTK_MENU_FUNC(timestamp_precision_cb),
                        TS_PREC_AUTO, "<RadioItem>", NULL,},
    {"/View/Time Display Format/Seconds:   0", NULL, GTK_MENU_FUNC(timestamp_precision_cb),
                        TS_PREC_FIXED_SEC, "/View/Time Display Format/Automatic (File Format Precision)", NULL,},
    {"/View/Time Display Format/Deciseconds:   0.1", NULL, GTK_MENU_FUNC(timestamp_precision_cb),
                        TS_PREC_FIXED_DSEC, "/View/Time Display Format/Automatic (File Format Precision)", NULL,},
    {"/View/Time Display Format/Centiseconds:   0.12", NULL, GTK_MENU_FUNC(timestamp_precision_cb),
                        TS_PREC_FIXED_CSEC, "/View/Time Display Format/Automatic (File Format Precision)", NULL,},
    {"/View/Time Display Format/Milliseconds:   0.123", NULL, GTK_MENU_FUNC(timestamp_precision_cb),
                        TS_PREC_FIXED_MSEC, "/View/Time Display Format/Automatic (File Format Precision)", NULL,},
    {"/View/Time Display Format/Microseconds:   0.123456", NULL, GTK_MENU_FUNC(timestamp_precision_cb),
                        TS_PREC_FIXED_USEC, "/View/Time Display Format/Automatic (File Format Precision)", NULL,},
    {"/View/Time Display Format/Nanoseconds:   0.123456789", NULL, GTK_MENU_FUNC(timestamp_precision_cb),
                        TS_PREC_FIXED_NSEC, "/View/Time Display Format/Automatic (File Format Precision)", NULL,},
    {"/View/Time Display Format/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/View/Time Display Format/Display Seconds with hours and minutes", "<alt><control>0", GTK_MENU_FUNC(timestamp_seconds_time_cb), 0, "<CheckItem>", NULL,},
    {"/View/Name Resol_ution", NULL, NULL, 0, "<Branch>", NULL,},
    {"/View/Name Resolution/_Resolve Name", NULL, GTK_MENU_FUNC(resolve_name_cb), 0, NULL, NULL,},
    {"/View/Name Resolution/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/View/Name Resolution/Enable for _MAC Layer", NULL, GTK_MENU_FUNC(name_resolution_cb), RESOLV_MAC, "<CheckItem>", NULL,},
    {"/View/Name Resolution/Enable for _Network Layer", NULL, GTK_MENU_FUNC(name_resolution_cb), RESOLV_NETWORK, "<CheckItem>", NULL,},
    {"/View/Name Resolution/Enable for _Transport Layer", NULL, GTK_MENU_FUNC(name_resolution_cb), RESOLV_TRANSPORT, "<CheckItem>", NULL,},
    {"/View/Colorize Packet List", NULL, colorize_cb, 0, "<CheckItem>", NULL,},
#ifdef HAVE_LIBPCAP
    {"/View/Auto Scroll in Li_ve Capture", NULL, GTK_MENU_FUNC(auto_scroll_live_cb), 0, "<CheckItem>", NULL,},
#endif
    {"/View/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/View/_Zoom In", "<control>plus", GTK_MENU_FUNC(view_zoom_in_cb),
                             0, "<StockItem>", GTK_STOCK_ZOOM_IN,},
    {"/View/Zoom _Out", "<control>minus", GTK_MENU_FUNC(view_zoom_out_cb),
                             0, "<StockItem>", GTK_STOCK_ZOOM_OUT,},
    {"/View/_Normal Size", "<control>equal", GTK_MENU_FUNC(view_zoom_100_cb),
                             0, "<StockItem>", GTK_STOCK_ZOOM_100,},
    {"/View/Resize All Columns", "<shift><control>R", GTK_MENU_FUNC(new_packet_list_resize_columns_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_RESIZE_COLUMNS,},
    {"/View/Displayed Columns", NULL, NULL, 0, NULL, NULL,},
    {"/View/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/View/E_xpand Subtrees", "<shift>Right", GTK_MENU_FUNC(expand_tree_cb), 0, NULL, NULL,},
    {"/View/_Expand All", "<control>Right", GTK_MENU_FUNC(expand_all_cb),
                       0, NULL, NULL,},
    {"/View/Collapse _All", "<control>Left", GTK_MENU_FUNC(collapse_all_cb),
                       0, NULL, NULL,},
    {"/View/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/View/Colorize Conversation", NULL, NULL, 0, "<Branch>",NULL,},
    {"/View/Colorize Conversation/Color 1", "<control>1",
                       GTK_MENU_FUNC(colorize_conversation_cb), 1*256, "<StockItem>", WIRESHARK_STOCK_COLOR1,},
    {"/View/Colorize Conversation/Color 2", "<control>2",
                       GTK_MENU_FUNC(colorize_conversation_cb), 2*256, "<StockItem>", WIRESHARK_STOCK_COLOR2,},
    {"/View/Colorize Conversation/Color 3", "<control>3",
                       GTK_MENU_FUNC(colorize_conversation_cb), 3*256, "<StockItem>", WIRESHARK_STOCK_COLOR3,},
    {"/View/Colorize Conversation/Color 4", "<control>4",
                       GTK_MENU_FUNC(colorize_conversation_cb), 4*256, "<StockItem>", WIRESHARK_STOCK_COLOR4,},
    {"/View/Colorize Conversation/Color 5", "<control>5",
                       GTK_MENU_FUNC(colorize_conversation_cb), 5*256, "<StockItem>", WIRESHARK_STOCK_COLOR5,},
    {"/View/Colorize Conversation/Color 6", "<control>6",
                       GTK_MENU_FUNC(colorize_conversation_cb), 6*256, "<StockItem>", WIRESHARK_STOCK_COLOR6,},
    {"/View/Colorize Conversation/Color 7", "<control>7",
                       GTK_MENU_FUNC(colorize_conversation_cb), 7*256, "<StockItem>", WIRESHARK_STOCK_COLOR7,},
    {"/View/Colorize Conversation/Color 8", "<control>8",
                       GTK_MENU_FUNC(colorize_conversation_cb), 8*256, "<StockItem>", WIRESHARK_STOCK_COLOR8,},
    {"/View/Colorize Conversation/Color 9", "<control>9",
                       GTK_MENU_FUNC(colorize_conversation_cb), 9*256, "<StockItem>", WIRESHARK_STOCK_COLOR9,},
    {"/View/Colorize Conversation/Color 10", "<control>0",
                       GTK_MENU_FUNC(colorize_conversation_cb), 10*256, "<StockItem>", WIRESHARK_STOCK_COLOR0,},
    {"/View/Colorize Conversation/<separator>", NULL,
                       NULL, 0, "<Separator>",NULL,},
    {"/View/Colorize Conversation/New Coloring Rule...", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), 0, "<StockItem>", GTK_STOCK_SELECT_COLOR,},
    {"/View/Reset Coloring 1-10", "<control>space",
                       GTK_MENU_FUNC(colorize_conversation_cb), 255*256, NULL, NULL,},
    {"/View/_Coloring Rules...", NULL, color_display_cb,
                       0, "<StockItem>", GTK_STOCK_SELECT_COLOR,},
    {"/View/<separator>", NULL, NULL, 0, "<Separator>", NULL,},


    {"/View/Show Packet in New _Window", NULL,
                       GTK_MENU_FUNC(new_window_cb), 0, NULL, NULL,},
    {"/View/_Reload", "<control>R", GTK_MENU_FUNC(file_reload_cmd_cb),
                             0, "<StockItem>", GTK_STOCK_REFRESH,},
    {"/_Go", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Go/_Back", "<alt>Left",
                             GTK_MENU_FUNC(history_back_cb), 0, "<StockItem>", GTK_STOCK_GO_BACK,},
    {"/Go/_Forward", "<alt>Right",
                             GTK_MENU_FUNC(history_forward_cb), 0, "<StockItem>", GTK_STOCK_GO_FORWARD,},
    {"/Go/_Go to Packet...", "<control>G",
                             GTK_MENU_FUNC(goto_frame_cb), 0, "<StockItem>", GTK_STOCK_JUMP_TO,},
    {"/Go/Go to _Corresponding Packet", NULL, GTK_MENU_FUNC(goto_framenum_cb),
                       0, NULL, NULL,},
    {"/Go/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Go/Previous Packet", "<control>Up",
                             GTK_MENU_FUNC(goto_previous_frame_cb), 0, "<StockItem>", GTK_STOCK_GO_UP,},
    {"/Go/Next Packet", "<control>Down",
                             GTK_MENU_FUNC(goto_next_frame_cb), 0, "<StockItem>", GTK_STOCK_GO_DOWN,},
    {"/Go/F_irst Packet", "<control>Home",
                             GTK_MENU_FUNC(goto_top_frame_cb), 0, "<StockItem>", GTK_STOCK_GOTO_TOP,},
    {"/Go/_Last Packet", "<control>End",
                             GTK_MENU_FUNC(goto_bottom_frame_cb), 0, "<StockItem>", GTK_STOCK_GOTO_BOTTOM,},
    {"/Go/Previous Packet In Conversation", "<control>comma",
                             GTK_MENU_FUNC(goto_previous_frame_conversation_cb), 0, NULL, NULL,},
    {"/Go/Next Packet In Conversation", "<control>period",
                             GTK_MENU_FUNC(goto_next_frame_conversation_cb), 0, NULL, NULL,},
#ifdef HAVE_LIBPCAP
    {"/_Capture", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Capture/_Interfaces...", "<control>I",
                             GTK_MENU_FUNC(capture_if_cb), 0, "<StockItem>", WIRESHARK_STOCK_CAPTURE_INTERFACES,},
    {"/Capture/_Options...", "<control>K",
                             GTK_MENU_FUNC(capture_prep_cb), 0, "<StockItem>", WIRESHARK_STOCK_CAPTURE_OPTIONS,},
    {"/Capture/_Start", "<control>E",
                             GTK_MENU_FUNC(capture_start_cb), 0, "<StockItem>", WIRESHARK_STOCK_CAPTURE_START,},
    {"/Capture/S_top", "<control>E", GTK_MENU_FUNC(capture_stop_cb),
                             0, "<StockItem>", WIRESHARK_STOCK_CAPTURE_STOP,},
    {"/Capture/_Restart", "<control>R", GTK_MENU_FUNC(capture_restart_cb),
                             0, "<StockItem>", WIRESHARK_STOCK_CAPTURE_RESTART,},
    {"/Capture/Capture _Filters...", NULL, GTK_MENU_FUNC(cfilter_dialog_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_CAPTURE_FILTER,},
#endif /* HAVE_LIBPCAP */
    {"/_Analyze", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Analyze/_Display Filters...", NULL, GTK_MENU_FUNC(dfilter_dialog_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_DISPLAY_FILTER,},
    {"/Analyze/Display Filter _Macros...", NULL, GTK_MENU_FUNC(macros_dialog_cb), 0, NULL, NULL,},
    {"/Analyze/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Analyze/Apply as Column", NULL, GTK_MENU_FUNC(apply_as_custom_column_cb), 0, NULL, NULL},
    {"/Analyze/Appl_y as Filter", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Analyze/Apply as Filter/_Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/_Not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " _and Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " _or Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " a_nd not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/" UTF8_HORIZONTAL_ELLIPSIS " o_r not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/_Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Analyze/Prepare a Filter/_Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_REPLACE, NULL, NULL,},
    {"/Analyze/Prepare a Filter/_Not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_NOT, NULL, NULL,},
    {"/Analyze/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " _and Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND, NULL, NULL,},
    {"/Analyze/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " _or Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR, NULL, NULL,},
    {"/Analyze/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " a_nd not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND_NOT, NULL, NULL,},
    {"/Analyze/Prepare a Filter/" UTF8_HORIZONTAL_ELLIPSIS " o_r not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR_NOT, NULL, NULL,},
    {"/Analyze/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Analyze/_Enabled Protocols...", "<shift><control>E", GTK_MENU_FUNC(proto_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_CHECKBOX,},
    {"/Analyze/Decode _As...", NULL, GTK_MENU_FUNC(decode_as_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_DECODE_AS,},
    {"/Analyze/_User Specified Decodes...", NULL,
                       GTK_MENU_FUNC(decode_show_cb), 0, "<StockItem>", WIRESHARK_STOCK_DECODE_AS,},
    {"/Analyze/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Analyze/_Follow TCP Stream", NULL,
                       GTK_MENU_FUNC(follow_tcp_stream_cb), 0, NULL, NULL,},
    {"/Analyze/_Follow UDP Stream", NULL,
                       GTK_MENU_FUNC(follow_udp_stream_cb), 0, NULL, NULL,},
    {"/Analyze/_Follow SSL Stream", NULL,
                       GTK_MENU_FUNC(follow_ssl_stream_cb), 0, NULL, NULL,},
    {"/_Statistics", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Statistics/_Summary", NULL, GTK_MENU_FUNC(summary_open_cb), 0, "<StockItem>", GTK_STOCK_PROPERTIES,},
    {"/Statistics/_Protocol Hierarchy", NULL,
                       GTK_MENU_FUNC(proto_hier_stats_cb), 0, NULL, NULL,},
    {"/Statistics/Conversations", NULL,
                       GTK_MENU_FUNC(init_conversation_notebook_cb), 0, "<StockItem>", WIRESHARK_STOCK_CONVERSATIONS,},
    {"/Statistics/Endpoints", NULL,
                       GTK_MENU_FUNC(init_hostlist_notebook_cb), 0, "<StockItem>", WIRESHARK_STOCK_ENDPOINTS,},
    {"/Telephon_y", NULL, NULL, 0, "<Branch>", NULL,},
    {"/_Tools", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Tools/Firewall ACL Rules", NULL,
                       firewall_rule_cb, 0, NULL, NULL,},
    {"/_Internals", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Internals/_Dissector tables", NULL, GTK_MENU_FUNC(dissector_tables_dlg_cb), 0, NULL, NULL,},
    {"/Internals/_Supported Protocols (slow!)", NULL, GTK_MENU_FUNC(supported_cb), 0, NULL, NULL,},
    {"/_Help", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Help/_Contents", "F1", GTK_MENU_FUNC(topic_menu_cb), HELP_CONTENT, "<StockItem>", GTK_STOCK_HELP,},
    {"/Help/Manual Pages", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Help/Manual Pages/Wireshark", NULL, GTK_MENU_FUNC(topic_menu_cb), LOCALPAGE_MAN_WIRESHARK, NULL, NULL,},
    {"/Help/Manual Pages/Wireshark Filter", NULL, GTK_MENU_FUNC(topic_menu_cb), LOCALPAGE_MAN_WIRESHARK_FILTER, NULL, NULL,},
    {"/Help/Manual Pages/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Help/Manual Pages/TShark", NULL, GTK_MENU_FUNC(topic_menu_cb), LOCALPAGE_MAN_TSHARK, NULL, NULL,},
    {"/Help/Manual Pages/RawShark", NULL, GTK_MENU_FUNC(topic_menu_cb), LOCALPAGE_MAN_RAWSHARK, NULL, NULL,},
    {"/Help/Manual Pages/Dumpcap", NULL, GTK_MENU_FUNC(topic_menu_cb), LOCALPAGE_MAN_DUMPCAP, NULL, NULL,},
    {"/Help/Manual Pages/Mergecap", NULL, GTK_MENU_FUNC(topic_menu_cb), LOCALPAGE_MAN_MERGECAP, NULL, NULL,},
    {"/Help/Manual Pages/Editcap", NULL, GTK_MENU_FUNC(topic_menu_cb), LOCALPAGE_MAN_EDITCAP, NULL, NULL,},
    {"/Help/Manual Pages/Text2pcap", NULL, GTK_MENU_FUNC(topic_menu_cb), LOCALPAGE_MAN_TEXT2PCAP, NULL, NULL,},
    {"/Help/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Help/Website", NULL, GTK_MENU_FUNC(topic_menu_cb), ONLINEPAGE_HOME, "<StockItem>", GTK_STOCK_HOME,},
    {"/Help/FAQ's", NULL, GTK_MENU_FUNC(topic_menu_cb), ONLINEPAGE_FAQ, NULL, NULL,},
    {"/Help/Downloads", NULL, GTK_MENU_FUNC(topic_menu_cb), ONLINEPAGE_DOWNLOAD, NULL, NULL,},
    {"/Help/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Help/Wiki", NULL, GTK_MENU_FUNC(topic_menu_cb), ONLINEPAGE_WIKI, "<StockItem>", WIRESHARK_STOCK_WIKI,},
    {"/Help/Sample Captures", NULL, GTK_MENU_FUNC(topic_menu_cb), ONLINEPAGE_SAMPLE_FILES, NULL, NULL,},
    {"/Help/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Help/_About Wireshark", NULL, GTK_MENU_FUNC(about_wireshark_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_ABOUT}
};

/* calculate the number of menu_items */
static int nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);
#endif /* MAIN_MENU_USE_UIMANAGER */


static void
select_bytes_view_cb (GtkRadioAction *action, GtkRadioAction *current _U_, gpointer user_data _U_)
{
	gint value;

	value = gtk_radio_action_get_current_value (action);
	/* Fix me */
	select_bytes_view( NULL, NULL, value);
}

static void
sort_ascending_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/SortAscending");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_SORT_ASCENDING);
}

static void
sort_descending_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/SortDescending");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_SORT_DESCENDING);
}

static void
no_sorting_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/NoSorting");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_SORT_NONE);
}

static void
packet_list_heading_show_resolved_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/ShowResolved");

	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_TOGGLE_RESOLVED);
}

static void
packet_list_heading_align_left_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/AlignLeft");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_ALIGN_LEFT);
}

static void
packet_list_heading_align_center_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/AlignCenter");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_ALIGN_CENTER);
}

static void
packet_list_heading_align_right_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/AlignRight");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_ALIGN_RIGHT);
}

static void
packet_list_heading_col_pref_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/ColumnPreferences");
	prefs_page_cb( widget , user_data, PREFS_PAGE_COLUMNS);
}

static void
packet_list_heading_resize_col_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/ResizeColumn");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_RESIZE);
}

static void
packet_list_heading_change_col_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/RenameColumnTitle");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_CHANGE);
}

static void
packet_list_heading_activate_all_columns_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	new_packet_list_set_all_columns_visible ();
}

static void
packet_list_heading_hide_col_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/RenameColumnTitle");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_HIDE);
}

static void
packet_list_heading_remove_col_cb(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/RemoveColumn");
	new_packet_list_column_menu_cb( widget , user_data, COLUMN_SELECTED_REMOVE);
}

static void
packet_list_menu_set_ref_time_cb(GtkAction *action _U_, gpointer user_data)
{
	reftime_frame_cb( NULL /* widget _U_ */ , user_data, REFTIME_TOGGLE);
}


static void
packet_list_menu_apply_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb( NULL /* widget _U_ */, user_data, MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW);
}

static void
packet_list_menu_apply_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW);
}

static void
packet_list_menu_apply_and_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW);
}

static void
packet_list_menu_apply_or_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW);
}

static void
packet_list_menu_apply_and_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW);
}

static void
packet_list_menu_apply_or_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data,MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW);
}
/* Prepare a filter */
static void
packet_list_menu_prepare_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_REPLACE);
}

static void
packet_list_menu_prepare_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_NOT);
}

static void
packet_list_menu_prepare_and_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_AND);
}

static void
packet_list_menu_prepare_or_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_OR);
}

static void
packet_list_menu_prepare_and_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_AND_NOT);
}

static void
packet_list_menu_prepare_or_not_selected_cb(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb(  NULL /* widget _U_ */ , user_data, MATCH_SELECTED_OR_NOT);
}

static void
packet_list_menu_conversation_ethernet_cb(GtkAction *action, gpointer user_data)
{
	conversation_cb(  action, user_data, CONV_ETHER);
}

static void
packet_list_menu_conversation_ip_cb(GtkAction *action _U_, gpointer user_data)
{
	conversation_cb( action, user_data, CONV_IP);
}

static void
packet_list_menu_conversation_tcp_cb(GtkAction *action _U_, gpointer user_data)
{
	conversation_cb(  action, user_data, CONV_TCP);
}

static void
packet_list_menu_conversation_udp_cb(GtkAction *action _U_, gpointer user_data)
{
	conversation_cb(  action, user_data, CONV_UDP);
}

static void
packet_list_menu_conversation_pn_cba_cb(GtkAction *action _U_, gpointer user_data)
{
	conversation_cb(  action, user_data, CONV_CBA);
}

/* Ethernet */

static void
packet_list_menu_color_conv_ethernet_color1_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */, user_data, CONV_ETHER+1*256);
}

static void
packet_list_menu_color_conv_ethernet_color2_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL/* widget _U_ */ , user_data, CONV_ETHER+1*256);
}

static void
packet_list_menu_color_conv_ethernet_color3_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_ETHER+3*256);
}

static void
packet_list_menu_color_conv_ethernet_color4_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_ETHER+4*256);
}

static void
packet_list_menu_color_conv_ethernet_color5_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_ETHER+5*256);
}

static void
packet_list_menu_color_conv_ethernet_color6_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_ETHER+6*256);
}

static void
packet_list_menu_color_conv_ethernet_color7_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_ETHER+7*256);
}

static void
packet_list_menu_color_conv_ethernet_color8_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_ETHER+8*256);
}

static void
packet_list_menu_color_conv_ethernet_color9_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_ETHER+9*256);
}

static void
packet_list_menu_color_conv_ethernet_color10_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_ETHER+10*256);
}

static void
packet_list_menu_color_conv_ethernet_new_rule_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_ETHER);
}

/* IP */

static void
packet_list_menu_color_conv_ip_color1_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+1*256);
}

static void
packet_list_menu_color_conv_ip_color2_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+1*256);
}

static void
packet_list_menu_color_conv_ip_color3_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+3*256);
}

static void
packet_list_menu_color_conv_ip_color4_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+4*256);
}

static void
packet_list_menu_color_conv_ip_color5_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+5*256);
}

static void
packet_list_menu_color_conv_ip_color6_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+6*256);
}

static void
packet_list_menu_color_conv_ip_color7_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+7*256);
}

static void
packet_list_menu_color_conv_ip_color8_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+8*256);
}

static void
packet_list_menu_color_conv_ip_color9_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+9*256);
}

static void
packet_list_menu_color_conv_ip_color10_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_IP+10*256);
}

static void
packet_list_menu_color_conv_ip_new_rule_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP);
}

/* TCP */

static void
packet_list_menu_color_conv_tcp_color1_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+1*256);
}

static void
packet_list_menu_color_conv_tcp_color2_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+1*256);
}

static void
packet_list_menu_color_conv_tcp_color3_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+3*256);
}

static void
packet_list_menu_color_conv_tcp_color4_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+4*256);
}

static void
packet_list_menu_color_conv_tcp_color5_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+5*256);
}

static void
packet_list_menu_color_conv_tcp_color6_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+6*256);
}

static void
packet_list_menu_color_conv_tcp_color7_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+7*256);
}

static void
packet_list_menu_color_conv_tcp_color8_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+8*256);
}

static void
packet_list_menu_color_conv_tcp_color9_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+9*256);
}

static void
packet_list_menu_color_conv_tcp_color10_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP+10*256);
}

static void
packet_list_menu_color_conv_tcp_new_rule_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_TCP);
}

/* UDP */

static void
packet_list_menu_color_conv_udp_color1_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+1*256);
}

static void
packet_list_menu_color_conv_udp_color2_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+1*256);
}

static void
packet_list_menu_color_conv_udp_color3_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+3*256);
}

static void
packet_list_menu_color_conv_udp_color4_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+4*256);
}

static void
packet_list_menu_color_conv_udp_color5_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+5*256);
}

static void
packet_list_menu_color_conv_udp_color6_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+6*256);
}

static void
packet_list_menu_color_conv_udp_color7_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+7*256);
}

static void
packet_list_menu_color_conv_udp_color8_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+8*256);
}

static void
packet_list_menu_color_conv_udp_color9_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+9*256);
}

static void
packet_list_menu_color_conv_udp_color10_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP+10*256);
}

static void
packet_list_menu_color_conv_udp_new_rule_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_UDP);
}

/* CONV_CBA */

static void
packet_list_menu_color_conv_cba_color1_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+1*256);
}

static void
packet_list_menu_color_conv_cba_color2_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+1*256);
}

static void
packet_list_menu_color_conv_cba_color3_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+3*256);
}

static void
packet_list_menu_color_conv_cba_color4_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+4*256);
}

static void
packet_list_menu_color_conv_cba_color5_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+5*256);
}

static void
packet_list_menu_color_conv_cba_color6_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+6*256);
}

static void
packet_list_menu_color_conv_cba_color7_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+7*256);
}

static void
packet_list_menu_color_conv_cba_color8_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+8*256);
}

static void
packet_list_menu_color_conv_cba_color9_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+9*256);
}

static void
packet_list_menu_color_conv_cba_color10_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA+10*256);
}

static void
packet_list_menu_color_conv_cba_new_rule_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_conversation_cb( NULL /* widget _U_ */ , user_data, CONV_CBA);
}

static void
packet_list_menu_copy_sum_txt(GtkAction *action _U_, gpointer user_data)
{
	new_packet_list_copy_summary_cb( NULL /* widget _U_ */ , user_data, CS_TEXT);
}

static void
packet_list_menu_copy_sum_csv(GtkAction *action _U_, gpointer user_data)
{
	new_packet_list_copy_summary_cb( NULL /* widget _U_ */ , user_data, CS_CSV);
}

static void
packet_list_menu_copy_as_flt(GtkAction *action _U_, gpointer user_data)
{
	match_selected_plist_cb( NULL /* widget _U_ */ , user_data, MATCH_SELECTED_REPLACE|MATCH_SELECTED_COPY_ONLY);
}

static void
packet_list_menu_copy_bytes_oht_cb(GtkAction *action _U_, gpointer user_data)
{
	copy_hex_cb( NULL /* widget _U_ */ , user_data,  CD_ALLINFO | CD_FLAGS_SELECTEDONLY);
}

static void
packet_list_menu_copy_bytes_oh_cb(GtkAction *action _U_, gpointer user_data)
{
	copy_hex_cb( NULL /* widget _U_ */ , user_data, CD_HEXCOLUMNS | CD_FLAGS_SELECTEDONLY);
}

static void
packet_list_menu_copy_bytes_text_cb(GtkAction *action _U_, gpointer user_data)
{
	copy_hex_cb( NULL /* widget _U_ */ , user_data, CD_TEXTONLY | CD_FLAGS_SELECTEDONLY);
}

static void
packet_list_menu_copy_bytes_hex_strm_cb(GtkAction *action _U_, gpointer user_data)
{
	copy_hex_cb( NULL /* widget _U_ */ , user_data,  CD_HEX | CD_FLAGS_SELECTEDONLY);
}

static void
packet_list_menu_copy_bytes_bin_strm_cb(GtkAction *action _U_, gpointer user_data)
{
	copy_hex_cb( NULL /* widget _U_ */ , user_data, CD_BINARY | CD_FLAGS_SELECTEDONLY);
}

/* tree */

static void
tree_view_menu_color_with_flt_color1_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 1);
}

static void
tree_view_menu_color_with_flt_color2_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 2);
}

static void
tree_view_menu_color_with_flt_color3_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 3);
}

static void
tree_view_menu_color_with_flt_color4_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 4);
}

static void
tree_view_menu_color_with_flt_color5_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 5);
}

static void
tree_view_menu_color_with_flt_color6_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 6);
}

static void
tree_view_menu_color_with_flt_color7_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 7);
}

static void
tree_view_menu_color_with_flt_color8_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 8);
}

static void
tree_view_menu_color_with_flt_color9_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 9);
}

static void
tree_view_menu_color_with_flt_color10_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 10);
}

static void
tree_view_menu_color_with_flt_new_rule_cb(GtkAction *action _U_, gpointer user_data)
{
	colorize_selected_ptree_cb( NULL /* widget _U_ */ , user_data, 0);
}


static void
tree_view_menu_copy_desc(GtkAction *action _U_, gpointer user_data)
{
	copy_selected_plist_cb( NULL /* widget _U_ */ , user_data, COPY_SELECTED_DESCRIPTION);
}

static void
tree_view_menu_copy_field(GtkAction *action _U_, gpointer user_data)
{
	copy_selected_plist_cb( NULL /* widget _U_ */ , user_data, COPY_SELECTED_FIELDNAME);
}

static void
tree_view_menu_copy_value(GtkAction *action _U_, gpointer user_data)
{
	copy_selected_plist_cb( NULL /* widget _U_ */ , user_data, COPY_SELECTED_VALUE);
}

static void
tree_view_menu_copy_as_flt(GtkAction *action _U_, gpointer user_data)
{
	GtkWidget *widget = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/Copy/AsFilter");
	match_selected_ptree_cb( widget , user_data, MATCH_SELECTED_REPLACE|MATCH_SELECTED_COPY_ONLY);
}

static const char *ui_desc_packet_list_heading_menu_popup =
"<ui>\n"
"  <popup name='PacketListHeadingPopup' action='PopupAction'>\n"
"     <menuitem name='SortAscending' action='/Sort Ascending'/>\n"
"     <menuitem name='SortDescending' action='/Sort Descending'/>\n"
"     <menuitem name='NoSorting' action='/No Sorting'/>\n"
"     <separator/>\n"
"     <menuitem name='ShowResolved' action='/Show Resolved'/>\n"
"     <separator/>\n"
"     <menuitem name='AlignLeft' action='/Align Left'/>\n"
"     <menuitem name='AlignCenter' action='/Align Center'/>\n"
"     <menuitem name='AlignRight' action='/Align Right'/>\n"
"     <separator/>\n"
"     <menuitem name='ColumnPreferences' action='/Column Preferences'/>\n"
"     <menuitem name='EditColumnDetails' action='/Edit Column Details'/>\n"
"     <menuitem name='ResizeColumn' action='/Resize Column'/>\n"
"     <separator/>\n"
"     <menu name='DisplayedColumns' action='/Displayed Columns'>\n"
"       <menuitem name='Display All' action='/Displayed Columns/Display All'/>\n"
"     </menu>\n"
"     <menuitem name='HideColumn' action='/Hide Column'/>\n"
"     <menuitem name='RemoveColumn' action='/Remove Column'/>\n"
"  </popup>\n"
"</ui>\n";

static const GtkActionEntry packet_list_heading_menu_popup_action_entries[] = {
  { "/Sort Ascending",					GTK_STOCK_SORT_ASCENDING,			"Sort Ascending",			NULL,	NULL,	G_CALLBACK(sort_ascending_cb) },
  { "/Sort Descending",					GTK_STOCK_SORT_DESCENDING,			"Sort Descending",			NULL,	NULL,	G_CALLBACK(sort_descending_cb) },
  { "/No Sorting",						NULL,								"No Sorting",				NULL,	NULL,	G_CALLBACK(no_sorting_cb) },
  { "/Align Left",						GTK_STOCK_JUSTIFY_LEFT,				"Align Left",				NULL,	NULL,	G_CALLBACK(packet_list_heading_align_left_cb) },
  { "/Align Center",					GTK_STOCK_JUSTIFY_CENTER,			"Align Center",				NULL,	NULL,	G_CALLBACK(packet_list_heading_align_center_cb) },
  { "/Align Right",						GTK_STOCK_JUSTIFY_RIGHT,			"Align Right",				NULL,	NULL,	G_CALLBACK(packet_list_heading_align_right_cb) },
  { "/Column Preferences",				GTK_STOCK_PREFERENCES,				"Column Preferences...",	NULL,	NULL,	G_CALLBACK(packet_list_heading_col_pref_cb) },
  { "/Edit Column Details",				WIRESHARK_STOCK_EDIT,			"Edit Column Details...",	NULL,	NULL,	G_CALLBACK(packet_list_heading_change_col_cb) },
  { "/Resize Column",					WIRESHARK_STOCK_RESIZE_COLUMNS,		"Resize Column",			NULL,	NULL,	G_CALLBACK(packet_list_heading_resize_col_cb) },
  { "/Displayed Columns",				NULL,								"Displayed Columns",		NULL,	NULL,	NULL },
  { "/Displayed Columns/Display All",				NULL,					"Display All",				NULL,	NULL,	G_CALLBACK(packet_list_heading_activate_all_columns_cb) },
  { "/Hide Column",						NULL,								"Hide Column",				NULL,	NULL,	G_CALLBACK(packet_list_heading_hide_col_cb) },
  { "/Remove Column",					GTK_STOCK_DELETE,					"Remove Column",			NULL,	NULL,	G_CALLBACK(packet_list_heading_remove_col_cb) },
};

static const GtkToggleActionEntry packet_list_heading_menu_toggle_action_entries[] =
{
	/* name, stock id, label, accel, tooltip, callback, is_active */
	{"/Show Resolved",	NULL, "Show Resolved",	NULL, NULL,	G_CALLBACK(packet_list_heading_show_resolved_cb), FALSE},
};

static const char *ui_desc_packet_list_menu_popup =
"<ui>\n"
"  <popup name='PacketListMenuPopup' action='PopupAction'>\n"
"     <menuitem name='MarkPacket' action='/MarkPacket'/>\n"
"     <menuitem name='IgnorePacket' action='/IgnorePacket'/>\n"
"     <menuitem name='SetTimeReference' action='/Set Time Reference'/>\n"
"     <separator/>\n"
"     <menuitem name='ManuallyResolveAddress' action='/ManuallyResolveAddress'/>\n"
"     <separator/>\n"
"     <menu name= 'ApplyAsFilter' action='/Apply as Filter'>\n"
"       <menuitem name='Selected' action='/Apply as Filter/Selected'/>\n"
"       <menuitem name='NotSelected' action='/Apply as Filter/Not Selected'/>\n"
"       <menuitem name='AndSelected' action='/Apply as Filter/AndSelected'/>\n"
"       <menuitem name='OrSelected' action='/Apply as Filter/OrSelected'/>\n"
"       <menuitem name='AndNotSelected' action='/Apply as Filter/AndNotSelected'/>\n"
"       <menuitem name='OrNotSelected' action='/Apply as Filter/OrNotSelected'/>\n"
"     </menu>\n"
"     <menu name= 'PrepareaFilter' action='/Prepare a Filter'>\n"
"       <menuitem name='Selected' action='/Prepare a Filter/Selected'/>\n"
"       <menuitem name='NotSelected' action='/Prepare a Filter/Not Selected'/>\n"
"       <menuitem name='AndSelected' action='/Prepare a Filter/AndSelected'/>\n"
"       <menuitem name='OrSelected' action='/Prepare a Filter/OrSelected'/>\n"
"       <menuitem name='AndNotSelected' action='/Prepare a Filter/AndNotSelected'/>\n"
"       <menuitem name='OrNotSelected' action='/Prepare a Filter/OrNotSelected'/>\n"
"     </menu>\n"
"     <menu name= 'ConversationFilter' action='/Conversation Filter'>\n"
"       <menuitem name='Ethernet' action='/Conversation Filter/Ethernet'/>\n"
"       <menuitem name='IP' action='/Conversation Filter/IP'/>\n"
"       <menuitem name='TCP' action='/Conversation Filter/TCP'/>\n"
"       <menuitem name='UDP' action='/Conversation Filter/UDP'/>\n"
"       <menuitem name='PN-CBA' action='/Conversation Filter/PN-CBA'/>\n"
"     </menu>\n"
"     <menu name= 'ColorizeConversation' action='/Colorize Conversation'>\n"
"        <menu name= 'Ethernet' action='/Colorize Conversation/Ethernet'>\n"
"          <menuitem name='Color1' action='/Colorize Conversation/Ethernet/Color 1'/>\n"
"          <menuitem name='Color2' action='/Colorize Conversation/Ethernet/Color 2'/>\n"
"          <menuitem name='Color3' action='/Colorize Conversation/Ethernet/Color 3'/>\n"
"          <menuitem name='Color4' action='/Colorize Conversation/Ethernet/Color 4'/>\n"
"          <menuitem name='Color5' action='/Colorize Conversation/Ethernet/Color 5'/>\n"
"          <menuitem name='Color6' action='/Colorize Conversation/Ethernet/Color 6'/>\n"
"          <menuitem name='Color7' action='/Colorize Conversation/Ethernet/Color 7'/>\n"
"          <menuitem name='Color8' action='/Colorize Conversation/Ethernet/Color 8'/>\n"
"          <menuitem name='Color9' action='/Colorize Conversation/Ethernet/Color 9'/>\n"
"          <menuitem name='Color10' action='/Colorize Conversation/Ethernet/Color 10'/>\n"
"          <menuitem name='NewColoringRule' action='/Colorize Conversation/Ethernet/New Coloring Rule'/>\n"
"        </menu>\n"
"        <menu name= 'IP' action='/Colorize Conversation/IP'>\n"
"          <menuitem name='Color1' action='/Colorize Conversation/IP/Color 1'/>\n"
"          <menuitem name='Color2' action='/Colorize Conversation/IP/Color 2'/>\n"
"          <menuitem name='Color3' action='/Colorize Conversation/IP/Color 3'/>\n"
"          <menuitem name='Color4' action='/Colorize Conversation/IP/Color 4'/>\n"
"          <menuitem name='Color5' action='/Colorize Conversation/IP/Color 5'/>\n"
"          <menuitem name='Color6' action='/Colorize Conversation/IP/Color 6'/>\n"
"          <menuitem name='Color7' action='/Colorize Conversation/IP/Color 7'/>\n"
"          <menuitem name='Color8' action='/Colorize Conversation/IP/Color 8'/>\n"
"          <menuitem name='Color9' action='/Colorize Conversation/IP/Color 9'/>\n"
"          <menuitem name='Color10' action='/Colorize Conversation/IP/Color 10'/>\n"
"          <menuitem name='NewColoringRule' action='/Colorize Conversation/IP/New Coloring Rule'/>\n"
"        </menu>\n"
"        <menu name= 'TCP' action='/Colorize Conversation/TCP'>\n"
"          <menuitem name='Color1' action='/Colorize Conversation/TCP/Color 1'/>\n"
"          <menuitem name='Color2' action='/Colorize Conversation/TCP/Color 2'/>\n"
"          <menuitem name='Color3' action='/Colorize Conversation/TCP/Color 3'/>\n"
"          <menuitem name='Color4' action='/Colorize Conversation/TCP/Color 4'/>\n"
"          <menuitem name='Color5' action='/Colorize Conversation/TCP/Color 5'/>\n"
"          <menuitem name='Color6' action='/Colorize Conversation/TCP/Color 6'/>\n"
"          <menuitem name='Color7' action='/Colorize Conversation/TCP/Color 7'/>\n"
"          <menuitem name='Color8' action='/Colorize Conversation/TCP/Color 8'/>\n"
"          <menuitem name='Color9' action='/Colorize Conversation/TCP/Color 9'/>\n"
"          <menuitem name='Color10' action='/Colorize Conversation/TCP/Color 10'/>\n"
"          <menuitem name='NewColoringRule' action='/Colorize Conversation/TCP/New Coloring Rule'/>\n"
"        </menu>\n"
"        <menu name= 'UDP' action='/Colorize Conversation/UDP'>\n"
"          <menuitem name='Color1' action='/Colorize Conversation/UDP/Color 1'/>\n"
"          <menuitem name='Color2' action='/Colorize Conversation/UDP/Color 2'/>\n"
"          <menuitem name='Color3' action='/Colorize Conversation/UDP/Color 3'/>\n"
"          <menuitem name='Color4' action='/Colorize Conversation/UDP/Color 4'/>\n"
"          <menuitem name='Color5' action='/Colorize Conversation/UDP/Color 5'/>\n"
"          <menuitem name='Color6' action='/Colorize Conversation/UDP/Color 6'/>\n"
"          <menuitem name='Color7' action='/Colorize Conversation/UDP/Color 7'/>\n"
"          <menuitem name='Color8' action='/Colorize Conversation/UDP/Color 8'/>\n"
"          <menuitem name='Color9' action='/Colorize Conversation/UDP/Color 9'/>\n"
"          <menuitem name='Color10' action='/Colorize Conversation/UDP/Color 10'/>\n"
"          <menuitem name='NewColoringRule' action='/Colorize Conversation/UDP/New Coloring Rule'/>\n"
"        </menu>\n"
"        <menu name= 'PN-CBA' action='/Colorize Conversation/PN-CBA'>\n"
"          <menuitem name='Color1' action='/Colorize Conversation/PN-CBA/Color 1'/>\n"
"          <menuitem name='Color2' action='/Colorize Conversation/PN-CBA/Color 2'/>\n"
"          <menuitem name='Color3' action='/Colorize Conversation/PN-CBA/Color 3'/>\n"
"          <menuitem name='Color4' action='/Colorize Conversation/PN-CBA/Color 4'/>\n"
"          <menuitem name='Color5' action='/Colorize Conversation/PN-CBA/Color 5'/>\n"
"          <menuitem name='Color6' action='/Colorize Conversation/PN-CBA/Color 6'/>\n"
"          <menuitem name='Color7' action='/Colorize Conversation/PN-CBA/Color 7'/>\n"
"          <menuitem name='Color8' action='/Colorize Conversation/PN-CBA/Color 8'/>\n"
"          <menuitem name='Color9' action='/Colorize Conversation/PN-CBA/Color 9'/>\n"
"          <menuitem name='Color10' action='/Colorize Conversation/PN-CBA/Color 10'/>\n"
"          <menuitem name='NewColoringRule' action='/Colorize Conversation/PN-CBA/New Coloring Rule'/>\n"
"        </menu>\n"
"     </menu>\n"
"     <menu name= 'SCTP' action='/SCTP'>\n"
"        <menuitem name='AnalysethisAssociation' action='/SCTP/Analyse this Association'/>\n"
"        <menuitem name='PrepareFilterforthisAssociation' action='/SCTP/Prepare Filter for this Association'/>\n"
"     </menu>\n"
"     <menuitem name='FollowTCPStream' action='/Follow TCP Stream'/>\n"
"     <menuitem name='FollowUDPStream' action='/Follow UDP Stream'/>\n"
"     <menuitem name='FollowSSLStream' action='/Follow SSL Stream'/>\n"
"     <separator/>\n"
"     <menu name= 'Copy' action='/Copy'>\n"
"        <menuitem name='SummaryTxt' action='/Copy/SummaryTxt'/>\n"
"        <menuitem name='SummaryCSV' action='/Copy/SummaryCSV'/>\n"
"        <menuitem name='AsFilter' action='/Copy/AsFilter'/>\n"
"        <separator/>\n"
"        <menu name= 'Bytes' action='/Copy/Bytes'>\n"
"           <menuitem name='OffsetHexText' action='/Copy/Bytes/OffsetHexText'/>\n"
"           <menuitem name='OffsetHex' action='/Copy/Bytes/OffsetHex'/>\n"
"           <menuitem name='PrintableTextOnly' action='/Copy/Bytes/PrintableTextOnly'/>\n"
"           <separator/>\n"
"           <menuitem name='HexStream' action='/Copy/Bytes/HexStream'/>\n"
"           <menuitem name='BinaryStream' action='/Copy/Bytes/BinaryStream'/>\n"
"        </menu>\n"
"     </menu>\n"
"     <separator/>\n"
"     <menuitem name='DecodeAs' action='/DecodeAs'/>\n"
"     <menuitem name='Print' action='/Print'/>\n"
"     <menuitem name='ShowPacketinNewWindow' action='/ShowPacketinNewWindow'/>\n"
"  </popup>\n"
"</ui>\n";

static const GtkActionEntry packet_list_menu_popup_action_entries[] = {
  { "/MarkPacket",						NULL,					"Mark Packet (toggle)",			NULL,					NULL,			G_CALLBACK(new_packet_list_mark_frame_cb) },
  { "/IgnorePacket",					NULL,					"Ignore Packet (toggle)",		NULL,					NULL,			G_CALLBACK(new_packet_list_ignore_frame_cb) },
  { "/Set Time Reference",				WIRESHARK_STOCK_TIME,	"Set Time Reference (toggle)",	NULL,					NULL,			G_CALLBACK(packet_list_menu_set_ref_time_cb) },
  { "/ManuallyResolveAddress",			NULL,					"Manually Resolve Address",		NULL,					NULL,			G_CALLBACK(manual_addr_resolv_dlg) },
  { "/Apply as Filter",					NULL,					"Apply as Filter",				NULL,					NULL,			NULL },

  { "/Apply as Filter/Selected",		NULL, "_Selected" ,				NULL, NULL, G_CALLBACK(packet_list_menu_apply_selected_cb) },
  { "/Apply as Filter/Not Selected",	NULL, "_Not Selected",			NULL, NULL, G_CALLBACK(packet_list_menu_apply_not_selected_cb) },
  { "/Apply as Filter/AndSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _and Selected",		NULL, NULL, G_CALLBACK(packet_list_menu_apply_and_selected_cb) },
  { "/Apply as Filter/OrSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _or Selected",		NULL, NULL, G_CALLBACK(packet_list_menu_apply_or_selected_cb) },
  { "/Apply as Filter/AndNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " a_nd not Selected",	NULL, NULL, G_CALLBACK(packet_list_menu_apply_and_not_selected_cb) },
  { "/Apply as Filter/OrNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " o_r not Selected",	NULL, NULL, G_CALLBACK(packet_list_menu_apply_or_not_selected_cb) },

  { "/Prepare a Filter",				NULL, "Prepare a Filter",		NULL, NULL, NULL },
  { "/Prepare a Filter/Selected",		NULL, "_Selected" ,				NULL, NULL, G_CALLBACK(packet_list_menu_prepare_selected_cb) },
  { "/Prepare a Filter/Not Selected",	NULL, "_Not Selected",			NULL, NULL, G_CALLBACK(packet_list_menu_prepare_not_selected_cb) },
  { "/Prepare a Filter/AndSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " _and Selected",		NULL, NULL, G_CALLBACK(packet_list_menu_prepare_and_selected_cb) },
  { "/Prepare a Filter/OrSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _or Selected",		NULL, NULL, G_CALLBACK(packet_list_menu_prepare_or_selected_cb) },
  { "/Prepare a Filter/AndNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " a_nd not Selected",	NULL, NULL, G_CALLBACK(packet_list_menu_prepare_and_not_selected_cb) },
  { "/Prepare a Filter/OrNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " o_r not Selected",	NULL, NULL, G_CALLBACK(packet_list_menu_prepare_or_not_selected_cb) },

  { "/Conversation Filter",				NULL, "Conversation Filter",	NULL, NULL, NULL },
  { "/Conversation Filter/Ethernet",	NULL, "Ethernet",				NULL, NULL, G_CALLBACK(packet_list_menu_conversation_ethernet_cb) },
  { "/Conversation Filter/IP",			NULL, "IP",						NULL, NULL, G_CALLBACK(packet_list_menu_conversation_ip_cb) },
  { "/Conversation Filter/TCP",			NULL, "TCP",					NULL, NULL, G_CALLBACK(packet_list_menu_conversation_tcp_cb) },
  { "/Conversation Filter/UDP",			NULL, "UDP",					NULL, NULL, G_CALLBACK(packet_list_menu_conversation_udp_cb) },
  { "/Conversation Filter/PN-CBA",		NULL, "PN-CBA",					NULL, NULL, G_CALLBACK(packet_list_menu_conversation_pn_cba_cb) },

  { "/Colorize Conversation",			NULL, "Colorize Conversation",	NULL, NULL, NULL },

  { "/Colorize Conversation/Ethernet",	NULL, "Ethernet",				NULL, NULL, NULL },

  { "/Colorize Conversation/Ethernet/Color 1",	WIRESHARK_STOCK_COLOR1, "Color 1",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color1_cb) },
  { "/Colorize Conversation/Ethernet/Color 2",	WIRESHARK_STOCK_COLOR2, "Color 2",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color2_cb) },
  { "/Colorize Conversation/Ethernet/Color 3",	WIRESHARK_STOCK_COLOR3, "Color 3",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color3_cb) },
  { "/Colorize Conversation/Ethernet/Color 4",	WIRESHARK_STOCK_COLOR4, "Color 4",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color4_cb) },
  { "/Colorize Conversation/Ethernet/Color 5",	WIRESHARK_STOCK_COLOR5, "Color 5",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color5_cb) },
  { "/Colorize Conversation/Ethernet/Color 6",	WIRESHARK_STOCK_COLOR6, "Color 6",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color6_cb) },
  { "/Colorize Conversation/Ethernet/Color 7",	WIRESHARK_STOCK_COLOR7, "Color 7",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color7_cb) },
  { "/Colorize Conversation/Ethernet/Color 8",	WIRESHARK_STOCK_COLOR8, "Color 8",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color8_cb) },
  { "/Colorize Conversation/Ethernet/Color 9",	WIRESHARK_STOCK_COLOR9, "Color 9",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color9_cb) },
  { "/Colorize Conversation/Ethernet/Color 10",	WIRESHARK_STOCK_COLOR0, "Color 10",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_color10_cb) },
  { "/Colorize Conversation/Ethernet/New Coloring Rule",	NULL,		"New Coloring Rule...",		NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ethernet_new_rule_cb) },

  { "/Colorize Conversation/IP",		NULL, "IP",				NULL, NULL, NULL },

  { "/Colorize Conversation/IP/Color 1",		WIRESHARK_STOCK_COLOR1, "Color 1",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color1_cb) },
  { "/Colorize Conversation/IP/Color 2",		WIRESHARK_STOCK_COLOR2, "Color 2",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color2_cb) },
  { "/Colorize Conversation/IP/Color 3",		WIRESHARK_STOCK_COLOR3, "Color 3",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color3_cb) },
  { "/Colorize Conversation/IP/Color 4",		WIRESHARK_STOCK_COLOR4, "Color 4",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color4_cb) },
  { "/Colorize Conversation/IP/Color 5",		WIRESHARK_STOCK_COLOR5, "Color 5",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color5_cb) },
  { "/Colorize Conversation/IP/Color 6",		WIRESHARK_STOCK_COLOR6, "Color 6",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color6_cb) },
  { "/Colorize Conversation/IP/Color 7",		WIRESHARK_STOCK_COLOR7, "Color 7",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color7_cb) },
  { "/Colorize Conversation/IP/Color 8",		WIRESHARK_STOCK_COLOR8, "Color 8",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color8_cb) },
  { "/Colorize Conversation/IP/Color 9",		WIRESHARK_STOCK_COLOR9, "Color 9",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color9_cb) },
  { "/Colorize Conversation/IP/Color 10",		WIRESHARK_STOCK_COLOR0, "Color 10",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_color10_cb) },
  { "/Colorize Conversation/IP/New Coloring Rule",	NULL,		"New Coloring Rule...",				NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_ip_new_rule_cb) },

  { "/Colorize Conversation/TCP",		NULL, "TCP",				NULL, NULL, NULL },

  { "/Colorize Conversation/TCP/Color 1",		WIRESHARK_STOCK_COLOR1, "Color 1",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color1_cb) },
  { "/Colorize Conversation/TCP/Color 2",		WIRESHARK_STOCK_COLOR2, "Color 2",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color2_cb) },
  { "/Colorize Conversation/TCP/Color 3",		WIRESHARK_STOCK_COLOR3, "Color 3",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color3_cb) },
  { "/Colorize Conversation/TCP/Color 4",		WIRESHARK_STOCK_COLOR4, "Color 4",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color4_cb) },
  { "/Colorize Conversation/TCP/Color 5",		WIRESHARK_STOCK_COLOR5, "Color 5",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color5_cb) },
  { "/Colorize Conversation/TCP/Color 6",		WIRESHARK_STOCK_COLOR6, "Color 6",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color6_cb) },
  { "/Colorize Conversation/TCP/Color 7",		WIRESHARK_STOCK_COLOR7, "Color 7",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color7_cb) },
  { "/Colorize Conversation/TCP/Color 8",		WIRESHARK_STOCK_COLOR8, "Color 8",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color8_cb) },
  { "/Colorize Conversation/TCP/Color 9",		WIRESHARK_STOCK_COLOR9, "Color 9",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color9_cb) },
  { "/Colorize Conversation/TCP/Color 10",		WIRESHARK_STOCK_COLOR0, "Color 10",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_color10_cb) },
  { "/Colorize Conversation/TCP/New Coloring Rule",	NULL,		"New Coloring Rule...",				NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_tcp_new_rule_cb) },

  { "/Colorize Conversation/UDP",		NULL, "UDP",				NULL, NULL, NULL },

  { "/Colorize Conversation/UDP/Color 1",		WIRESHARK_STOCK_COLOR1, "Color 1",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color1_cb) },
  { "/Colorize Conversation/UDP/Color 2",		WIRESHARK_STOCK_COLOR2, "Color 2",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color2_cb) },
  { "/Colorize Conversation/UDP/Color 3",		WIRESHARK_STOCK_COLOR3, "Color 3",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color3_cb) },
  { "/Colorize Conversation/UDP/Color 4",		WIRESHARK_STOCK_COLOR4, "Color 4",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color4_cb) },
  { "/Colorize Conversation/UDP/Color 5",		WIRESHARK_STOCK_COLOR5, "Color 5",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color5_cb) },
  { "/Colorize Conversation/UDP/Color 6",		WIRESHARK_STOCK_COLOR6, "Color 6",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color6_cb) },
  { "/Colorize Conversation/UDP/Color 7",		WIRESHARK_STOCK_COLOR7, "Color 7",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color7_cb) },
  { "/Colorize Conversation/UDP/Color 8",		WIRESHARK_STOCK_COLOR8, "Color 8",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color8_cb) },
  { "/Colorize Conversation/UDP/Color 9",		WIRESHARK_STOCK_COLOR9, "Color 9",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color9_cb) },
  { "/Colorize Conversation/UDP/Color 10",		WIRESHARK_STOCK_COLOR0, "Color 10",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_color10_cb) },
  { "/Colorize Conversation/UDP/New Coloring Rule",	NULL,		"New Coloring Rule...",				NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_udp_new_rule_cb) },

  { "/Colorize Conversation/PN-CBA",		NULL, "PN-CBA Server",				NULL, NULL, NULL },

  { "/Colorize Conversation/PN-CBA/Color 1",		WIRESHARK_STOCK_COLOR1, "Color 1",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color1_cb) },
  { "/Colorize Conversation/PN-CBA/Color 2",		WIRESHARK_STOCK_COLOR2, "Color 2",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color2_cb) },
  { "/Colorize Conversation/PN-CBA/Color 3",		WIRESHARK_STOCK_COLOR3, "Color 3",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color3_cb) },
  { "/Colorize Conversation/PN-CBA/Color 4",		WIRESHARK_STOCK_COLOR4, "Color 4",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color4_cb) },
  { "/Colorize Conversation/PN-CBA/Color 5",		WIRESHARK_STOCK_COLOR5, "Color 5",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color5_cb) },
  { "/Colorize Conversation/PN-CBA/Color 6",		WIRESHARK_STOCK_COLOR6, "Color 6",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color6_cb) },
  { "/Colorize Conversation/PN-CBA/Color 7",		WIRESHARK_STOCK_COLOR7, "Color 7",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color7_cb) },
  { "/Colorize Conversation/PN-CBA/Color 8",		WIRESHARK_STOCK_COLOR8, "Color 8",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color8_cb) },
  { "/Colorize Conversation/PN-CBA/Color 9",		WIRESHARK_STOCK_COLOR9, "Color 9",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color9_cb) },
  { "/Colorize Conversation/PN-CBA/Color 10",		WIRESHARK_STOCK_COLOR0, "Color 10",					NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_color10_cb) },
  { "/Colorize Conversation/PN-CBA/New Coloring Rule",	NULL,		"New Coloring Rule...",				NULL, NULL, G_CALLBACK(packet_list_menu_color_conv_cba_new_rule_cb) },

  { "/SCTP",		NULL, "SCTP",				NULL, NULL, NULL },
  { "/SCTP/Analyse this Association",				NULL,		"Analyse this Association",				NULL, NULL, G_CALLBACK(sctp_analyse_start) },
  { "/SCTP/Prepare Filter for this Association",	NULL,		"Prepare Filter for this Association",	NULL, NULL, G_CALLBACK(sctp_set_assoc_filter) },


  { "/Follow TCP Stream",							NULL,		"Follow TCP Stream",					NULL, NULL, G_CALLBACK(follow_tcp_stream_cb) },
  { "/Follow UDP Stream",							NULL,		"Follow UDP Stream",					NULL, NULL, G_CALLBACK(follow_udp_stream_cb) },
  { "/Follow SSL Stream",							NULL,		"Follow SSL Stream",					NULL, NULL, G_CALLBACK(follow_ssl_stream_cb) },

  { "/Copy",		NULL, "Copy",					NULL, NULL, NULL },
  { "/Copy/SummaryTxt",								NULL,		"Summary (Text)",						NULL, NULL, G_CALLBACK(packet_list_menu_copy_sum_txt) },
  { "/Copy/SummaryCSV",								NULL,		"Summary (CSV)",						NULL, NULL, G_CALLBACK(packet_list_menu_copy_sum_csv) },
  { "/Copy/AsFilter",								NULL,		"As Filter",							NULL, NULL, G_CALLBACK(packet_list_menu_copy_as_flt) },


  { "/Copy/Bytes",									NULL,		"Bytes",					NULL, NULL, NULL },
  { "/Copy/Bytes/OffsetHexText",					NULL,		"Offset Hex Text",						NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_oht_cb) },
  { "/Copy/Bytes/OffsetHex",						NULL,		"Offset Hex",							NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_oh_cb) },
  { "/Copy/Bytes/PrintableTextOnly",				NULL,		"Printable Text Only",					NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_text_cb) },

  { "/Copy/Bytes/HexStream",						NULL,		"Hex Stream",							NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_hex_strm_cb) },
  { "/Copy/Bytes/BinaryStream",						NULL,		"Binary Stream",						NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_bin_strm_cb) },

  { "/DecodeAs",									WIRESHARK_STOCK_DECODE_AS,	"Decode As...",			NULL, NULL, G_CALLBACK(decode_as_cb) },
  { "/Print",										GTK_STOCK_PRINT,			"Print...",				NULL, NULL, G_CALLBACK(file_print_selected_cmd_cb) },
  { "/ShowPacketinNewWindow",						NULL,			"Show Packet in New Window",		NULL, NULL, G_CALLBACK(new_window_cb) },

};

static const char *ui_desc_tree_view_menu_popup =
"<ui>\n"
"  <popup name='TreeViewPopup' action='PopupAction'>\n"
"     <menuitem name='ExpandSubtrees' action='/ExpandSubtrees'/>\n"
"     <menuitem name='ExpandAll' action='/ExpandAll'/>\n"
"     <menuitem name='CollapseAll' action='/CollapseAll'/>\n"
"     <separator/>\n"
"     <menuitem name='ApplyasColumn' action='/Apply as Column'/>\n"
"     <separator/>\n"
"     <menu name= 'ApplyAsFilter' action='/Apply as Filter'>\n"
"       <menuitem name='Selected' action='/Apply as Filter/Selected'/>\n"
"       <menuitem name='NotSelected' action='/Apply as Filter/Not Selected'/>\n"
"       <menuitem name='AndSelected' action='/Apply as Filter/AndSelected'/>\n"
"       <menuitem name='OrSelected' action='/Apply as Filter/OrSelected'/>\n"
"       <menuitem name='AndNotSelected' action='/Apply as Filter/AndNotSelected'/>\n"
"       <menuitem name='OrNotSelected' action='/Apply as Filter/OrNotSelected'/>\n"
"     </menu>\n"
"     <menu name= 'PrepareaFilter' action='/Prepare a Filter'>\n"
"       <menuitem name='Selected' action='/Prepare a Filter/Selected'/>\n"
"       <menuitem name='NotSelected' action='/Prepare a Filter/Not Selected'/>\n"
"       <menuitem name='AndSelected' action='/Prepare a Filter/AndSelected'/>\n"
"       <menuitem name='OrSelected' action='/Prepare a Filter/OrSelected'/>\n"
"       <menuitem name='AndNotSelected' action='/Prepare a Filter/AndNotSelected'/>\n"
"       <menuitem name='OrNotSelected' action='/Prepare a Filter/OrNotSelected'/>\n"
"     </menu>\n"
"     <menu name= 'ColorizewithFilter' action='/Colorize with Filter'>\n"
"       <menuitem name='Color1' action='/Colorize with Filter/Color 1'/>\n"
"       <menuitem name='Color2' action='/Colorize with Filter/Color 2'/>\n"
"       <menuitem name='Color3' action='/Colorize with Filter/Color 3'/>\n"
"       <menuitem name='Color4' action='/Colorize with Filter/Color 4'/>\n"
"       <menuitem name='Color5' action='/Colorize with Filter/Color 5'/>\n"
"       <menuitem name='Color6' action='/Colorize with Filter/Color 6'/>\n"
"       <menuitem name='Color7' action='/Colorize with Filter/Color 7'/>\n"
"       <menuitem name='Color8' action='/Colorize with Filter/Color 8'/>\n"
"       <menuitem name='Color9' action='/Colorize with Filter/Color 9'/>\n"
"       <menuitem name='Color10' action='/Colorize with Filter/Color 10'/>\n"
"       <menuitem name='NewColoringRule' action='/Colorize with Filter/New Coloring Rule'/>\n"
"     </menu>\n"
"     <menuitem name='FollowTCPStream' action='/Follow TCP Stream'/>\n"
"     <menuitem name='FollowUDPStream' action='/Follow UDP Stream'/>\n"
"     <menuitem name='FollowSSLStream' action='/Follow SSL Stream'/>\n"
"     <separator/>\n"
"     <menu name= 'Copy' action='/Copy'>\n"
"        <menuitem name='Description' action='/Copy/Description'/>\n"
"        <menuitem name='Fieldname' action='/Copy/Fieldname'/>\n"
"        <menuitem name='Value' action='/Copy/Value'/>\n"
"        <separator/>\n"
"        <menuitem name='AsFilter' action='/Copy/AsFilter'/>\n"
"        <separator/>\n"
"        <menu name= 'Bytes' action='/Copy/Bytes'>\n"
"           <menuitem name='OffsetHexText' action='/Copy/Bytes/OffsetHexText'/>\n"
"           <menuitem name='OffsetHex' action='/Copy/Bytes/OffsetHex'/>\n"
"           <menuitem name='PrintableTextOnly' action='/Copy/Bytes/PrintableTextOnly'/>\n"
"           <separator/>\n"
"           <menuitem name='HexStream' action='/Copy/Bytes/HexStream'/>\n"
"           <menuitem name='BinaryStream' action='/Copy/Bytes/BinaryStream'/>\n"
"        </menu>\n"
"     </menu>\n"
"     <menuitem name='ExportSelectedPacketBytes' action='/ExportSelectedPacketBytes'/>\n"
"     <separator/>\n"
"     <menuitem name='WikiProtocolPage' action='/WikiProtocolPage'/>\n"
"     <menuitem name='FilterFieldReference' action='/FilterFieldReference'/>\n"
#if GLIB_CHECK_VERSION(2,14,0) /* GRegex */
"     <menuitem name='ProtocolHelp' action='/ProtocolHelp'/>\n"
#endif /* GLIB_CHECK_VERSION(2,14,0) */
"     <menuitem name='ProtocolPreferences' action='/ProtocolPreferences'/>\n"
"     <separator/>\n"
"     <menuitem name='DecodeAs' action='/DecodeAs'/>\n"
"     <menuitem name='DisableProtocol' action='/DisableProtocol'/>\n"
"     <menuitem name='ResolveName' action='/ResolveName'/>\n"
"     <menuitem name='GotoCorrespondingPacket' action='/GotoCorrespondingPacket'/>\n"
"  </popup>\n"
"</ui>\n";

static const GtkActionEntry tree_view_menu_popup_action_entries[] = {
  { "/ExpandSubtrees",					NULL,							"Expand Subtrees",		NULL,					NULL,			G_CALLBACK(expand_tree_cb) },
  { "/ExpandAll",						NULL,							"Expand All",			NULL,					NULL,			G_CALLBACK(expand_all_cb) },
  { "/CollapseAll",						NULL,							"Collapse All",			NULL,					NULL,			G_CALLBACK(collapse_all_cb) },
  { "/Apply as Column",					NULL,							"Apply as Column",		NULL,					NULL,			G_CALLBACK(apply_as_custom_column_cb) },
  { "/Apply as Filter",					NULL,							"Apply as Filter",		NULL,					NULL,			NULL },

  { "/Apply as Filter/Selected",		NULL, "_Selected" ,				NULL, NULL, G_CALLBACK(tree_view_menu_apply_selected_cb) },
  { "/Apply as Filter/Not Selected",	NULL, "_Not Selected",			NULL, NULL, G_CALLBACK(tree_view_menu_apply_not_selected_cb) },
  { "/Apply as Filter/AndSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _and Selected",		NULL, NULL, G_CALLBACK(tree_view_menu_apply_and_selected_cb) },
  { "/Apply as Filter/OrSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _or Selected",		NULL, NULL, G_CALLBACK(tree_view_menu_apply_or_selected_cb) },
  { "/Apply as Filter/AndNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " a_nd not Selected",	NULL, NULL, G_CALLBACK(tree_view_menu_apply_and_not_selected_cb) },
  { "/Apply as Filter/OrNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " o_r not Selected",	NULL, NULL, G_CALLBACK(tree_view_menu_apply_or_not_selected_cb) },

  { "/Prepare a Filter",				NULL, "Prepare a Filter",		NULL, NULL, NULL },
  { "/Prepare a Filter/Selected",		NULL, "_Selected" ,				NULL, NULL, G_CALLBACK(tree_view_menu_prepare_selected_cb) },
  { "/Prepare a Filter/Not Selected",	NULL, "_Not Selected",			NULL, NULL, G_CALLBACK(tree_view_menu_prepare_not_selected_cb) },
  { "/Prepare a Filter/AndSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " _and Selected",		NULL, NULL, G_CALLBACK(tree_view_menu_prepare_and_selected_cb) },
  { "/Prepare a Filter/OrSelected",		NULL, UTF8_HORIZONTAL_ELLIPSIS " _or Selected",		NULL, NULL, G_CALLBACK(tree_view_menu_prepare_or_selected_cb) },
  { "/Prepare a Filter/AndNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " a_nd not Selected",	NULL, NULL, G_CALLBACK(tree_view_menu_prepare_and_not_selected_cb) },
  { "/Prepare a Filter/OrNotSelected",	NULL, UTF8_HORIZONTAL_ELLIPSIS " o_r not Selected",	NULL, NULL, G_CALLBACK(tree_view_menu_prepare_or_not_selected_cb) },

  { "/Colorize with Filter",			NULL, "Colorize with Filter",	NULL, NULL, NULL },
  { "/Colorize with Filter/Color 1",		WIRESHARK_STOCK_COLOR1, "Color 1",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color1_cb) },
  { "/Colorize with Filter/Color 2",		WIRESHARK_STOCK_COLOR2, "Color 2",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color2_cb) },
  { "/Colorize with Filter/Color 3",		WIRESHARK_STOCK_COLOR3, "Color 3",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color3_cb) },
  { "/Colorize with Filter/Color 4",		WIRESHARK_STOCK_COLOR4, "Color 4",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color4_cb) },
  { "/Colorize with Filter/Color 5",		WIRESHARK_STOCK_COLOR5, "Color 5",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color5_cb) },
  { "/Colorize with Filter/Color 6",		WIRESHARK_STOCK_COLOR6, "Color 6",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color6_cb) },
  { "/Colorize with Filter/Color 7",		WIRESHARK_STOCK_COLOR7, "Color 7",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color7_cb) },
  { "/Colorize with Filter/Color 8",		WIRESHARK_STOCK_COLOR8, "Color 8",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color8_cb) },
  { "/Colorize with Filter/Color 9",		WIRESHARK_STOCK_COLOR9, "Color 9",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color9_cb) },
  { "/Colorize with Filter/Color 10",		WIRESHARK_STOCK_COLOR0, "Color 10",					NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_color10_cb) },
  { "/Colorize with Filter/New Coloring Rule",	NULL,		"New Coloring Rule...",				NULL, NULL, G_CALLBACK(tree_view_menu_color_with_flt_new_rule_cb) },

  { "/Follow TCP Stream",							NULL,		"Follow TCP Stream",					NULL, NULL, G_CALLBACK(follow_tcp_stream_cb) },
  { "/Follow UDP Stream",							NULL,		"Follow UDP Stream",					NULL, NULL, G_CALLBACK(follow_udp_stream_cb) },
  { "/Follow SSL Stream",							NULL,		"Follow SSL Stream",					NULL, NULL, G_CALLBACK(follow_ssl_stream_cb) },

  { "/Copy",		NULL, "Copy",					NULL, NULL, NULL },
  { "/Copy/Description",							NULL,		"Description",						NULL, NULL, G_CALLBACK(tree_view_menu_copy_desc) },
  { "/Copy/Fieldname",								NULL,		"Fieldname",						NULL, NULL, G_CALLBACK(tree_view_menu_copy_field) },
  { "/Copy/Value",									NULL,		"Value",							NULL, NULL, G_CALLBACK(tree_view_menu_copy_value) },

  { "/Copy/AsFilter",								NULL,		"As Filter",						NULL, NULL, G_CALLBACK(tree_view_menu_copy_as_flt) },

  { "/Copy/Bytes",									NULL,		"Bytes",								NULL, NULL, NULL },
  { "/Copy/Bytes/OffsetHexText",					NULL,		"Offset Hex Text",						NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_oht_cb) },
  { "/Copy/Bytes/OffsetHex",						NULL,		"Offset Hex",							NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_oh_cb) },
  { "/Copy/Bytes/PrintableTextOnly",				NULL,		"Printable Text Only",					NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_text_cb) },

  { "/Copy/Bytes/HexStream",						NULL,		"Hex Stream",							NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_hex_strm_cb) },
  { "/Copy/Bytes/BinaryStream",						NULL,		"Binary Stream",						NULL, NULL, G_CALLBACK(packet_list_menu_copy_bytes_bin_strm_cb) },

  { "/ExportSelectedPacketBytes",					NULL,		"Export Selected Packet Bytes...",		NULL, NULL, G_CALLBACK(savehex_cb) },

  { "/WikiProtocolPage",			WIRESHARK_STOCK_WIKI,		"Wiki Protocol Page",					NULL, NULL, G_CALLBACK(selected_ptree_info_cb) },
  { "/FilterFieldReference",	WIRESHARK_STOCK_INTERNET,		"Filter Field Reference",				NULL, NULL, G_CALLBACK(selected_ptree_ref_cb) },
#if GLIB_CHECK_VERSION(2,14,0) /* GRegex */
  { "/ProtocolHelp",								NULL,		"Protocol Help",						NULL, NULL, NULL },
#endif /* GLIB_CHECK_VERSION(2,14,0) */
  { "/ProtocolPreferences",							NULL,		"Protocol Preferences",					NULL, NULL, NULL },
  { "/DecodeAs",				WIRESHARK_STOCK_DECODE_AS,		"Decode As...",							NULL, NULL, G_CALLBACK(decode_as_cb) },
  { "/DisableProtocol",			WIRESHARK_STOCK_CHECKBOX,		"Disable Protocol...",					NULL, NULL, G_CALLBACK(proto_disable_cb) },
  { "/ResolveName",									NULL,		"_Resolve Name",						NULL, NULL, G_CALLBACK(resolve_name_cb) },
  { "/GotoCorrespondingPacket",						NULL,		"_Go to Corresponding Packet",			NULL, NULL, G_CALLBACK(goto_framenum_cb) },
};

static const char *ui_desc_bytes_menu_popup =
"<ui>\n"
"  <popup name='BytesMenuPopup' action='PopupAction'>\n"
"     <menuitem name='HexView' action='/HexView'/>\n"
"     <menuitem name='BitsView' action='/BitsView'/>\n"
"  </popup>\n"
"</ui>\n";
static const GtkRadioActionEntry bytes_menu_radio_action_entries [] =
{
	/* name,	stock id,	label,		accel,	tooltip,  value */
	{ "/HexView",	NULL,		"Hex View",	NULL,	NULL,	  BYTES_HEX },
	{ "/BitsView",	NULL,		"Bits View",	NULL,	NULL,	  BYTES_BITS },
};

static const char *ui_statusbar_profiles_menu_popup =
"<ui>\n"
"  <popup name='ProfilesMenuPopup' action='PopupAction'>\n"
"     <menuitem name='Profiles' action='/Profiles'/>\n"
"     <separator/>\n"
"     <menuitem name='New' action='/New'/>\n"
"     <menuitem name='Copy' action='/Copy'/>\n"
"     <menuitem name='Delete' action='/Delete'/>\n"
"     <menuitem name='Rename' action='/Rename'/>\n"
"     <separator/>\n"
"     <menu name='Change' action='/Change'>\n"
"        <menuitem name='Default' action='/Change/Default'/>\n"
"     </menu>\n"
"  </popup>\n"
"</ui>\n";
static const GtkActionEntry statusbar_profiles_menu_action_entries [] =
{
	{ "/Profiles",	NULL,	"Configuration Profiles...",	NULL,	NULL,	  G_CALLBACK(profile_dialog_cb) },
	{ "/New",	GTK_STOCK_NEW,	"New...",	NULL,	NULL,	  G_CALLBACK(profile_new_cb) },
	{ "/Copy",	GTK_STOCK_COPY,	"Copy...",	NULL,	NULL,	  G_CALLBACK(profile_copy_cb) },
	{ "/Delete",	GTK_STOCK_DELETE,	"Delete",	NULL,	NULL,	  G_CALLBACK(profile_delete_cb) },
#if GLIB_CHECK_VERSION(2,6,0)
	{ "/Rename",	GTK_STOCK_EDIT,	"Rename...",	NULL,	NULL,	  G_CALLBACK(profile_rename_cb) },
#else
	{ "/Rename",	NULL,	"Rename...",	NULL,	NULL,	  G_CALLBACK(profile_rename_cb) },
#endif
	{ "/Change",	NULL,		"Change",	NULL,	NULL,	NULL },
	{ "/Change/Default",	NULL,	"Default",	NULL,	NULL,	  NULL },
};

GtkWidget *
main_menu_new(GtkAccelGroup ** table) {
    GtkWidget *menubar;
#ifdef HAVE_IGE_MAC_INTEGRATION
    GtkWidget *quit_item, *about_item, *preferences_item;
    IgeMacMenuGroup *group;
#endif
#ifdef HAVE_GTKOSXAPPLICATION
    GtkOSXApplication *theApp;
    GtkWidget * item;
    GtkOSXApplicationMenuGroup *group;
    GtkWidget * dock_menu;
#endif

    grp = gtk_accel_group_new();

    if (initialize)
        menus_init();

#ifdef MAIN_MENU_USE_UIMANAGER
    menubar = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar");
#else
    menubar = main_menu_factory->widget;
#endif
#ifdef HAVE_IGE_MAC_INTEGRATION
    if(prefs.gui_macosx_style) {
        ige_mac_menu_set_menu_bar(GTK_MENU_SHELL(menubar));
        ige_mac_menu_set_global_key_handler_enabled(TRUE);

        /* Create menu items to populate the application menu with.  We have to
         * do this because we are still using the old GtkItemFactory API for
         * the main menu. */
        group = ige_mac_menu_add_app_menu_group();
        about_item = gtk_menu_item_new_with_label("About");
        g_signal_connect(about_item, "activate", G_CALLBACK(about_wireshark_cb),
                         NULL);
        ige_mac_menu_add_app_menu_item(group, GTK_MENU_ITEM(about_item), NULL);

        group = ige_mac_menu_add_app_menu_group();
        preferences_item = gtk_menu_item_new_with_label("Preferences");
        g_signal_connect(preferences_item, "activate", G_CALLBACK(prefs_cb),
                         NULL);
        ige_mac_menu_add_app_menu_item(group, GTK_MENU_ITEM(preferences_item),
                                       NULL);
    }

    /* The quit item in the application menu shows up whenever ige mac
     * integration is enabled, even if the OS X UI style in Wireshark isn't
     * turned on. */
    quit_item = gtk_menu_item_new_with_label("Quit");
    g_signal_connect(quit_item, "activate", G_CALLBACK(file_quit_cmd_cb), NULL);
    ige_mac_menu_set_quit_menu_item(GTK_MENU_ITEM(quit_item));
#endif

#ifdef HAVE_GTKOSXAPPLICATION
    theApp = g_object_new(GTK_TYPE_OSX_APPLICATION, NULL);

    if(prefs.gui_macosx_style) {
        gtk_osxapplication_set_menu_bar(theApp, GTK_MENU_SHELL(menubar));
        gtk_osxapplication_set_use_quartz_accelerators(theApp, TRUE);

        group = gtk_osxapplication_add_app_menu_group (theApp);
        item = gtk_item_factory_get_item(main_menu_factory,"/Help/About Wireshark");
        gtk_osxapplication_add_app_menu_item(theApp, group,GTK_MENU_ITEM (item));

        group = gtk_osxapplication_add_app_menu_group (theApp);
        item = gtk_item_factory_get_item(main_menu_factory,"/Edit/Preferences...");
        gtk_osxapplication_add_app_menu_item(theApp, group,GTK_MENU_ITEM (item));

        group = gtk_osxapplication_add_app_menu_group (theApp);
        item = gtk_item_factory_get_item(main_menu_factory,"/Help");
        gtk_osxapplication_set_help_menu(theApp,GTK_MENU_ITEM(item));

        /* Quit item is not needed */
        gtk_item_factory_delete_item(main_menu_factory,"/File/Quit");
    }

    /* generate dock menu */
    dock_menu = gtk_menu_new();

    item = gtk_menu_item_new_with_label("Start");
    g_signal_connect(item, "activate", G_CALLBACK (capture_start_cb), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(dock_menu), item);

    item = gtk_menu_item_new_with_label("Stop");
    g_signal_connect(item, "activate", G_CALLBACK (capture_stop_cb), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(dock_menu), item);

    item = gtk_menu_item_new_with_label("Restart");
    g_signal_connect(item, "activate", G_CALLBACK (capture_restart_cb), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(dock_menu), item);

    gtk_osxapplication_set_dock_menu(theApp, GTK_MENU_SHELL(dock_menu));
#endif

    if (table)
        *table = grp;

    return menubar;
}

#ifdef MAIN_MENU_USE_UIMANAGER
static void
menu_dissector_filter_cb(  GtkAction *action _U_,  gpointer callback_data)
{
#else
static void
menu_dissector_filter_cb(  GtkWidget *widget _U_,
                                gpointer callback_data,
                                guint callback_action _U_)
{
#endif
    dissector_filter_t      *filter_entry = callback_data;
    GtkWidget               *filter_te;
    const char              *buf;

    filter_te = gtk_bin_get_child(GTK_BIN(g_object_get_data(G_OBJECT(top_level), E_DFILTER_CM_KEY)));

    /* XXX - this gets the packet_info of the last dissected packet, */
    /* which is not necessarily the last selected packet */
    /* e.g. "Update list of packets in real time" won't work correct */
    buf = filter_entry->build_filter_string(&cfile.edt->pi);

    gtk_entry_set_text(GTK_ENTRY(filter_te), buf);

    /* Run the display filter so it goes in effect - even if it's the
       same as the previous display filter. */
    main_filter_packets(&cfile, buf, TRUE);

    g_free( (void *) buf);
}

gboolean menu_dissector_filter_spe_cb(frame_data *fd _U_, epan_dissect_t *edt, gpointer callback_data) {
    dissector_filter_t *filter_entry = callback_data;

    /* XXX - this gets the packet_info of the last dissected packet, */
    /* which is not necessarily the last selected packet */
    /* e.g. "Update list of packets in real time" won't work correct */
    return (edt != NULL) ? filter_entry->is_filter_valid(&edt->pi) : FALSE;
}

void menu_dissector_filter(void) {
    GList *list_entry = dissector_filter_list;
    dissector_filter_t *filter_entry;

    while(list_entry != NULL) {
        filter_entry = list_entry->data;

#ifdef MAIN_MENU_USE_UIMANAGER
	register_stat_menu_item_stock(
		REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER,	  /* Group */
		"/Menubar/AnalyzeMenu/ConversationFilterMenu/Filters", /* GUI path */
		filter_entry->name,                           /* Name */
		NULL,                                         /* stock_id */
		filter_entry->name,                           /* label */
		NULL,                                         /* accelerator */
		NULL,                                         /* tooltip */
		G_CALLBACK(menu_dissector_filter_cb),         /* callback */
		FALSE,                                        /* enabled */
		menu_dissector_filter_spe_cb,                 /* selected_packet_enabled */
		NULL,                                         /* selected_tree_row_enabled */
		filter_entry);                                /* callback_data */
#else
        register_stat_menu_item(filter_entry->name, REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER,
            menu_dissector_filter_cb,
            menu_dissector_filter_spe_cb,
            NULL /* selected_tree_row_enabled */,
            filter_entry);
#endif

        list_entry = g_list_next(list_entry);
    }
}


static void
menus_init(void) {
    GtkActionGroup *packet_list_heading_action_group, *packet_list_action_group,
        *packet_list_details_action_group, *packet_list_byte_menu_action_group,
        *statusbar_profiles_action_group;
    GError *error = NULL;
#ifdef MAIN_MENU_USE_UIMANAGER
    guint merge_id;
#endif /* MAIN_MENU_USE_UIMANAGER */


    if (initialize) {
        initialize = FALSE;

        popup_menu_object = gtk_menu_new();

        /* packet list heading pop-up menu */
        packet_list_heading_action_group = gtk_action_group_new ("PacketListHeadingPopUpMenuActionGroup");

        gtk_action_group_add_actions (packet_list_heading_action_group,            /* the action group */
            packet_list_heading_menu_popup_action_entries,                         /* an array of action descriptions */
            G_N_ELEMENTS(packet_list_heading_menu_popup_action_entries),           /* the number of entries */
            popup_menu_object);                                                    /* data to pass to the action callbacks */

        gtk_action_group_add_toggle_actions(packet_list_heading_action_group,          /* the action group */
                                    packet_list_heading_menu_toggle_action_entries,    /* an array of action descriptions */
                                    G_N_ELEMENTS(packet_list_heading_menu_toggle_action_entries), /* the number of entries */
                                    NULL);                                                /* data to pass to the action callbacks */

        ui_manager_packet_list_heading = gtk_ui_manager_new ();
        gtk_ui_manager_insert_action_group (ui_manager_packet_list_heading,
            packet_list_heading_action_group,
            0); /* the position at which the group will be inserted.  */

        gtk_ui_manager_add_ui_from_string (ui_manager_packet_list_heading,ui_desc_packet_list_heading_menu_popup, -1, &error);
        if (error != NULL)
        {
            fprintf (stderr, "Warning: building Packet List Heading Pop-Up failed: %s\n",
                    error->message);
            g_error_free (error);
            error = NULL;
        }

        g_object_set_data(G_OBJECT(popup_menu_object), PM_PACKET_LIST_COL_KEY,
                       gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup"));

        popup_menu_list = g_slist_append((GSList *)popup_menu_list, ui_manager_packet_list_heading);

        /* packet list pop-up menu */
        packet_list_action_group = gtk_action_group_new ("PacketListPopUpMenuActionGroup");

        gtk_action_group_add_actions (packet_list_action_group,                    /* the action group */
            packet_list_menu_popup_action_entries,                                 /* an array of action descriptions */
            G_N_ELEMENTS(packet_list_menu_popup_action_entries),                   /* the number of entries */
            popup_menu_object);                                                    /* data to pass to the action callbacks */

        ui_manager_packet_list_menu = gtk_ui_manager_new ();

        gtk_ui_manager_insert_action_group (ui_manager_packet_list_menu,
            packet_list_action_group,
            0); /* the position at which the group will be inserted.  */

        gtk_ui_manager_add_ui_from_string (ui_manager_packet_list_menu, ui_desc_packet_list_menu_popup, -1, &error);
        if (error != NULL)
        {
            fprintf (stderr, "Warning: building Packet List Pop-Up menu failed: %s\n",
                    error->message);
            g_error_free (error);
            error = NULL;
        }

        g_object_set_data(G_OBJECT(popup_menu_object), PM_PACKET_LIST_KEY,
                        gtk_ui_manager_get_widget(ui_manager_packet_list_menu, "/PacketListMenuPopup"));

        popup_menu_list = g_slist_append((GSList *)popup_menu_list, ui_manager_packet_list_menu);


        /* packet detail pop-up menu */
        packet_list_details_action_group = gtk_action_group_new ("PacketListDetailsMenuPopUpActionGroup");

        gtk_action_group_add_actions (packet_list_details_action_group,            /* the action group */
            tree_view_menu_popup_action_entries,                                   /* an array of action descriptions */
            G_N_ELEMENTS(tree_view_menu_popup_action_entries),                     /* the number of entries */
            popup_menu_object);                                                    /* data to pass to the action callbacks */

        ui_manager_tree_view_menu = gtk_ui_manager_new ();

        gtk_ui_manager_insert_action_group (ui_manager_tree_view_menu,
            packet_list_details_action_group,
            0); /* the position at which the group will be inserted.  */

        gtk_ui_manager_add_ui_from_string (ui_manager_tree_view_menu, ui_desc_tree_view_menu_popup, -1, &error);
        if (error != NULL)
        {
            fprintf (stderr, "Warning: building TreeWiew Pop-Up menu failed: %s\n",
                    error->message);
            g_error_free (error);
            error = NULL;
        }

        g_object_set_data(G_OBJECT(popup_menu_object), PM_TREE_VIEW_KEY,
                         gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup"));

        popup_menu_list = g_slist_append((GSList *)popup_menu_list, ui_manager_tree_view_menu);

        /*
         * Hex dump pop-up menu.
         * We provide our own empty menu to suppress the default pop-up menu
         * for text widgets.
         */
        packet_list_byte_menu_action_group = gtk_action_group_new ("PacketListByteMenuPopUpActionGroup");


        gtk_action_group_add_radio_actions  (packet_list_byte_menu_action_group,            /* the action group */
                                    bytes_menu_radio_action_entries,                        /* an array of radio action descriptions  */
                                    G_N_ELEMENTS(bytes_menu_radio_action_entries),          /* the number of entries */
                                    recent.gui_bytes_view,                                  /* the value of the action to activate initially, or -1 if no action should be activated  */
                                    G_CALLBACK(select_bytes_view_cb),                       /* the callback to connect to the changed signal  */
                                    popup_menu_object);                                     /* data to pass to the action callbacks  */

        ui_manager_bytes_menu = gtk_ui_manager_new ();

        gtk_ui_manager_insert_action_group (ui_manager_bytes_menu,
            packet_list_byte_menu_action_group,
            0); /* the position at which the group will be inserted.  */

        gtk_ui_manager_add_ui_from_string (ui_manager_bytes_menu, ui_desc_bytes_menu_popup, -1, &error);
        if (error != NULL)
        {
            fprintf (stderr, "Warning: building Bytes Pop-Up menu failed: %s\n",
                    error->message);
            g_error_free (error);
            error = NULL;
        }

        g_object_unref(packet_list_byte_menu_action_group);

        g_object_set_data(G_OBJECT(popup_menu_object), PM_BYTES_VIEW_KEY,
                        gtk_ui_manager_get_widget(ui_manager_bytes_menu, "/BytesMenuPopup"));

        popup_menu_list = g_slist_append((GSList *)popup_menu_list, ui_manager_bytes_menu);

        /* main */
#ifdef MAIN_MENU_USE_UIMANAGER
        main_menu_bar_action_group = gtk_action_group_new ("MenuActionGroup"); 
        gtk_action_group_add_actions (main_menu_bar_action_group,                       /* the action group */
                                    main_menu_bar_entries,                              /* an array of action descriptions */
                                    G_N_ELEMENTS(main_menu_bar_entries),                /* the number of entries */
                                    NULL);                                              /* data to pass to the action callbacks */

        gtk_action_group_add_toggle_actions(main_menu_bar_action_group,                 /* the action group */
                                    main_menu_bar_toggle_action_entries,                /* an array of action descriptions */
                                    G_N_ELEMENTS(main_menu_bar_toggle_action_entries),  /* the number of entries */
                                    NULL);                                              /* data to pass to the action callbacks */

        gtk_action_group_add_radio_actions  (main_menu_bar_action_group,                 /* the action group */
                                    main_menu_bar_radio_view_time_entries,               /* an array of radio action descriptions  */
                                    G_N_ELEMENTS(main_menu_bar_radio_view_time_entries), /* the number of entries */
                                    recent.gui_time_format,                              /* the value of the action to activate initially, or -1 if no action should be activated  */
                                    G_CALLBACK(timestamp_format_new_cb),                 /* the callback to connect to the changed signal  */
                                    NULL);                                               /* data to pass to the action callbacks  */

        gtk_action_group_add_radio_actions  (main_menu_bar_action_group,                                    /* the action group */
                                    main_menu_bar_radio_view_time_fileformat_prec_entries,                  /* an array of radio action descriptions  */
                                    G_N_ELEMENTS(main_menu_bar_radio_view_time_fileformat_prec_entries),    /* the number of entries */
                                    recent.gui_time_precision,                                /* the value of the action to activate initially, or -1 if no action should be activated  */
                                    G_CALLBACK(timestamp_precision_new_cb),                   /* the callback to connect to the changed signal  */
                                    NULL);                                                    /* data to pass to the action callbacks  */



        ui_manager_main_menubar = gtk_ui_manager_new ();
        gtk_ui_manager_insert_action_group (ui_manager_main_menubar, main_menu_bar_action_group, 0);
        gtk_ui_manager_add_ui_from_string (ui_manager_main_menubar,ui_desc_menubar, -1, &error); 
        if (error != NULL) 
        { 
            fprintf (stderr, "Warning: building main menubar failed: %s\n", 
                    error->message); 
            g_error_free (error); 
            error = NULL; 
        }
        g_object_unref(main_menu_bar_action_group);
        gtk_window_add_accel_group (GTK_WINDOW(top_level),
                                gtk_ui_manager_get_accel_group(ui_manager_main_menubar));


        /* Add the recent files items to the menu
         * use place holders and
         * gtk_ui_manager_add_ui().
         */
        merge_id = gtk_ui_manager_new_merge_id (ui_manager_main_menubar);
        add_recent_items (merge_id, ui_manager_main_menubar);
#else /* MAIN_MENU_USE_UIMANAGER */
        main_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU_BAR, "<main>", grp);
        gtk_item_factory_create_items_ac(main_menu_factory, nmenu_items, menu_items, NULL, 2);
#endif /* MAIN_MENU_USE_UIMANAGER */

        statusbar_profiles_action_group = gtk_action_group_new ("StatusBarProfilesPopUpMenuActionGroup");

        gtk_action_group_add_actions (statusbar_profiles_action_group,            /* the action group */
            statusbar_profiles_menu_action_entries,                        /* an array of action descriptions */
            G_N_ELEMENTS(statusbar_profiles_menu_action_entries),        /* the number of entries */
            popup_menu_object);                                                    /* data to pass to the action callbacks */

        ui_manager_statusbar_profiles_menu = gtk_ui_manager_new ();
        gtk_ui_manager_insert_action_group (ui_manager_statusbar_profiles_menu,
            statusbar_profiles_action_group,
            0); /* the position at which the group will be inserted.  */

        gtk_ui_manager_add_ui_from_string (ui_manager_statusbar_profiles_menu,ui_statusbar_profiles_menu_popup, -1, &error);
        if (error != NULL)
        {
            fprintf (stderr, "Warning: building Statusbar Profiles Pop-Up failed: %s\n",
                    error->message);
            g_error_free (error);
            error = NULL;
        }

        g_object_unref(statusbar_profiles_action_group);

        g_object_set_data(G_OBJECT(popup_menu_object), PM_STATUSBAR_PROFILES_KEY,
                       gtk_ui_manager_get_widget(ui_manager_statusbar_profiles_menu, "/ProfilesMenuPopup"));

        popup_menu_list = g_slist_append((GSList *)popup_menu_list, ui_manager_statusbar_profiles_menu);

        menu_dissector_filter();
        merge_all_tap_menus(tap_menu_tree_root);

        /* Initialize enabled/disabled state of menu items */
        set_menus_for_capture_file(NULL);
#if 0
        /* Un-#if this when we actually implement Cut/Copy/Paste.
           Then make sure you enable them when they can be done. */
        set_menu_sensitivity_old("/Edit/Cut", FALSE);
        set_menu_sensitivity_old("/Edit/Copy", FALSE);
        set_menu_sensitivity_old("/Edit/Paste", FALSE);
#endif

        set_menus_for_captured_packets(FALSE);
        set_menus_for_selected_packet(&cfile);
        set_menus_for_selected_tree_row(&cfile);
        set_menus_for_capture_in_progress(FALSE);
        set_menus_for_file_set(/* dialog */TRUE, /* previous file */ FALSE, /* next_file */ FALSE);

#ifndef MAIN_MENU_USE_UIMANAGER
        /* Init with an empty recent files list */
        clear_menu_recent_capture_file_cmd_cb(NULL, NULL);
#endif /* MAIN_MENU_USE_UIMANAGER */
        /* Protocol help links */
        proto_help_menu_init(gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup"));
    }
}


static gint tap_menu_item_add_compare(gconstpointer a, gconstpointer b)
{
    return strcmp(
        ((const menu_item_t *) a)->name,
        ((const menu_item_t *) b)->name);
}


/* add a menuitem below the current node */
static GList * tap_menu_item_add(
    gint        group,
    const char *gui_path,
    const char *name,
    const char *label,
    const char *stock_id,
    const char *accelerator,
    const char *tooltip,
#ifdef MAIN_MENU_USE_UIMANAGER
    GCallback   callback,
#else
    GtkItemFactoryCallback callback,
#endif
    gboolean    enabled,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *, gpointer callback_data),
    gboolean (*selected_tree_row_enabled)(field_info *, gpointer callback_data),
    gpointer callback_data,
    GList *curnode)
{
    menu_item_t *curr;
    menu_item_t *child;

    child = g_malloc(sizeof (menu_item_t));
    child->group            = group;
    child->gui_path         = gui_path;
    child->name             = name;
    child->label            = label;
    child->stock_id         = stock_id;
    child->accelerator      = accelerator;
    child->stock_id         = stock_id;
    child->tooltip          = tooltip;
    child->callback         = callback;
	child->enabled          = enabled;
    child->selected_packet_enabled = selected_packet_enabled;
    child->selected_tree_row_enabled = selected_tree_row_enabled;
    child->callback_data    = callback_data;
    child->children         = NULL;

    /* insert the new child node into the parent */
    curr = curnode->data;
    curr->children = g_list_insert_sorted(curr->children, child, tap_menu_item_add_compare);

    /* return the new node */
    /* XXX: improve this */
    return g_list_find(curr->children, child);
}

/*
 * Add a new menu item for a tap.
 * This must be called after we've created the main menu, so it can't
 * be called from the routine that registers taps - we have to introduce
 * another per-tap registration routine.
 *
 * "callback" gets called when the menu item is selected; it should do
 * the work of creating the tap window.
 *
 * "selected_packet_enabled" gets called by "set_menus_for_selected_packet()";
 * it's passed a Boolean that's TRUE if a packet is selected and FALSE
 * otherwise, and should return TRUE if the tap will work now (which
 * might depend on whether a packet is selected and, if one is, on the
 * packet) and FALSE if not.
 *
 * "selected_tree_row_enabled" gets called by
 * "set_menus_for_selected_tree_row()"; it's passed a Boolean that's TRUE if
 * a protocol tree row is selected and FALSE otherwise, and should return
 * TRUE if the tap will work now (which might depend on whether a tree row
 * is selected and, if one is, on the tree row) and FALSE if not.
 */

void
register_stat_menu_item_stock(
#ifdef MAIN_MENU_USE_UIMANAGER
    register_stat_group_t group,
    const char *gui_path,
    const char *name,
    const char *stock_id,
	const char *label,
	const char *accelerator,
	const char *tooltip,
    GCallback   callback,
	gboolean    enabled,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *, gpointer callback_data),
    gboolean (*selected_tree_row_enabled)(field_info *, gpointer callback_data),
    gpointer callback_data)
#else
    const char *name,
    register_stat_group_t group,
    const char *stock_id,
    GtkItemFactoryCallback callback,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *, gpointer callback_data),
    gboolean (*selected_tree_row_enabled)(field_info *, gpointer callback_data),
    gpointer callback_data)
#endif
{
#ifdef MAIN_MENU_USE_UIMANAGER
#else
const char *gui_path = NULL;
const char *label = name;
const char *accelerator = NULL;
const char *tooltip = NULL;
gboolean    enabled = FALSE;
#endif
    /*static const char toolspath[] = "/Statistics/";*/
    const char *toolspath;
    const char *p;
    char *menupath;
    size_t menupathlen;
    menu_item_t *child;
    GList *curnode;
    GList *childnode;

    /*
     * The menu path must be relative.
     */
    g_assert(*name != '/');
#ifdef MAIN_MENU_USE_UIMANAGER
    switch(group) {
    case(REGISTER_STAT_GROUP_GENERIC): toolspath = "/Menubar/StatisticsMenu/"; break;
    case(REGISTER_STAT_GROUP_CONVERSATION_LIST): toolspath = "/Menubar/StatisticsMenu/ConversationListMenu/"; break;
    case(REGISTER_STAT_GROUP_ENDPOINT_LIST): toolspath = "/Menubar/StatisticsMenu/EndpointListMenu/"; break;
    case(REGISTER_STAT_GROUP_RESPONSE_TIME): toolspath = "/Menubar/StatisticsMenu/ServiceResponseTimeMenu/"; break;
    case(REGISTER_STAT_GROUP_UNSORTED): toolspath = "/Menubar/StatisticsMenu/"; break;
    case(REGISTER_ANALYZE_GROUP_UNSORTED): toolspath = "/Menubar/AnalyzeMenu/"; break;
    case(REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER): toolspath = "/Menubar/AnalyzeMenu/ConversationFilterMenu/"; break;
    case(REGISTER_STAT_GROUP_TELEPHONY): toolspath = "/Menubar/TelephonyMenu/"; break;
    case(REGISTER_TOOLS_GROUP_UNSORTED): toolspath = "/Menubar/ToolsMenu/"; break;
    default:
        g_assert(!"no such menu group");
        toolspath = NULL;
    }
	if(!gui_path){
		gui_path = toolspath;
	}
#else
    switch(group) {
    case(REGISTER_STAT_GROUP_GENERIC): toolspath = "/Statistics/"; break;
    case(REGISTER_STAT_GROUP_CONVERSATION_LIST): toolspath = "/Statistics/_Conversation List/"; break;
    case(REGISTER_STAT_GROUP_ENDPOINT_LIST): toolspath = "/Statistics/_Endpoint List/"; break;
    case(REGISTER_STAT_GROUP_RESPONSE_TIME): toolspath = "/Statistics/Service _Response Time/"; break;
    case(REGISTER_STAT_GROUP_UNSORTED): toolspath = "/Statistics/"; break;
    case(REGISTER_ANALYZE_GROUP_UNSORTED): toolspath = "/Analyze/"; break;
    case(REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER): toolspath = "/Analyze/Conversation Filter/"; break;
    case(REGISTER_STAT_GROUP_TELEPHONY): toolspath = "/Telephony/"; break;
    case(REGISTER_TOOLS_GROUP_UNSORTED): toolspath = "/Tools/"; break;
    default:
        g_assert(!"no such menu group");
        toolspath = NULL;
    }
#endif
    /* add the (empty) root node, if not already done */
    if(tap_menu_tree_root == NULL) {
        child = g_malloc0(sizeof (menu_item_t));
        tap_menu_tree_root = g_list_append(NULL, child);
    }

    /*
     * Create any submenus required.
     */
    curnode = tap_menu_tree_root;
    p = name;
    while ((p = strchr(p, '/')) != NULL) {
        /*
         * OK, everything between "name" and "p" is
         * a menu relative subtree into which the menu item
         * will be placed.
         *
         * Construct the absolute path name of that subtree.
         */
        menupathlen = strlen(toolspath) + 1 + (p - name);
        menupath = g_malloc(menupathlen);
        g_strlcpy(menupath, toolspath, menupathlen);
        g_strlcat(menupath, name, menupathlen);

        /*
         * Does there exist an entry with that path at this
         * level of the Analyze menu tree?
         */
        child = curnode->data;
        for (childnode = child->children; childnode != NULL; childnode = childnode->next) {
            child = childnode->data;
            if (strcmp(child->gui_path, menupath) == 0)
                break;
        }
        if (childnode == NULL) {
            /*
             * No.  Create such an item as a subtree, and
             * add it to the Tools menu tree.
             */
#ifdef MAIN_MENU_USE_UIMANAGER
            childnode = tap_menu_item_add(
                group, gui_path, name, label, NULL, NULL, NULL, NULL ,FALSE, NULL, NULL, NULL, curnode);
#else
            childnode = tap_menu_item_add(
                group, (const char*)menupath, name, name, NULL, NULL, NULL, NULL ,FALSE, NULL, NULL, NULL, curnode);
#endif
        } else {
            /*
             * Yes.  We don't need this "menupath" any longer.
             */
            g_free(menupath);
        }
        curnode = childnode;

        /*
         * Skip over the '/' we found.
         */
        p++;
    }

    /*
     * Construct the main menu path for the menu item.
     */
    menupathlen = strlen(toolspath) + 1 + strlen(name);
    menupath = g_malloc(menupathlen);
    g_strlcpy(menupath, toolspath, menupathlen);
    g_strlcat(menupath, name, menupathlen);

#ifdef MAIN_MENU_USE_UIMANAGER
#else
	gui_path = menupath;
#endif
    /*
     * Construct an item factory entry for the item, and add it to
     * the main menu.
     */
    tap_menu_item_add(
        group, gui_path, name, label, stock_id, 
        accelerator, tooltip, callback, enabled,
        selected_packet_enabled, selected_tree_row_enabled,
        callback_data, curnode);
}

/*
 * Add a new menu item for a stat.
 * This must be called after we've created the main menu, so it can't
 * be called from the routine that registers stats - we have to introduce
 * another per-stat registration routine.
 *
 * @param name the menu label
 *
 * @param group the menu group this stat should be registered to
 *
 * @param callback gets called when the menu item is selected; it should do
 * the work of creating the stat window.
 *
 * @param selected_packet_enabled gets called by set_menus_for_selected_packet();
 * it's passed a pointer to the "frame_data" structure for the current frame,
 * if any, and to the "epan_dissect_t" structure for that frame, if any, and
 * should return TRUE if the stat will work now (which might depend on whether
 * a frame is selected and, if one is, on the frame) and FALSE if not.
 *
 * @param selected_tree_row_enabled gets called by
 * set_menus_for_selected_tree_row(); it's passed a pointer to the
 * "field_info" structure for the currently selected field, if any,
 * and should return TRUE if the stat will work now (which might depend on
 * whether a tree row is selected and, if one is, on the tree row) and
 * FALSE if not.
 *
 * @param callback_data data for callback function
 */
void
register_stat_menu_item(
    const char *name,
    register_stat_group_t group,
    GtkItemFactoryCallback callback,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *, gpointer callback_data),
    gboolean (*selected_tree_row_enabled)(field_info *, gpointer callback_data),
    gpointer callback_data)
{
#ifdef MAIN_MENU_USE_UIMANAGER
#if 0
register_stat_menu_item_stock(
		group,
        NULL,                       /* gui_path */
        name,                       /* name */
        NULL,                       /* stock_id */
        name,                       /* label */
        NULL,                       /* accelerator */
        NULL,                       /* tooltip */
        G_CALLBACK(callback),
        FALSE,
        selected_packet_enabled,
        selected_tree_row_enabled,
        callback_data);
#endif
#else
    register_stat_menu_item_stock(
        name,
        group,
		NULL,         /* stock_id */              
        callback,
        selected_packet_enabled,
        selected_tree_row_enabled,
        callback_data);
#endif
}

#ifdef MAIN_MENU_USE_UIMANAGER
static void
add_menu_item(menu_item_t *node_data){
    GtkActionGroup *action_group = NULL;
    GtkAction *action;
	GList *action_groups, *l;
	guint merge_id;

	g_warning("path '%s', node_data->name '%s'",node_data->gui_path,node_data->name);
	if(node_data->stock_id){
		g_warning("node_data->stock_id %s",node_data->stock_id);
	}

	action_groups = gtk_ui_manager_get_action_groups (ui_manager_main_menubar);
    for (l = action_groups; l != NULL; l = l->next)
    {
        GtkActionGroup *group = l->data;

        if (strcmp (gtk_action_group_get_name (group), "MenuActionGroup") == 0){
            /* This unrefs the action group and all of its actions */
            action_group = group;
            break;
       }
    }
	if(!action_group){
		g_warning("Failed to find the action group");
		return;
	}
	merge_id = gtk_ui_manager_new_merge_id (ui_manager_main_menubar);

    action = g_object_new (GTK_TYPE_ACTION,
               "name", node_data->name,
               "label", node_data->label,
			   "stock_id", node_data->stock_id,
               "sensitive", node_data->enabled,
               NULL);
    gtk_action_group_add_action (action_group, action);
    g_signal_connect (action, "activate",
               G_CALLBACK (node_data->callback), node_data->callback_data);

    g_object_unref (action);

    gtk_ui_manager_add_ui (ui_manager_main_menubar, merge_id,
               node_data->gui_path,
               node_data->name, /* XXX is this ok, the name for the added UI element  */
               node_data->name, /* the name of the action to be proxied, or NULL to add a separator */
               GTK_UI_MANAGER_MENUITEM,
               FALSE);

}

static guint merge_tap_menus_layered(GList *node, gint group) {
    /*GtkItemFactoryEntry *entry;*/
    GList       *child;
    guint       added = 0;
    menu_item_t *node_data = node->data;

    /*
     * Is this a leaf node or an interior node?
     */
    if (node_data->children == NULL) {
        /*
         * It's a leaf node.
         */

        /*
         * The root node doesn't correspond to a menu tree item; it
         * has a null name pointer.
         */
        if (node_data->gui_path != NULL && group == node_data->group) {
           /* entry = g_malloc0(sizeof (GtkItemFactoryEntry));*/
            /*entry->path = node_data->name;*/
           /* entry->callback = node_data->callback;*/
            switch(group) {
            case(REGISTER_STAT_GROUP_UNSORTED):
				/*add_menu_item(node_data);*/
                break;
            case(REGISTER_STAT_GROUP_GENERIC):
				/*add_menu_item(node_data);*/
                break;
            case(REGISTER_STAT_GROUP_CONVERSATION_LIST):
                /*entry->item_type = "<StockItem>";*/
                /*entry->extra_data = WIRESHARK_STOCK_CONVERSATIONS;*/
				/*add_menu_item(node_data);*/
                break;
            case(REGISTER_STAT_GROUP_ENDPOINT_LIST):
                /*entry->item_type = "<StockItem>";*/
                /*entry->extra_data = WIRESHARK_STOCK_ENDPOINTS;*/
				/*add_menu_item(node_data);*/
                break;
            case(REGISTER_STAT_GROUP_RESPONSE_TIME):
                /*entry->item_type = "<StockItem>";*/
                /*entry->extra_data = WIRESHARK_STOCK_TIME;*/
				/*add_menu_item(node_data);*/
                break;
            case(REGISTER_STAT_GROUP_TELEPHONY):
				/*add_menu_item(node_data);*/
                break;
            case(REGISTER_ANALYZE_GROUP_UNSORTED):
				/*add_menu_item(node_data);*/
                break;
            case(REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER):
				/*add_menu_item(node_data);*/
                break;
            case(REGISTER_TOOLS_GROUP_UNSORTED):
                break;
            default:
                g_assert_not_reached();
            }
        }
    } else {
        /*
         * It's an interior node; call
         * "merge_tap_menus_layered()" on all its children
         */

        /*
         * The root node doesn't correspond to a menu tree item; it
         * has a null name pointer.
         */
        if (node_data->gui_path != NULL && group == node_data->group) {
			/* We don't create the sub-menus */
        }

        for (child = node_data->children; child != NULL; child =
            child->next) {
            added += merge_tap_menus_layered(child, group);
        }
    }

    return added;
}

#else
static guint merge_tap_menus_layered(GList *node, gint group) {
    GtkItemFactoryEntry *entry;

    GList       *child;
    guint       added = 0;
    menu_item_t *node_data = node->data;
	size_t		namelen;

    /*
     * Is this a leaf node or an interior node?
     */
    if (node_data->children == NULL) {
        /*
         * It's a leaf node.
         */

        /*
         * The root node doesn't correspond to a menu tree item; it
         * has a null name pointer.
         */
        if (node_data->gui_path != NULL && group == node_data->group) {
            entry = g_malloc0(sizeof (GtkItemFactoryEntry));
			namelen = strlen(node_data->gui_path) + 1;
			entry->path = g_malloc(namelen);
			g_strlcpy(entry->path, node_data->gui_path, namelen);
            entry->callback = node_data->callback;
            switch(group) {
            case(REGISTER_STAT_GROUP_UNSORTED):
                break;
            case(REGISTER_STAT_GROUP_GENERIC):
                break;
            case(REGISTER_STAT_GROUP_CONVERSATION_LIST):
                entry->item_type = "<StockItem>";
                entry->extra_data = WIRESHARK_STOCK_CONVERSATIONS;
                break;
            case(REGISTER_STAT_GROUP_ENDPOINT_LIST):
                entry->item_type = "<StockItem>";
                entry->extra_data = WIRESHARK_STOCK_ENDPOINTS;
                break;
            case(REGISTER_STAT_GROUP_RESPONSE_TIME):
                entry->item_type = "<StockItem>";
                entry->extra_data = WIRESHARK_STOCK_TIME;
                break;
            case(REGISTER_STAT_GROUP_TELEPHONY):
                break;
            case(REGISTER_ANALYZE_GROUP_UNSORTED):
                break;
            case(REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER):
                break;
            case(REGISTER_TOOLS_GROUP_UNSORTED):
                break;
            default:
                g_assert_not_reached();
            }
            if(node_data->stock_id!= NULL) {
                entry->item_type = "<StockItem>";
                entry->extra_data = node_data->stock_id;
            }
            gtk_item_factory_create_item(main_menu_factory, entry, node_data->callback_data, /* callback_type */ 2);
            set_menu_sensitivity_old(node_data->gui_path, FALSE); /* no capture file yet */
            added++;
            g_free(entry);
        }
    } else {
        /*
         * It's an interior node; call
         * "merge_tap_menus_layered()" on all its children
         */

        /*
         * The root node doesn't correspond to a menu tree item; it
         * has a null name pointer.
         */
        if (node_data->gui_path != NULL && group == node_data->group) {
            entry = g_malloc0(sizeof (GtkItemFactoryEntry));
			namelen = strlen(node_data->gui_path) + 1;
			entry->path = g_malloc(namelen);
			g_strlcpy(entry->path, node_data->gui_path, namelen);
            entry->item_type = "<Branch>";

            gtk_item_factory_create_item(main_menu_factory, entry,
                NULL, 2);
            set_menu_sensitivity_old(node_data->gui_path, FALSE);    /* no children yet */
            added++;
            g_free(entry);
        }

        for (child = node_data->children; child != NULL; child =
            child->next) {
            added += merge_tap_menus_layered(child, group);
        }
    }

    return added;
}
#endif /* MAIN_MENU_USE_UIMANAGER */



static void merge_all_tap_menus(GList *node) {
    GtkItemFactoryEntry *sep_entry;

    sep_entry = g_malloc0(sizeof (GtkItemFactoryEntry));
    sep_entry->item_type = "<Separator>";
    sep_entry->path = "/Statistics/";
#ifdef MAIN_MENU_USE_UIMANAGER
    /* build the new menus */
#if 0
    merge_id = gtk_ui_manager_new_merge_id (ui_manager_main_menubar);
#endif
#endif
    /*
     * merge only the menu items of the specific group,
     * and then append a seperator
     */
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_GENERIC)) {
#ifdef MAIN_MENU_USE_UIMANAGER
        /* XXX fix me */
#else
        gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);
#endif /* MAIN_MENU_USE_UIMANAGER */
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_CONVERSATION_LIST)) {
        /*gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_ENDPOINT_LIST)) {
        /*gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_RESPONSE_TIME)) {
#ifdef MAIN_MENU_USE_UIMANAGER
        /* XXX fix me */
#else
        gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);
#endif /* MAIN_MENU_USE_UIMANAGER */
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_TELEPHONY)) {
        /*gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_UNSORTED)) {
        /*gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_ANALYZE_GROUP_UNSORTED)) {
        sep_entry->path = "/Analyze/";
        /*gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER)) {
        sep_entry->path = "/Analyze/Conversation Filter/";
        /*gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_TOOLS_GROUP_UNSORTED)) {
        /*gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);*/
    }

    g_free (sep_entry);
}

/*
 * Enable/disable menu sensitivity.
 */
static void
set_menu_sensitivity(GtkUIManager *ui_manager, const gchar *path, gint val)
{
    GtkAction *action;

    action = gtk_ui_manager_get_action(ui_manager, path);
    if(!action){
#if 0
        fprintf (stderr, "Warning: couldn't find action path= %s\n",
                path);
#endif
        return;
    }
#if GLIB_CHECK_VERSION(2,6,0)
    gtk_action_set_sensitive (action,
        val); /* TRUE to make the action sensitive */
#else
    g_object_set (G_OBJECT (action), "sensitive", val, NULL);
#endif
}

#ifndef MAIN_MENU_USE_UIMANAGER
/*
 * Enable/disable menu sensitivity for the old menubar code.
 */
static void
set_menu_sensitivity_old(const gchar *path, gint val)
{
    GtkWidget *menu_item;
    gchar *dup;
    gchar *dest;
    /* the underscore character regularly confuses things, as it will prevent finding
     * the menu_item, so it has to be removed first */
    dup = g_strdup(path);
    dest = dup;
    while(*path) {
        if (*path != '_') {
            *dest = *path;
            dest++;
        }
        path++;
    }
    *dest = '\0';

    if ((menu_item = gtk_item_factory_get_widget(main_menu_factory, dup)) != NULL) {
        if (GTK_IS_MENU(menu_item)) {
            /*
             * "dup" refers to a submenu; "gtk_item_factory_get_widget()"
             * gets the menu, not the item that, when selected, pops up
             * the submenu.
             *
             * We have to change the latter item's sensitivity, so that
             * it shows up normally if sensitive and grayed-out if
             * insensitive.
             */
            menu_item = gtk_menu_get_attach_widget(GTK_MENU(menu_item));
        }
        gtk_widget_set_sensitive(menu_item, val);
    }

    g_free(dup);
}

#endif /* MAIN_MENU_USE_UIMANAGER */

static void
set_menu_object_data_meat(GtkUIManager *ui_manager, const gchar *path, const gchar *key, gpointer data)
{
    GtkWidget *menu = NULL;

    if ((menu =  gtk_ui_manager_get_widget(ui_manager, path)) != NULL){
        g_object_set_data(G_OBJECT(menu), key, data);
    }else{
#if 0
        g_warning("set_menu_object_data_meat: no menu, path: %s",path);
#endif
    }
}

#ifndef MAIN_MENU_USE_UIMANAGER
static void
set_menu_object_data_meat_old(const gchar *path, const gchar *key, gpointer data)
{
    GtkWidget *menu = NULL;

    if ((menu = gtk_item_factory_get_widget(main_menu_factory, path)) != NULL){
        g_object_set_data(G_OBJECT(menu), key, data);
    }
}


void
set_menu_object_data_old (const gchar *path, const gchar *key, gpointer data) {

    set_menu_object_data_meat_old(path, key, data);
}
#endif
void
set_menu_object_data (const gchar *path, const gchar *key, gpointer data) {

    if (strncmp (path,"/Menubar",8) == 0){
        set_menu_object_data_meat(ui_manager_main_menubar, path, key, data);
    }else if (strncmp (path,"/PacketListMenuPopup",20) == 0){
        set_menu_object_data_meat(ui_manager_packet_list_menu, path, key, data);
    }else if (strncmp (path,"/TreeViewPopup",14) == 0){
        set_menu_object_data_meat(ui_manager_tree_view_menu, path, key, data);
    }else if (strncmp (path,"/BytesMenuPopup",15) == 0){
        set_menu_object_data_meat(ui_manager_bytes_menu, path, key, data);
    }else if (strncmp (path,"/ProfilesMenuPopup",18) == 0){
        set_menu_object_data_meat(ui_manager_statusbar_profiles_menu, path, key, data);
    }
}


/* Recently used capture files submenu:
 * Submenu containing the recently used capture files.
 * The capture filenames are always kept with the absolute path, to be independant
 * of the current path.
 * They are only stored inside the labels of the submenu (no separate list). */

#define MENU_RECENT_FILES_PATH_OLD "/File/Open Recent"
#define MENU_RECENT_FILES_PATH "/Menubar/FileMenu/OpenRecent"
#define MENU_RECENT_FILES_KEY "Recent File Name"


#ifndef MAIN_MENU_USE_UIMANAGER
static void
update_menu_recent_capture_file1(GtkWidget *widget, gpointer cnt) {
    gchar *widget_cf_name;

    widget_cf_name = g_object_get_data(G_OBJECT(widget), MENU_RECENT_FILES_KEY);

    /* if this menu item is a file, count it */
    if (widget_cf_name) {
        (*(guint *)cnt)++;
        main_welcome_add_recent_capture_files(widget_cf_name);
    }
}

/* update the menu */
static void
update_menu_recent_capture_file(GtkWidget *submenu_recent_files) {
    guint cnt = 0;
    GtkWidget    *menu_item;


    main_welcome_reset_recent_capture_files();

    gtk_container_foreach(GTK_CONTAINER(submenu_recent_files),
                          update_menu_recent_capture_file1, &cnt);

    if(cnt==0){
        /* Empty list */
        menu_item = gtk_menu_item_new_with_label("No recently used files");
        gtk_menu_shell_append (GTK_MENU_SHELL(submenu_recent_files), menu_item);
        gtk_widget_show (menu_item);
    }

    /* make parent menu item sensitive only, if we have any valid files in the list */
    set_menu_sensitivity_old(MENU_RECENT_FILES_PATH_OLD, cnt);
}

#endif /* MAIN_MENU_USE_UIMANAGER */

#ifndef MAIN_MENU_USE_UIMANAGER
/* remove the capture filename from the "Recent Files" menu */
static void
remove_menu_recent_capture_filename(gchar *cf_name) {
    GtkWidget *submenu_recent_files;
    GList* child_list;
    GList* child_list_item;
    GtkWidget    *menu_item_child;
    const gchar *menu_item_cf_name;

    /* get the submenu container item */
#ifdef MAIN_MENU_USE_UIMANAGER
    submenu_recent_files = gtk_ui_manager_get_widget(ui_manager_main_menubar, MENU_RECENT_FILES_PATH);
    if(!submenu_recent_files){
        g_warning("remove_menu_recent_capture_filename: No submenu_recent_files found, path= MENU_RECENT_FILES_PATH");
    }
#else
    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH_OLD);
#endif
    /* find the corresponding menu item to be removed */
    child_list = gtk_container_get_children(GTK_CONTAINER(submenu_recent_files));
    child_list_item = child_list;
    while(child_list_item) {
        menu_item_child = gtk_bin_get_child(GTK_BIN(child_list_item->data));
        if (menu_item_child != NULL) { /* Note: there are two "extra" items on the end of the child_list: */
                                       /*  - a separator (with no menu_item_child and thus no text label) */
                                       /*  - a 2nd item with a menu_child with text label "Clear"         */
                                       /*       [See add_menu_recent_capture_file_absolute() ]            */
                                       /* 'if (menu_item_child != NULL)' skips the separator item;        */
                                       /* An absolute filename in cf_name will never match  "Clear".      */
            menu_item_cf_name = gtk_label_get_text(GTK_LABEL(menu_item_child));
            if(strcmp(menu_item_cf_name, cf_name) == 0) {
                /* XXX: is this all we need to do, to free the menu item and its label?
                   The reference count of widget will go to 0, so it'll be freed;
                   will that free the label? */
                gtk_container_remove(GTK_CONTAINER(submenu_recent_files), child_list_item->data);
            }
        }
        child_list_item = g_list_next(child_list_item);
    }
    g_list_free(child_list);

    update_menu_recent_capture_file(submenu_recent_files);
}

/* remove the capture filename from the "Recent Files" menu */
static void
remove_menu_recent_capture_file(GtkWidget *widget, gpointer unused _U_) {
    GtkWidget *submenu_recent_files;
    gchar *widget_cf_name;


    widget_cf_name = g_object_get_data(G_OBJECT(widget), MENU_RECENT_FILES_KEY);
    g_free(widget_cf_name);

    /* get the submenu container item */
#ifdef MAIN_MENU_USE_UIMANAGER
    submenu_recent_files = gtk_ui_manager_get_widget(ui_manager_main_menubar, MENU_RECENT_FILES_PATH);
    if(!submenu_recent_files){
        g_warning("remove_menu_recent_capture_file: No submenu_recent_files found, path= MENU_RECENT_FILES_PATH");
    }
#else
    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH_OLD);
#endif
    /* XXX: is this all we need to do, to free the menu item and its label?
       The reference count of widget will go to 0, so it'll be freed;
       will that free the label? */
    gtk_container_remove(GTK_CONTAINER(submenu_recent_files), widget);
}
#endif

#ifdef MAIN_MENU_USE_UIMANAGER
/* Add a file name to the top of the list, if its allrady present remove it first */
static GList *
remove_present_file_name(GList *recent_files_list, const gchar *cf_name){
GList *li;
gchar *widget_cf_name;

    for (li = g_list_first(recent_files_list); li; li = li->next) {
        widget_cf_name = li->data;
        if (
#ifdef _WIN32
            /* do a case insensitive compare on win32 */
            g_ascii_strncasecmp(widget_cf_name, cf_name, 1000) == 0){
#else   /* _WIN32 */
            /* do a case sensitive compare on unix */
            strncmp(widget_cf_name, cf_name, 1000) == 0 ){
#endif
            recent_files_list = g_list_remove(recent_files_list,widget_cf_name);
        }
    }

    return recent_files_list;
}

static void
recent_changed_cb (GtkUIManager *ui_manager,
                   gpointer          user_data _U_)
{
  guint merge_id;
  GList *action_groups, *l;


  merge_id = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (ui_manager),
                               "recent-files-merge-id"));
  
  /* remove the UI */
  gtk_ui_manager_remove_ui (ui_manager, merge_id);

  /* remove the action group; gtk_ui_manager_remove_action_group()
   * should really take the action group's name instead of its 
   * pointer.
   */
  action_groups = gtk_ui_manager_get_action_groups (ui_manager);
  for (l = action_groups; l != NULL; l = l->next)
  {
      GtkActionGroup *group = l->data;

      if (strcmp (gtk_action_group_get_name (group), "recent-files-group") == 0){
          /* this unrefs the action group and all of its actions */
          gtk_ui_manager_remove_action_group (ui_manager, group);
          break;
      }
  }

  /* generate a new merge id and re-add everything */
  merge_id = gtk_ui_manager_new_merge_id (ui_manager);
  add_recent_items (merge_id, ui_manager);
}

static void
recent_clear_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	GtkWidget *submenu_recent_files;
	GList *recent_files_list;

	/* Get the list of recent files, free the list and store the empty list with the widget */
	submenu_recent_files = gtk_ui_manager_get_widget(ui_manager_main_menubar, MENU_RECENT_FILES_PATH);
	recent_files_list = g_object_get_data(G_OBJECT(submenu_recent_files), "recent-files-list");
	/* Free the name strings ?? */
	g_list_free(recent_files_list);
	recent_files_list = NULL;
	g_object_set_data(G_OBJECT(submenu_recent_files), "recent-files-list", recent_files_list);
	/* Calling recent_changed_cb will rebuild the GUI call add_recent_items which will in turn call 
	 * main_welcome_reset_recent_capture_files
	 */
	recent_changed_cb(ui_manager_main_menubar, NULL);
}

static void
add_recent_items (guint merge_id, GtkUIManager *ui_manager)
{
    GtkActionGroup *action_group;
    GtkAction *action;
    GtkWidget *submenu_recent_files;
    GList *items, *l;
    gchar *name;
    gchar *action_name;
    guint i;

    /* Reset the recent files list in the welcome screen */
    main_welcome_reset_recent_capture_files();

    action_group = gtk_action_group_new ("recent-files-group");

    submenu_recent_files = gtk_ui_manager_get_widget(ui_manager_main_menubar, MENU_RECENT_FILES_PATH);
    if(!submenu_recent_files){
        g_warning("add_recent_items: No submenu_recent_files found, path= MENU_RECENT_FILES_PATH");
    }
    items = g_object_get_data(G_OBJECT(submenu_recent_files), "recent-files-list");

    gtk_ui_manager_insert_action_group (ui_manager, action_group, 0);
    g_object_set_data (G_OBJECT (ui_manager),
                     "recent-files-merge-id", GUINT_TO_POINTER (merge_id));

    /* no items */
    if (!items){

      action = g_object_new (GTK_TYPE_ACTION,
                 "name", "recent-info-empty",
                 "label", "No recently used files",
                 "sensitive", FALSE,
                 NULL);
      gtk_action_group_add_action (action_group, action);
      g_object_unref (action);

      gtk_ui_manager_add_ui (ui_manager, merge_id,
                 "/Menubar/FileMenu/OpenRecent/RecentFiles",
                 "recent-info-empty",
                 "recent-info-empty",
                 GTK_UI_MANAGER_MENUITEM,
                 FALSE);
      
      return;
    }

  for (i = 0, l = items;
       i < prefs.gui_recent_files_count_max && l != NULL;
       i +=1, l = l->next)
    {
      gchar *item_name = l->data;
      name = g_strdup_printf ("recent-info-%u", i);
      action_name = g_strdup (name);

      action = g_object_new (GTK_TYPE_ACTION,
                 "name", action_name,
                 "label", item_name,
                 "stock_id", WIRESHARK_STOCK_FILE,
                 NULL);
      g_signal_connect (action, "activate",
                        G_CALLBACK (menu_open_recent_file_cmd_cb), NULL);
      gtk_action_group_add_action (action_group, action);
      g_object_unref (action);

      gtk_ui_manager_add_ui (ui_manager, merge_id,
                 "/Menubar/FileMenu/OpenRecent/RecentFiles",
                 name,
                 action_name,
                 GTK_UI_MANAGER_MENUITEM,
                 FALSE);

      /* Add the file name to the recent files list on the Welcome screen */
      main_welcome_add_recent_capture_files(item_name);

      g_free (action_name);
      g_free (name);
    }
    /* Add a Separator */
    gtk_ui_manager_add_ui (ui_manager, merge_id,
             "/Menubar/FileMenu/OpenRecent/RecentFiles",
             "separator-recent-info",
             NULL,
             GTK_UI_MANAGER_SEPARATOR,
             FALSE);

    /* Add a clear Icon */
    action = g_object_new (GTK_TYPE_ACTION,
             "name", "clear-recent-info",
             "label", "Clear the recent files list",
             "stock_id", GTK_STOCK_CLEAR,
             NULL);

    g_signal_connect (action, "activate",
                        G_CALLBACK (recent_clear_cb), NULL);

    gtk_action_group_add_action (action_group, action);
    g_object_unref (action);

    gtk_ui_manager_add_ui (ui_manager, merge_id,
             "/Menubar/FileMenu/OpenRecent/RecentFiles",
             "clear-recent-info",
             "clear-recent-info",
             GTK_UI_MANAGER_MENUITEM,
             FALSE);
  
}
#endif /* MAIN_MENU_USE_UIMANAGER */

#ifndef MAIN_MENU_USE_UIMANAGER
/* callback, if the user pushed the <Clear> menu item */
static void
clear_menu_recent_capture_file_cmd_cb(GtkWidget *w _U_, gpointer unused _U_) {
    GtkWidget *submenu_recent_files;

    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH_OLD);

    gtk_container_foreach(GTK_CONTAINER(submenu_recent_files),
                          remove_menu_recent_capture_file, NULL);

    update_menu_recent_capture_file(submenu_recent_files);
}
#endif /* MAIN_MENU_USE_UIMANAGER */

/* Open a file by it's name
   (Beware: will not ask to close existing capture file!) */
void
menu_open_filename(gchar *cf_name)
{
    GtkWidget *submenu_recent_files;
    int       err;
#ifdef MAIN_MENU_USE_UIMANAGER
    GList *recent_files_list;


    submenu_recent_files = gtk_ui_manager_get_widget(ui_manager_main_menubar, MENU_RECENT_FILES_PATH);
    if(!submenu_recent_files){
        g_warning("menu_open_filename: No submenu_recent_files found, path= MENU_RECENT_FILES_PATH");
    }
    recent_files_list = g_object_get_data(G_OBJECT(submenu_recent_files), "recent-files-list");
    /* XXX: ask user to remove item, it's maybe only a temporary problem */
    /* open and read the capture file (this will close an existing file) */
    if (cf_open(&cfile, cf_name, FALSE, &err) == CF_OK) {
        cf_read(&cfile, FALSE);
    }else{
        recent_files_list = remove_present_file_name(recent_files_list, cf_name);
        g_object_set_data(G_OBJECT(submenu_recent_files), "recent-files-list", recent_files_list);
        /* Calling recent_changed_cb will rebuild the GUI call add_recent_items which will in turn call
         * main_welcome_reset_recent_capture_files
         */
        recent_changed_cb(ui_manager_main_menubar, NULL);
    }
#else
    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH_OLD);
    /* open and read the capture file (this will close an existing file) */
    if (cf_open(&cfile, cf_name, FALSE, &err) == CF_OK) {
        cf_read(&cfile, FALSE);
    } else {
        /* the capture file apparently no longer exists; remove menu item    */
        /* XXX: ask user to remove item, it's maybe only a temporary problem */
        remove_menu_recent_capture_filename(cf_name);
    }

    update_menu_recent_capture_file(submenu_recent_files);
#endif /* MAIN_MENU_USE_UIMANAGER */
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
menu_open_recent_file_cmd(GtkAction *action)
{
    GtkWidget *submenu_recent_files;
    GList *recent_files_list;
    const gchar *cf_name;
    int         err;

    cf_name = gtk_action_get_label(action);

    /* open and read the capture file (this will close an existing file) */
    if (cf_open(&cfile, cf_name, FALSE, &err) == CF_OK) {
        cf_read(&cfile, FALSE);
    } else {
        submenu_recent_files = gtk_ui_manager_get_widget(ui_manager_main_menubar, MENU_RECENT_FILES_PATH);
        recent_files_list = g_object_get_data(G_OBJECT(submenu_recent_files), "recent-files-list");

        recent_files_list = remove_present_file_name(recent_files_list, cf_name);
        g_object_set_data(G_OBJECT(submenu_recent_files), "recent-files-list", recent_files_list);
        /* Calling recent_changed_cb will rebuild the GUI call add_recent_items which will in turn call
         * main_welcome_reset_recent_capture_files
         */
        recent_changed_cb(ui_manager_main_menubar, NULL);
    }
}
#else
/* callback, if the user pushed a recent file submenu item */
void
menu_open_recent_file_cmd(GtkWidget *w)
{
    GtkWidget   *submenu_recent_files;
    GtkWidget   *menu_item_child;
    const gchar *cf_name;
    int         err;


    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH_OLD);

    /* get capture filename from the menu item label */
    menu_item_child = gtk_bin_get_child(GTK_BIN(w));
    cf_name = gtk_label_get_text(GTK_LABEL(menu_item_child));

    /* open and read the capture file (this will close an existing file) */
    if (cf_open(&cfile, cf_name, FALSE, &err) == CF_OK) {
        cf_read(&cfile, FALSE);
    } else {
        /* the capture file apparently no longer exists; remove menu item    */
        /* XXX: ask user to remove item, it's maybe only a temporary problem */
        remove_menu_recent_capture_file(w, NULL);
    }

    update_menu_recent_capture_file(submenu_recent_files);
}
#endif /* MAIN_MENU_USE_UIMANAGER */

static void menu_open_recent_file_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
    switch(btn) {
    case(ESD_BTN_YES):
        /* save file first */
        file_save_as_cmd(after_save_open_recent_file, data);
        break;
    case(ESD_BTN_NO):
        cf_close(&cfile);
        menu_open_recent_file_cmd(data);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}
#ifdef MAIN_MENU_USE_UIMANAGER
static void
menu_open_recent_file_cmd_cb(GtkAction *action, gpointer data _U_) {
    gpointer  dialog;


    if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
        /* user didn't saved his current file, ask him */
        dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_YES_NO_CANCEL,
                               "%sSave capture file before opening a new one?%s\n\n"
                               "If you open a new capture file without saving, your current capture data will be discarded.",
                               simple_dialog_primary_start(), simple_dialog_primary_end());
        simple_dialog_set_cb(dialog, menu_open_recent_file_answered_cb, action);
    } else {
        /* unchanged file */
        menu_open_recent_file_cmd(action);
    }
}
#else
static void
menu_open_recent_file_cmd_cb(GtkWidget *widget, gpointer data _U_) {
    gpointer  dialog;


    if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
        /* user didn't saved his current file, ask him */
        dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_YES_NO_CANCEL,
                               "%sSave capture file before opening a new one?%s\n\n"
                               "If you open a new capture file without saving, your current capture data will be discarded.",
                               simple_dialog_primary_start(), simple_dialog_primary_end());
        simple_dialog_set_cb(dialog, menu_open_recent_file_answered_cb, widget);
    } else {
        /* unchanged file */
        menu_open_recent_file_cmd(widget);
    }
}
#endif /* MAIN_MENU_USE_UIMANAGER */

#ifdef MAIN_MENU_USE_UIMANAGER
static void
add_menu_recent_capture_file_absolute(gchar *cf_name) {
    GtkWidget *submenu_recent_files;
    GList *li;
    gchar *widget_cf_name;
    gchar *normalized_cf_name;
    guint cnt;
    GList *recent_files_list;

    normalized_cf_name = g_strdup(cf_name);
#ifdef _WIN32
    /* replace all slashes by backslashes */
    g_strdelimit(normalized_cf_name, "/", '\\');
#endif

    /* get the submenu container item */
    submenu_recent_files = gtk_ui_manager_get_widget(ui_manager_main_menubar, MENU_RECENT_FILES_PATH);
    if(!submenu_recent_files){
        g_warning("add_menu_recent_capture_file_absolute: No submenu_recent_files found, path= MENU_RECENT_FILES_PATH");
        return;
    }
    recent_files_list = g_object_get_data(G_OBJECT(submenu_recent_files), "recent-files-list");
    cnt = 1;
    for (li = g_list_first(recent_files_list); li; li = li->next, cnt++) {
        widget_cf_name = li->data;
        if (
#ifdef _WIN32
            /* do a case insensitive compare on win32 */
            g_ascii_strncasecmp(widget_cf_name, normalized_cf_name, 1000) == 0 ||
#else   /* _WIN32 */
            /* do a case sensitive compare on unix */
            strncmp(widget_cf_name, normalized_cf_name, 1000) == 0 ||
#endif
            cnt >= prefs.gui_recent_files_count_max) {
            recent_files_list = g_list_remove(recent_files_list,widget_cf_name);
            cnt--;
        }
    }
    recent_files_list = g_list_prepend(recent_files_list, normalized_cf_name);
    g_object_set_data(G_OBJECT(submenu_recent_files), "recent-files-list", recent_files_list);
    recent_changed_cb( ui_manager_main_menubar, NULL);
}

#else /* MAIN_MENU_USE_UIMANAGER */

/* add the capture filename (with an absolute path) to the "Recent Files" menu */
static void
add_menu_recent_capture_file_absolute(gchar *cf_name) {
    GtkWidget *submenu_recent_files;
    GList *menu_item_list_old;
    GList *li;
    gchar *widget_cf_name;
    gchar *normalized_cf_name;
    GtkWidget *menu_item;
    guint cnt;

    normalized_cf_name = g_strdup(cf_name);
#ifdef _WIN32
    /* replace all slashes by backslashes */
    g_strdelimit(normalized_cf_name, "/", '\\');
#endif
    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH_OLD);
    /* convert container to a GList */
    menu_item_list_old = gtk_container_get_children(GTK_CONTAINER(submenu_recent_files));

    /* iterate through list items of menu_item_list,
     * removing special items, a maybe duplicate entry and every item above count_max */
    cnt = 1;
    for (li = g_list_first(menu_item_list_old); li; li = li->next, cnt++) {
        /* get capture filename */
        menu_item = GTK_WIDGET(li->data);
        widget_cf_name = g_object_get_data(G_OBJECT(menu_item), MENU_RECENT_FILES_KEY);

        /* if this element string is one of our special items (seperator, ...) or
         * already in the list or
         * this element is above maximum count (too old), remove it
         */
        if (!widget_cf_name ||
#ifdef _WIN32
            /* do a case insensitive compare on win32 */
            g_ascii_strncasecmp(widget_cf_name, normalized_cf_name, 1000) == 0 ||
#else   /* _WIN32 */
            /* do a case sensitive compare on unix */
            strncmp(widget_cf_name, normalized_cf_name, 1000) == 0 ||
#endif
            cnt >= prefs.gui_recent_files_count_max) {
            remove_menu_recent_capture_file(li->data, NULL);
            cnt--;
        }
    }

    g_list_free(menu_item_list_old);

    /* add new item at latest position */
    menu_item = gtk_menu_item_new_with_label(normalized_cf_name);
    g_object_set_data(G_OBJECT(menu_item), MENU_RECENT_FILES_KEY, normalized_cf_name);
    gtk_menu_shell_prepend (GTK_MENU_SHELL(submenu_recent_files), menu_item);
    g_signal_connect_swapped(GTK_OBJECT(menu_item), "activate",
                             G_CALLBACK(menu_open_recent_file_cmd_cb), (GtkObject *) menu_item);
    gtk_widget_show (menu_item);

    /* add seperator at last position */
    menu_item = gtk_menu_item_new();
    gtk_menu_shell_append (GTK_MENU_SHELL(submenu_recent_files), menu_item);
    gtk_widget_show (menu_item);

    /* add new "clear list" item at last position */
    menu_item = gtk_image_menu_item_new_from_stock(GTK_STOCK_CLEAR, NULL);
    gtk_menu_shell_append (GTK_MENU_SHELL(submenu_recent_files), menu_item);
    g_signal_connect_swapped(GTK_OBJECT(menu_item), "activate",
                             G_CALLBACK(clear_menu_recent_capture_file_cmd_cb), (GtkObject *) menu_item);
    gtk_widget_show (menu_item);

    update_menu_recent_capture_file(submenu_recent_files);
}
#endif /* MAIN_MENU_USE_UIMANAGER */

/* add the capture filename to the "Recent Files" menu */
/* (will change nothing, if this filename is already in the menu) */
/*
 * XXX - We might want to call SHAddToRecentDocs under Windows 7:
 * http://stackoverflow.com/questions/437212/how-do-you-register-a-most-recently-used-list-with-windows-in-preparation-for-win
 */
void
add_menu_recent_capture_file(gchar *cf_name) {
    gchar *curr;
    gchar *absolute;


    /* if this filename is an absolute path, we can use it directly */
    if (g_path_is_absolute(cf_name)) {
        add_menu_recent_capture_file_absolute(cf_name);
        return;
    }

    /* this filename is not an absolute path, prepend the current dir */
    curr = g_get_current_dir();
    absolute = g_strdup_printf("%s%s%s", curr, G_DIR_SEPARATOR_S, cf_name);
    add_menu_recent_capture_file_absolute(absolute);
    g_free(curr);
    g_free(absolute);
}


/* write all capture filenames of the menu to the user's recent file */
void
menu_recent_file_write_all(FILE *rf) {
    GtkWidget   *submenu_recent_files;
    GList       *children;
    GList       *child;
    gchar       *cf_name;
#ifdef MAIN_MENU_USE_UIMANAGER
    GList       *recent_files_list, *list;

    submenu_recent_files = gtk_ui_manager_get_widget(ui_manager_main_menubar, MENU_RECENT_FILES_PATH);
    if(!submenu_recent_files){
        g_warning("menu_recent_file_write_all: No submenu_recent_files found, path= MENU_RECENT_FILES_PATH");
    }
    recent_files_list = g_object_get_data(G_OBJECT(submenu_recent_files), "recent-files-list");
    list =  g_list_last(recent_files_list);
    while(list != NULL) {
        cf_name = list->data;
        if (cf_name) {
            if(u3_active())
                fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", u3_contract_device_path(cf_name));
            else
                fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", cf_name);
        }
        list = g_list_previous(list);
    }
    g_list_free(recent_files_list);
    return;

#else
    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH_OLD);
#endif
    /* we have to iterate backwards through the children's list,
     * so we get the latest item last in the file.
     * (don't use gtk_container_foreach() here, it will return the wrong iteration order) */
    children = gtk_container_get_children(GTK_CONTAINER(submenu_recent_files));
    child = g_list_last(children);
    while(child != NULL) {
        /* get capture filename from the menu item label */
        cf_name = g_object_get_data(G_OBJECT(child->data), MENU_RECENT_FILES_KEY);
        if (cf_name) {
            if(u3_active())
                fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", u3_contract_device_path(cf_name));
            else
                fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", cf_name);
        }

        child = g_list_previous(child);
    }

    g_list_free(children);
}


static void
show_hide_cb(GtkWidget *w, gpointer data _U_, gint action)
{

    /* save current setting in recent */
    switch(action) {
    case(SHOW_HIDE_MAIN_TOOLBAR):
        recent.main_toolbar_show = gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w));
        break;
    case(SHOW_HIDE_FILTER_TOOLBAR):
        recent.filter_toolbar_show = gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w));
        break;
#ifdef HAVE_AIRPCAP
    case(SHOW_HIDE_AIRPCAP_TOOLBAR):
        recent.airpcap_toolbar_show = gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w));
        break;
#endif
    case(SHOW_HIDE_STATUSBAR):
        recent.statusbar_show = gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w));
        break;
    case(SHOW_HIDE_PACKET_LIST):
        recent.packet_list_show = gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w));
        break;
    case(SHOW_HIDE_TREE_VIEW):
        recent.tree_view_show = gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w));
        break;
    case(SHOW_HIDE_BYTE_VIEW):
        recent.byte_view_show = gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w));
        break;
    default:
        g_assert_not_reached();
    }

    main_widgets_show_or_hide();
}

#ifndef MAIN_MENU_USE_UIMANAGER
static void
timestamp_format_cb(GtkWidget *w _U_, gpointer d _U_, gint action)
{
    if (recent.gui_time_format != action) {
        timestamp_set_type(action);
        recent.gui_time_format = action;
        /* This call adjusts column width */
        cf_timestamp_auto_precision(&cfile);
        new_packet_list_queue_draw();
    }
}


static void
timestamp_precision_cb(GtkWidget *w _U_, gpointer d _U_, gint action)
{
    if (recent.gui_time_precision != action) {
        /* the actual precision will be set in new_packet_list_queue_draw() below */
        if (action == TS_PREC_AUTO) {
            timestamp_set_precision(TS_PREC_AUTO_SEC);
        } else {
            timestamp_set_precision(action);
        }
        recent.gui_time_precision  = action;
        /* This call adjusts column width */
        cf_timestamp_auto_precision(&cfile);
        new_packet_list_queue_draw();
    }
}
#endif

static void
timestamp_seconds_time_cb(GtkWidget *w, gpointer d _U_, gint action _U_)
{
    if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w))) {
        recent.gui_seconds_format = TS_SECONDS_HOUR_MIN_SEC;
    } else {
        recent.gui_seconds_format = TS_SECONDS_DEFAULT;
    }
    timestamp_set_seconds_type (recent.gui_seconds_format);

    /* This call adjusts column width */
    cf_timestamp_auto_precision(&cfile);
    new_packet_list_queue_draw();
}

void
menu_name_resolution_changed(void)
{
    GtkWidget *menu = NULL;
#ifdef MAIN_MENU_USE_UIMANAGER
    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/NameResolution/EnableforMACLayer");
    if(!menu){
        g_warning("menu_name_resolution_changed: No menu found, path= /Menubar/ViewMenu/NameResolution/EnableforMACLayer");
    }
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), gbl_resolv_flags & RESOLV_MAC);

    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/NameResolution/EnableforNetworkLayer");
    if(!menu){
        g_warning("menu_name_resolution_changed: No menu found, path= /Menubar/ViewMenu/NameResolution/EnableforNetworkLayer");
    }
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), gbl_resolv_flags & RESOLV_NETWORK);

    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/NameResolution/EnableforTransportLayer");
    if(!menu){
        g_warning("menu_name_resolution_changed: No menu found, path= /Menubar/ViewMenu/NameResolution/EnableforTransportLayer");
    }
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), gbl_resolv_flags & RESOLV_TRANSPORT);

#else
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Name Resolution/Enable for MAC Layer");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), gbl_resolv_flags & RESOLV_MAC);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Name Resolution/Enable for Network Layer");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), gbl_resolv_flags & RESOLV_NETWORK);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Name Resolution/Enable for Transport Layer");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), gbl_resolv_flags & RESOLV_TRANSPORT);
#endif /* MAIN_MENU_USE_UIMANAGER */
}

static void
name_resolution_cb(GtkWidget *w, gpointer d _U_, gint action)
{
    if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w))) {
        gbl_resolv_flags |= action;
    } else {
        gbl_resolv_flags &= ~action;
    }
}

#ifdef HAVE_LIBPCAP
void
menu_auto_scroll_live_changed(gboolean auto_scroll_live_in) {
    GtkWidget *menu;


    /* tell menu about it */
#ifdef MAIN_MENU_USE_UIMANAGER
    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/AutoScrollinLiveCapture");
    if(!menu){
        g_warning("menu_auto_scroll_live_changed: No menu found, path= /Menubar/ViewMenu/AutoScrollinLiveCapture");
    }
#else
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Auto Scroll in Live Capture");
#endif /* MAIN_MENU_USE_UIMANAGER */
    if( ((gboolean) gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menu)) != auto_scroll_live_in) ) {
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), auto_scroll_live_in);
    }

    /* tell toolbar about it */
    toolbar_auto_scroll_live_changed(auto_scroll_live_in);

    /* change auto scroll */
    if(auto_scroll_live_in != auto_scroll_live) {
        auto_scroll_live  = auto_scroll_live_in;
    }
}

#ifndef MAIN_MENU_USE_UIMANAGER
static void
auto_scroll_live_cb(GtkWidget *w _U_, gpointer d _U_)
{
    menu_auto_scroll_live_changed(gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w)));
}
#endif /* MAIN_MENU_USE_UIMANAGER */

#endif /*HAVE_LIBPCAP */


void
menu_colorize_changed(gboolean packet_list_colorize) {
    GtkWidget *menu;


    /* tell menu about it */
#ifdef MAIN_MENU_USE_UIMANAGER
    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/ColorizePacketList");
    if(!menu){
        g_warning("menu_colorize_changed: No menu found, path= /Menubar/ViewMenu/ColorizePacketList");
    }
#else
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Colorize Packet List");
#endif /* MAIN_MENU_USE_UIMANAGER */
    if( (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menu)) != packet_list_colorize) ) {
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), packet_list_colorize);
    }

    /* tell toolbar about it */
    toolbar_colorize_changed(packet_list_colorize);

    /* change colorization */
    if(packet_list_colorize != recent.packet_list_colorize) {
        recent.packet_list_colorize = packet_list_colorize;
        color_filters_enable(packet_list_colorize);
        new_packet_list_colorize_packets();
    }
}

static void
colorize_cb(GtkWidget *w, gpointer d _U_)
{
    menu_colorize_changed(gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w)));
}


/* the recent file read has finished, update the menu corresponding */
void
menu_recent_read_finished(void) {
    GtkWidget *menu = NULL;

#ifdef MAIN_MENU_USE_UIMANAGER
    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/MainToolbar");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/MainToolbar");
    }else{
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.main_toolbar_show);
    }
    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/FilterToolbar");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/FilterToolbar");
    }else{
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.filter_toolbar_show);
    };
#else /* MAIN_MENU_USE_UIMANAGER */
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Main Toolbar");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.main_toolbar_show);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Filter Toolbar");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.filter_toolbar_show);
#endif /* MAIN_MENU_USE_UIMANAGER*/
#ifdef HAVE_AIRPCAP
#ifdef MAIN_MENU_USE_UIMANAGER
    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/WirelessToolbar");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/WirelessToolbar");
    }else{
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.airpcap_toolbar_show);
    }
#else /* MAIN_MENU_USE_UIMANAGER */
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Wireless Toolbar");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.airpcap_toolbar_show);
#endif /* MAIN_MENU_USE_UIMANAGER */
#endif /* HAVE_AIRPCAP */

#ifdef MAIN_MENU_USE_UIMANAGER
    /* Fix me? */
    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/Statusbar");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/Statusbar");
    }else{
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.statusbar_show);
    }

    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/PacketList");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/PacketList");
    }else{
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.packet_list_show);
    }

    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/PacketDetails");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/PacketDetails");
    }else{
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.tree_view_show);
    }

    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/PacketBytes");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/PacketBytes");
    }else{
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.byte_view_show);
    }

    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/ColorizePacketList");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/ColorizePacketList");
    }else{
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.packet_list_colorize);
    }
#else /* MAIN_MENU_USE_UIMANAGER */
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Statusbar");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.statusbar_show);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Packet List");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.packet_list_show);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Packet Details");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.tree_view_show);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Packet Bytes");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.byte_view_show);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Colorize Packet List");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.packet_list_colorize);
#endif /* MAIN_MENU_USE_UIMANAGER*/

    menu_name_resolution_changed();

#ifdef HAVE_LIBPCAP
#ifdef MAIN_MENU_USE_UIMANAGER
    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/AutoScrollinLiveCapture");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/AutoScrollinLiveCapture");
    }else{
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), auto_scroll_live);
    }
#else /* MAIN_MENU_USE_UIMANAGER */
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Auto Scroll in Live Capture");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), auto_scroll_live);
#endif /* MAIN_MENU_USE_UIMANAGER*/
#endif /* HAVE_LIBPCAP */

    main_widgets_rearrange();

    /* don't change the time format, if we had a command line value */
    if (timestamp_get_type() != TS_NOT_SET) {
        recent.gui_time_format = timestamp_get_type();
    }

#ifdef MAIN_MENU_USE_UIMANAGER
    /* XXX Fix me */
    timestamp_set_type(recent.gui_time_format);
    /* This call adjusts column width */
    cf_timestamp_auto_precision(&cfile);
    new_packet_list_queue_draw();
#if 0
/* This should not be needed as we set the active radioItem when we crate the actiongroup */
    switch(recent.gui_time_format) {
    case(TS_ABSOLUTE_WITH_DATE):
        menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/TimeDisplayFormat/DateandTimeofDay");
        if(!menu){
            g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/TimeDisplayFormat/DateandTimeofDay");
        }
        break;
    case(TS_ABSOLUTE):
        menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/TimeDisplayFormat/TimeofDay");
        if(!menu){
            g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/TimeDisplayFormat/TimeofDay");
        }
        break;
    case(TS_RELATIVE):
        g_warning("TS_RELATIVE");
        action = gtk_ui_manager_get_action(ui_manager_main_menubar, "/Menubar/ViewMenu/TimeDisplayFormat/SecondsSinceBeginningofCapture");
        gtk_action_activate(action);
        if(gtk_action_is_sensitive(action))
            g_warning("ACTION IS SENSIBLE");
        if(!action)
            g_warning("NO ACTION");


        menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/TimeDisplayFormat/SecondsSinceBeginningofCapture");
        if(!menu){
            g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/TimeDisplayFormat/SecondsSinceBeginningofCapture");
        }
        break;
    case(TS_DELTA):
        menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/TimeDisplayFormat/SecondsSincePreviousCapturedPacket");
        if(!menu){
            g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/TimeDisplayFormat/SecondsSincePreviousCapturedPacket");
        }
        break;
    case(TS_DELTA_DIS):
        menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/TimeDisplayFormat/SecondsSincePreviousDisplayedPacket");
        if(!menu){
            g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/TimeDisplayFormat/SecondsSincePreviousDisplayedPacket");
        }
        break;
    case(TS_EPOCH):
        menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/TimeDisplayFormat/SecondsSinceEpoch");
        if(!menu){
            g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/TimeDisplayFormat/SecondsSinceEpoch");
        }
        break;
    default:
        g_assert_not_reached();
    }
    /* set_active will not trigger the callback when activating an active item! */
    recent.gui_time_format = -1;
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), FALSE);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
#endif /* 0 */
#else /* MAIN_MENU_USE_UIMANAGER */
    switch(recent.gui_time_format) {
    case(TS_ABSOLUTE_WITH_DATE):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456");
        break;
    case(TS_ABSOLUTE):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Time of Day:   01:02:03.123456");
        break;
    case(TS_RELATIVE):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds Since Beginning of Capture:   123.123456");
        break;
    case(TS_DELTA):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds Since Previous Captured Packet:   1.123456");
        break;
    case(TS_DELTA_DIS):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds Since Previous Displayed Packet:   1.123456");
        break;
    case(TS_EPOCH):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds Since Epoch (1970-01-01):   1234567890.123456");
        break;
    default:
        g_assert_not_reached();
    }
    /* set_active will not trigger the callback when activating an active item! */
    recent.gui_time_format = -1;
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), FALSE);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
#endif /* MAIN_MENU_USE_UIMANAGER */
#ifdef MAIN_MENU_USE_UIMANAGER
    /* the actual precision will be set in new_packet_list_queue_draw() below */
    if (recent.gui_time_precision == TS_PREC_AUTO) {
        timestamp_set_precision(TS_PREC_AUTO_SEC);
    } else {
        timestamp_set_precision(recent.gui_time_precision);
    }
    /* This call adjusts column width */
    cf_timestamp_auto_precision(&cfile);
    new_packet_list_queue_draw();
#else /* MAIN_MENU_USE_UIMANAGER */
    switch(recent.gui_time_precision) {
    case(TS_PREC_AUTO):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Automatic (File Format Precision)");
        break;
    case(TS_PREC_FIXED_SEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds:   0");
        break;
    case(TS_PREC_FIXED_DSEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Deciseconds:   0.1");
        break;
    case(TS_PREC_FIXED_CSEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Centiseconds:   0.12");
        break;
    case(TS_PREC_FIXED_MSEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Milliseconds:   0.123");
        break;
    case(TS_PREC_FIXED_USEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Microseconds:   0.123456");
        break;
    case(TS_PREC_FIXED_NSEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Nanoseconds:   0.123456789");
        break;
    default:
        g_assert_not_reached();
    }

    /* set_active will not trigger the callback when activating an active item! */
    recent.gui_time_precision = -1;
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), FALSE);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
#endif /* MAIN_MENU_USE_UIMANAGER */

    /* don't change the seconds format, if we had a command line value */
    if (timestamp_get_seconds_type() != TS_SECONDS_NOT_SET) {
        recent.gui_seconds_format = timestamp_get_seconds_type();
    }
#ifdef MAIN_MENU_USE_UIMANAGER
    menu = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/TimeDisplayFormat/DisplaySecondsWithHoursAndMinutes");
    if(!menu){
        g_warning("menu_recent_read_finished: No menu found, path= /Menubar/ViewMenu/TimeDisplayFormat/DisplaySecondsWithHoursAndMinutes");
    }
#else /* MAIN_MENU_USE_UIMANAGER */
    menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Display Seconds with hours and minutes");
#endif /* MAIN_MENU_USE_UIMANAGER */

    switch (recent.gui_seconds_format) {
    case TS_SECONDS_DEFAULT:
        recent.gui_seconds_format = -1;
        /* set_active will not trigger the callback when deactivating an inactive item! */
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), FALSE);
        break;
    case TS_SECONDS_HOUR_MIN_SEC:
        recent.gui_seconds_format = -1;
        /* set_active will not trigger the callback when activating an active item! */
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), FALSE);
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    default:
        g_assert_not_reached();
    }

    menu_colorize_changed(recent.packet_list_colorize);
}


gboolean
popup_menu_handler(GtkWidget *widget, GdkEvent *event, gpointer data)
{
    GtkWidget *menu = (GtkWidget *)data;
    GdkEventButton *event_button = NULL;
    gint row, column;

    if(widget == NULL || event == NULL || data == NULL) {
        return FALSE;
    }

    /*
     * If we ever want to make the menu differ based on what row
     * and/or column we're above, we'd use "eth_clist_get_selection_info()"
     * to find the row and column number for the coordinates; a CTree is,
     * I guess, like a CList with one column(?) and the expander widget
     * as a pixmap.
     */
    /* Check if we are on packet_list object */
    if (widget == g_object_get_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_KEY) &&
        ((GdkEventButton *)event)->button != 1) {
        gint physical_row;
        if (new_packet_list_get_event_row_column((GdkEventButton *)event, &physical_row, &row, &column)) {
            g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_ROW_KEY,
                            GINT_TO_POINTER(row));
            g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_COL_KEY,
                            GINT_TO_POINTER(column));
            new_packet_list_set_selected_row(row);
        }
    }

    /* Check if we are on tree_view object */
    if (widget == tree_view_gbl) {
        tree_view_select(widget, (GdkEventButton *) event);
    }

    /* context menu handler */
    if(event->type == GDK_BUTTON_PRESS) {
        event_button = (GdkEventButton *) event;

        /* To quote the "Gdk Event Structures" doc:
         * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
        if(event_button->button == 3) {
            gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
                           event_button->button,
                           event_button->time);
            g_signal_stop_emission_by_name(widget, "button_press_event");
            return TRUE;
        }
    }

    /* Check if we are on byte_view object */
    if(widget == get_notebook_bv_ptr(byte_nb_ptr_gbl)) {
        byte_view_select(widget, (GdkEventButton *) event);
    }

    /* GDK_2BUTTON_PRESS is a doubleclick -> expand/collapse tree row */
    /* GTK version 1 seems to be doing this automatically */
    if (widget == tree_view_gbl && event->type == GDK_2BUTTON_PRESS) {
        GtkTreePath      *path;

        if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(widget),
                                          (gint) (((GdkEventButton *)event)->x),
                                          (gint) (((GdkEventButton *)event)->y),
                                          &path, NULL, NULL, NULL))
        {
            if (gtk_tree_view_row_expanded(GTK_TREE_VIEW(widget), path))
                gtk_tree_view_collapse_row(GTK_TREE_VIEW(widget), path);
            else
                gtk_tree_view_expand_row(GTK_TREE_VIEW(widget), path,
                                         FALSE);
            gtk_tree_path_free(path);
        }
    }
    return FALSE;
}

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading and, if you have one, whether it's been saved
   and whether it could be saved except by copying the raw packet data. */
void
set_menus_for_capture_file(capture_file *cf)
{
    if (cf == NULL) {
        /* We have no capture file */
#ifdef MAIN_MENU_USE_UIMANAGER
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Merge", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Close", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Save", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/SaveAs", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Export", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/Reload", FALSE);
#else /* MAIN_MENU_USE_UIMANAGER */
        set_menu_sensitivity_old("/File/Merge...", FALSE);
        set_menu_sensitivity_old("/File/Close", FALSE);
        set_menu_sensitivity_old("/File/Save", FALSE);
        set_menu_sensitivity_old("/File/Save As...", FALSE);
        set_menu_sensitivity_old("/File/Export", FALSE);
        set_menu_sensitivity_old("/View/Reload", FALSE);
#endif /* MAIN_MENU_USE_UIMANAGER */

        set_toolbar_for_capture_file(FALSE);
        set_toolbar_for_unsaved_capture_file(FALSE);
    } else {
#ifdef MAIN_MENU_USE_UIMANAGER
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Merge", TRUE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Close", TRUE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Save", !cf->user_saved);
        /*
         * "Save As..." works only if we can write the file out in at least
         * one format (so we can save the whole file or just a subset) or
         * if we have an unsaved capture (so writing the whole file out
         * with a raw data copy makes sense).
         */
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/SaveAs",
                             cf_can_save_as(cf) || !cf->user_saved);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Export", TRUE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/Reload", TRUE);
#else /* MAIN_MENU_USE_UIMANAGER */
        set_menu_sensitivity_old("/File/Merge...", TRUE);
        set_menu_sensitivity_old("/File/Close", TRUE);
        set_menu_sensitivity_old("/File/Save", !cf->user_saved);
        /*
         * "Save As..." works only if we can write the file out in at least
         * one format (so we can save the whole file or just a subset) or
         * if we have an unsaved capture (so writing the whole file out
         * with a raw data copy makes sense).
         */
        set_menu_sensitivity_old("/File/Save As...",
                             cf_can_save_as(cf) || !cf->user_saved);
        set_menu_sensitivity_old("/File/Export", TRUE);
        set_menu_sensitivity_old("/View/Reload", TRUE);
#endif /* MAIN_MENU_USE_UIMANAGER */
        set_toolbar_for_unsaved_capture_file(!cf->user_saved);
        set_toolbar_for_capture_file(TRUE);
    }
}

/* Enable or disable menu items based on whether there's a capture in
   progress. */
void
set_menus_for_capture_in_progress(gboolean capture_in_progress)
{
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Open",
                         !capture_in_progress);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/OpenRecent",
                         !capture_in_progress);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Export",
                         capture_in_progress);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Set",
                         !capture_in_progress);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/File/Open...",
                         !capture_in_progress);
    set_menu_sensitivity_old("/File/Open Recent",
                         !capture_in_progress);
    set_menu_sensitivity_old("/File/Export",
                         capture_in_progress);
    set_menu_sensitivity_old("/File/File Set",
                         !capture_in_progress);
#endif /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/SortAscending",
                         !capture_in_progress);
    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/SortDescending",
                         !capture_in_progress);
    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/NoSorting",
                         !capture_in_progress);

#ifdef HAVE_LIBPCAP
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/CaptureMenu/Options",
                         !capture_in_progress);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/CaptureMenu/Start",
                         !capture_in_progress);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/CaptureMenu/Stop",
                         capture_in_progress);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/CaptureMenu/Restart",
                         capture_in_progress);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/Capture/Options...",
                         !capture_in_progress);
    set_menu_sensitivity_old("/Capture/Start",
                         !capture_in_progress);
    set_menu_sensitivity_old("/Capture/Stop",
                         capture_in_progress);
    set_menu_sensitivity_old("/Capture/Restart",
                         capture_in_progress);
#endif /* MAIN_MENU_USE_UIMANAGER */
    set_toolbar_for_capture_in_progress(capture_in_progress);

    set_capture_if_dialog_for_capture_in_progress(capture_in_progress);
#endif /* HAVE_LIBPCAP */
}

/* Enable or disable menu items based on whether you have some captured
   packets. */
static gboolean
walk_menu_tree_for_captured_packets(GList *node,
    gboolean have_captured_packets)
{
    gboolean    is_enabled;
    GList       *child;
    menu_item_t *node_data = node->data;

    /*
     * Is this a leaf node or an interior node?
     */
    if (node_data->children == NULL) {
        /*
         * It's a leaf node.
         *
         * If it has no "selected_packet_enabled()" or
         * "selected_tree_row_enabled()" routines, we enable
         * it.  This allows tap windows to be popped up even
         * if you have no capture file; this is done to let
         * the user pop up multiple tap windows before reading
         * in a capture file, so that they can be processed in
         * parallel while the capture file is being read rather
         * than one at at time as you pop up the windows, and to
         * let the user pop up tap windows before starting an
         * "Update list of packets in real time" capture, so that
         * the statistics can be displayed while the capture is
         * in progress.
         *
         * If it has either of those routines, we disable it for
         * now - as long as, when a capture is first available,
         * we don't get called after a packet or tree row is
         * selected, that's OK.
         * XXX - that should be done better.
         */
        if (node_data->selected_packet_enabled == NULL &&
            node_data->selected_tree_row_enabled == NULL)
            node_data->enabled = TRUE;
        else
            node_data->enabled = FALSE;
    } else {
        /*
         * It's an interior node; call
         * "walk_menu_tree_for_captured_packets()" on all its
         * children and, if any of them are enabled, enable
         * this node, otherwise disable it.
         *
         * XXX - should we just leave all interior nodes enabled?
         * Which is a better UI choice?
         */
        is_enabled = FALSE;
        for (child = node_data->children; child != NULL; child =
                 child->next) {
            if (walk_menu_tree_for_captured_packets(child,
                                                    have_captured_packets))
                is_enabled = TRUE;
        }
        node_data->enabled = is_enabled;
    }

    /*
     * The root node doesn't correspond to a menu tree item; it
     * has a null name pointer.
     */
    if (node_data->gui_path != NULL) {
#ifdef MAIN_MENU_USE_UIMANAGER
        set_menu_sensitivity(ui_manager_main_menubar, node_data->gui_path,
                              node_data->enabled);
#else
        set_menu_sensitivity_old(node_data->gui_path,
                             node_data->enabled);
#endif
    }
    return node_data->enabled;
}

void
set_menus_for_captured_packets(gboolean have_captured_packets)
{
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Print",
                         have_captured_packets);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/File/Print...",
                         have_captured_packets);
#endif /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/Print",
                         have_captured_packets);

#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/FindPacket",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/FindNext",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/FindPrevious",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ZoomIn",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ZoomOut",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/NormalSize",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/GotoCorrespondingPacket",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/PreviousPacket",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/NextPacket",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/FirstPacket",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/LastPacket",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/PreviousPacketInConversation",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/NextPacketInConversation",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/StatisticsMenu/Summary",
                         have_captured_packets);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/StatisticsMenu/ProtocolHierarchy",
                         have_captured_packets);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/Edit/Find Packet...",
                         have_captured_packets);
    set_menu_sensitivity_old("/Edit/Find Next",
                         have_captured_packets);
    set_menu_sensitivity_old("/Edit/Find Previous",
                         have_captured_packets);
    set_menu_sensitivity_old("/View/Zoom In",
                         have_captured_packets);
    set_menu_sensitivity_old("/View/Zoom Out",
                         have_captured_packets);
    set_menu_sensitivity_old("/View/Normal Size",
                         have_captured_packets);
    set_menu_sensitivity_old("/Go/Go to Packet...",
                         have_captured_packets);
    set_menu_sensitivity_old("/Go/Previous Packet",
                         have_captured_packets);
    set_menu_sensitivity_old("/Go/Next Packet",
                         have_captured_packets);
    set_menu_sensitivity_old("/Go/First Packet",
                         have_captured_packets);
    set_menu_sensitivity_old("/Go/Last Packet",
                         have_captured_packets);
    set_menu_sensitivity_old("/Go/Previous Packet In Conversation",
                         have_captured_packets);
    set_menu_sensitivity_old("/Go/Next Packet In Conversation",
                         have_captured_packets);
    set_menu_sensitivity_old("/Statistics/Summary",
                         have_captured_packets);
    set_menu_sensitivity_old("/Statistics/Protocol Hierarchy",
                         have_captured_packets);
#endif /* MAIN_MENU_USE_UIMANAGER */
    walk_menu_tree_for_captured_packets(tap_menu_tree_root,
                                        have_captured_packets);
    set_toolbar_for_captured_packets(have_captured_packets);
}

/* Enable or disable menu items based on whether a packet is selected and,
   if so, on the properties of the packet. */
static gboolean
walk_menu_tree_for_selected_packet(GList *node, frame_data *fd,
    epan_dissect_t *edt)
{
    gboolean is_enabled;
    GList *child;
    menu_item_t *node_data = node->data;

    /*
     * Is this a leaf node or an interior node?
     */
    if (node_data->children == NULL) {
        /*
         * It's a leaf node.
         *
         * If it has no "selected_packet_enabled()" routine,
         * leave its enabled/disabled status alone - it
         * doesn't depend on whether we have a packet selected
         * or not or on the selected packet.
         *
         * If it has a "selected_packet_enabled()" routine,
         * call it and set the item's enabled/disabled status
         * based on its return value.
         */
        if (node_data->selected_packet_enabled != NULL)
            node_data->enabled = node_data->selected_packet_enabled(fd, edt, node_data->callback_data);
    } else {
        /*
         * It's an interior node; call
         * "walk_menu_tree_for_selected_packet()" on all its
         * children and, if any of them are enabled, enable
         * this node, otherwise disable it.
         *
         * XXX - should we just leave all interior nodes enabled?
         * Which is a better UI choice?
         */
        is_enabled = FALSE;
        for (child = node_data->children; child != NULL; child =
                 child->next) {
            if (walk_menu_tree_for_selected_packet(child, fd, edt))
                is_enabled = TRUE;
        }
        node_data->enabled = is_enabled;
    }

    /*
     * The root node doesn't correspond to a menu tree item; it
     * has a null name pointer.
     */
    if (node_data->gui_path != NULL) {
#ifdef MAIN_MENU_USE_UIMANAGER
        set_menu_sensitivity(ui_manager_main_menubar, node_data->gui_path,
                              node_data->enabled);
#else /* MAIN_MENU_USE_UIMANAGER */
        set_menu_sensitivity_old(node_data->gui_path,
                             node_data->enabled);
#endif /* MAIN_MENU_USE_UIMANAGER */
    }
    return node_data->enabled;
}

gboolean
packet_is_ssl(epan_dissect_t* edt)
{
    GPtrArray* array;
    int ssl_id;
    gboolean is_ssl;

    if (!edt || !edt->tree)
        return FALSE;
    ssl_id = proto_get_id_by_filter_name("ssl");
    if (ssl_id < 0)
        return FALSE;
    array = proto_find_finfo(edt->tree, ssl_id);
    is_ssl = (array->len > 0) ? TRUE : FALSE;
    g_ptr_array_free(array, TRUE);
    return is_ssl;
}

void
set_menus_for_selected_packet(capture_file *cf)
{
    /* Making the menu context-sensitive allows for easier selection of the
       desired item and has the added benefit, with large captures, of
       avoiding needless looping through huge lists for marked, ignored,
       or time-referenced packets. */
    gboolean is_ssl = packet_is_ssl(cf->edt);
    gboolean frame_selected = cf->current_frame != NULL;
        /* A frame is selected */
    gboolean have_marked = frame_selected && cf->marked_count > 0;
        /* We have marked frames.  (XXX - why check frame_selected?) */
    gboolean another_is_marked = have_marked &&
        !(cf->marked_count == 1 && cf->current_frame->flags.marked);
        /* We have a marked frame other than the current frame (i.e.,
           we have at least one marked frame, and either there's more
           than one marked frame or the current frame isn't marked). */
    gboolean have_time_ref = cf->ref_time_count > 0;
    gboolean another_is_time_ref = frame_selected && have_time_ref &&
        !(cf->ref_time_count == 1 && cf->current_frame->flags.ref_time);
        /* We have a time reference frame other than the current frame (i.e.,
           we have at least one time reference frame, and either there's more
           than one time reference frame or the current frame isn't a
           time reference frame). (XXX - why check frame_selected?) */

#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/MarkPacket",
                         frame_selected);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/Edit/Mark Packet (toggle)",
                         frame_selected);
#endif /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/MarkPacket",
                         frame_selected);
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/MarkAllDisplayedPackets",
                         cf->displayed_count > 0);
    /* Unlike un-ignore, do not allow unmark of all frames when no frames are displayed  */
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/UnmarkAllDisplayedPackets",
                         have_marked);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/FindNextMark",
                         another_is_marked);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/FindPreviousMark",
                         another_is_marked);

    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/IgnorePacket",
                         frame_selected);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/EditPacket",
                         frame_selected);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/Edit/Mark All Displayed Packets (toggle)",
                         cf->displayed_count > 0);
    /* Unlike un-ignore, do not allow unmark of all frames when no frames are displayed  */
    set_menu_sensitivity_old("/Edit/Unmark All Packets",
                         have_marked);
    set_menu_sensitivity_old("/Edit/Find Next Mark",
                         another_is_marked);
    set_menu_sensitivity_old("/Edit/Find Previous Mark",
                         another_is_marked);

    set_menu_sensitivity_old("/Edit/Ignore Packet (toggle)",
                         frame_selected);
    set_menu_sensitivity_old("/Edit/Edit packet",
                         frame_selected);
#endif /* MAIN_MENU_USE_UIMANAGER */
   set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/IgnorePacket",
                         frame_selected);
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/IgnoreAllDisplayedPackets",
                         cf->displayed_count > 0 && cf->displayed_count != cf->count);
    /* Allow un-ignore of all frames even with no frames currently displayed */
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Un-IgnoreAllPackets",
                         cf->ignored_count > 0);

    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/SetTimeReference",
                         frame_selected);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/Edit/Ignore All Displayed Packets (toggle)",
                         cf->displayed_count > 0 && cf->displayed_count != cf->count);
    /* Allow un-ignore of all frames even with no frames currently displayed */
    set_menu_sensitivity_old("/Edit/Un-Ignore All Packets",
                         cf->ignored_count > 0);

    set_menu_sensitivity_old("/Edit/Set Time Reference (toggle)",
                         frame_selected);
#endif /* MAIN_MENU_USE_UIMANAGER */
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Un-TimeReferenceAllPackets",
                         have_time_ref);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/Edit/Un-Time Reference All Packets",
                         have_time_ref);
#endif /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/SetTimeReference",
                         frame_selected);
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/FindNextTimeReference",
                         another_is_time_ref);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/FindPreviousTimeReference",
                         another_is_time_ref);

    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ResizeAllColumns",
                         frame_selected);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/CollapseAll",
                         frame_selected);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/Edit/Find Next Time Reference",
                         another_is_time_ref);
    set_menu_sensitivity_old("/Edit/Find Previous Time Reference",
                         another_is_time_ref);

    set_menu_sensitivity_old("/View/Resize All Columns",
                         frame_selected);
    set_menu_sensitivity_old("/View/Collapse All",
                         frame_selected);
#endif /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/CollapseAll",
                         frame_selected);
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ExpandAll",
                         frame_selected);
#else /* MAIN_MENU_USE_UIMANAGER */
     set_menu_sensitivity_old("/View/Expand All",
                          frame_selected);
#endif /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ExpandAll",
                         frame_selected);
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ColorizeConversation",
                         frame_selected);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ResetColoring1-10",
                         tmp_color_filters_used());
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ShowPacketinNewWindow",
                         frame_selected);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/View/Colorize Conversation",
                         frame_selected);
    set_menu_sensitivity_old("/View/Reset Coloring 1-10",
                         tmp_color_filters_used());
    set_menu_sensitivity_old("/View/Show Packet in New Window",
                         frame_selected);
#endif /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ShowPacketinNewWindow",
                         frame_selected);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ManuallyResolveAddress",
                         frame_selected ? ((cf->edt->pi.ethertype == ETHERTYPE_IP)||(cf->edt->pi.ethertype == ETHERTYPE_IPv6)) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/SCTP",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_SCTP) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/FollowTCPStream",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FollowTCPStream",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/FollowUDPStream",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/FollowSSLStream",
                         frame_selected ? is_ssl : FALSE);
    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FollowSSLStream",
                         frame_selected ? is_ssl : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter",
                         frame_selected);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/Ethernet",
                         frame_selected ? (cf->edt->pi.dl_src.type == AT_ETHER) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/IP",
                         frame_selected ? ((cf->edt->pi.ethertype == ETHERTYPE_IP)||(cf->edt->pi.ethertype == ETHERTYPE_IPv6)) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/TCP",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/UDP",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FollowUDPStream",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/PN-CBA",
                         frame_selected ? (cf->edt->pi.profinet_type != 0 && cf->edt->pi.profinet_type < 10) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation",
                         frame_selected);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/Ethernet",
                         frame_selected ? (cf->edt->pi.dl_src.type == AT_ETHER) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/IP",
                         frame_selected ? ((cf->edt->pi.ethertype == ETHERTYPE_IP)||(cf->edt->pi.ethertype == ETHERTYPE_IPv6)) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/TCP",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/UDP",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/PN-CBA",
                         frame_selected ? (cf->edt->pi.profinet_type != 0 && cf->edt->pi.profinet_type < 10) : FALSE);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/DecodeAs",
                         frame_selected && decode_as_ok());
    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/DecodeAs",
                         frame_selected && decode_as_ok());
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/Copy",
                         frame_selected);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ApplyAsFilter",
                         frame_selected);
    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/PrepareaFilter",
                         frame_selected);
    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ResolveName",
                         frame_selected && (gbl_resolv_flags & RESOLV_ALL_ADDRS) != RESOLV_ALL_ADDRS);
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/FollowTCPStream",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/FollowUDPStream",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/FollowSSLStream",
                         frame_selected ? is_ssl : FALSE);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/DecodeAs",
                         frame_selected && decode_as_ok());
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/NameResolution/ResolveName",
                         frame_selected && (gbl_resolv_flags & RESOLV_ALL_ADDRS) != RESOLV_ALL_ADDRS);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ToolsMenu/FirewallACLRules",
                         frame_selected);

#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/Analyze/Follow TCP Stream",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity_old("/Analyze/Follow UDP Stream",
                         frame_selected ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity_old("/Analyze/Follow SSL Stream",
                         frame_selected ? is_ssl : FALSE);
    set_menu_sensitivity_old("/Analyze/Decode As...",
                         frame_selected && decode_as_ok());
    set_menu_sensitivity_old("/View/Name Resolution/Resolve Name",
                         frame_selected && (gbl_resolv_flags & RESOLV_ALL_ADDRS) != RESOLV_ALL_ADDRS);
    set_menu_sensitivity_old("/Tools/Firewall ACL Rules",
                         frame_selected);
#endif /* MAIN_MENU_USE_UIMANAGER */
    walk_menu_tree_for_selected_packet(tap_menu_tree_root, cf->current_frame,
                                       cf->edt);
}

/* Enable or disable menu items based on whether a tree row is selected
   and, if so, on the properties of the tree row. */
static gboolean
walk_menu_tree_for_selected_tree_row(GList *node, field_info *fi)
{
    gboolean is_enabled;
    GList *child;
    menu_item_t *node_data = node->data;

    /*
     * Is this a leaf node or an interior node?
     */
    if (node_data->children == NULL) {
        /*
         * It's a leaf node.
         *
         * If it has no "selected_tree_row_enabled()" routine,
         * leave its enabled/disabled status alone - it
         * doesn't depend on whether we have a tree row selected
         * or not or on the selected tree row.
         *
         * If it has a "selected_tree_row_enabled()" routine,
         * call it and set the item's enabled/disabled status
         * based on its return value.
         */
        if (node_data->selected_tree_row_enabled != NULL)
            node_data->enabled = node_data->selected_tree_row_enabled(fi, node_data->callback_data);
    } else {
        /*
         * It's an interior node; call
         * "walk_menu_tree_for_selected_tree_row()" on all its
         * children and, if any of them are enabled, enable
         * this node, otherwise disable it.
         *
         * XXX - should we just leave all interior nodes enabled?
         * Which is a better UI choice?
         */
        is_enabled = FALSE;
        for (child = node_data->children; child != NULL; child =
                 child->next) {
            if (walk_menu_tree_for_selected_tree_row(child, fi))
                is_enabled = TRUE;
        }
        node_data->enabled = is_enabled;
    }

    /*
     * The root node doesn't correspond to a menu tree item; it
     * has a null name pointer.
     */
    if (node_data->gui_path != NULL) {
#ifdef MAIN_MENU_USE_UIMANAGER
        set_menu_sensitivity(ui_manager_main_menubar, node_data->gui_path,
                             node_data->enabled);
#else /* MAIN_MENU_USE_UIMANAGER */
        set_menu_sensitivity_old(node_data->gui_path,
                             node_data->enabled);
#endif /* MAIN_MENU_USE_UIMANAGER */
    }
    return node_data->enabled;
}

static void
menu_prefs_toggle_bool (GtkWidget *w, gpointer data)
{
    gboolean *value = data;
    module_t *module = g_object_get_data (G_OBJECT(w), "module");

    module->prefs_changed = TRUE;
    *value = !(*value);

    prefs_apply (module);
    if (!prefs.gui_use_pref_save) {
        prefs_main_write();
    }
    redissect_packets();
}

static void
menu_prefs_change_enum (GtkWidget *w, gpointer data)
{
    gint *value = data;
    module_t *module = g_object_get_data (G_OBJECT(w), "module");
    gint new_value = GPOINTER_TO_INT(g_object_get_data (G_OBJECT(w), "enumval"));

    if (!gtk_check_menu_item_get_active (GTK_CHECK_MENU_ITEM(w)))
        return;

    if (*value != new_value) {
        module->prefs_changed = TRUE;
        *value = new_value;

        prefs_apply (module);
        if (!prefs.gui_use_pref_save) {
            prefs_main_write();
        }
        redissect_packets();
    }
}

void
menu_prefs_reset(void)
{
        g_free (g_object_get_data(G_OBJECT(ui_manager_tree_view_menu), "menu_abbrev"));
        g_object_set_data(G_OBJECT(ui_manager_tree_view_menu), "menu_abbrev", NULL);
}

static void
menu_prefs_change_ok (GtkWidget *w, gpointer parent_w)
{
    GtkWidget *entry = g_object_get_data (G_OBJECT(w), "entry");
    module_t *module = g_object_get_data (G_OBJECT(w), "module");
    pref_t *pref = g_object_get_data (G_OBJECT(w), "pref");
    const gchar *new_value =  gtk_entry_get_text(GTK_ENTRY(entry));
    range_t *newrange;
    gchar *p;
    guint uval;

    switch (pref->type) {
    case PREF_UINT:
        uval = strtoul(new_value, &p, pref->info.base);
        if (p == new_value || *p != '\0') {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                          "The value \"%s\" isn't a valid number.",
                          new_value);
            return;
        }
        if (*pref->varp.uint != uval) {
            module->prefs_changed = TRUE;
            *pref->varp.uint = uval;
        }
        break;
    case PREF_STRING:
        if (strcmp (*pref->varp.string, new_value) != 0) {
            module->prefs_changed = TRUE;
            g_free((void*)*pref->varp.string);
            *pref->varp.string = g_strdup(new_value);
        }
        break;
    case PREF_RANGE:
        if (range_convert_str(&newrange, new_value, pref->info.max_value) != CVT_NO_ERROR) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                          "The value \"%s\" isn't a valid range.",
                          new_value);
            return;
        }
        if (!ranges_are_equal(*pref->varp.range, newrange)) {
            module->prefs_changed = TRUE;
            g_free(*pref->varp.range);
            *pref->varp.range = newrange;
        } else {
            g_free (newrange);
        }
        break;
    default:
        g_assert_not_reached();
        break;
    }

    if (module->prefs_changed) {
        /* Ensure we reload the sub menu */
        menu_prefs_reset();
        prefs_apply (module);
        if (!prefs.gui_use_pref_save) {
            prefs_main_write();
        }
        redissect_packets();
    }

    window_destroy(GTK_WIDGET(parent_w));
}

static void
menu_prefs_change_cancel (GtkWidget *w _U_, gpointer parent_w)
{
    window_destroy(GTK_WIDGET(parent_w));
}

static void
menu_prefs_edit_dlg (GtkWidget *w, gpointer data)
{
    pref_t *pref = data;
    module_t *module = g_object_get_data (G_OBJECT(w), "module");
    gchar *value = NULL;

    GtkWidget *win, *main_tb, *main_vb, *bbox, *cancel_bt, *ok_bt;
    GtkWidget *entry, *label;
    GtkTooltips *tooltips;

    switch (pref->type) {
    case PREF_UINT:
        switch (pref->info.base) {
        case 8:
            value = g_strdup_printf("%o", *pref->varp.uint);
            break;
        case 10:
            value = g_strdup_printf("%u", *pref->varp.uint);
            break;
        case 16:
            value = g_strdup_printf("%x", *pref->varp.uint);
            break;
        default:
            g_assert_not_reached();
            break;
        }
        break;
    case PREF_STRING:
        value = g_strdup(*pref->varp.string);
        break;
    case PREF_RANGE:
        value = g_strdup(range_convert_range (*pref->varp.range));
        break;
    default:
        g_assert_not_reached();
        break;
    }

    tooltips = gtk_tooltips_new();

    win = dlg_window_new(module->description);

    gtk_window_set_resizable(GTK_WINDOW(win),FALSE);
    gtk_window_resize(GTK_WINDOW(win), 400, 100);

    main_vb = gtk_vbox_new(FALSE, 5);
    gtk_container_add(GTK_CONTAINER(win), main_vb);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 6);

    main_tb = gtk_table_new(2, 2, FALSE);
    gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
    gtk_table_set_col_spacings(GTK_TABLE(main_tb), 10);

    label = gtk_label_new(ep_strdup_printf("%s:", pref->title));
    gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, 1, 2);
    gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);
    if (pref->description)
        gtk_tooltips_set_tip(tooltips, label, pref->description, NULL);

    entry = gtk_entry_new();
    gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2, 1, 2);
    gtk_entry_set_text(GTK_ENTRY(entry), value);
    if (pref->description)
        gtk_tooltips_set_tip(tooltips, entry, pref->description, NULL);

    bbox = dlg_button_row_new(GTK_STOCK_CANCEL,GTK_STOCK_OK, NULL);
    gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

    ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
    g_object_set_data (G_OBJECT(ok_bt), "module", module);
    g_object_set_data (G_OBJECT(ok_bt), "entry", entry);
    g_object_set_data (G_OBJECT(ok_bt), "pref", pref);
    g_signal_connect(ok_bt, "clicked", G_CALLBACK(menu_prefs_change_ok), win);

    dlg_set_activate(entry, ok_bt);

    cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
    g_signal_connect(cancel_bt, "clicked", G_CALLBACK(menu_prefs_change_cancel), win);
    window_set_cancel_button(win, cancel_bt, NULL);

    gtk_widget_grab_default(ok_bt);
    gtk_widget_show_all(win);
    g_free(value);
}

static guint
add_protocol_prefs_menu (pref_t *pref, gpointer data)
{
    GtkWidget *menu_preferences;
    GtkWidget *menu_item, *menu_sub_item, *sub_menu;
    GSList *group = NULL;
    module_t *module = data;
    const enum_val_t *enum_valp;
    gchar *label = NULL;

    switch (pref->type) {
    case PREF_UINT:
        switch (pref->info.base) {
        case 8:
            label = g_strdup_printf ("%s: %o", pref->title, *pref->varp.uint);
            break;
        case 10:
            label = g_strdup_printf ("%s: %u", pref->title, *pref->varp.uint);
            break;
        case 16:
            label = g_strdup_printf ("%s: %x", pref->title, *pref->varp.uint);
            break;
        default:
            g_assert_not_reached();
            break;
        }
        menu_item = gtk_menu_item_new_with_label(label);
        g_object_set_data (G_OBJECT(menu_item), "module", module);
        g_signal_connect(menu_item, "activate", G_CALLBACK(menu_prefs_edit_dlg), pref);
        g_free (label);
        break;
    case PREF_BOOL:
        menu_item = gtk_check_menu_item_new_with_label(pref->title);
        gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu_item), *pref->varp.boolp);
        g_object_set_data (G_OBJECT(menu_item), "module", module);
        g_signal_connect(menu_item, "activate", G_CALLBACK(menu_prefs_toggle_bool), pref->varp.boolp);
        break;
    case PREF_ENUM:
        menu_item = gtk_menu_item_new_with_label(pref->title);
        sub_menu = gtk_menu_new();
        gtk_menu_item_set_submenu (GTK_MENU_ITEM(menu_item), sub_menu);
        enum_valp = pref->info.enum_info.enumvals;
        while (enum_valp->name != NULL) {
            menu_sub_item = gtk_radio_menu_item_new_with_label(group, enum_valp->description);
            group = gtk_radio_menu_item_get_group (GTK_RADIO_MENU_ITEM (menu_sub_item));
            if (enum_valp->value == *pref->varp.enump) {
                gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu_sub_item), TRUE);
            }
            g_object_set_data (G_OBJECT(menu_sub_item), "module", module);
            g_object_set_data (G_OBJECT(menu_sub_item), "enumval", GINT_TO_POINTER(enum_valp->value));
            g_signal_connect(menu_sub_item, "activate", G_CALLBACK(menu_prefs_change_enum), pref->varp.enump);
            gtk_menu_shell_append (GTK_MENU_SHELL(sub_menu), menu_sub_item);
            gtk_widget_show (menu_sub_item);
            enum_valp++;
        }
        break;
    case PREF_STRING:
        label = g_strdup_printf ("%s: %s", pref->title, *pref->varp.string);
        menu_item = gtk_menu_item_new_with_label(label);
        g_object_set_data (G_OBJECT(menu_item), "module", module);
        g_signal_connect(menu_item, "activate", G_CALLBACK(menu_prefs_edit_dlg), pref);
        g_free (label);
        break;
    case PREF_RANGE:
        label = g_strdup_printf ("%s: %s", pref->title, range_convert_range (*pref->varp.range));
        menu_item = gtk_menu_item_new_with_label(label);
        g_object_set_data (G_OBJECT(menu_item), "module", module);
        g_signal_connect(menu_item, "activate", G_CALLBACK(menu_prefs_edit_dlg), pref);
        g_free (label);
        break;
    case PREF_UAT:
        label = g_strdup_printf ("%s...", pref->title);
        menu_item = gtk_menu_item_new_with_label(label);
        g_signal_connect (menu_item, "activate", G_CALLBACK(uat_window_cb), pref->varp.uat);
        g_free (label);
        break;
    case PREF_STATIC_TEXT:
    case PREF_OBSOLETE:
    default:
        /* Nothing to add */
        return 0;
    }

    menu_preferences = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/ProtocolPreferences");
    if(!menu_preferences)
        g_warning("menu_preferences Not found path:TreeViewPopup/ProtocolPreferences");
    sub_menu = gtk_menu_item_get_submenu (GTK_MENU_ITEM(menu_preferences));
    gtk_menu_shell_append (GTK_MENU_SHELL(sub_menu), menu_item);
    gtk_widget_show (menu_item);

    return 0;
}

static void
rebuild_protocol_prefs_menu (module_t *prefs_module_p, gboolean preferences)
{
    GtkWidget *menu_preferences, *menu_item;
    GtkWidget *sub_menu;
    gchar *label;

    menu_preferences = gtk_ui_manager_get_widget(ui_manager_tree_view_menu, "/TreeViewPopup/ProtocolPreferences");
    if (preferences) {
        sub_menu = gtk_menu_new();
        gtk_menu_item_set_submenu (GTK_MENU_ITEM(menu_preferences), sub_menu);

        label = g_strdup_printf ("%s Preferences...", prefs_module_p->description);
        menu_item = gtk_image_menu_item_new_with_label (label);
        gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM(menu_item),
                                       gtk_image_new_from_stock(GTK_STOCK_PREFERENCES, GTK_ICON_SIZE_MENU));
        gtk_menu_shell_append (GTK_MENU_SHELL(sub_menu), menu_item);
        g_signal_connect_swapped(GTK_OBJECT(menu_item), "activate",
                                 G_CALLBACK(properties_cb), (GtkObject *) menu_item);
        gtk_widget_show (menu_item);
        g_free (label);

        menu_item = gtk_menu_item_new();
        gtk_menu_shell_append (GTK_MENU_SHELL(sub_menu), menu_item);
        gtk_widget_show (menu_item);

        prefs_pref_foreach(prefs_module_p, add_protocol_prefs_menu, prefs_module_p);
    } else {
        /* No preferences, remove sub menu */
        gtk_menu_item_set_submenu (GTK_MENU_ITEM(menu_preferences), NULL);
    }

}

static void
menu_visible_column_toggle (GtkWidget *w _U_, gpointer data)
{
    new_packet_list_toggle_visible_column (GPOINTER_TO_INT(data));
}

void
rebuild_visible_columns_menu (void)
{
    GtkWidget *menu_columns[2], *menu_item;
    GtkWidget *sub_menu;
    GList     *clp;
    fmt_data  *cfmt;
    gchar     *title;
    gint       i, col_id, cur_fmt;
#ifdef MAIN_MENU_USE_UIMANAGER
    menu_columns[0] = gtk_ui_manager_get_widget(ui_manager_main_menubar, "/Menubar/ViewMenu/DisplayedColumns");
    if(! menu_columns[0]){
        fprintf (stderr, "Warning: couldn't find menu_columns[0] path=/Menubar/ViewMenu/DisplayedColumns");
    }
#else /* MAIN_MENU_USE_UIMANAGER */
    menu_columns[0] = gtk_item_factory_get_widget(main_menu_factory, "/View/Displayed Columns");
#endif /* MAIN_MENU_USE_UIMANAGER */
    menu_columns[1] = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/DisplayedColumns");
    /* Debug */
    if(! menu_columns[1]){
        fprintf (stderr, "Warning: couldn't find menu_columns[1] path=/PacketListHeadingPopup/DisplayedColumns");
    }

    for (i = 0; i < 2; i++) {
        sub_menu = gtk_menu_new();
        gtk_menu_item_set_submenu (GTK_MENU_ITEM(menu_columns[i]), sub_menu);

        clp = g_list_first (prefs.col_list);
        col_id = 0;
        while (clp) {
            cfmt = (fmt_data *) clp->data;
            cur_fmt = get_column_format_from_str(cfmt->fmt);
            if (cfmt->title[0]) {
                if (cur_fmt == COL_CUSTOM) {
                    title = g_strdup_printf ("%s  (%s)", cfmt->title, cfmt->custom_field);
                } else {
                    title = g_strdup_printf ("%s  (%s)", cfmt->title, col_format_desc (cur_fmt));
                }
            } else {
                if (cur_fmt == COL_CUSTOM) {
                    title = g_strdup_printf ("(%s)", cfmt->custom_field);
                } else {
                    title = g_strdup_printf ("(%s)", col_format_desc (cur_fmt));
                }
            }
            menu_item = gtk_check_menu_item_new_with_label(title);
            g_free (title);
            gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu_item), cfmt->visible);
            g_signal_connect(menu_item, "activate", G_CALLBACK(menu_visible_column_toggle), GINT_TO_POINTER(col_id));
            gtk_menu_shell_append (GTK_MENU_SHELL(sub_menu), menu_item);
            gtk_widget_show (menu_item);
            clp = g_list_next (clp);
            col_id++;
        }

        menu_item = gtk_menu_item_new();
        gtk_menu_shell_append (GTK_MENU_SHELL(sub_menu), menu_item);
        gtk_widget_show (menu_item);

        menu_item = gtk_menu_item_new_with_label ("Display All");
        gtk_menu_shell_append (GTK_MENU_SHELL(sub_menu), menu_item);
        g_signal_connect(menu_item, "activate", G_CALLBACK(packet_list_heading_activate_all_columns_cb), NULL);
        gtk_widget_show (menu_item);
    }
}

void
menus_set_column_resolved (gboolean resolved, gboolean can_resolve)
{
    GtkWidget *menu;

    menu = gtk_ui_manager_get_widget(ui_manager_packet_list_heading, "/PacketListHeadingPopup/ShowResolved");
    if(!menu){
        fprintf (stderr, "Warning: couldn't find menu path=/PacketListHeadingPopup/ShowResolved");
    }
    g_object_set_data(G_OBJECT(menu), "skip-update", (void *)1);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), resolved && can_resolve);
    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/ShowResolved", can_resolve);
    g_object_set_data(G_OBJECT(menu), "skip-update", NULL);
}

void
menus_set_column_align_default (gboolean right_justify)
{
    GtkWidget   *submenu, *menu_item_child;
    GList       *child_list, *child_list_item;
    const gchar *menu_item_name;
    size_t       menu_item_len;

    /* get the submenu container item */
    submenu = gtk_ui_manager_get_widget (ui_manager_packet_list_heading, "/PacketListHeadingPopup");
    if(!submenu){
        fprintf (stderr, "Warning: couldn't find submenu path=/PacketListHeadingPopup");
    }

    /* find the corresponding menu items to update */
    child_list = gtk_container_get_children(GTK_CONTAINER(submenu));
    child_list_item = child_list;
    while(child_list_item) {
        menu_item_child = gtk_bin_get_child(GTK_BIN(child_list_item->data));
        if (menu_item_child != NULL) {
            menu_item_name = gtk_label_get_text(GTK_LABEL(menu_item_child));
            menu_item_len = strlen (menu_item_name);
            if(strncmp(menu_item_name, "Align Left", 10) == 0) {
                if (!right_justify && menu_item_len == 10) {
                    gtk_label_set_text(GTK_LABEL(menu_item_child), "Align Left\t(default)");
                } else if (right_justify && menu_item_len > 10) {
                    gtk_label_set_text(GTK_LABEL(menu_item_child), "Align Left");
                }
            } else if (strncmp (menu_item_name, "Align Right", 11) == 0) {
                if (right_justify && menu_item_len == 11) {
                    gtk_label_set_text(GTK_LABEL(menu_item_child), "Align Right\t(default)");
                } else if (!right_justify && menu_item_len > 11) {
                    gtk_label_set_text(GTK_LABEL(menu_item_child), "Align Right");
                }
            }
        }
        child_list_item = g_list_next(child_list_item);
    }
    g_list_free(child_list);
}

void
set_menus_for_selected_tree_row(capture_file *cf)
{
    gboolean properties;
    gint id;

    if (cf->finfo_selected != NULL) {
        header_field_info *hfinfo = cf->finfo_selected->hfinfo;
        const char *abbrev;
        char *prev_abbrev;

        if (hfinfo->parent == -1) {
            abbrev = hfinfo->abbrev;
            id = (hfinfo->type == FT_PROTOCOL) ? proto_get_id((protocol_t *)hfinfo->strings) : -1;
        } else {
            abbrev = proto_registrar_get_abbrev(hfinfo->parent);
            id = hfinfo->parent;
        }
        properties = prefs_is_registered_protocol(abbrev);
        set_menu_sensitivity(ui_manager_tree_view_menu,
                             "/TreeViewPopup/GotoCorrespondingPacket", hfinfo->type == FT_FRAMENUM);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/Copy",
                             TRUE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/Copy/AsFilter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyasColumn",
                             hfinfo->type != FT_NONE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyAsFilter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/PrepareaFilter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ColorizewithFilter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ProtocolPreferences",
                             properties);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/DisableProtocol",
                             (id == -1) ? FALSE : proto_can_toggle_protocol(id));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ExpandSubtrees",
                             cf->finfo_selected->tree_type != -1);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/WikiProtocolPage",
                             (id == -1) ? FALSE : TRUE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FilterFieldReference",
                             (id == -1) ? FALSE : TRUE);
#ifdef MAIN_MENU_USE_UIMANAGER
        set_menu_sensitivity(ui_manager_tree_view_menu,
                             "/Menubar/MenuFile/Export/SelectedPacketBytes", TRUE);
        set_menu_sensitivity(ui_manager_tree_view_menu,
                             "/Menubar/MenuGo/GotoCorrespondingPacket", hfinfo->type == FT_FRAMENUM);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/Menubar/MenuEdit/Copy/Description",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/Menubar/MenuEdit/Copy/Fieldname",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/Menubar/MenuEdit/Copy/Value",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/Menubar/MenuEdit/Copy/AsFilter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/Menubar/MenuAnalyze/ApplyasColumn",
                             hfinfo->type != FT_NONE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/Menubar/MenuAnalyze/ApplyAsFilter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/Menubar/MenuAnalyze/PrepareaFilter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(ui_manager_tree_view_menu, "/Menubar/MenuView/ExpandSubtrees",
                             cf->finfo_selected->tree_type != -1);
#else
        set_menu_sensitivity_old(
                             "/File/Export/Selected Packet Bytes...", TRUE);
        set_menu_sensitivity_old(
                             "/Go/Go to Corresponding Packet", hfinfo->type == FT_FRAMENUM);
        set_menu_sensitivity_old("/Edit/Copy/Description",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity_old("/Edit/Copy/Fieldname",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity_old("/Edit/Copy/Value",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity_old("/Edit/Copy/As Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity_old("/Analyze/Apply as Column",
                             hfinfo->type != FT_NONE);
        set_menu_sensitivity_old("/Analyze/Apply as Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity_old("/Analyze/Prepare a Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity_old("/View/Expand Subtrees",
                             cf->finfo_selected->tree_type != -1);
#endif
        prev_abbrev = g_object_get_data(G_OBJECT(ui_manager_tree_view_menu), "menu_abbrev");
        if (!prev_abbrev || (strcmp (prev_abbrev, abbrev) != 0)) {
            /* No previous protocol or protocol changed - update Protocol Preferences menu */
            module_t *prefs_module_p = prefs_find_module(abbrev);
            rebuild_protocol_prefs_menu (prefs_module_p, properties);

            g_object_set_data(G_OBJECT(ui_manager_tree_view_menu), "menu_abbrev", g_strdup(abbrev));
            g_free (prev_abbrev);
        }
    } else {
        set_menu_sensitivity(ui_manager_tree_view_menu,
                             "/TreeViewPopup/GotoCorrespondingPacket", FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/Copy", FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyasColumn", FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyAsFilter", FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/PrepareaFilter", FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ColorizewithFilter", FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ProtocolPreferences",
                             FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/DisableProtocol", FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ExpandSubtrees", FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/WikiProtocolPage",
                             FALSE);
        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FilterFieldReference",
                             FALSE);
#ifdef MAIN_MENU_USE_UIMANAGER
        set_menu_sensitivity(ui_manager_main_menubar,
                             "/Menubar/FileMenu/Export/SelectedPacketBytes", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar,
                             "/Menubar/GoMenu/GotoCorrespondingPacket", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Copy/Description", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Copy/Fieldname", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Copy/Value", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Copy/AsFilter", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/ApplyasColumn", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/ApplyAsFilter", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/PrepareaFilter", FALSE);
        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ExpandSubtrees", FALSE);
#else /* MAIN_MENU_USE_UIMANAGER */
        set_menu_sensitivity_old("/File/Export/Selected Packet Bytes...", FALSE);
        set_menu_sensitivity_old("/Go/Go to Corresponding Packet", FALSE);
        set_menu_sensitivity_old("/Edit/Copy/Description", FALSE);
        set_menu_sensitivity_old("/Edit/Copy/Fieldname", FALSE);
        set_menu_sensitivity_old("/Edit/Copy/Value", FALSE);
        set_menu_sensitivity_old("/Edit/Copy/As Filter", FALSE);
        set_menu_sensitivity_old("/Analyze/Apply as Column", FALSE);
        set_menu_sensitivity_old("/Analyze/Apply as Filter", FALSE);
        set_menu_sensitivity_old("/Analyze/Prepare a Filter", FALSE);
        set_menu_sensitivity_old("/View/Expand Subtrees", FALSE);
#endif /* MAIN_MENU_USE_UIMANAGER */
    }

    walk_menu_tree_for_selected_tree_row(tap_menu_tree_root, cf->finfo_selected);
}

void set_menus_for_packet_history(gboolean back_history, gboolean forward_history) {
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/Back", back_history);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/Forward", forward_history);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/Go/Back", back_history);
    set_menu_sensitivity_old("/Go/Forward", forward_history);
#endif /* MAIN_MENU_USE_UIMANAGER */
    set_toolbar_for_packet_history(back_history, forward_history);
}


void set_menus_for_file_set(gboolean file_set, gboolean previous_file, gboolean next_file) {
#ifdef MAIN_MENU_USE_UIMANAGER
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Set/ListFiles", file_set);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Set/PreviousFile", previous_file);
    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/FileMenu/Set/NextFile", next_file);
#else /* MAIN_MENU_USE_UIMANAGER */
    set_menu_sensitivity_old("/File/File Set/List Files", file_set);
    set_menu_sensitivity_old("/File/File Set/Previous File", previous_file);
    set_menu_sensitivity_old("/File/File Set/Next File", next_file);
#endif /* MAIN_MENU_USE_UIMANAGER */
}

GtkWidget *menus_get_profiles_menu (void)
{
    return gtk_ui_manager_get_widget(ui_manager_statusbar_profiles_menu, "/ProfilesMenuPopup/Change");
}

void set_menus_for_profiles(gboolean default_profile)
{
    set_menu_sensitivity(ui_manager_statusbar_profiles_menu, "/ProfilesMenuPopup/Delete", !default_profile);
    set_menu_sensitivity(ui_manager_statusbar_profiles_menu, "/ProfilesMenuPopup/Rename", !default_profile);
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

