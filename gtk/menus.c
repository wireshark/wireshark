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

#include "../print.h"
#include "../register.h"
#include "../ui_util.h"
#include "../simple_dialog.h"
#include "../color_filters.h"
#include "../stat_menu.h"

#include "gtk/about_dlg.h"
#include "gtk/capture_dlg.h"
#include "gtk/capture_if_dlg.h"
#include "gtk/color_dlg.h"
#include "gtk/filter_dlg.h"
#include "gtk/profile_dlg.h"
#include "gtk/dlg_utils.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/fileset_dlg.h"
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
#include "gtk/u3.h"
#include "gtk/macros_dlg.h"
#include "gtk/export_object.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/main.h"
#include "gtk/menus.h"
#include "gtk/main_packet_list.h"
#include "gtk/main_toolbar.h"
#include "gtk/main_welcome.h"
#include "gtk/uat_gui.h"
#include "gtk/gui_utils.h"

#ifdef HAVE_IGE_MAC_INTEGRATION
#include <ige-mac-menu.h>
#endif

typedef struct _menu_item {
    char    *name;
    gint    group;
    const char *stock_id;
    gboolean enabled;
    GtkItemFactoryCallback callback;
    gpointer callback_data;
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *, gpointer callback_data);
    gboolean (*selected_tree_row_enabled)(field_info *, gpointer callback_data);
    GList *children;
} menu_item_t;

static GList *tap_menu_tree_root = NULL;

GtkWidget *popup_menu_object;


#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

static void merge_all_tap_menus(GList *node);
static void clear_menu_recent_capture_file_cmd_cb(GtkWidget *w, gpointer unused _U_);

static void menus_init(void);
static void set_menu_sensitivity (GtkItemFactory *, const gchar *, gint);
static void show_hide_cb(GtkWidget *w, gpointer data, gint action);
static void timestamp_format_cb(GtkWidget *w, gpointer d, gint action);
static void timestamp_precision_cb(GtkWidget *w, gpointer d, gint action);
static void name_resolution_cb(GtkWidget *w, gpointer d, gint action);
#ifdef HAVE_LIBPCAP
static void auto_scroll_live_cb(GtkWidget *w, gpointer d);
#endif
static void colorize_cb(GtkWidget *w, gpointer d);


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
               "<ImageItem>"      -> create an item holding an image (gtk2)
               "<StockItem>"      -> create an item holding a stock image (gtk2)
               "<CheckItem>"      -> create a check item
               "<ToggleItem>"     -> create a toggle item
               "<RadioItem>"      -> create a radio item
               <path>             -> path of a radio item to link against
               "<Separator>"      -> create a separator
               "<Tearoff>"        -> create a tearoff separator (gtk2)
               "<Branch>"         -> create an item to hold sub items (optional)
               "<LastBranch>"     -> create a right justified branch
       Item 6: extra data needed for ImageItem and StockItem (gtk2)
    */

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

void
conversation_cb(GtkWidget * w, gpointer data _U_, int action)
{
    gchar       *filter;
    GtkWidget   *filter_te;

    if (cfile.current_frame) {
        /* create a filter-string based on the selected packet and action */
        filter = build_conversation_filter(action, TRUE);

        /* Run the display filter so it goes in effect - even if it's the
        same as the previous display filter. */
        filter_te = g_object_get_data(G_OBJECT(w), E_DFILTER_TE_KEY);
        gtk_entry_set_text(GTK_ENTRY(filter_te), filter);
        main_filter_packets(&cfile, filter, TRUE);

        g_free(filter);
    }
}

void
colorize_conversation_cb(GtkWidget * w _U_, gpointer data _U_, int action)
{
    gchar        *filter = NULL;

    if( (action>>8) == 255 ) {
        color_filters_reset_tmp();
        cf_colorize_packets(&cfile);
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
            cf_colorize_packets(&cfile);
        }

        g_free(filter);
    }
}

/* main menu */
static GtkItemFactoryEntry menu_items[] =
{
    {"/_File", NULL, NULL, 0, "<Branch>", NULL,},
    {"/File/_Open...", "<control>O", GTK_MENU_FUNC(file_open_cmd_cb),
                             0, "<StockItem>", GTK_STOCK_OPEN,},
    {"/File/Open _Recent", NULL, NULL, 0, "<Branch>", NULL,},
    {"/File/_Merge...", NULL, GTK_MENU_FUNC(file_merge_cmd_cb), 0, NULL, NULL,},
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
    /* Un-#if this when we actually implement Cut/Copy/Paste. */
    {"/Edit/Cut", "<control>X", NULL,
                             0, "<StockItem>", GTK_STOCK_CUT,},
    {"/Edit/Copy", "<control>C", NULL,
                             0, "<StockItem>", GTK_STOCK_COPY,},
    {"/Edit/Paste", "<control>V", NULL,
                             0, "<StockItem>", GTK_STOCK_PASTE,},
#endif
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/_Find Packet...", "<control>F",
                             GTK_MENU_FUNC(find_frame_cb), 0, "<StockItem>", GTK_STOCK_FIND,},
    {"/Edit/Find Ne_xt", "<control>N", GTK_MENU_FUNC(find_next_cb), 0, NULL, NULL,},
    {"/Edit/Find Pre_vious", "<control>B", GTK_MENU_FUNC(find_previous_cb), 0, NULL, NULL,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/_Mark Packet (toggle)", "<control>M", GTK_MENU_FUNC(packet_list_mark_frame_cb),
                       0, NULL, NULL,},
    {"/Edit/Find Next Mark", "<shift><control>N", GTK_MENU_FUNC(find_next_mark_cb),
                       0, NULL, NULL,},
    {"/Edit/Find Previous Mark", "<shift><control>B", GTK_MENU_FUNC(find_prev_mark_cb),
                       0, NULL, NULL,},
    {"/Edit/Mark _All Packets", "<control>A", GTK_MENU_FUNC(packet_list_mark_all_frames_cb),
                       0, NULL, NULL,},
    {"/Edit/_Unmark All Packets", "<control>D", GTK_MENU_FUNC(packet_list_unmark_all_frames_cb),
                       0, NULL, NULL,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/Set Time Reference (toggle)", "<control>T", GTK_MENU_FUNC(reftime_frame_cb),
                        REFTIME_TOGGLE, "<StockItem>", WIRESHARK_STOCK_TIME,},
    {"/Edit/Find Next Reference", "<alt><shift><control>N", GTK_MENU_FUNC(reftime_frame_cb), REFTIME_FIND_NEXT, NULL, NULL,},
    {"/Edit/Find Previous Reference", "<alt><shift><control>B", GTK_MENU_FUNC(reftime_frame_cb), REFTIME_FIND_PREV, NULL, NULL,},
    {"/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Edit/_Configuration Profiles...", "<shift><control>A", GTK_MENU_FUNC(profile_dialog_cb), 0, NULL, NULL,},
    {"/Edit/_Preferences...", "<shift><control>P", GTK_MENU_FUNC(prefs_cb),
                             0, "<StockItem>", GTK_STOCK_PREFERENCES,},
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
    {"/View/Resize All Columns", "<shift><control>R", GTK_MENU_FUNC(packet_list_resize_columns_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_RESIZE_COLUMNS,},
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
                             GTK_MENU_FUNC(packet_list_prev), 0, "<StockItem>", GTK_STOCK_GO_UP,},
    {"/Go/Next Packet", "<control>Down",
                             GTK_MENU_FUNC(packet_list_next), 0, "<StockItem>", GTK_STOCK_GO_DOWN,},
    {"/Go/F_irst Packet", "<control>Home",
                             GTK_MENU_FUNC(goto_top_frame_cb), 0, "<StockItem>", GTK_STOCK_GOTO_TOP,},
    {"/Go/_Last Packet", "<control>End",
                             GTK_MENU_FUNC(goto_bottom_frame_cb), 0, "<StockItem>", GTK_STOCK_GOTO_BOTTOM,},
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
    {"/Analyze/Appl_y as Filter", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Analyze/Apply as Filter/_Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/_Not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/... _and Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/... _or Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/... a_nd not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/Apply as Filter/... o_r not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Analyze/_Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Analyze/Prepare a Filter/_Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_REPLACE, NULL, NULL,},
    {"/Analyze/Prepare a Filter/_Not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_NOT, NULL, NULL,},
    {"/Analyze/Prepare a Filter/... _and Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND, NULL, NULL,},
    {"/Analyze/Prepare a Filter/... _or Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR, NULL, NULL,},
    {"/Analyze/Prepare a Filter/... a_nd not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND_NOT, NULL, NULL,},
    {"/Analyze/Prepare a Filter/... o_r not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
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
    {"/_Help", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Help/_Contents", "F1", GTK_MENU_FUNC(topic_menu_cb), HELP_CONTENT, "<StockItem>", GTK_STOCK_HELP,},
    {"/Help/FAQ's", NULL, GTK_MENU_FUNC(topic_menu_cb), ONLINEPAGE_FAQ, NULL, NULL,},
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
    {"/Help/Wiki", NULL, GTK_MENU_FUNC(topic_menu_cb), ONLINEPAGE_WIKI, "<StockItem>", WIRESHARK_STOCK_WIKI,},
    {"/Help/Downloads", NULL, GTK_MENU_FUNC(topic_menu_cb), ONLINEPAGE_DOWNLOAD, NULL, NULL,},
    {"/Help/Sample Captures", NULL, GTK_MENU_FUNC(topic_menu_cb), ONLINEPAGE_SAMPLE_FILES, NULL, NULL,},
    {"/Help/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Help/_Supported Protocols (slow!)", NULL, GTK_MENU_FUNC(supported_cb), 0, NULL, NULL,},
    {"/Help/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Help/_About Wireshark", NULL, GTK_MENU_FUNC(about_wireshark_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_ABOUT}
};


/* calculate the number of menu_items */
static int nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

/* packet list popup */
static GtkItemFactoryEntry packet_list_menu_items[] =
{
    {"/Mark Packet (toggle)", NULL, GTK_MENU_FUNC(packet_list_mark_frame_cb), 0, NULL, NULL,},
    {"/Set Time Reference (toggle)", NULL, GTK_MENU_FUNC(reftime_frame_cb), REFTIME_TOGGLE, "<StockItem>", WIRESHARK_STOCK_TIME,},

    {"/<separator>", NULL, NULL, 0, "<Separator>", NULL,},

    {"/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Apply as Filter/_Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/_Not Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/... _and Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/... _or Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/... a_nd not Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/... o_r not Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},

    {"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Prepare a Filter/_Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_REPLACE, NULL, NULL,},
    {"/Prepare a Filter/_Not Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_NOT, NULL, NULL,},
    {"/Prepare a Filter/... _and Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_AND, NULL, NULL,},
    {"/Prepare a Filter/... _or Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_OR, NULL, NULL,},
    {"/Prepare a Filter/... a_nd not Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_AND_NOT, NULL, NULL,},
    {"/Prepare a Filter/... o_r not Selected", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_OR_NOT, NULL, NULL,},

    {"/Conversation Filter", NULL, NULL, 0, "<Branch>",NULL,},
    {"/Conversation Filter/Ethernet", NULL, GTK_MENU_FUNC(conversation_cb),
                       CONV_ETHER, NULL, NULL,},
    {"/Conversation Filter/IP", NULL, GTK_MENU_FUNC(conversation_cb),
                       CONV_IP, NULL, NULL,},
    {"/Conversation Filter/TCP", NULL, GTK_MENU_FUNC(conversation_cb),
                       CONV_TCP, NULL, NULL,},
    {"/Conversation Filter/UDP", NULL, GTK_MENU_FUNC(conversation_cb),
                       CONV_UDP, NULL, NULL,},
    {"/Conversation Filter/PN-CBA Server", NULL, GTK_MENU_FUNC(conversation_cb),
                       CONV_CBA, NULL, NULL,},

    {"/Colorize Conversation", NULL, NULL, 0, "<Branch>",NULL,},
    {"/Colorize Conversation/Ethernet", NULL, NULL, 0, "<Branch>",NULL,},
    {"/Colorize Conversation/Ethernet/Color 1", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+1*256, "<StockItem>", WIRESHARK_STOCK_COLOR1,},
    {"/Colorize Conversation/Ethernet/Color 2", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+2*256, "<StockItem>", WIRESHARK_STOCK_COLOR2,},
    {"/Colorize Conversation/Ethernet/Color 3", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+3*256, "<StockItem>", WIRESHARK_STOCK_COLOR3,},
    {"/Colorize Conversation/Ethernet/Color 4", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+4*256, "<StockItem>", WIRESHARK_STOCK_COLOR4,},
    {"/Colorize Conversation/Ethernet/Color 5", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+5*256, "<StockItem>", WIRESHARK_STOCK_COLOR5,},
    {"/Colorize Conversation/Ethernet/Color 6", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+6*256, "<StockItem>", WIRESHARK_STOCK_COLOR6,},
    {"/Colorize Conversation/Ethernet/Color 7", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+7*256, "<StockItem>", WIRESHARK_STOCK_COLOR7,},
    {"/Colorize Conversation/Ethernet/Color 8", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+8*256, "<StockItem>", WIRESHARK_STOCK_COLOR8,},
    {"/Colorize Conversation/Ethernet/Color 9", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+9*256, "<StockItem>", WIRESHARK_STOCK_COLOR9,},
    {"/Colorize Conversation/Ethernet/Color 10", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER+10*256, "<StockItem>", WIRESHARK_STOCK_COLOR0,},
    {"/Colorize Conversation/Ethernet/<separator>", NULL,
                       NULL, 0, "<Separator>",NULL,},
    {"/Colorize Conversation/Ethernet/New Coloring Rule...", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_ETHER, "<StockItem>", GTK_STOCK_SELECT_COLOR,},
    {"/Colorize Conversation/IP", NULL, NULL, 0, "<Branch>",NULL,},
    {"/Colorize Conversation/IP/Color 1", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+1*256, "<StockItem>", WIRESHARK_STOCK_COLOR1,},
    {"/Colorize Conversation/IP/Color 2", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+2*256, "<StockItem>", WIRESHARK_STOCK_COLOR2,},
    {"/Colorize Conversation/IP/Color 3", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+3*256, "<StockItem>", WIRESHARK_STOCK_COLOR3,},
    {"/Colorize Conversation/IP/Color 4", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+4*256, "<StockItem>", WIRESHARK_STOCK_COLOR4,},
    {"/Colorize Conversation/IP/Color 5", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+5*256, "<StockItem>", WIRESHARK_STOCK_COLOR5,},
    {"/Colorize Conversation/IP/Color 6", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+6*256, "<StockItem>", WIRESHARK_STOCK_COLOR6,},
    {"/Colorize Conversation/IP/Color 7", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+7*256, "<StockItem>", WIRESHARK_STOCK_COLOR7,},
    {"/Colorize Conversation/IP/Color 8", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+8*256, "<StockItem>", WIRESHARK_STOCK_COLOR8,},
    {"/Colorize Conversation/IP/Color 9", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+9*256, "<StockItem>", WIRESHARK_STOCK_COLOR9,},
    {"/Colorize Conversation/IP/Color 10", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP+10*256, "<StockItem>", WIRESHARK_STOCK_COLOR0,},
    {"/Colorize Conversation/IP/<separator>", NULL,
                       NULL, 0, "<Separator>",NULL,},
    {"/Colorize Conversation/IP/New Coloring Rule...", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_IP, "<StockItem>", GTK_STOCK_SELECT_COLOR,},
    {"/Colorize Conversation/TCP", NULL, NULL, 0, "<Branch>",NULL,},
    {"/Colorize Conversation/TCP/Color 1", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+1*256, "<StockItem>", WIRESHARK_STOCK_COLOR1,},
    {"/Colorize Conversation/TCP/Color 2", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+2*256, "<StockItem>", WIRESHARK_STOCK_COLOR2,},
    {"/Colorize Conversation/TCP/Color 3", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+3*256, "<StockItem>", WIRESHARK_STOCK_COLOR3,},
    {"/Colorize Conversation/TCP/Color 4", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+4*256, "<StockItem>", WIRESHARK_STOCK_COLOR4,},
    {"/Colorize Conversation/TCP/Color 5", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+5*256, "<StockItem>", WIRESHARK_STOCK_COLOR5,},
    {"/Colorize Conversation/TCP/Color 6", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+6*256, "<StockItem>", WIRESHARK_STOCK_COLOR6,},
    {"/Colorize Conversation/TCP/Color 7", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+7*256, "<StockItem>", WIRESHARK_STOCK_COLOR7,},
    {"/Colorize Conversation/TCP/Color 8", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+8*256, "<StockItem>", WIRESHARK_STOCK_COLOR8,},
    {"/Colorize Conversation/TCP/Color 9", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+9*256, "<StockItem>", WIRESHARK_STOCK_COLOR9,},
    {"/Colorize Conversation/TCP/Color 10", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP+10*256, "<StockItem>", WIRESHARK_STOCK_COLOR0,},
    {"/Colorize Conversation/TCP/<separator>", NULL,
                       NULL, 0, "<Separator>",NULL,},
    {"/Colorize Conversation/TCP/New Coloring Rule...", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_TCP, "<StockItem>", GTK_STOCK_SELECT_COLOR,},
    {"/Colorize Conversation/UDP", NULL, NULL, 0, "<Branch>",NULL,},
    {"/Colorize Conversation/UDP/Color 1", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+1*256, "<StockItem>", WIRESHARK_STOCK_COLOR1,},
    {"/Colorize Conversation/UDP/Color 2", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+2*256, "<StockItem>", WIRESHARK_STOCK_COLOR2,},
    {"/Colorize Conversation/UDP/Color 3", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+3*256, "<StockItem>", WIRESHARK_STOCK_COLOR3,},
    {"/Colorize Conversation/UDP/Color 4", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+4*256, "<StockItem>", WIRESHARK_STOCK_COLOR4,},
    {"/Colorize Conversation/UDP/Color 5", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+5*256, "<StockItem>", WIRESHARK_STOCK_COLOR5,},
    {"/Colorize Conversation/UDP/Color 6", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+6*256, "<StockItem>", WIRESHARK_STOCK_COLOR6,},
    {"/Colorize Conversation/UDP/Color 7", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+7*256, "<StockItem>", WIRESHARK_STOCK_COLOR7,},
    {"/Colorize Conversation/UDP/Color 8", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+8*256, "<StockItem>", WIRESHARK_STOCK_COLOR8,},
    {"/Colorize Conversation/UDP/Color 9", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+9*256, "<StockItem>", WIRESHARK_STOCK_COLOR9,},
    {"/Colorize Conversation/UDP/Color 10", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP+10*256, "<StockItem>", WIRESHARK_STOCK_COLOR0,},
    {"/Colorize Conversation/UDP/<separator>", NULL,
                       NULL, 0, "<Separator>",NULL,},
    {"/Colorize Conversation/UDP/New Coloring Rule...", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_UDP, "<StockItem>", GTK_STOCK_SELECT_COLOR,},
    {"/Colorize Conversation/PN-CBA Server", NULL, NULL, 0, "<Branch>",NULL,},
    {"/Colorize Conversation/PN-CBA Server/Color 1", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+1*256, "<StockItem>", WIRESHARK_STOCK_COLOR1,},
    {"/Colorize Conversation/PN-CBA Server/Color 2", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+2*256, "<StockItem>", WIRESHARK_STOCK_COLOR2,},
    {"/Colorize Conversation/PN-CBA Server/Color 3", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+3*256, "<StockItem>", WIRESHARK_STOCK_COLOR3,},
    {"/Colorize Conversation/PN-CBA Server/Color 4", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+4*256, "<StockItem>", WIRESHARK_STOCK_COLOR4,},
    {"/Colorize Conversation/PN-CBA Server/Color 5", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+5*256, "<StockItem>", WIRESHARK_STOCK_COLOR5,},
    {"/Colorize Conversation/PN-CBA Server/Color 6", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+6*256, "<StockItem>", WIRESHARK_STOCK_COLOR6,},
    {"/Colorize Conversation/PN-CBA Server/Color 7", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+7*256, "<StockItem>", WIRESHARK_STOCK_COLOR7,},
    {"/Colorize Conversation/PN-CBA Server/Color 8", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+8*256, "<StockItem>", WIRESHARK_STOCK_COLOR8,},
    {"/Colorize Conversation/PN-CBA Server/Color 9", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+9*256, "<StockItem>", WIRESHARK_STOCK_COLOR9,},
    {"/Colorize Conversation/PN-CBA Server/Color 10", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA+10*256, "<StockItem>", WIRESHARK_STOCK_COLOR0,},
    {"/Colorize Conversation/PN-CBA Server/<separator>", NULL,
                       NULL, 0, "<Separator>",NULL,},
    {"/Colorize Conversation/PN-CBA Server/New Coloring Rule...", NULL,
                       GTK_MENU_FUNC(colorize_conversation_cb), CONV_CBA, "<StockItem>", GTK_STOCK_SELECT_COLOR,},

    {"/SCTP", NULL, NULL, 0, "<Branch>",NULL,},
    {"/SCTP/Analyse this Association", NULL, GTK_MENU_FUNC(sctp_analyse_start),
                       0, NULL,NULL,},
    {"/SCTP/Prepare Filter for this Association", NULL, (sctp_set_assoc_filter),
                       0, NULL,NULL,},

    {"/Follow TCP Stream", NULL, (follow_tcp_stream_cb),
                       0, NULL, NULL,},
    {"/Follow UDP Stream", NULL, (follow_udp_stream_cb),
                       0, NULL, NULL,},
    {"/Follow SSL Stream", NULL, (follow_ssl_stream_cb),
                       0, NULL, NULL,},

    {"/<separator>", NULL, NULL, 0, "<Separator>", NULL,},

    {"/Copy", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Copy/Summary (Text)", NULL, GTK_MENU_FUNC(packet_list_copy_summary_cb), CS_TEXT, NULL, NULL,},
    {"/Copy/Summary (CSV)", NULL, GTK_MENU_FUNC(packet_list_copy_summary_cb), CS_CSV, NULL, NULL,},
    {"/Copy/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Copy/As Filter", NULL, GTK_MENU_FUNC(match_selected_plist_cb),
                       MATCH_SELECTED_REPLACE|MATCH_SELECTED_COPY_ONLY, NULL, NULL,},
    {"/Copy/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Copy/Bytes (Offset Hex Text)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_ALLINFO, NULL, NULL,},
    {"/Copy/Bytes (Offset Hex)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_HEXCOLUMNS, NULL, NULL,},
    {"/Copy/Bytes (Printable Text Only)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_TEXTONLY, NULL, NULL,},
    {"/Copy/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Copy/Bytes (Hex Stream)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_HEX, NULL, NULL,},
    {"/Copy/Bytes (Binary Stream)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_BINARY, NULL, NULL,},

    {"/<separator>", NULL, NULL, 0, "<Separator>", NULL,},

    {"/Decode As...", NULL, GTK_MENU_FUNC(decode_as_cb), 0, "<StockItem>", WIRESHARK_STOCK_DECODE_AS,},
    {"/Print...", NULL, GTK_MENU_FUNC(file_print_selected_cmd_cb), 0, "<StockItem>", GTK_STOCK_PRINT,},
    {"/Show Packet in New Window", NULL, GTK_MENU_FUNC(new_window_cb),
                       0, NULL, NULL}
};

static GtkItemFactoryEntry tree_view_menu_items[] =
{

    {"/Expand Subtrees", NULL, GTK_MENU_FUNC(expand_tree_cb), 0, NULL, NULL,},
    {"/Expand All", NULL, GTK_MENU_FUNC(expand_all_cb), 0, NULL, NULL,},
    {"/Collapse All", NULL, GTK_MENU_FUNC(collapse_all_cb), 0, NULL, NULL,},

    {"/<separator>", NULL, NULL, 0, "<Separator>", NULL,},

    {"/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Apply as Filter/_Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/_Not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/... _and Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/... _or Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/... a_nd not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},
    {"/Apply as Filter/... o_r not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL,},

    {"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Prepare a Filter/_Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_REPLACE, NULL, NULL,},
    {"/Prepare a Filter/_Not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_NOT, NULL, NULL,},
    {"/Prepare a Filter/... _and Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND, NULL, NULL,},
    {"/Prepare a Filter/... _or Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR, NULL, NULL,},
    {"/Prepare a Filter/... a_nd not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_AND_NOT, NULL, NULL,},
    {"/Prepare a Filter/... o_r not Selected", NULL, GTK_MENU_FUNC(match_selected_ptree_cb),
                       MATCH_SELECTED_OR_NOT, NULL, NULL,},

    {"/Colorize with Filter", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Colorize with Filter/Color 1", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 1, "<StockItem>", WIRESHARK_STOCK_COLOR1,},
    {"/Colorize with Filter/Color 2", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 2, "<StockItem>", WIRESHARK_STOCK_COLOR2,},
    {"/Colorize with Filter/Color 3", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 3, "<StockItem>", WIRESHARK_STOCK_COLOR3,},
    {"/Colorize with Filter/Color 4", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 4, "<StockItem>", WIRESHARK_STOCK_COLOR4,},
    {"/Colorize with Filter/Color 5", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 5, "<StockItem>", WIRESHARK_STOCK_COLOR5,},
    {"/Colorize with Filter/Color 6", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 6, "<StockItem>", WIRESHARK_STOCK_COLOR6,},
    {"/Colorize with Filter/Color 7", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 7, "<StockItem>", WIRESHARK_STOCK_COLOR7,},
    {"/Colorize with Filter/Color 8", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 8, "<StockItem>", WIRESHARK_STOCK_COLOR8,},
    {"/Colorize with Filter/Color 9", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 9, "<StockItem>", WIRESHARK_STOCK_COLOR9,},
    {"/Colorize with Filter/Color 10", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 10, "<StockItem>", WIRESHARK_STOCK_COLOR0,},
    {"/Colorize with Filter/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Colorize with Filter/New Coloring Rule...", NULL, GTK_MENU_FUNC(colorize_selected_ptree_cb), 0, "<StockItem>", GTK_STOCK_SELECT_COLOR,},

    {"/Follow TCP Stream", NULL, GTK_MENU_FUNC(follow_tcp_stream_cb),
                       0, NULL, NULL,},
    {"/Follow UDP Stream", NULL, GTK_MENU_FUNC(follow_udp_stream_cb),
                       0, NULL, NULL,},
    {"/Follow SSL Stream", NULL, GTK_MENU_FUNC(follow_ssl_stream_cb),
                       0, NULL, NULL,},

    {"/<separator>", NULL, NULL, 0, "<Separator>", NULL,},

    {"/Copy", NULL, NULL, 0, "<Branch>", NULL,},
    {"/Copy/Description", NULL, GTK_MENU_FUNC(copy_selected_plist_cb), COPY_SELECTED_DESCRIPTION, NULL, NULL,},
    {"/Copy/Fieldname", NULL, GTK_MENU_FUNC(copy_selected_plist_cb), COPY_SELECTED_FIELDNAME, NULL, NULL,},
    {"/Copy/Value", NULL, GTK_MENU_FUNC(copy_selected_plist_cb), COPY_SELECTED_VALUE, NULL, NULL,},
    {"/Copy/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Copy/As Filter", NULL, GTK_MENU_FUNC(match_selected_ptree_cb), MATCH_SELECTED_REPLACE|MATCH_SELECTED_COPY_ONLY, NULL, NULL,},
    {"/Copy/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Copy/Bytes (Offset Hex Text)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_ALLINFO | CD_FLAGS_SELECTEDONLY, NULL, NULL,},
    {"/Copy/Bytes (Offset Hex)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_HEXCOLUMNS | CD_FLAGS_SELECTEDONLY, NULL, NULL,},
    {"/Copy/Bytes (Printable Text Only)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_TEXTONLY | CD_FLAGS_SELECTEDONLY, NULL, NULL,},
    {"/Copy/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Copy/Bytes (Hex Stream)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_HEX | CD_FLAGS_SELECTEDONLY, NULL, NULL,},
    {"/Copy/Bytes (Binary Stream)", NULL, GTK_MENU_FUNC(copy_hex_cb), CD_BINARY | CD_FLAGS_SELECTEDONLY, NULL, NULL,},

    {"/Export Selected Packet Bytes...", NULL, GTK_MENU_FUNC(savehex_cb),
                       0, NULL, NULL,},

    {"/<separator>", NULL, NULL, 0, "<Separator>", NULL,},

    {"/Wiki Protocol Page", NULL, GTK_MENU_FUNC(selected_ptree_info_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_WIKI,},
    {"/Filter Field Reference", NULL, GTK_MENU_FUNC(selected_ptree_ref_cb),
                       0, "<StockItem>", WIRESHARK_STOCK_INTERNET,},
    {"/Protocol Preferences", NULL, NULL, 0, NULL, NULL,},
    {"/<separator>", NULL, NULL, 0, "<Separator>", NULL,},
    {"/Decode As...", NULL, GTK_MENU_FUNC(decode_as_cb), 0, "<StockItem>", WIRESHARK_STOCK_DECODE_AS,},
    {"/Disable Protocol...", NULL, GTK_MENU_FUNC(proto_disable_cb), 0, "<StockItem>", WIRESHARK_STOCK_CHECKBOX,},
    {"/_Resolve Name", NULL, GTK_MENU_FUNC(resolve_name_cb), 0, NULL, NULL,},
    {"/_Go to Corresponding Packet", NULL, GTK_MENU_FUNC(goto_framenum_cb), 0, NULL, NULL,}
};


static int initialize = TRUE;
static GtkItemFactory *main_menu_factory = NULL;
static GtkItemFactory *packet_list_menu_factory = NULL;
static GtkItemFactory *tree_view_menu_factory = NULL;
static GtkItemFactory *hexdump_menu_factory = NULL;

static GSList *popup_menu_list = NULL;

static GtkAccelGroup *grp;

GtkWidget *
main_menu_new(GtkAccelGroup ** table) {
    GtkWidget *menubar;
#ifdef HAVE_IGE_MAC_INTEGRATION
    GtkWidget *quit_item, *about_item, *preferences_item;
    IgeMacMenuGroup *group;
#endif

    grp = gtk_accel_group_new();

    if (initialize)
        menus_init();

    menubar = main_menu_factory->widget;

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

    if (table)
        *table = grp;

    return menubar;
}


void menu_dissector_filter_cb(  GtkWidget *widget _U_,
                                gpointer callback_data,
                                guint callback_action _U_)
{
    dissector_filter_t      *filter_entry = callback_data;
    GtkWidget               *filter_te;
    const char              *buf;    


    filter_te = g_object_get_data(G_OBJECT(popup_menu_object), E_DFILTER_TE_KEY);

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

        register_stat_menu_item(filter_entry->name, REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER,
            menu_dissector_filter_cb,
            menu_dissector_filter_spe_cb,
            NULL /* selected_tree_row_enabled */,
            filter_entry);

        list_entry = g_list_next(list_entry);
    }
}


static void
menus_init(void) {
    if (initialize) {
        initialize = FALSE;

    /* packet list pop-up menu */
    packet_list_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    popup_menu_object = gtk_menu_new();
    gtk_item_factory_create_items_ac(packet_list_menu_factory, sizeof(packet_list_menu_items)/sizeof(packet_list_menu_items[0]), packet_list_menu_items, popup_menu_object, 2);
    g_object_set_data(G_OBJECT(popup_menu_object), PM_PACKET_LIST_KEY,
                    packet_list_menu_factory->widget);
    popup_menu_list = g_slist_append((GSList *)popup_menu_list, packet_list_menu_factory);

    /* packet detail pop-up menu */
    tree_view_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    gtk_item_factory_create_items_ac(tree_view_menu_factory, sizeof(tree_view_menu_items)/sizeof(tree_view_menu_items[0]), tree_view_menu_items, popup_menu_object, 2);
    g_object_set_data(G_OBJECT(popup_menu_object), PM_TREE_VIEW_KEY,
                    tree_view_menu_factory->widget);
    popup_menu_list = g_slist_append((GSList *)popup_menu_list, tree_view_menu_factory);

    /*
     * Hex dump pop-up menu.
     * We provide our own empty menu to suppress the default pop-up menu
     * for text widgets.
     */
    hexdump_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    g_object_set_data(G_OBJECT(popup_menu_object), PM_HEXDUMP_KEY,
                    hexdump_menu_factory->widget);
    popup_menu_list = g_slist_append((GSList *)popup_menu_list, hexdump_menu_factory);

    /* main */
    main_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU_BAR, "<main>", grp);
    gtk_item_factory_create_items_ac(main_menu_factory, nmenu_items, menu_items, NULL, 2);

    menu_dissector_filter();
    merge_all_tap_menus(tap_menu_tree_root);

    /* Initialize enabled/disabled state of menu items */
    set_menus_for_capture_file(NULL);
#if 0
    /* Un-#if this when we actually implement Cut/Copy/Paste.
       Then make sure you enable them when they can be done. */
    set_menu_sensitivity(main_menu_factory, "/Edit/Cut", FALSE);
    set_menu_sensitivity(main_menu_factory, "/Edit/Copy", FALSE);
    set_menu_sensitivity(main_menu_factory, "/Edit/Paste", FALSE);
#endif

    set_menus_for_captured_packets(FALSE);
    set_menus_for_selected_packet(&cfile);
    set_menus_for_selected_tree_row(&cfile);
    set_menus_for_capture_in_progress(FALSE);
    set_menus_for_file_set(/* dialog */TRUE, /* previous file */ FALSE, /* next_file */ FALSE);

    /* init with an empty recent files list */
    clear_menu_recent_capture_file_cmd_cb(NULL, NULL);

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
    char *name,
    gint group,
    const char *stock_id,
    GtkItemFactoryCallback callback,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *, gpointer callback_data),
    gboolean (*selected_tree_row_enabled)(field_info *, gpointer callback_data),
    gpointer callback_data,
    GList *curnode)
{
    menu_item_t *curr;
    menu_item_t *child;


    child = g_malloc(sizeof (menu_item_t));
    child->name             = name;
    child->group            = group;
    child->stock_id         = stock_id;
    child->callback         = callback;
    child->selected_packet_enabled = selected_packet_enabled;
    child->selected_tree_row_enabled = selected_tree_row_enabled;
    child->callback_data    = callback_data;
    child->enabled          = FALSE;
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
    const char *name,
    register_stat_group_t group,
    const char *stock_id,
    GtkItemFactoryCallback callback,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *, gpointer callback_data),
    gboolean (*selected_tree_row_enabled)(field_info *, gpointer callback_data),
    gpointer callback_data)
{
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
            if (strcmp(child->name, menupath) == 0)
                break;
        }
        if (childnode == NULL) {
            /*
             * No.  Create such an item as a subtree, and
             * add it to the Tools menu tree.
             */
            childnode = tap_menu_item_add(
                menupath, group, "", NULL, NULL ,NULL, NULL, curnode);
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

    /*
     * Construct an item factory entry for the item, and add it to
     * the main menu.
     */
    tap_menu_item_add(
        menupath, group, stock_id, callback,
        selected_packet_enabled, selected_tree_row_enabled,
        callback_data, curnode);
}


void
register_stat_menu_item(
    const char *name,
    register_stat_group_t group,
    GtkItemFactoryCallback callback,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *, gpointer callback_data),
    gboolean (*selected_tree_row_enabled)(field_info *, gpointer callback_data),
    gpointer callback_data)
{
    register_stat_menu_item_stock(
        name,
        group,
        NULL,
        callback,
        selected_packet_enabled,
        selected_tree_row_enabled,
        callback_data);
}

static guint merge_tap_menus_layered(GList *node, gint group) {
    GtkItemFactoryEntry *entry;
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
        if (node_data->name != NULL && group == node_data->group) {
            entry = g_malloc0(sizeof (GtkItemFactoryEntry));
            entry->path = node_data->name;
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
            set_menu_sensitivity(main_menu_factory, node_data->name, FALSE); /* no capture file yet */
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
        if (node_data->name != NULL && group == node_data->group) {
            entry = g_malloc0(sizeof (GtkItemFactoryEntry));
            entry->path = node_data->name;
            entry->item_type = "<Branch>";
            gtk_item_factory_create_item(main_menu_factory, entry,
                NULL, 2);
            set_menu_sensitivity(main_menu_factory, node_data->name,
                FALSE);    /* no children yet */
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


void merge_all_tap_menus(GList *node) {
    GtkItemFactoryEntry *sep_entry;

    sep_entry = g_malloc0(sizeof (GtkItemFactoryEntry));
    sep_entry->item_type = "<Separator>";
    sep_entry->path = "/Statistics/";

    /*
     * merge only the menu items of the specific group,
     * and then append a seperator
     */
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_GENERIC)) {
        gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_CONVERSATION_LIST)) {
        /*gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_ENDPOINT_LIST)) {
        /*gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_RESPONSE_TIME)) {
        gtk_item_factory_create_item(main_menu_factory, sep_entry, NULL, 2);
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
set_menu_sensitivity(GtkItemFactory *ifactory, const gchar *path, gint val)
{
    GSList *menu_list;
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

    if (ifactory == NULL) {
        /*
         * Do it for all pop-up menus.
         */
        for (menu_list = popup_menu_list; menu_list != NULL;
             menu_list = g_slist_next(menu_list))
            set_menu_sensitivity(menu_list->data, dup, val);
    } else {
        /*
         * Do it for that particular menu.
         */
        if ((menu_item = gtk_item_factory_get_widget(ifactory, dup)) != NULL) {
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
        } else{
            /* be sure this menu item *is* existing */
            g_assert_not_reached();
        }
    }

    g_free(dup);
}

static void
set_menu_object_data_meat(GtkItemFactory *ifactory, const gchar *path, const gchar *key, gpointer data)
{
    GtkWidget *menu = NULL;

    if ((menu = gtk_item_factory_get_widget(ifactory, path)) != NULL)
        g_object_set_data(G_OBJECT(menu), key, data);
}

void
set_menu_object_data (const gchar *path, const gchar *key, gpointer data) {
    GSList *menu_list = popup_menu_list;
    gchar *shortpath = strrchr(path, '/');

    set_menu_object_data_meat(main_menu_factory, path, key, data);
    while (menu_list != NULL) {
        set_menu_object_data_meat(menu_list->data, shortpath, key, data);
        set_menu_object_data_meat(menu_list->data, path, key, data);
        menu_list = g_slist_next(menu_list);
    }
}


/* Recently used capture files submenu:
 * Submenu containing the recently used capture files.
 * The capture filenames are always kept with the absolute path, to be independant
 * of the current path.
 * They are only stored inside the labels of the submenu (no separate list). */

#define MENU_RECENT_FILES_PATH "/File/Open Recent"
#define MENU_RECENT_FILES_KEY "Recent File Name"



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


    main_welcome_reset_recent_capture_files();

    gtk_container_foreach(GTK_CONTAINER(submenu_recent_files),
                          update_menu_recent_capture_file1, &cnt);

    /* make parent menu item sensitive only, if we have any valid files in the list */
    set_menu_sensitivity(main_menu_factory, MENU_RECENT_FILES_PATH, cnt);
}



/* remove the capture filename from the "Recent Files" menu */
static void
remove_menu_recent_capture_filename(gchar *cf_name) {
    GtkWidget *submenu_recent_files;
    GList* child_list;
    GList* child_list_item;
    GtkWidget    *menu_item_child;
    const gchar *menu_item_cf_name;
    

    /* get the submenu container item */
    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

    /* find the corresponding menu item to be removed */
    child_list = gtk_container_get_children(GTK_CONTAINER(submenu_recent_files));
    child_list_item = child_list;
    while(child_list_item) {
        menu_item_child = (GTK_BIN(child_list_item->data))->child;
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
    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

    /* XXX: is this all we need to do, to free the menu item and its label?
       The reference count of widget will go to 0, so it'll be freed;
       will that free the label? */
    gtk_container_remove(GTK_CONTAINER(submenu_recent_files), widget);
}


/* callback, if the user pushed the <Clear> menu item */
static void
clear_menu_recent_capture_file_cmd_cb(GtkWidget *w _U_, gpointer unused _U_) {
    GtkWidget *submenu_recent_files;


    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

    gtk_container_foreach(GTK_CONTAINER(submenu_recent_files),
                          remove_menu_recent_capture_file, NULL);

    update_menu_recent_capture_file(submenu_recent_files);
}


/* Open a file by it's name
   (Beware: will not ask to close existing capture file!) */
void
menu_open_filename(gchar *cf_name)
{
    GtkWidget *submenu_recent_files;
    int       err;

    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

    /* open and read the capture file (this will close an existing file) */
    if (cf_open(&cfile, cf_name, FALSE, &err) == CF_OK) {
        cf_read(&cfile);
    } else {
        /* the capture file apparently no longer exists; remove menu item    */
        /* XXX: ask user to remove item, it's maybe only a temporary problem */
        remove_menu_recent_capture_filename(cf_name);
    }

    update_menu_recent_capture_file(submenu_recent_files);
}


/* callback, if the user pushed a recent file submenu item */
void
menu_open_recent_file_cmd(GtkWidget *w)
{
    GtkWidget   *submenu_recent_files;
    GtkWidget   *menu_item_child;
    const gchar *cf_name;
    int         err;

    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

    /* get capture filename from the menu item label */
    menu_item_child = (GTK_BIN(w))->child;
    cf_name = gtk_label_get_text(GTK_LABEL(menu_item_child));

    /* open and read the capture file (this will close an existing file) */
    if (cf_open(&cfile, cf_name, FALSE, &err) == CF_OK) {
        cf_read(&cfile);
    } else {
        /* the capture file apparently no longer exists; remove menu item    */
        /* XXX: ask user to remove item, it's maybe only a temporary problem */
        remove_menu_recent_capture_file(w, NULL);
    }

    update_menu_recent_capture_file(submenu_recent_files);
}

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

/* add the capture filename (with an absolute path) to the "Recent Files" menu */
static void
add_menu_recent_capture_file_absolute(gchar *cf_name) {
    GtkWidget *submenu_recent_files;
    GList *menu_item_list;
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

    /* get the submenu container item */
    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

    /* convert container to a GList */
    menu_item_list = gtk_container_get_children(GTK_CONTAINER(submenu_recent_files));

    /* iterate through list items of menu_item_list,
     * removing special items, a maybe duplicate entry and every item above count_max */
    cnt = 1;
    for (li = g_list_first(menu_item_list); li; li = li->next, cnt++) {
        /* get capture filename */
        menu_item = GTK_WIDGET(li->data);
        widget_cf_name = g_object_get_data(G_OBJECT(menu_item), MENU_RECENT_FILES_KEY);

        /* if this element string is one of our special items (seperator, ...) or
         * already in the list or
         * this element is above maximum count (too old), remove it */
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

    g_list_free(menu_item_list);

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


    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

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
        recent.main_toolbar_show = GTK_CHECK_MENU_ITEM(w)->active;
        break;
        case(SHOW_HIDE_FILTER_TOOLBAR):
        recent.filter_toolbar_show = GTK_CHECK_MENU_ITEM(w)->active;
        break;
#ifdef HAVE_AIRPCAP
        case(SHOW_HIDE_AIRPCAP_TOOLBAR):
        recent.airpcap_toolbar_show = GTK_CHECK_MENU_ITEM(w)->active;
        break;
#endif
        case(SHOW_HIDE_STATUSBAR):
        recent.statusbar_show = GTK_CHECK_MENU_ITEM(w)->active;
        break;
        case(SHOW_HIDE_PACKET_LIST):
        recent.packet_list_show = GTK_CHECK_MENU_ITEM(w)->active;
        break;
        case(SHOW_HIDE_TREE_VIEW):
        recent.tree_view_show = GTK_CHECK_MENU_ITEM(w)->active;
        break;
        case(SHOW_HIDE_BYTE_VIEW):
        recent.byte_view_show = GTK_CHECK_MENU_ITEM(w)->active;
        break;
        default:
            g_assert_not_reached();
    }

    main_widgets_show_or_hide();
}


static void
timestamp_format_cb(GtkWidget *w _U_, gpointer d _U_, gint action)
{
    if (recent.gui_time_format != action) {
        timestamp_set_type(action);
        recent.gui_time_format = action;
        cf_change_time_formats(&cfile);
    }
}


static void
timestamp_precision_cb(GtkWidget *w _U_, gpointer d _U_, gint action)
{
    if (recent.gui_time_precision != action) {
        /* the actual precision will be set in cf_change_time_formats() below */
        if (action == TS_PREC_AUTO) {
            timestamp_set_precision(TS_PREC_AUTO_SEC);
        } else {
            timestamp_set_precision(action);
        }
        recent.gui_time_precision  = action;
        cf_change_time_formats(&cfile);
    }
}


void
menu_name_resolution_changed(void)
{
    GtkWidget *menu = NULL;

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Name Resolution/Enable for MAC Layer");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), g_resolv_flags & RESOLV_MAC);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Name Resolution/Enable for Network Layer");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), g_resolv_flags & RESOLV_NETWORK);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Name Resolution/Enable for Transport Layer");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), g_resolv_flags & RESOLV_TRANSPORT);
}

static void
name_resolution_cb(GtkWidget *w, gpointer d _U_, gint action)
{
    if (GTK_CHECK_MENU_ITEM(w)->active) {
        g_resolv_flags |= action;
    } else {
        g_resolv_flags &= ~action;
    }
}

#ifdef HAVE_LIBPCAP
void
menu_auto_scroll_live_changed(gboolean auto_scroll_live_in) {
    GtkWidget *menu;


    /* tell menu about it */
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Auto Scroll in Live Capture");
    if( ((gboolean) GTK_CHECK_MENU_ITEM(menu)->active) != auto_scroll_live_in) {
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), auto_scroll_live_in);
    }

    /* tell toolbar about it */
    toolbar_auto_scroll_live_changed(auto_scroll_live_in);

    /* change auto scroll */
    if(auto_scroll_live_in != auto_scroll_live) {
        auto_scroll_live  = auto_scroll_live_in;
    }
}

static void
auto_scroll_live_cb(GtkWidget *w _U_, gpointer d _U_)
{
    menu_auto_scroll_live_changed(GTK_CHECK_MENU_ITEM(w)->active);
}
#endif


void
menu_colorize_changed(gboolean packet_list_colorize) {
    GtkWidget *menu;


    /* tell menu about it */
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Colorize Packet List");
    if( ((gboolean) GTK_CHECK_MENU_ITEM(menu)->active) != packet_list_colorize) {
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), packet_list_colorize);
    }

    /* tell toolbar about it */
    toolbar_colorize_changed(packet_list_colorize);

    /* change colorization */
    if(packet_list_colorize != recent.packet_list_colorize) {
        recent.packet_list_colorize = packet_list_colorize;
        color_filters_enable(packet_list_colorize);
        cf_colorize_packets(&cfile);
    }
}

static void
colorize_cb(GtkWidget *w, gpointer d _U_)
{
    menu_colorize_changed(GTK_CHECK_MENU_ITEM(w)->active);
}


/* the recent file read has finished, update the menu corresponding */
void
menu_recent_read_finished(void) {
    GtkWidget *menu = NULL;

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Main Toolbar");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.main_toolbar_show);

    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Filter Toolbar");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.filter_toolbar_show);

#ifdef HAVE_AIRPCAP
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Wireless Toolbar");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), recent.airpcap_toolbar_show);
#endif

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

    menu_name_resolution_changed();

#ifdef HAVE_LIBPCAP
    menu = gtk_item_factory_get_widget(main_menu_factory, "/View/Auto Scroll in Live Capture");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), auto_scroll_live);
#endif

    main_widgets_rearrange();

    /* don't change the time format, if we had a command line value */
    if (timestamp_get_type() != TS_NOT_SET) {
        recent.gui_time_format = timestamp_get_type();
    }

    switch(recent.gui_time_format) {
    case(TS_ABSOLUTE_WITH_DATE):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456");
        /* set_active will not trigger the callback when activating an active item! */
        recent.gui_time_format = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), FALSE);
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_ABSOLUTE):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Time of Day:   01:02:03.123456");
        /* set_active will not trigger the callback when activating an active item! */
        recent.gui_time_format = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_RELATIVE):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds Since Beginning of Capture:   123.123456");
        recent.gui_time_format = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_DELTA):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds Since Previous Captured Packet:   1.123456");
        recent.gui_time_format = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_DELTA_DIS):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds Since Previous Displayed Packet:   1.123456");
        recent.gui_time_format = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_EPOCH):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds Since Epoch (1970-01-01):   1234567890.123456");
        recent.gui_time_format = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    default:
        g_assert_not_reached();
    }

    switch(recent.gui_time_precision) {
    case(TS_PREC_AUTO):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Automatic (File Format Precision)");
        /* set_active will not trigger the callback when activating an active item! */
        recent.gui_time_precision = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), FALSE);
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_PREC_FIXED_SEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Seconds:   0");
        recent.gui_time_precision = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_PREC_FIXED_DSEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Deciseconds:   0.1");
        recent.gui_time_precision = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_PREC_FIXED_CSEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Centiseconds:   0.12");
        recent.gui_time_precision = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_PREC_FIXED_MSEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Milliseconds:   0.123");
        recent.gui_time_precision = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_PREC_FIXED_USEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Microseconds:   0.123456");
        recent.gui_time_precision = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    case(TS_PREC_FIXED_NSEC):
        menu = gtk_item_factory_get_widget(main_menu_factory,
            "/View/Time Display Format/Nanoseconds:   0.123456789");
        recent.gui_time_precision = -1;
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu), TRUE);
        break;
    default:
        g_assert_not_reached();
    }

    menu_colorize_changed(recent.packet_list_colorize);
}


gint
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
        if (packet_list_get_event_row_column(widget, (GdkEventButton *)event,
                                             &row, &column)) {
            g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_ROW_KEY,
                            GINT_TO_POINTER(row));
            g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_COL_KEY,
                            GINT_TO_POINTER(column));
            packet_list_set_selected_row(row);
        }
    }

    /* Check if we are on tree_view object */
    if (widget == tree_view) {
        tree_view_select(widget, (GdkEventButton *) event);
    }

    /* Check if we are on byte_view object */
    if(widget == get_notebook_bv_ptr(byte_nb_ptr)) {
        byte_view_select(widget, (GdkEventButton *) event);
    }

    /* context menu handler */
    if(event->type == GDK_BUTTON_PRESS) {
        event_button = (GdkEventButton *) event;

        /* To qoute the "Gdk Event Structures" doc:
         * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
        if(event_button->button == 3) {
            /* No popup window in the byte view */
            if(widget != get_notebook_bv_ptr(byte_nb_ptr)) {
                gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
                               event_button->button,
                               event_button->time);
            }
            g_signal_stop_emission_by_name(widget, "button_press_event");
            return TRUE;
        }
    }
    /* GDK_2BUTTON_PRESS is a doubleclick -> expand/collapse tree row */
    /* GTK version 1 seems to be doing this automatically */
    if (widget == tree_view && event->type == GDK_2BUTTON_PRESS) {
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
        set_menu_sensitivity(main_menu_factory, "/File/Merge...", FALSE);
        set_menu_sensitivity(main_menu_factory, "/File/Close", FALSE);
        set_menu_sensitivity(main_menu_factory, "/File/Save", FALSE);
        set_menu_sensitivity(main_menu_factory, "/File/Save As...", FALSE);
        set_menu_sensitivity(main_menu_factory, "/File/Export", FALSE);
        set_menu_sensitivity(main_menu_factory, "/View/Reload", FALSE);
        set_toolbar_for_capture_file(FALSE);
        set_toolbar_for_unsaved_capture_file(FALSE);
    } else {
        set_menu_sensitivity(main_menu_factory, "/File/Merge...", TRUE);
        set_menu_sensitivity(main_menu_factory, "/File/Close", TRUE);
        set_menu_sensitivity(main_menu_factory, "/File/Save", !cf->user_saved);
        /*
         * "Save As..." works only if we can write the file out in at least
         * one format (so we can save the whole file or just a subset) or
         * if we have an unsaved capture (so writing the whole file out
         * with a raw data copy makes sense).
         */
        set_menu_sensitivity(main_menu_factory, "/File/Save As...",
                             cf_can_save_as(cf) || !cf->user_saved);
        set_menu_sensitivity(main_menu_factory, "/File/Export", TRUE);
        set_menu_sensitivity(main_menu_factory, "/View/Reload", TRUE);
        set_toolbar_for_unsaved_capture_file(!cf->user_saved);
        set_toolbar_for_capture_file(TRUE);
    }
}

/* Enable or disable menu items based on whether there's a capture in
   progress. */
void
set_menus_for_capture_in_progress(gboolean capture_in_progress)
{
    set_menu_sensitivity(main_menu_factory, "/File/Open...",
                         !capture_in_progress);
    set_menu_sensitivity(main_menu_factory, "/File/Open Recent",
                         !capture_in_progress);
    set_menu_sensitivity(main_menu_factory, "/File/Export",
                         capture_in_progress);
#ifdef HAVE_LIBPCAP
    set_menu_sensitivity(main_menu_factory, "/Capture/Options...",
                         !capture_in_progress);
    set_menu_sensitivity(main_menu_factory, "/Capture/Start",
                         !capture_in_progress);
    set_menu_sensitivity(main_menu_factory, "/Capture/Stop",
                         capture_in_progress);
    set_menu_sensitivity(main_menu_factory, "/Capture/Restart",
                         capture_in_progress);
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
    if (node_data->name != NULL) {
        set_menu_sensitivity(main_menu_factory, node_data->name,
                             node_data->enabled);
    }
    return node_data->enabled;
}

void
set_menus_for_captured_packets(gboolean have_captured_packets)
{
    set_menu_sensitivity(main_menu_factory, "/File/Print...",
                         have_captured_packets);
    set_menu_sensitivity(packet_list_menu_factory, "/Print...",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Edit/Find Packet...",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Edit/Find Next",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Edit/Find Previous",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/View/Zoom In",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/View/Zoom Out",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/View/Normal Size",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Go/Go to Packet...",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Go/Previous Packet",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Go/Next Packet",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Go/First Packet",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Go/Last Packet",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Statistics/Summary",
                         have_captured_packets);
    set_menu_sensitivity(main_menu_factory, "/Statistics/Protocol Hierarchy",
                         have_captured_packets);

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
    if (node_data->name != NULL) {
        set_menu_sensitivity(main_menu_factory, node_data->name,
                             node_data->enabled);
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
    g_ptr_array_free(array, FALSE);
    return is_ssl;
}

void
set_menus_for_selected_packet(capture_file *cf)
{
    gboolean is_ssl = packet_is_ssl(cf->edt);
    set_menu_sensitivity(main_menu_factory, "/Edit/Mark Packet (toggle)",
                         cf->current_frame != NULL);
    set_menu_sensitivity(packet_list_menu_factory, "/Mark Packet (toggle)",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/Edit/Find Next Mark",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/Edit/Find Previous Mark",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/Edit/Mark All Packets",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/Edit/Unmark All Packets",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/Edit/Set Time Reference (toggle)",
                         cf->current_frame != NULL);
    set_menu_sensitivity(packet_list_menu_factory, "/Set Time Reference (toggle)",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/Edit/Find Next Reference",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/Edit/Find Previous Reference",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/View/Resize All Columns",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/View/Collapse All",
                         cf->current_frame != NULL);
    set_menu_sensitivity(tree_view_menu_factory, "/Collapse All",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/View/Expand All",
                         cf->current_frame != NULL);
    set_menu_sensitivity(tree_view_menu_factory, "/Expand All",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/View/Colorize Conversation",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/View/Reset Coloring 1-10",
                         tmp_color_filters_used());
    set_menu_sensitivity(main_menu_factory, "/View/Show Packet in New Window",
                         cf->current_frame != NULL);
    set_menu_sensitivity(packet_list_menu_factory, "/Show Packet in New Window",
                         cf->current_frame != NULL);
    set_menu_sensitivity(packet_list_menu_factory, "/SCTP",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_SCTP) : FALSE);
    set_menu_sensitivity(main_menu_factory, "/Analyze/Follow TCP Stream",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Follow TCP Stream",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(tree_view_menu_factory, "/Follow TCP Stream",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(main_menu_factory, "/Analyze/Follow UDP Stream",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Follow UDP Stream",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(tree_view_menu_factory, "/Follow UDP Stream",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(main_menu_factory, "/Analyze/Follow SSL Stream",
                         cf->current_frame != NULL ? is_ssl : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Follow SSL Stream",
                         cf->current_frame != NULL ? is_ssl : FALSE);
    set_menu_sensitivity(tree_view_menu_factory, "/Follow SSL Stream",
                         cf->current_frame != NULL ? is_ssl : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Conversation Filter",
                         cf->current_frame != NULL);
    set_menu_sensitivity(packet_list_menu_factory, "/Conversation Filter/Ethernet",
                         cf->current_frame != NULL ? (cf->edt->pi.dl_src.type == AT_ETHER) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Conversation Filter/IP",
                         cf->current_frame != NULL ? ((cf->edt->pi.ethertype == ETHERTYPE_IP)||(cf->edt->pi.ethertype == ETHERTYPE_IPv6)) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Conversation Filter/TCP",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Conversation Filter/UDP",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Conversation Filter/PN-CBA Server",
                         cf->current_frame != NULL ? (cf->edt->pi.profinet_type != 0 && cf->edt->pi.profinet_type < 10) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Colorize Conversation",
                         cf->current_frame != NULL);
    set_menu_sensitivity(packet_list_menu_factory, "/Colorize Conversation/Ethernet",
                         cf->current_frame != NULL ? (cf->edt->pi.dl_src.type == AT_ETHER) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Colorize Conversation/IP",
                         cf->current_frame != NULL ? ((cf->edt->pi.ethertype == ETHERTYPE_IP)||(cf->edt->pi.ethertype == ETHERTYPE_IPv6)) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Colorize Conversation/TCP",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Colorize Conversation/UDP",
                         cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_UDP) : FALSE);
    set_menu_sensitivity(packet_list_menu_factory, "/Colorize Conversation/PN-CBA Server",
                         cf->current_frame != NULL ? (cf->edt->pi.profinet_type != 0 && cf->edt->pi.profinet_type < 10) : FALSE);
    set_menu_sensitivity(main_menu_factory, "/Analyze/Decode As...",
                         cf->current_frame != NULL && decode_as_ok());
    set_menu_sensitivity(packet_list_menu_factory, "/Decode As...",
                         cf->current_frame != NULL && decode_as_ok());
    set_menu_sensitivity(tree_view_menu_factory, "/Decode As...",
                         cf->current_frame != NULL && decode_as_ok());
    set_menu_sensitivity(main_menu_factory, "/View/Name Resolution/Resolve Name",
                         cf->current_frame != NULL && (g_resolv_flags & RESOLV_ALL_ADDRS) != RESOLV_ALL_ADDRS);
    set_menu_sensitivity(tree_view_menu_factory, "/Resolve Name",
                         cf->current_frame != NULL && (g_resolv_flags & RESOLV_ALL_ADDRS) != RESOLV_ALL_ADDRS);
    set_menu_sensitivity(packet_list_menu_factory, "/Copy",
                         cf->current_frame != NULL);
    set_menu_sensitivity(packet_list_menu_factory, "/Apply as Filter",
                         cf->current_frame != NULL);
    set_menu_sensitivity(packet_list_menu_factory, "/Prepare a Filter",
                         cf->current_frame != NULL);
    set_menu_sensitivity(main_menu_factory, "/Tools/Firewall ACL Rules",
                         cf->current_frame != NULL);

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
    if (node_data->name != NULL) {
        set_menu_sensitivity(main_menu_factory, node_data->name,
                             node_data->enabled);
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
        g_free (g_object_get_data(G_OBJECT(tree_view_menu_factory), "menu_abbrev"));
        g_object_set_data(G_OBJECT(tree_view_menu_factory), "menu_abbrev", NULL);
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

    menu_preferences = gtk_item_factory_get_widget(tree_view_menu_factory, "/Protocol Preferences");
    sub_menu = gtk_menu_item_get_submenu (GTK_MENU_ITEM(menu_preferences));
    gtk_menu_shell_append (GTK_MENU_SHELL(sub_menu), menu_item);
    gtk_widget_show (menu_item);

    return 0;
}

static void
rebuild_protocol_prefs_menu (module_t *prefs, gboolean preferences)
{
    GtkWidget *menu_preferences, *menu_item;
    GtkWidget *sub_menu;
    gchar *label;

    menu_preferences = gtk_item_factory_get_widget(tree_view_menu_factory, "/Protocol Preferences");

    if (preferences) {
        sub_menu = gtk_menu_new();
        gtk_menu_item_set_submenu (GTK_MENU_ITEM(menu_preferences), sub_menu);

        label = g_strdup_printf ("%s Preferences...", prefs->description);
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

        prefs_pref_foreach(prefs, add_protocol_prefs_menu, prefs);
    } else {
        /* No preferences, remove sub menu */
        gtk_menu_item_set_submenu (GTK_MENU_ITEM(menu_preferences), NULL);
    }

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

        set_menu_sensitivity(main_menu_factory,
                             "/File/Export/Selected Packet Bytes...", TRUE);
        set_menu_sensitivity(main_menu_factory,
                             "/Go/Go to Corresponding Packet", hfinfo->type == FT_FRAMENUM);
        set_menu_sensitivity(tree_view_menu_factory,
                             "/Go to Corresponding Packet", hfinfo->type == FT_FRAMENUM);
        set_menu_sensitivity(main_menu_factory, "/Edit/Copy/Description",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(main_menu_factory, "/Edit/Copy/Fieldname",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(main_menu_factory, "/Edit/Copy/Value",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(main_menu_factory, "/Edit/Copy/As Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(tree_view_menu_factory, "/Copy",
                             TRUE);
        set_menu_sensitivity(tree_view_menu_factory, "/Copy/As Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(main_menu_factory, "/Analyze/Apply as Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(tree_view_menu_factory, "/Apply as Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(main_menu_factory, "/Analyze/Prepare a Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(tree_view_menu_factory, "/Prepare a Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(tree_view_menu_factory, "/Colorize with Filter",
                             proto_can_match_selected(cf->finfo_selected, cf->edt));
        set_menu_sensitivity(tree_view_menu_factory, "/Protocol Preferences",
                             properties);
        set_menu_sensitivity(tree_view_menu_factory, "/Disable Protocol...",
                             (id == -1) ? FALSE : proto_can_toggle_protocol(id));
        set_menu_sensitivity(main_menu_factory, "/View/Expand Subtrees", cf->finfo_selected->tree_type != -1);
        set_menu_sensitivity(tree_view_menu_factory, "/Expand Subtrees", cf->finfo_selected->tree_type != -1);
        set_menu_sensitivity(tree_view_menu_factory, "/Wiki Protocol Page",
                             TRUE);
        set_menu_sensitivity(tree_view_menu_factory, "/Filter Field Reference",
                             TRUE);
        
        prev_abbrev = g_object_get_data(G_OBJECT(tree_view_menu_factory), "menu_abbrev");
        if (!prev_abbrev || (strcmp (prev_abbrev, abbrev) != 0)) {
            /* No previous protocol or protocol changed - update Protocol Preferences menu */
            module_t *prefs = prefs_find_module(abbrev);
            rebuild_protocol_prefs_menu (prefs, properties);

            g_object_set_data(G_OBJECT(tree_view_menu_factory), "menu_abbrev", g_strdup(abbrev));
            g_free (prev_abbrev);
        }
    } else {
        set_menu_sensitivity(main_menu_factory,
                             "/File/Export/Selected Packet Bytes...", FALSE);
        set_menu_sensitivity(main_menu_factory,
                             "/Go/Go to Corresponding Packet", FALSE);
        set_menu_sensitivity(tree_view_menu_factory,
                             "/Go to Corresponding Packet", FALSE);
        set_menu_sensitivity(main_menu_factory, "/Edit/Copy/Description", FALSE);
        set_menu_sensitivity(main_menu_factory, "/Edit/Copy/Fieldname", FALSE);
        set_menu_sensitivity(main_menu_factory, "/Edit/Copy/Value", FALSE);
        set_menu_sensitivity(main_menu_factory, "/Edit/Copy/As Filter", FALSE);
        set_menu_sensitivity(tree_view_menu_factory, "/Copy", FALSE);
        set_menu_sensitivity(main_menu_factory, "/Analyze/Apply as Filter", FALSE);
        set_menu_sensitivity(tree_view_menu_factory, "/Apply as Filter", FALSE);
        set_menu_sensitivity(main_menu_factory, "/Analyze/Prepare a Filter", FALSE);
        set_menu_sensitivity(tree_view_menu_factory, "/Prepare a Filter", FALSE);
        set_menu_sensitivity(tree_view_menu_factory, "/Colorize with Filter", FALSE);
        set_menu_sensitivity(tree_view_menu_factory, "/Protocol Preferences",
                             FALSE);
        set_menu_sensitivity(tree_view_menu_factory, "/Disable Protocol...", FALSE);
        set_menu_sensitivity(main_menu_factory, "/View/Expand Subtrees", FALSE);
        set_menu_sensitivity(tree_view_menu_factory, "/Expand Subtrees", FALSE);
        set_menu_sensitivity(tree_view_menu_factory, "/Wiki Protocol Page",
                             FALSE);
        set_menu_sensitivity(tree_view_menu_factory, "/Filter Field Reference",
                             FALSE);
    }

    walk_menu_tree_for_selected_tree_row(tap_menu_tree_root, cf->finfo_selected);
}

void set_menus_for_packet_history(gboolean back_history, gboolean forward_history) {

    set_menu_sensitivity(main_menu_factory, "/Go/Back", back_history);
    set_menu_sensitivity(main_menu_factory, "/Go/Forward", forward_history);

    set_toolbar_for_packet_history(back_history, forward_history);
}


void set_menus_for_file_set(gboolean file_set, gboolean previous_file, gboolean next_file) {

    set_menu_sensitivity(main_menu_factory, "/File/File Set/List Files", file_set);
    set_menu_sensitivity(main_menu_factory, "/File/File Set/Previous File", previous_file);
    set_menu_sensitivity(main_menu_factory, "/File/File Set/Next File", next_file);
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

