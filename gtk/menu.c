/* menu.c
 * Menu routines
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "main.h"
#include "menu.h"
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/timestamp.h>
#include <epan/ipproto.h>

#include "about_dlg.h"
#include "capture_dlg.h"
#include "color_dlg.h"
#include "filter_dlg.h"
#include "dlg_utils.h"
#include "file_dlg.h"
#include "fileset_dlg.h"
#include "find_dlg.h"
#include "goto_dlg.h"
#include "summary_dlg.h"
#include "prefs_dlg.h"
#include "packet_win.h"
#include "print.h"
#include "follow_dlg.h"
#include "decode_as_dlg.h"
#include "help_dlg.h"
#include "supported_protos_dlg.h"
#include "proto_dlg.h"
#include "proto_hier_stats_dlg.h"
#include "keys.h"
#include <epan/plugins.h>
#include <epan/epan_dissect.h>
#include "compat_macros.h"
#include "toolbar.h"
#include "gtkglobals.h"
#include "register.h"
#include "../menu.h"
#include "packet_list.h"
#include "ethclist.h"
#include "recent.h"
#include "../ui_util.h"
#include "proto_draw.h"
#include "conversations_table.h"
#include "hostlist_table.h"
#include "simple_dialog.h"
#include "packet_history.h"
#include "color_filters.h"
#include "ssl-dlg.h"

GtkWidget *popup_menu_object;

static void
clear_menu_recent_capture_file_cmd_cb(GtkWidget *w, gpointer unused _U_);

typedef struct _menu_item {
    char    *name;
    gint    group;
    gboolean enabled;
    GtkItemFactoryCallback callback;
    gpointer callback_data;
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *);
    gboolean (*selected_tree_row_enabled)(field_info *);
    GList *children;
} menu_item_t;

static GList *tap_menu_tree_root = NULL;

static void 
merge_all_tap_menus(GList *node);

#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

static void menus_init(void);
static void set_menu_sensitivity (GtkItemFactory *, const gchar *, gint);
static void main_toolbar_show_cb(GtkWidget *w _U_, gpointer d _U_);
static void filter_toolbar_show_cb(GtkWidget *w _U_, gpointer d _U_);
static void packet_list_show_cb(GtkWidget *w _U_, gpointer d _U_);
static void tree_view_show_cb(GtkWidget *w _U_, gpointer d _U_);
static void byte_view_show_cb(GtkWidget *w _U_, gpointer d _U_);
static void statusbar_show_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_absolute_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_absolute_date_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_relative_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_delta_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_auto_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_sec_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_dsec_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_csec_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_msec_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_usec_cb(GtkWidget *w _U_, gpointer d _U_);
static void timestamp_nsec_cb(GtkWidget *w _U_, gpointer d _U_);
static void name_resolution_mac_cb(GtkWidget *w _U_, gpointer d _U_);
static void name_resolution_network_cb(GtkWidget *w _U_, gpointer d _U_);
static void name_resolution_transport_cb(GtkWidget *w _U_, gpointer d _U_);
#ifdef HAVE_LIBPCAP
static void auto_scroll_live_cb(GtkWidget *w _U_, gpointer d _U_);
#endif
static void colorize_cb(GtkWidget *w _U_, gpointer d _U_);

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
               "<StockItem>"	  -> create an item holding a stock image (gtk2)
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

/* main menu */
static GtkItemFactoryEntry menu_items[] =
{
    ITEM_FACTORY_ENTRY("/_File", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Open...", "<control>O", file_open_cmd_cb,
                             0, GTK_STOCK_OPEN),
    ITEM_FACTORY_ENTRY("/File/Open _Recent", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/File/_Merge...", NULL, file_merge_cmd_cb, 0, NULL, NULL),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Close", "<control>W", file_close_cmd_cb,
                             0, GTK_STOCK_CLOSE),
    ITEM_FACTORY_ENTRY("/File/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Save", "<control>S", file_save_cmd_cb,
                             0, GTK_STOCK_SAVE),
    ITEM_FACTORY_STOCK_ENTRY("/File/Save _As...", "<shift><control>S", file_save_as_cmd_cb,
                             0, GTK_STOCK_SAVE_AS),
    ITEM_FACTORY_ENTRY("/File/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/File/File Set", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/File/File Set/List Files", NULL, fileset_cb, 0, ETHEREAL_STOCK_FILE_SET_LIST),
    ITEM_FACTORY_STOCK_ENTRY("/File/File Set/Next File", NULL, fileset_next_cb, 0, ETHEREAL_STOCK_FILE_SET_NEXT),
    ITEM_FACTORY_STOCK_ENTRY("/File/File Set/Previous File", NULL, fileset_previous_cb, 0, ETHEREAL_STOCK_FILE_SET_PREVIOUS),
    ITEM_FACTORY_ENTRY("/File/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/File/_Export", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/File/Export/as \"Plain _Text\" file...", NULL, export_text_cmd_cb,
                             0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/File/Export/as \"_PostScript\" file...", NULL, export_ps_cmd_cb,
                             0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/File/Export/as \"_CSV\" (Comma Separated Values packet summary) file...",
                             NULL, export_csv_cmd_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/File/Export/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/File/Export/as XML - \"P_SML\" (packet summary) file...", NULL, export_psml_cmd_cb,
                             0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/File/Export/as XML - \"P_DML\" (packet details) file...", NULL, export_pdml_cmd_cb,
                             0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/File/Export/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/File/Export/Selected Packet _Bytes...", "<control>H", savehex_cb,
                             0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/File/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Print...", "<control>P", file_print_cmd_cb,
                             0, GTK_STOCK_PRINT),
    ITEM_FACTORY_ENTRY("/File/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Quit", "<control>Q", file_quit_cmd_cb,
                             0, GTK_STOCK_QUIT),
    ITEM_FACTORY_ENTRY("/_Edit", NULL, NULL, 0, "<Branch>", NULL),
#if 0
    /* Un-#if this when we actually implement Cut/Copy/Paste. */
    ITEM_FACTORY_STOCK_ENTRY("/Edit/Cut", "<control>X", NULL,
                             0, GTK_STOCK_CUT),
    ITEM_FACTORY_STOCK_ENTRY("/Edit/Copy", "<control>C", NULL,
                             0, GTK_STOCK_COPY),
    ITEM_FACTORY_STOCK_ENTRY("/Edit/Paste", "<control>V", NULL,
                             0, GTK_STOCK_PASTE),
    ITEM_FACTORY_ENTRY("/Edit/<separator>", NULL, NULL, 0, "<Separator>"),
#endif
    ITEM_FACTORY_STOCK_ENTRY("/Edit/_Find Packet...", "<control>F",
                             find_frame_cb, 0, GTK_STOCK_FIND),
    ITEM_FACTORY_ENTRY("/Edit/Find Ne_xt", "<control>N", find_next_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/Find Pre_vious", "<control>B", find_previous_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/Edit/_Time Reference", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Edit/Time Reference/Set Time Reference (toggle)", "<control>T", reftime_frame_cb, 
                        REFTIME_TOGGLE, ETHEREAL_STOCK_TIME),
    ITEM_FACTORY_ENTRY("/Edit/Time Reference/Find Next", NULL, reftime_frame_cb, REFTIME_FIND_NEXT, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/Time Reference/Find Previous", NULL, reftime_frame_cb, REFTIME_FIND_PREV, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/_Mark Packet (toggle)", "<control>M", packet_list_mark_frame_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/Mark _All Packets", NULL, packet_list_mark_all_frames_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/_Unmark All Packets", NULL, packet_list_unmark_all_frames_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Edit/_Preferences...", "<shift><control>P", prefs_cb,
                             0, GTK_STOCK_PREFERENCES),
    ITEM_FACTORY_ENTRY("/_View", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/View/_Main Toolbar", NULL, main_toolbar_show_cb, 0, "<CheckItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/_Filter Toolbar", NULL, filter_toolbar_show_cb, 0, "<CheckItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/_Statusbar", NULL, statusbar_show_cb, 0, "<CheckItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/View/Packet _List", NULL, packet_list_show_cb, 0, "<CheckItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/Packet _Details", NULL, tree_view_show_cb, 0, "<CheckItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/Packet _Bytes", NULL, byte_view_show_cb, 0, "<CheckItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/View/_Time Display Format", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", NULL, timestamp_absolute_date_cb, 
                        0, "<RadioItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Time of Day:   01:02:03.123456", NULL, timestamp_absolute_cb, 
                        0, "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Seconds Since Beginning of Capture:   123.123456", NULL, timestamp_relative_cb, 
                        0, "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Seconds Since Previous Packet:   1.123456", NULL, timestamp_delta_cb, 
                        0, "/View/Time Display Format/Date and Time of Day:   1970-01-01 01:02:03.123456", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Automatic (File Format Precision)", NULL, timestamp_auto_cb, 
                        0, "<RadioItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Seconds:   0", NULL, timestamp_sec_cb, 
                        0, "/View/Time Display Format/Automatic (File Format Precision)", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Deciseconds:   0.1", NULL, timestamp_dsec_cb, 
                        0, "/View/Time Display Format/Automatic (File Format Precision)", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Centiseconds:   0.12", NULL, timestamp_csec_cb, 
                        0, "/View/Time Display Format/Automatic (File Format Precision)", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Milliseconds:   0.123", NULL, timestamp_msec_cb, 
                        0, "/View/Time Display Format/Automatic (File Format Precision)", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Microseconds:   0.123456", NULL, timestamp_usec_cb, 
                        0, "/View/Time Display Format/Automatic (File Format Precision)", NULL),
    ITEM_FACTORY_ENTRY("/View/Time Display Format/Nanoseconds:   0.123456789", NULL, timestamp_nsec_cb, 
                        0, "/View/Time Display Format/Automatic (File Format Precision)", NULL),
    ITEM_FACTORY_ENTRY("/View/Name Resol_ution", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/View/Name Resolution/_Resolve Name", NULL, resolve_name_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/View/Name Resolution/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/View/Name Resolution/Enable for _MAC Layer", NULL, name_resolution_mac_cb, 0, "<CheckItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/Name Resolution/Enable for _Network Layer", NULL, name_resolution_network_cb, 0, "<CheckItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/Name Resolution/Enable for _Transport Layer", NULL, name_resolution_transport_cb, 0, "<CheckItem>", NULL),
    ITEM_FACTORY_ENTRY("/View/Colorize Packet List", NULL, colorize_cb, 0, "<CheckItem>", NULL),
#ifdef HAVE_LIBPCAP
    ITEM_FACTORY_ENTRY("/View/Auto Scroll in Li_ve Capture", NULL, auto_scroll_live_cb, 0, "<CheckItem>", NULL),
#endif
    ITEM_FACTORY_ENTRY("/View/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/View/_Zoom In", "<control>plus", view_zoom_in_cb,
                             0, GTK_STOCK_ZOOM_IN),
    ITEM_FACTORY_STOCK_ENTRY("/View/Zoom _Out", "<control>minus", view_zoom_out_cb,
                             0, GTK_STOCK_ZOOM_OUT),
    ITEM_FACTORY_STOCK_ENTRY("/View/_Normal Size", "<control>equal", view_zoom_100_cb,
                             0, GTK_STOCK_ZOOM_100),
    ITEM_FACTORY_STOCK_ENTRY("/View/Resize All Columns", NULL, packet_list_resize_columns_cb,
                       0, ETHEREAL_STOCK_RESIZE_COLUMNS),
    ITEM_FACTORY_ENTRY("/View/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/View/E_xpand Subtrees", NULL, expand_tree_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/View/_Expand All", NULL, expand_all_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/View/Collapse _All", NULL, collapse_all_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/View/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/View/_Coloring Rules...", NULL, color_display_cb,
                       0, GTK_STOCK_SELECT_COLOR),
    ITEM_FACTORY_ENTRY("/View/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/View/Show Packet in New _Window", NULL,
                       new_window_cb, 0, NULL, NULL),
    ITEM_FACTORY_STOCK_ENTRY("/View/_Reload", "<control>R", file_reload_cmd_cb,
                             0, GTK_STOCK_REFRESH),
    ITEM_FACTORY_ENTRY("/_Go", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Go/_Back", "<alt>Left",
                             history_back_cb, 0, GTK_STOCK_GO_BACK),
    ITEM_FACTORY_STOCK_ENTRY("/Go/_Forward", "<alt>Right",
                             history_forward_cb, 0, GTK_STOCK_GO_FORWARD),
    ITEM_FACTORY_STOCK_ENTRY("/Go/_Go to Packet...", "<control>G",
                             goto_frame_cb, 0, GTK_STOCK_JUMP_TO),
    ITEM_FACTORY_ENTRY("/Go/Go to _Corresponding Packet", NULL, goto_framenum_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Go/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Go/F_irst Packet", NULL,
                             goto_top_frame_cb, 0, GTK_STOCK_GOTO_TOP),
    ITEM_FACTORY_STOCK_ENTRY("/Go/_Last Packet", NULL,
                             goto_bottom_frame_cb, 0, GTK_STOCK_GOTO_BOTTOM),
#ifdef HAVE_LIBPCAP
    ITEM_FACTORY_ENTRY("/_Capture", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Capture/_Interfaces...", NULL,
                             capture_if_cb, 0, ETHEREAL_STOCK_CAPTURE_INTERFACES),
    ITEM_FACTORY_STOCK_ENTRY("/Capture/_Options...", "<control>K",
                             capture_prep_cb, 0, ETHEREAL_STOCK_CAPTURE_OPTIONS),
    ITEM_FACTORY_STOCK_ENTRY("/Capture/_Start", NULL,
                             capture_start_cb, 0, ETHEREAL_STOCK_CAPTURE_START),
    ITEM_FACTORY_STOCK_ENTRY("/Capture/S_top", "<control>E", capture_stop_cb,
                             0, ETHEREAL_STOCK_CAPTURE_STOP),
    ITEM_FACTORY_STOCK_ENTRY("/Capture/_Restart", NULL, capture_restart_cb,
                             0, ETHEREAL_STOCK_CAPTURE_RESTART),
    ITEM_FACTORY_STOCK_ENTRY("/Capture/Capture _Filters...", NULL, cfilter_dialog_cb,
                       0, ETHEREAL_STOCK_CAPTURE_FILTER),
#endif /* HAVE_LIBPCAP */
    ITEM_FACTORY_ENTRY("/_Analyze", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Analyze/_Display Filters...", NULL, dfilter_dialog_cb,
                       0, ETHEREAL_STOCK_DISPLAY_FILTER),
    ITEM_FACTORY_ENTRY("/Analyze/Appl_y as Filter", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Apply as Filter/_Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Apply as Filter/_Not Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Apply as Filter/... _and Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Apply as Filter/... _or Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Apply as Filter/... a_nd not Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Apply as Filter/... o_r not Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/_Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Prepare a Filter/_Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_REPLACE, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Prepare a Filter/_Not Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_NOT, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Prepare a Filter/... _and Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_AND, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Prepare a Filter/... _or Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_OR, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Prepare a Filter/... a_nd not Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_AND_NOT, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/Prepare a Filter/... o_r not Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_OR_NOT, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Analyze/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Analyze/_Enabled Protocols...", "<shift><control>R", proto_cb, 0, ETHEREAL_STOCK_CHECKBOX),
    ITEM_FACTORY_STOCK_ENTRY("/Analyze/Decode _As...", NULL, decode_as_cb,
                       0, ETHEREAL_STOCK_DECODE_AS),
    ITEM_FACTORY_STOCK_ENTRY("/Analyze/_User Specified Decodes...", NULL,
                       decode_show_cb, 0, ETHEREAL_STOCK_DECODE_AS),
    ITEM_FACTORY_ENTRY("/Analyze/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/Analyze/_Follow TCP Stream", NULL,
                       follow_stream_cb, 0, NULL, NULL),    
    ITEM_FACTORY_ENTRY("/Analyze/_Follow SSL Stream", NULL,
                       ssl_stream_cb, 0, NULL, NULL),    
    ITEM_FACTORY_ENTRY("/_Statistics", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Statistics/_Summary", NULL, summary_open_cb, 0, GTK_STOCK_PROPERTIES),
    ITEM_FACTORY_ENTRY("/Statistics/_Protocol Hierarchy", NULL,
                       proto_hier_stats_cb, 0, NULL, NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Statistics/Conversations", NULL,
                       init_conversation_notebook_cb, 0, ETHEREAL_STOCK_CONVERSATIONS),
    ITEM_FACTORY_STOCK_ENTRY("/Statistics/Endpoints", NULL,
                       init_hostlist_notebook_cb, 0, ETHEREAL_STOCK_ENDPOINTS),
    ITEM_FACTORY_ENTRY("/_Help", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Help/_Contents", "F1", topic_menu_cb, HELP_CONTENT, GTK_STOCK_HELP),
    ITEM_FACTORY_ENTRY("/Help/_Supported Protocols", NULL, supported_cb, 0, NULL, NULL),
#if (GLIB_MAJOR_VERSION >= 2)
#ifdef ETHEREAL_EUG_DIR
    ITEM_FACTORY_ENTRY("/Help/User's Guide", NULL, url_page_menu_cb, HELP_CONTENT, NULL, NULL),
#endif
    ITEM_FACTORY_ENTRY("/Help/Manual Pages", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Help/Manual Pages/Ethereal", NULL, topic_menu_cb, LOCALPAGE_MAN_ETHEREAL, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Help/Manual Pages/Ethereal Filter", NULL, topic_menu_cb, LOCALPAGE_MAN_ETHEREAL_FILTER, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Help/Manual Pages/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/Help/Manual Pages/Tethereal", NULL, topic_menu_cb, LOCALPAGE_MAN_TETHEREAL, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Help/Manual Pages/Mergecap", NULL, topic_menu_cb, LOCALPAGE_MAN_MERGECAP, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Help/Manual Pages/Editcap", NULL, topic_menu_cb, LOCALPAGE_MAN_EDITCAP, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Help/Manual Pages/Text2pcap", NULL, topic_menu_cb, LOCALPAGE_MAN_TEXT2PCAP, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Help/Ethereal Online", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Help/Ethereal Online/Home Page", NULL, topic_menu_cb, ONLINEPAGE_HOME, GTK_STOCK_HOME),
    ITEM_FACTORY_STOCK_ENTRY("/Help/Ethereal Online/Wiki", NULL, topic_menu_cb, ONLINEPAGE_WIKI, ETHEREAL_STOCK_WIKI),
    ITEM_FACTORY_STOCK_ENTRY("/Help/Ethereal Online/User's Guide", NULL, topic_menu_cb, ONLINEPAGE_USERGUIDE, ETHEREAL_STOCK_WEB_SUPPORT),
    ITEM_FACTORY_ENTRY("/Help/Ethereal Online/FAQ's", NULL, topic_menu_cb, ONLINEPAGE_FAQ, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Help/Ethereal Online/Downloads", NULL, topic_menu_cb, ONLINEPAGE_DOWNLOAD, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Help/Ethereal Online/Example Files", NULL, topic_menu_cb, ONLINEPAGE_SAMPLE_FILES, NULL, NULL),
#endif
    ITEM_FACTORY_ENTRY("/Help/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Help/_About Ethereal", NULL, about_ethereal_cb,
                       0, ETHEREAL_STOCK_ABOUT)
};


/* calculate the number of menu_items */
static int nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

/* packet list popup */
static GtkItemFactoryEntry packet_list_menu_items[] =
{
    ITEM_FACTORY_ENTRY("/Mark Packet (toggle)", NULL, packet_list_mark_frame_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Time Reference", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Time Reference/Set Time Reference (toggle)", NULL, reftime_frame_cb, REFTIME_TOGGLE, ETHEREAL_STOCK_TIME),
    ITEM_FACTORY_ENTRY("/Time Reference/Find Next", NULL, reftime_frame_cb, REFTIME_FIND_NEXT, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Time Reference/Find Previous", NULL, reftime_frame_cb, REFTIME_FIND_PREV, NULL, NULL),

    ITEM_FACTORY_ENTRY("/<separator>", NULL, NULL, 0, "<Separator>", NULL),

    ITEM_FACTORY_ENTRY("/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/_Selected", NULL, match_selected_plist_cb, 
                       MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/_Not Selected", NULL, match_selected_plist_cb, 
                       MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/... _and Selected", NULL, match_selected_plist_cb, 
                       MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/... _or Selected", NULL, match_selected_plist_cb, 
                       MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/... a_nd not Selected", NULL, match_selected_plist_cb, 
                       MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/... o_r not Selected", NULL, match_selected_plist_cb,
                       MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL),

    ITEM_FACTORY_ENTRY("/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/_Selected", NULL, match_selected_plist_cb,
                       MATCH_SELECTED_REPLACE, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/_Not Selected", NULL, match_selected_plist_cb,
                       MATCH_SELECTED_NOT, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/... _and Selected", NULL, match_selected_plist_cb,
                       MATCH_SELECTED_AND, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/... _or Selected", NULL, match_selected_plist_cb,
                       MATCH_SELECTED_OR, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/... a_nd not Selected", NULL, match_selected_plist_cb,
                       MATCH_SELECTED_AND_NOT, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/... o_r not Selected", NULL, match_selected_plist_cb,
                       MATCH_SELECTED_OR_NOT, NULL, NULL),

    ITEM_FACTORY_ENTRY("/Follow TCP Stream", NULL, follow_stream_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Follow SSL Stream", NULL, ssl_stream_cb,
                       0, NULL, NULL),

    ITEM_FACTORY_ENTRY("/<separator>", NULL, NULL, 0, "<Separator>", NULL),

    ITEM_FACTORY_STOCK_ENTRY("/Decode As...", NULL, decode_as_cb, 0, ETHEREAL_STOCK_DECODE_AS),
    ITEM_FACTORY_STOCK_ENTRY("/Print...", NULL, file_print_selected_cmd_cb, 0, GTK_STOCK_PRINT),
    ITEM_FACTORY_ENTRY("/Show Packet in New Window", NULL, new_window_cb,
                       0, NULL, NULL)
};

static GtkItemFactoryEntry tree_view_menu_items[] =
{
    ITEM_FACTORY_ENTRY("/Expand Subtrees", NULL, expand_tree_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Expand All", NULL, expand_all_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Collapse All", NULL, collapse_all_cb, 0, NULL, NULL),

    ITEM_FACTORY_ENTRY("/<separator>", NULL, NULL, 0, "<Separator>", NULL),

    ITEM_FACTORY_ENTRY("/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/_Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/_Not Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/... _and Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/... _or Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/... a_nd not Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Apply as Filter/... o_r not Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW, NULL, NULL),

    ITEM_FACTORY_ENTRY("/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/_Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_REPLACE, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/_Not Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_NOT, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/... _and Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_AND, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/... _or Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_OR, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/... a_nd not Selected", NULL, match_selected_ptree_cb, 
                       MATCH_SELECTED_AND_NOT, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare a Filter/... o_r not Selected", NULL, match_selected_ptree_cb,
                       MATCH_SELECTED_OR_NOT, NULL, NULL),

    ITEM_FACTORY_ENTRY("/Follow TCP Stream", NULL, follow_stream_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Follow SSL Stream", NULL, ssl_stream_cb,
                       0, NULL, NULL),

    ITEM_FACTORY_ENTRY("/<separator>", NULL, NULL, 0, "<Separator>", NULL),

    ITEM_FACTORY_STOCK_ENTRY("/Wiki Protocol Page", NULL, selected_ptree_info_cb,
                       0, ETHEREAL_STOCK_WIKI),
    ITEM_FACTORY_STOCK_ENTRY("/Filter Field Reference", NULL, selected_ptree_ref_cb,
                       0, ETHEREAL_STOCK_INTERNET),
    ITEM_FACTORY_ENTRY("/Protocol Preferences...", NULL, properties_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Decode As...", NULL, decode_as_cb, 0, ETHEREAL_STOCK_DECODE_AS),
    ITEM_FACTORY_ENTRY("/_Resolve Name", NULL, resolve_name_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/_Go to Corresponding Packet", NULL, goto_framenum_cb, 0, NULL, NULL),
};

static GtkItemFactoryEntry hexdump_menu_items[] =
{
    ITEM_FACTORY_ENTRY("/Copy", NULL, copy_hex_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Export Selected Packet Bytes...", NULL, savehex_cb,
                       0, NULL, NULL),
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

  grp = gtk_accel_group_new();

  if (initialize)
    menus_init();

  menubar = main_menu_factory->widget;

  if (table)
    *table = grp;

  return menubar;
}

static void
menus_init(void) {
  if (initialize) {
    initialize = FALSE;

    /* popup */
    packet_list_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    popup_menu_object = gtk_menu_new();
    gtk_item_factory_create_items_ac(packet_list_menu_factory, sizeof(packet_list_menu_items)/sizeof(packet_list_menu_items[0]), packet_list_menu_items, popup_menu_object, 2);
    OBJECT_SET_DATA(popup_menu_object, PM_PACKET_LIST_KEY,
                    packet_list_menu_factory->widget);
    popup_menu_list = g_slist_append((GSList *)popup_menu_list, packet_list_menu_factory);

    tree_view_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    gtk_item_factory_create_items_ac(tree_view_menu_factory, sizeof(tree_view_menu_items)/sizeof(tree_view_menu_items[0]), tree_view_menu_items, popup_menu_object, 2);
    OBJECT_SET_DATA(popup_menu_object, PM_TREE_VIEW_KEY,
                    tree_view_menu_factory->widget);
    popup_menu_list = g_slist_append((GSList *)popup_menu_list, tree_view_menu_factory);

    hexdump_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    gtk_item_factory_create_items_ac(hexdump_menu_factory, sizeof(hexdump_menu_items)/sizeof(hexdump_menu_items[0]), hexdump_menu_items, popup_menu_object, 2);
    OBJECT_SET_DATA(popup_menu_object, PM_HEXDUMP_KEY,
                    hexdump_menu_factory->widget);
    popup_menu_list = g_slist_append((GSList *)popup_menu_list, hexdump_menu_factory);

    /* main */
    main_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU_BAR, "<main>", grp);
    gtk_item_factory_create_items_ac(main_menu_factory, nmenu_items, menu_items, NULL, 2);

    merge_all_tap_menus(tap_menu_tree_root);

    /* Initialize enabled/disabled state of menu items */
    set_menus_for_unsaved_capture_file(FALSE);
    set_menus_for_capture_file(FALSE);
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
    GtkItemFactoryCallback callback,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *),
    gboolean (*selected_tree_row_enabled)(field_info *),
    gpointer callback_data,
	GList *curnode)
{
    menu_item_t *curr;
    menu_item_t *child;


    child = g_malloc(sizeof (menu_item_t));
    child->group            = group;
    child->name             = name;
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
register_stat_menu_item(
    const char *name, 
    REGISTER_STAT_GROUP_E group,
    GtkItemFactoryCallback callback,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *),
    gboolean (*selected_tree_row_enabled)(field_info *),
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
    case(REGISTER_STAT_GROUP_TELEPHONY): toolspath = "/Statistics/"; break;
    case(REGISTER_STAT_GROUP_NONE): toolspath = "/Statistics/"; break;
    case(REGISTER_ANALYZE_GROUP_NONE): toolspath = "/Analyze/"; break;
    default:
        g_assert(0);
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
        strcpy(menupath, toolspath);
        strncat(menupath, name, p - name);

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
                menupath, group, NULL, NULL ,NULL, NULL, curnode);
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
    strcpy(menupath, toolspath);
    strcat(menupath, name);

    /*
     * Construct an item factory entry for the item, and add it to
     * the main menu.
     */
    tap_menu_item_add(
        menupath, group, callback, 
        selected_packet_enabled, selected_tree_row_enabled, 
        callback_data, curnode);
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
#if GTK_MAJOR_VERSION >= 2
            switch(group) {
            case(REGISTER_STAT_GROUP_NONE):
                break;
            case(REGISTER_STAT_GROUP_GENERIC):
                break;
            case(REGISTER_STAT_GROUP_CONVERSATION_LIST):
                entry->item_type = "<StockItem>";
                entry->extra_data = ETHEREAL_STOCK_CONVERSATIONS;
                break;
            case(REGISTER_STAT_GROUP_ENDPOINT_LIST):
                entry->item_type = "<StockItem>";
                entry->extra_data = ETHEREAL_STOCK_ENDPOINTS;
                break;
            case(REGISTER_STAT_GROUP_RESPONSE_TIME):
                entry->item_type = "<StockItem>";
                entry->extra_data = ETHEREAL_STOCK_TIME;
                break;
            case(REGISTER_STAT_GROUP_TELEPHONY):
                entry->item_type = "<StockItem>";
                entry->extra_data = ETHEREAL_STOCK_TELEPHONY;
                break;
            case(REGISTER_ANALYZE_GROUP_NONE):
                break;
            default:
                g_assert_not_reached();
            }
#endif
            gtk_item_factory_create_item(main_menu_factory, entry, node_data->callback_data, 2);
            set_menu_sensitivity(main_menu_factory, node_data->name, FALSE); /* no capture file yet */
            added++;
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
        }

        for (child = node_data->children; child != NULL; child =
            child->next) {
            added += merge_tap_menus_layered(child, group);
        }
    }

    return added;
}


void merge_all_tap_menus(GList *node) {
    GtkItemFactoryEntry *entry;

    entry = g_malloc0(sizeof (GtkItemFactoryEntry));
    entry->item_type = "<Separator>";
    entry->path = "/Statistics/";

    /* 
     * merge only the menu items of the specific group,
     * and then append a seperator
     */
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_GENERIC)) {
        gtk_item_factory_create_item(main_menu_factory, entry, NULL, 2);
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_CONVERSATION_LIST)) {
        /*gtk_item_factory_create_item(main_menu_factory, entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_ENDPOINT_LIST)) {
        /*gtk_item_factory_create_item(main_menu_factory, entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_RESPONSE_TIME)) {
        gtk_item_factory_create_item(main_menu_factory, entry, NULL, 2);
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_TELEPHONY)) {
        gtk_item_factory_create_item(main_menu_factory, entry, NULL, 2);
    }
    if (merge_tap_menus_layered(node, REGISTER_STAT_GROUP_NONE)) {
        /*gtk_item_factory_create_item(main_menu_factory, entry, NULL, 2);*/
    }
    if (merge_tap_menus_layered(node, REGISTER_ANALYZE_GROUP_NONE)) {
		entry->path = "/Analyze/";
        /*gtk_item_factory_create_item(main_menu_factory, entry, NULL, 2);*/
    }
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
		OBJECT_SET_DATA(menu, key, data);
}

void
set_menu_object_data (const gchar *path, const gchar *key, gpointer data) {
  GSList *menu_list = popup_menu_list;
  gchar *shortpath = strrchr(path, '/');

  set_menu_object_data_meat(main_menu_factory, path, key, data);
  while (menu_list != NULL) {
  	set_menu_object_data_meat(menu_list->data, shortpath, key, data);
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

    widget_cf_name = OBJECT_GET_DATA(widget, MENU_RECENT_FILES_KEY);

    /* if this menu item is a file, count it */
    if (widget_cf_name) {
        (*(guint *)cnt)++;
    }
}


/* update the menu */
static void
update_menu_recent_capture_file(GtkWidget *submenu_recent_files) {
    guint cnt = 0;

    gtk_container_foreach(GTK_CONTAINER(submenu_recent_files), 
		update_menu_recent_capture_file1, &cnt);

    /* make parent menu item sensitive only, if we have any valid files in the list */
    set_menu_sensitivity(main_menu_factory, MENU_RECENT_FILES_PATH, cnt);
}


/* remove the capture filename from the "Recent Files" menu */
static void
remove_menu_recent_capture_file(GtkWidget *widget, gpointer unused _U_) {
    GtkWidget *submenu_recent_files;
    gchar *widget_cf_name;


    widget_cf_name = OBJECT_GET_DATA(widget, MENU_RECENT_FILES_KEY);
    g_free(widget_cf_name);

    /* get the submenu container item */
    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

    /* XXX: is this all we need to do, to free the menu item and its label?
       The reference count of widget will go to 0, so it'll be freed;
       will that free the label? */
    gtk_container_remove(GTK_CONTAINER(submenu_recent_files), widget);
}


/* callback, if the user pushed the <Clear File List> item */
static void
clear_menu_recent_capture_file_cmd_cb(GtkWidget *w _U_, gpointer unused _U_) {
    GtkWidget *submenu_recent_files;


    submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

    gtk_container_foreach(GTK_CONTAINER(submenu_recent_files), 
		remove_menu_recent_capture_file, NULL);

    update_menu_recent_capture_file(submenu_recent_files);
}


/* callback, if the user pushed a recent file submenu item */
void
menu_open_recent_file_cmd(GtkWidget *w)
{
	GtkWidget *submenu_recent_files;
	GtkWidget *menu_item_child;
	gchar     *cf_name;
	int       err;

	submenu_recent_files = gtk_item_factory_get_widget(main_menu_factory, MENU_RECENT_FILES_PATH);

	/* get capture filename from the menu item label */
	menu_item_child = (GTK_BIN(w))->child;
	gtk_label_get(GTK_LABEL(menu_item_child), &cf_name);

	/* open and read the capture file (this will close an existing file) */
	if (cf_open(&cfile, cf_name, FALSE, &err) == CF_OK) {
		cf_read(&cfile);
	} else {
		/* the capture file isn't existing any longer, remove menu item */
		/* XXX: ask user to remove item, it's maybe only a temporary problem */
		remove_menu_recent_capture_file(w, NULL);
	}

	update_menu_recent_capture_file(submenu_recent_files);
}

static void menu_open_recent_file_answered_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
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
                PRIMARY_TEXT_START "Save capture file before opening a new one?" PRIMARY_TEXT_END "\n\n"
                "If you open a new capture file without saving, your current capture data will be discarded.");
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
	menu_item_list = gtk_container_children(GTK_CONTAINER(submenu_recent_files));

	/* iterate through list items of menu_item_list, 
	 * removing special items, a maybe duplicate entry and every item above count_max */
	cnt = 1;
	for (li = g_list_first(menu_item_list); li; li = li->next, cnt++) {
		/* get capture filename */
		menu_item = GTK_WIDGET(li->data);
		widget_cf_name = OBJECT_GET_DATA(menu_item, MENU_RECENT_FILES_KEY);

		/* if this element string is one of our special items (seperator, ...) or
		 * already in the list or 
		 * this element is above maximum count (too old), remove it */
		if (!widget_cf_name ||
#ifdef _WIN32
		    /* do a case insensitive compare on win32 */
#if GLIB_MAJOR_VERSION < 2
		    g_strncasecmp(widget_cf_name, normalized_cf_name, 1000) == 0 ||
#else
		    g_ascii_strncasecmp(widget_cf_name, normalized_cf_name, 1000) == 0 ||
#endif
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
	OBJECT_SET_DATA(menu_item, MENU_RECENT_FILES_KEY, normalized_cf_name);
	gtk_menu_prepend (GTK_MENU(submenu_recent_files), menu_item);
	SIGNAL_CONNECT_OBJECT(GTK_OBJECT(menu_item), "activate", 
		menu_open_recent_file_cmd_cb, (GtkObject *) menu_item);
	gtk_widget_show (menu_item);

	/* add seperator at last position */
	menu_item = gtk_menu_item_new();
	gtk_menu_append (GTK_MENU(submenu_recent_files), menu_item);
	gtk_widget_show (menu_item);

	/* add new "clear list" item at last position */
#if GTK_MAJOR_VERSION < 2
	menu_item = gtk_menu_item_new_with_label("<Clear File List>");
#else
        menu_item = gtk_image_menu_item_new_from_stock(GTK_STOCK_CLEAR, NULL);
#endif
	gtk_menu_append (GTK_MENU(submenu_recent_files), menu_item);
	SIGNAL_CONNECT_OBJECT(GTK_OBJECT(menu_item), "activate", 
		clear_menu_recent_capture_file_cmd_cb, (GtkObject *) menu_item);
	gtk_widget_show (menu_item);

	update_menu_recent_capture_file(submenu_recent_files);
}


/* add the capture filename to the "Recent Files" menu */
/* (will change nothing, if this filename is already in the menu) */
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
    children = gtk_container_children(GTK_CONTAINER(submenu_recent_files));
    child = g_list_last(children);
    while(child != NULL) {
        /* get capture filename from the menu item label */
        cf_name = OBJECT_GET_DATA(child->data, MENU_RECENT_FILES_KEY);
        if (cf_name) {
            fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", cf_name);
        }

        child = g_list_previous(child);
    }

    g_list_free(children);
}


static void
main_toolbar_show_cb(GtkWidget *w _U_, gpointer d _U_)
{

    /* save current setting in recent */
    recent.main_toolbar_show = GTK_CHECK_MENU_ITEM(w)->active;

    main_widgets_show_or_hide();
}


static void
filter_toolbar_show_cb(GtkWidget *w _U_, gpointer d _U_)
{

    /* save current setting in recent */
    recent.filter_toolbar_show = GTK_CHECK_MENU_ITEM(w)->active;

    main_widgets_show_or_hide();
}


static void
packet_list_show_cb(GtkWidget *w _U_, gpointer d _U_)
{

    /* save current setting in recent */
    recent.packet_list_show = GTK_CHECK_MENU_ITEM(w)->active;

    main_widgets_show_or_hide();
}


static void
tree_view_show_cb(GtkWidget *w _U_, gpointer d _U_)
{

    /* save current setting in recent */
    recent.tree_view_show = GTK_CHECK_MENU_ITEM(w)->active;

    main_widgets_show_or_hide();
}


static void
byte_view_show_cb(GtkWidget *w _U_, gpointer d _U_)
{

    /* save current setting in recent */
    recent.byte_view_show = GTK_CHECK_MENU_ITEM(w)->active;

    main_widgets_show_or_hide();
}


static void
statusbar_show_cb(GtkWidget *w _U_, gpointer d _U_)
{

    /* save current setting in recent */
    recent.statusbar_show = GTK_CHECK_MENU_ITEM(w)->active;

    main_widgets_show_or_hide();
}


static void 
timestamp_absolute_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_format != TS_ABSOLUTE) {
        timestamp_set_type(TS_ABSOLUTE);
        recent.gui_time_format  = TS_ABSOLUTE;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_absolute_date_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_format != TS_ABSOLUTE_WITH_DATE) {
        timestamp_set_type(TS_ABSOLUTE_WITH_DATE);
        recent.gui_time_format  = TS_ABSOLUTE_WITH_DATE;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_relative_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_format != TS_RELATIVE) {
        timestamp_set_type(TS_RELATIVE);
        recent.gui_time_format  = TS_RELATIVE;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_delta_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_format != TS_DELTA) {
        timestamp_set_type(TS_DELTA);
        recent.gui_time_format  = TS_DELTA;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_auto_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_precision != TS_PREC_AUTO) {
		/* the actual precision will be set in cf_change_time_formats() below */
        timestamp_set_precision(TS_PREC_AUTO_SEC);
        recent.gui_time_precision  = TS_PREC_AUTO;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_sec_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_precision != TS_PREC_FIXED_SEC) {
        timestamp_set_precision(TS_PREC_FIXED_SEC);
        recent.gui_time_precision  = TS_PREC_FIXED_SEC;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_dsec_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_precision != TS_PREC_FIXED_DSEC) {
        timestamp_set_precision(TS_PREC_FIXED_DSEC);
        recent.gui_time_precision  = TS_PREC_FIXED_DSEC;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_csec_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_precision != TS_PREC_FIXED_CSEC) {
        timestamp_set_precision(TS_PREC_FIXED_CSEC);
        recent.gui_time_precision  = TS_PREC_FIXED_CSEC;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_msec_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_precision != TS_PREC_FIXED_MSEC) {
        timestamp_set_precision(TS_PREC_FIXED_MSEC);
        recent.gui_time_precision  = TS_PREC_FIXED_MSEC;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_usec_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_precision != TS_PREC_FIXED_USEC) {
        timestamp_set_precision(TS_PREC_FIXED_USEC);
        recent.gui_time_precision  = TS_PREC_FIXED_USEC;
        cf_change_time_formats(&cfile);
    }
}

static void 
timestamp_nsec_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (recent.gui_time_precision != TS_PREC_FIXED_NSEC) {
        timestamp_set_precision(TS_PREC_FIXED_NSEC);
        recent.gui_time_precision  = TS_PREC_FIXED_NSEC;
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
name_resolution_mac_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (GTK_CHECK_MENU_ITEM(w)->active) {
        g_resolv_flags |= RESOLV_MAC;
    } else {
        g_resolv_flags &= ~RESOLV_MAC;
    }
}

static void 
name_resolution_network_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (GTK_CHECK_MENU_ITEM(w)->active) {
        g_resolv_flags |= RESOLV_NETWORK;
    } else {
        g_resolv_flags &= ~RESOLV_NETWORK;
    }
}

static void 
name_resolution_transport_cb(GtkWidget *w _U_, gpointer d _U_)
{
    if (GTK_CHECK_MENU_ITEM(w)->active) {
        g_resolv_flags |= RESOLV_TRANSPORT;
    } else {
        g_resolv_flags &= ~RESOLV_TRANSPORT;
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
            "/View/Time Display Format/Seconds Since Previous Packet:   1.123456");
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
    if (widget == OBJECT_GET_DATA(popup_menu_object, E_MPACKET_LIST_KEY)) {
        if (packet_list_get_event_row_column(widget, (GdkEventButton *)event,
                                             &row, &column)) {
            OBJECT_SET_DATA(popup_menu_object, E_MPACKET_LIST_ROW_KEY,
                            GINT_TO_POINTER(row));
            OBJECT_SET_DATA(popup_menu_object, E_MPACKET_LIST_COL_KEY,
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

    /* context menu handler (but the byte view notebook pages have their own handler) */
    if(event->type == GDK_BUTTON_PRESS && widget != byte_nb_ptr) {
        event_button = (GdkEventButton *) event;

        /* To qoute the "Gdk Event Structures" doc:
         * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
        if(event_button->button == 3) {
            gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
                           event_button->button,
                           event_button->time);
            SIGNAL_EMIT_STOP_BY_NAME(widget, "button_press_event");
            return TRUE;
        }
    }
#if GTK_MAJOR_VERSION >= 2
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
#endif
    return FALSE;
}

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading. */
void
set_menus_for_capture_file(gboolean have_capture_file)
{
  set_menu_sensitivity(main_menu_factory, "/File/Open...", have_capture_file);
  set_menu_sensitivity(main_menu_factory, "/File/Open Recent", have_capture_file);
  set_menu_sensitivity(main_menu_factory, "/File/Merge...", have_capture_file);
  set_menu_sensitivity(main_menu_factory, "/File/Close", have_capture_file);
  set_menu_sensitivity(main_menu_factory, "/File/Save As...",
      have_capture_file);
  set_menu_sensitivity(main_menu_factory, "/File/Export", have_capture_file);
  set_menu_sensitivity(main_menu_factory, "/View/Reload", have_capture_file);
  set_toolbar_for_capture_file(have_capture_file);
  packets_bar_update();
}

/* Enable or disable menu items based on whether you have an unsaved
   capture file you've finished reading. */
void
set_menus_for_unsaved_capture_file(gboolean have_unsaved_capture_file)
{
  set_menu_sensitivity(main_menu_factory, "/File/Save",
      have_unsaved_capture_file);
  set_toolbar_for_unsaved_capture_file(have_unsaved_capture_file);
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
  packets_bar_update();
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
			node_data->enabled = node_data->selected_packet_enabled(fd, edt);
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

void
set_menus_for_selected_packet(capture_file *cf)
{
  set_menu_sensitivity(main_menu_factory, "/Edit/Mark Packet (toggle)",
      cf->current_frame != NULL);
  set_menu_sensitivity(packet_list_menu_factory, "/Mark Packet (toggle)",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Edit/Time Reference",
      cf->current_frame != NULL);
  set_menu_sensitivity(packet_list_menu_factory, "/Time Reference",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Edit/Mark All Packets",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Edit/Unmark All Packets",
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
  set_menu_sensitivity(main_menu_factory, "/View/Show Packet in New Window",
      cf->current_frame != NULL);
  set_menu_sensitivity(packet_list_menu_factory, "/Show Packet in New Window",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Analyze/Follow TCP Stream",
      cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
  set_menu_sensitivity(packet_list_menu_factory, "/Follow TCP Stream",
      cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
  set_menu_sensitivity(tree_view_menu_factory, "/Follow TCP Stream",
      cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
  set_menu_sensitivity(main_menu_factory, "/Analyze/Follow SSL Stream",
      cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
  set_menu_sensitivity(packet_list_menu_factory, "/Follow SSL Stream",
      cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
  set_menu_sensitivity(tree_view_menu_factory, "/Follow SSL Stream",
      cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
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
  set_menu_sensitivity(packet_list_menu_factory, "/Apply as Filter",
      cf->current_frame != NULL);
  set_menu_sensitivity(packet_list_menu_factory, "/Prepare a Filter",
      cf->current_frame != NULL);

  walk_menu_tree_for_selected_packet(tap_menu_tree_root, cf->current_frame,
      cf->edt);
  packets_bar_update();
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
			node_data->enabled = node_data->selected_tree_row_enabled(fi);
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

void
set_menus_for_selected_tree_row(capture_file *cf)
{
  gboolean properties;


  set_menu_sensitivity(main_menu_factory, "/File/Export/Selected Packet Bytes...", 
      cf->finfo_selected != NULL);  
  set_menu_sensitivity(hexdump_menu_factory, "/Copy", 
      cf->finfo_selected != NULL);
  set_menu_sensitivity(hexdump_menu_factory, "/Export Selected Packet Bytes...", 
      cf->finfo_selected != NULL);
  
  if (cf->finfo_selected != NULL) {
	header_field_info *hfinfo = cf->finfo_selected->hfinfo;
	if (hfinfo->parent == -1) {
	  properties = prefs_is_registered_protocol(hfinfo->abbrev);
	} else {
	  properties = prefs_is_registered_protocol(proto_registrar_get_abbrev(hfinfo->parent));
	}
	set_menu_sensitivity(main_menu_factory,
	  "/Go/Go to Corresponding Packet", hfinfo->type == FT_FRAMENUM);
	set_menu_sensitivity(tree_view_menu_factory,
	  "/Go to Corresponding Packet", hfinfo->type == FT_FRAMENUM);
	set_menu_sensitivity(main_menu_factory, "/Analyze/Apply as Filter",
	  proto_can_match_selected(cf->finfo_selected, cf->edt));
	set_menu_sensitivity(tree_view_menu_factory, "/Apply as Filter",
	  proto_can_match_selected(cf->finfo_selected, cf->edt));
	set_menu_sensitivity(main_menu_factory, "/Analyze/Prepare a Filter",
	  proto_can_match_selected(cf->finfo_selected, cf->edt));
	set_menu_sensitivity(tree_view_menu_factory, "/Prepare a Filter",
	  proto_can_match_selected(cf->finfo_selected, cf->edt));
	set_menu_sensitivity(tree_view_menu_factory, "/Protocol Preferences...",
	  properties);
	set_menu_sensitivity(main_menu_factory, "/View/Expand Subtrees", cf->finfo_selected->tree_type != -1);
	set_menu_sensitivity(tree_view_menu_factory, "/Expand Subtrees", cf->finfo_selected->tree_type != -1);
	set_menu_sensitivity(tree_view_menu_factory, "/Wiki Protocol Page",
	  TRUE);
	set_menu_sensitivity(tree_view_menu_factory, "/Filter Field Reference",
	  TRUE);
  } else {
	set_menu_sensitivity(main_menu_factory,
	    "/Go/Go to Corresponding Packet", FALSE);
	set_menu_sensitivity(tree_view_menu_factory,
	    "/Go to Corresponding Packet", FALSE);
	set_menu_sensitivity(main_menu_factory, "/Analyze/Apply as Filter", FALSE);
	set_menu_sensitivity(tree_view_menu_factory, "/Apply as Filter", FALSE);
	set_menu_sensitivity(main_menu_factory, "/Analyze/Prepare a Filter", FALSE);
	set_menu_sensitivity(tree_view_menu_factory, "/Prepare a Filter", FALSE);
	set_menu_sensitivity(tree_view_menu_factory, "/Protocol Preferences...",
	  FALSE);
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
