/* menu.c
 * Menu routines
 *
 * $Id: menu.c,v 1.109 2003/11/19 00:04:15 ulfl Exp $
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
#include <epan/packet.h>
#include <epan/resolv.h>
#include "prefs.h"
#include "capture_dlg.h"
#include "color_dlg.h"
#include "file_dlg.h"
#include "filter_prefs.h"
#include "find_dlg.h"
#include "goto_dlg.h"
#include "summary_dlg.h"
#include "display_opts.h"
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
#include "tcp_graph.h"
#include <epan/epan_dissect.h>
#include "compat_macros.h"
#include "toolbar.h"
#include "gtkglobals.h"
#include "register.h"
#include "../tap.h"
#include "../menu.h"
#include "../ipproto.h"

GtkWidget *popup_menu_object;

#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

static void menus_init(void);
static void set_menu_sensitivity (GtkItemFactory *, gchar *, gint);

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

/* main menu */
static GtkItemFactoryEntry menu_items[] =
{
    ITEM_FACTORY_ENTRY("/_File", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Open...", "<control>O", file_open_cmd_cb,
                             0, GTK_STOCK_OPEN),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Close", "<control>W", file_close_cmd_cb,
                             0, GTK_STOCK_CLOSE),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Save", "<control>S", file_save_cmd_cb,
                             0, GTK_STOCK_SAVE),
    ITEM_FACTORY_STOCK_ENTRY("/File/Save _As...", "<shift><control>S", file_save_as_cmd_cb,
                             0, GTK_STOCK_SAVE_AS),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Reload", "<control>R", file_reload_cmd_cb,
                             0, GTK_STOCK_REFRESH),
    ITEM_FACTORY_ENTRY("/File/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/File/_Print...", NULL, file_print_cmd_cb,
                             0, GTK_STOCK_PRINT),
    ITEM_FACTORY_ENTRY("/File/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/File/Print Pac_ket", "<control>P",
                       file_print_packet_cmd_cb, 0, NULL, NULL),
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
    ITEM_FACTORY_STOCK_ENTRY("/Edit/_Find Frame...", "<control>F",
                             find_frame_cb, 0, GTK_STOCK_FIND),
    ITEM_FACTORY_STOCK_ENTRY("/Edit/Find _Next", "<control>N", find_next_cb,
                             0, GTK_STOCK_GO_FORWARD),
    ITEM_FACTORY_STOCK_ENTRY("/Edit/Find _Previous", "<control>B",
                             find_previous_cb, 0, GTK_STOCK_GO_BACK),
    ITEM_FACTORY_STOCK_ENTRY("/Edit/_Go To Frame...", "<control>G",
                             goto_frame_cb, 0, GTK_STOCK_JUMP_TO),
    ITEM_FACTORY_ENTRY("/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/Edit/Time Reference", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Edit/Time Reference/Set Time Reference (toggle)", "<control>T", reftime_frame_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/Time Reference/Find Next", NULL, reftime_frame_cb, 1, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/Time Reference/Find Previous", NULL, reftime_frame_cb, 2, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/_Mark Frame", "<control>M", mark_frame_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/Mark _All Frames", NULL, mark_all_frames_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/_Unmark All Frames", NULL, unmark_all_frames_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Edit/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Edit/_Preferences...", "<shift><control>P", prefs_cb,
                             0, GTK_STOCK_PREFERENCES),
#ifdef HAVE_LIBPCAP
    ITEM_FACTORY_STOCK_ENTRY("/Edit/_Capture Filters...", NULL, cfilter_dialog_cb,
                       0, ETHEREAL_STOCK_CAPTURE_FILTER),
#endif /* HAVE_LIBPCAP */
    ITEM_FACTORY_STOCK_ENTRY("/Edit/_Display Filters...", NULL, dfilter_dialog_cb,
                       0, ETHEREAL_STOCK_DISPLAY_FILTER),
    ITEM_FACTORY_ENTRY("/Edit/P_rotocols...", "<shift><control>R", proto_cb, 0, NULL, NULL),
#ifdef HAVE_LIBPCAP
    ITEM_FACTORY_ENTRY("/_Capture", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Capture/_Start...", "<control>K",
                             capture_prep_cb, 0, ETHEREAL_STOCK_CAPTURE_START),
  /*
   * XXX - this doesn't yet work in Win32.
   */
#ifndef _WIN32
    ITEM_FACTORY_STOCK_ENTRY("/Capture/S_top", "<control>E", capture_stop_cb,
                             0, GTK_STOCK_STOP),
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */
    ITEM_FACTORY_ENTRY("/_Display", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Display/_Options...", NULL, display_opt_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/_Match", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Display/Match/_Selected", NULL,
                       match_selected_cb_replace_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Match/_Not Selected", NULL,
                       match_selected_cb_not_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Match/_And Selected", NULL,
                       match_selected_cb_and_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Match/_Or Selected", NULL,
                       match_selected_cb_or_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Match/A_nd Not Selected", NULL,
                       match_selected_cb_and_ptree_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Match/O_r Not Selected", NULL,
                       match_selected_cb_or_ptree_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/_Prepare", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Display/Prepare/_Selected", NULL,
                       prepare_selected_cb_replace_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Prepare/_Not Selected", NULL,
                       prepare_selected_cb_not_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Prepare/_And Selected", NULL,
                       prepare_selected_cb_and_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Prepare/_Or Selected", NULL,
                       prepare_selected_cb_or_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Prepare/A_nd Not Selected", NULL,
                       prepare_selected_cb_and_ptree_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/Prepare/O_r Not Selected", NULL,
                       prepare_selected_cb_or_ptree_not, 0, NULL, NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Display/_Colorize Display...", NULL, color_display_cb,
                       0, GTK_STOCK_SELECT_COLOR),
    ITEM_FACTORY_ENTRY("/Display/Collapse _All", NULL, collapse_all_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/_Expand All", NULL, expand_all_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/_Show Packet In New Window", NULL,
                       new_window_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display/User Specified Decodes...", NULL,
                       decode_show_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/_Tools", NULL, NULL, 0, "<Branch>", NULL),
#ifdef HAVE_PLUGINS
    ITEM_FACTORY_ENTRY("/Tools/_Plugins...", NULL, tools_plugins_cmd_cb,
                       0, NULL, NULL),
#endif /* HAVE_PLUGINS */
    ITEM_FACTORY_ENTRY("/Tools/_Follow TCP Stream", NULL, follow_stream_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Tools/_Decode As...", NULL, decode_as_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Tools/_Go To Corresponding Frame", NULL, goto_framenum_cb,
                       0, NULL, NULL),
/*  {"/Tools/Graph", NULL, NULL, 0, NULL}, future use */
    ITEM_FACTORY_ENTRY("/_Tools/TCP Stream Analysis", NULL, NULL,
                       0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/_Tools/TCP Stream Analysis/Time-Sequence Graph (Stevens)",
                       NULL, tcp_graph_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/_Tools/TCP Stream Analysis/Time-Sequence Graph (tcptrace)",
                       NULL, tcp_graph_cb, 1, NULL, NULL),
    ITEM_FACTORY_ENTRY("/_Tools/TCP Stream Analysis/Throughput Graph", NULL,
                       tcp_graph_cb, 2, NULL, NULL),
    ITEM_FACTORY_ENTRY("/_Tools/TCP Stream Analysis/RTT Graph", NULL,
                       tcp_graph_cb, 3, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Tools/_Summary", NULL, summary_open_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Tools/Protocol Hierarchy Statistics", NULL,
                       proto_hier_stats_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/_Help", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_STOCK_ENTRY("/Help/_Help", NULL, help_cb, 0, GTK_STOCK_HELP),
    ITEM_FACTORY_ENTRY("/Help/_Supported Protocols", NULL, supported_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Help/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/Help/_About Ethereal...", NULL, about_ethereal,
                       0, NULL, NULL)
};


/* calculate the number of menu_items */
static int nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

/* packet list popup */
static GtkItemFactoryEntry packet_list_menu_items[] =
{
    ITEM_FACTORY_ENTRY("/Follow TCP Stream", NULL, follow_stream_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Decode As...", NULL, decode_as_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display Filters...", NULL, dfilter_dialog_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/Mark Frame", NULL, mark_frame_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Time Reference", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Time Reference/Set Time Reference (toggle)", NULL, reftime_frame_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Time Reference/Find Next", NULL, reftime_frame_cb, 1, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Time Reference/Find Previous", NULL, reftime_frame_cb, 2, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Match/_Selected", NULL,
                       match_selected_cb_replace_plist, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/_Not Selected", NULL,
                       match_selected_cb_not_plist, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/_And Selected", NULL,
                       match_selected_cb_and_plist, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/_Or Selected", NULL, match_selected_cb_or_plist,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/A_nd Not Selected", NULL,
                       match_selected_cb_and_plist_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/O_r Not Selected", NULL,
                       match_selected_cb_or_plist_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Prepare/_Selected", NULL,
                       prepare_selected_cb_replace_plist, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/_Not Selected", NULL,
                       prepare_selected_cb_not_plist, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/_And Selected", NULL,
                       prepare_selected_cb_and_plist, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/_Or Selected", NULL,
                       prepare_selected_cb_or_plist, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/A_nd Not Selected", NULL,
                       prepare_selected_cb_and_plist_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/O_r Not Selected", NULL,
                       prepare_selected_cb_or_plist_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/Colorize Display...", NULL, color_display_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Print...", NULL, file_print_cmd_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Print Packet", NULL, file_print_packet_cmd_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Show Packet In New Window", NULL, new_window_cb,
                       0, NULL, NULL),
};

static GtkItemFactoryEntry tree_view_menu_items[] =
{
    ITEM_FACTORY_ENTRY("/Follow TCP Stream", NULL, follow_stream_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Decode As...", NULL, decode_as_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display Filters...", NULL, dfilter_dialog_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/_Resolve Name", NULL, resolve_name_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/_Go To Corresponding Frame", NULL, goto_framenum_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Protocol Properties...", NULL, properties_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Match/_Selected", NULL,
                       match_selected_cb_replace_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/_Not Selected", NULL,
                       match_selected_cb_not_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/_And Selected", NULL,
                       match_selected_cb_and_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/_Or Selected", NULL, match_selected_cb_or_ptree,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/A_nd Not Selected", NULL,
                       match_selected_cb_and_ptree_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Match/O_r Not Selected", NULL,
                       match_selected_cb_or_ptree_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare", NULL, NULL, 0, "<Branch>", NULL),
    ITEM_FACTORY_ENTRY("/Prepare/_Selected", NULL,
                       prepare_selected_cb_replace_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/_Not Selected", NULL,
                       prepare_selected_cb_not_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/_And Selected", NULL,
                       prepare_selected_cb_and_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/_Or Selected", NULL,
                       prepare_selected_cb_or_ptree, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/A_nd Not Selected", NULL,
                       prepare_selected_cb_and_ptree_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Prepare/O_r Not Selected", NULL,
                       prepare_selected_cb_or_ptree_not, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/<separator>", NULL, NULL, 0, "<Separator>", NULL),
    ITEM_FACTORY_ENTRY("/Collapse All", NULL, collapse_all_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Expand All", NULL, expand_all_cb, 0, NULL, NULL)
};

static GtkItemFactoryEntry hexdump_menu_items[] =
{
    ITEM_FACTORY_ENTRY("/Follow TCP Stream", NULL, follow_stream_cb,
                       0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Decode As...", NULL, decode_as_cb, 0, NULL, NULL),
    ITEM_FACTORY_ENTRY("/Display Filters...", NULL, dfilter_dialog_cb,
                       0, NULL, NULL)
};

static int initialize = TRUE;
static GtkItemFactory *main_menu_factory = NULL;
static GtkItemFactory *packet_list_menu_factory = NULL;
static GtkItemFactory *tree_view_menu_factory = NULL;
static GtkItemFactory *hexdump_menu_factory = NULL;

static GSList *popup_menu_list = NULL;

static GtkAccelGroup *grp;

void
get_main_menu(GtkWidget ** menubar, GtkAccelGroup ** table) {

  grp = gtk_accel_group_new();

  if (initialize)
    menus_init();

  if (menubar)
    *menubar = main_menu_factory->widget;

  if (table)
    *table = grp;
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
    gtk_item_factory_create_items_ac(main_menu_factory, nmenu_items, menu_items, NULL,2);
    register_all_tap_menus();	/* must be done after creating the main menu */

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
  }
}

typedef struct _menu_item {
	char	*name;
	gboolean enabled;
	gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *);
	gboolean (*selected_tree_row_enabled)(field_info *);
	struct _menu_item *parent;
	struct _menu_item *children;
	struct _menu_item *next;
} menu_item_t;

static menu_item_t tap_menu_tree_root;

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
register_tap_menu_item(char *name, GtkItemFactoryCallback callback,
    gboolean (*selected_packet_enabled)(frame_data *, epan_dissect_t *),
    gboolean (*selected_tree_row_enabled)(field_info *))
{
	static const char toolspath[] = "/Tools/";
	char *p;
	char *menupath;
	size_t menupathlen;
	GtkItemFactoryEntry *entry;
	menu_item_t *curnode, *child;

	/*
	 * The menu path must be relative.
	 */
	g_assert(*name != '/');

	/*
	 * Create any submenus required.
	 */
	curnode = &tap_menu_tree_root;
	p = name;
	while ((p = strchr(p, '/')) != NULL) {
		/*
		 * OK, everything between "name" and "p" is
		 * a menu relative subtree into which the menu item
		 * will be placed.
		 *
		 * Construct the absolute path name of that subtree.
		 */
		menupathlen = sizeof toolspath + (p - name);
		menupath = g_malloc(menupathlen);
		strcpy(menupath, toolspath);
		strncat(menupath, name, p - name);

		/*
		 * Does there exist an entry with that path at this
		 * level of the Tools menu tree?
		 */
		for (child = curnode->children; child != NULL;
		    child = child->next) {
			if (strcmp(child->name, menupath) == 0)
				break;
		}
		if (child == NULL) {
			/*
			 * No.  Create such an item as a subtree, and
			 * add it to the Tools menu tree.
			 */
			entry = g_malloc0(sizeof (GtkItemFactoryEntry));
			entry->path = menupath;
			entry->item_type = "<Branch>";
			gtk_item_factory_create_item(main_menu_factory, entry,
			    NULL, 2);
			set_menu_sensitivity(main_menu_factory, menupath,
			    FALSE);	/* no children yet */
			child = g_malloc(sizeof (menu_item_t));
			child->name = menupath;
			child->selected_packet_enabled = NULL;
			child->selected_tree_row_enabled = NULL;
			child->enabled = FALSE;	/* no children yet */
			child->parent = curnode;
			child->children = NULL;
			child->next = curnode->children;
			curnode->children = child;
		} else {
			/*
			 * Yes.  We don't need "menupath" any more.
			 */
			g_free(menupath);
		}
		curnode = child;

		/*
		 * Skip over the '/' we found.
		 */
		p++;
	}

	/*
	 * Construct the main menu path for the menu item.
	 *
	 * "sizeof toolspath" includes the trailing '\0', so the sum
	 * of that and the length of "name" is enough to hold a string
	 * containing their concatenation.
	 */
	menupathlen = sizeof toolspath + strlen(name);
	menupath = g_malloc(menupathlen);
	strcpy(menupath, toolspath);
	strcat(menupath, name);

	/*
	 * Construct an item factory entry for the item, and add it to
	 * the main menu.
	 */
	entry = g_malloc0(sizeof (GtkItemFactoryEntry));
	entry->path = menupath;
	entry->callback = callback;
	gtk_item_factory_create_item(main_menu_factory, entry, NULL, 2);
	set_menu_sensitivity(main_menu_factory, menupath, FALSE); /* no capture file yet */
	child = g_malloc(sizeof (menu_item_t));
	child->name = menupath;
	child->enabled = FALSE;	/* no capture file yet, hence no taps yet */
	child->selected_packet_enabled = selected_packet_enabled;
	child->selected_tree_row_enabled = selected_tree_row_enabled;
	child->parent = curnode;
	child->children = NULL;
	child->next = curnode->children;
	curnode->children = child;
}

/*
 * Enable/disable menu sensitivity.
 */
static void
set_menu_sensitivity(GtkItemFactory *ifactory, gchar *path, gint val)
{
  GSList *menu_list;
  GtkWidget *menu_item;

  if (ifactory == NULL) {
    /*
     * Do it for all pop-up menus.
     */
    for (menu_list = popup_menu_list; menu_list != NULL;
         menu_list = g_slist_next(menu_list))
      set_menu_sensitivity(menu_list->data, path, val);
  } else {
    /*
     * Do it for that particular menu.
     */
    if ((menu_item = gtk_item_factory_get_widget(ifactory, path)) != NULL) {
      if (GTK_IS_MENU(menu_item)) {
        /*
         * "path" refers to a submenu; "gtk_item_factory_get_widget()"
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
  }
}

void
set_menu_object_data_meat(GtkItemFactory *ifactory, gchar *path, gchar *key, gpointer data)
{
	GtkWidget *menu = NULL;

	if ((menu = gtk_item_factory_get_widget(ifactory, path)) != NULL)
		OBJECT_SET_DATA(menu, key, data);
}

void
set_menu_object_data (gchar *path, gchar *key, gpointer data) {
  GSList *menu_list = popup_menu_list;
  gchar *shortpath = strrchr(path, '/');

  set_menu_object_data_meat(main_menu_factory, path, key, data);
  while (menu_list != NULL) {
  	set_menu_object_data_meat(menu_list->data, shortpath, key, data);
	menu_list = g_slist_next(menu_list);
  }
}

gint
popup_menu_handler(GtkWidget *widget, GdkEvent *event, gpointer data)
{
    GtkWidget *menu = NULL;
    GdkEventButton *event_button = NULL;
    GtkCList *packet_list = NULL;
    gint row, column;

    if(widget == NULL || event == NULL || data == NULL) {
        return FALSE;
    }

    /*
     * If we ever want to make the menu differ based on what row
     * and/or column we're above, we'd use "gtk_clist_get_selection_info()"
     * to find the row and column number for the coordinates; a CTree is,
     * I guess, like a CList with one column(?) and the expander widget
     * as a pixmap.
     */
    /* Check if we are on packet_list object */
    if (widget == OBJECT_GET_DATA(popup_menu_object, E_MPACKET_LIST_KEY)) {
        packet_list=GTK_CLIST(widget);
        if (gtk_clist_get_selection_info(GTK_CLIST(packet_list),
                                         ((GdkEventButton *)event)->x,
                                         ((GdkEventButton *)event)->y,&row,&column)) {
            OBJECT_SET_DATA(popup_menu_object, E_MPACKET_LIST_ROW_KEY,
                            GINT_TO_POINTER(row));
            OBJECT_SET_DATA(popup_menu_object, E_MPACKET_LIST_COL_KEY,
                            GINT_TO_POINTER(column));
        }
    }
    menu = (GtkWidget *)data;
    if(event->type == GDK_BUTTON_PRESS) {
        event_button = (GdkEventButton *) event;

        if(event_button->button == 3) {
            gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
                           event_button->button,
                           event_button->time);
            SIGNAL_EMIT_STOP_BY_NAME(widget, "button_press_event");
            return TRUE;
        }
    }
#if GTK_MAJOR_VERSION >= 2
    if (widget == tree_view && event->type == GDK_2BUTTON_PRESS) {
        GtkTreePath      *path;

        if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(widget),
                                          ((GdkEventButton *)event)->x,
                                          ((GdkEventButton *)event)->y,
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
  set_menu_sensitivity(main_menu_factory, "/File/Save As...",
      have_capture_file);
  set_menu_sensitivity(main_menu_factory, "/File/Close", have_capture_file);
  set_menu_sensitivity(main_menu_factory, "/File/Reload", have_capture_file);
  set_toolbar_for_capture_file(have_capture_file);
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
#ifdef HAVE_LIBPCAP
  set_menu_sensitivity(main_menu_factory, "/Capture/Start...",
      !capture_in_progress);
  /*
   * XXX - this doesn't yet work in Win32.
   */
#ifndef _WIN32
  set_menu_sensitivity(main_menu_factory, "/Capture/Stop",
      capture_in_progress);
#endif
#endif /* HAVE_LIBPCAP */
  set_toolbar_for_capture_in_progress(capture_in_progress);
}

/* Enable or disable menu items based on whether you have some captured
   packets. */
static gboolean
walk_menu_tree_for_captured_packets(menu_item_t *node,
    gboolean have_captured_packets)
{
	gboolean is_enabled;
	menu_item_t *child;

	/*
	 * Is this a leaf node or an interior node?
	 */
	if (node->children == NULL) {
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
		if (node->selected_packet_enabled == NULL &&
		    node->selected_tree_row_enabled == NULL)
			node->enabled = TRUE;
		else
			node->enabled = FALSE;
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
		for (child = node->children; child != NULL; child =
		    child->next) {
			if (walk_menu_tree_for_captured_packets(child,
			    have_captured_packets))
				is_enabled = TRUE;
		}
		node->enabled = is_enabled;
	}

	/*
	 * The root node doesn't correspond to a menu tree item; it
	 * has a null name pointer.
	 */
	if (node->name != NULL) {
		set_menu_sensitivity(main_menu_factory, node->name,
		    node->enabled);
	}
	return node->enabled;
}

void
set_menus_for_captured_packets(gboolean have_captured_packets)
{
  set_menu_sensitivity(main_menu_factory, "/File/Print...",
      have_captured_packets);
  set_menu_sensitivity(packet_list_menu_factory, "/Print...",
      have_captured_packets);
  set_menu_sensitivity(main_menu_factory, "/Edit/Find Frame...",
      have_captured_packets);
  set_menu_sensitivity(main_menu_factory, "/Edit/Find Next",
      have_captured_packets);
  set_menu_sensitivity(main_menu_factory, "/Edit/Find Previous",
      have_captured_packets);
  set_menu_sensitivity(main_menu_factory, "/Edit/Go To Frame...",
      have_captured_packets);
  set_menu_sensitivity(main_menu_factory, "/Display/Colorize Display...",
      have_captured_packets);
  set_menu_sensitivity(packet_list_menu_factory, "/Colorize Display...",
      have_captured_packets);
  set_menu_sensitivity(main_menu_factory, "/Tools/Summary",
      have_captured_packets);
  set_menu_sensitivity(main_menu_factory,
      "/Tools/Protocol Hierarchy Statistics", have_captured_packets);
  set_menu_sensitivity(packet_list_menu_factory, "/Match",
      have_captured_packets);
  set_menu_sensitivity(packet_list_menu_factory, "/Prepare",
      have_captured_packets);
  walk_menu_tree_for_captured_packets(&tap_menu_tree_root,
      have_captured_packets);
  set_toolbar_for_captured_packets(have_captured_packets);
}

/* Enable or disable menu items based on whether a packet is selected and,
   if so, on the properties of the packet. */
static gboolean
walk_menu_tree_for_selected_packet(menu_item_t *node, frame_data *fd,
    epan_dissect_t *edt)
{
	gboolean is_enabled;
	menu_item_t *child;

	/*
	 * Is this a leaf node or an interior node?
	 */
	if (node->children == NULL) {
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
		if (node->selected_packet_enabled != NULL)
			node->enabled = node->selected_packet_enabled(fd, edt);
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
		for (child = node->children; child != NULL; child =
		    child->next) {
			if (walk_menu_tree_for_selected_packet(child, fd, edt))
				is_enabled = TRUE;
		}
		node->enabled = is_enabled;
	}

	/*
	 * The root node doesn't correspond to a menu tree item; it
	 * has a null name pointer.
	 */
	if (node->name != NULL) {
		set_menu_sensitivity(main_menu_factory, node->name,
		    node->enabled);
	}
	return node->enabled;
}

void
set_menus_for_selected_packet(capture_file *cf)
{
  set_menu_sensitivity(main_menu_factory, "/File/Print Packet",
      cf->current_frame != NULL);
  set_menu_sensitivity(packet_list_menu_factory, "/Print Packet",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Edit/Mark Frame",
      cf->current_frame != NULL);
  set_menu_sensitivity(packet_list_menu_factory, "/Mark Frame",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Edit/Mark All Frames",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Edit/Unmark All Frames",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Display/Collapse All",
      cf->current_frame != NULL);
  set_menu_sensitivity(tree_view_menu_factory, "/Collapse All",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Display/Expand All",
      cf->current_frame != NULL);
  set_menu_sensitivity(tree_view_menu_factory, "/Expand All",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Display/Show Packet In New Window",
      cf->current_frame != NULL);
  set_menu_sensitivity(packet_list_menu_factory, "/Show Packet In New Window",
      cf->current_frame != NULL);
  set_menu_sensitivity(main_menu_factory, "/Tools/Follow TCP Stream",
      cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
  set_menu_sensitivity(NULL, "/Follow TCP Stream",
      cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
  set_menu_sensitivity(main_menu_factory, "/Tools/Decode As...",
      cf->current_frame != NULL && decode_as_ok());
  set_menu_sensitivity(NULL, "/Decode As...",
      cf->current_frame != NULL && decode_as_ok());
  set_menu_sensitivity(tree_view_menu_factory, "/Resolve Name",
      cf->current_frame != NULL && g_resolv_flags == 0);
  set_menu_sensitivity(main_menu_factory, "/Tools/TCP Stream Analysis",
      cf->current_frame != NULL ? (cf->edt->pi.ipproto == IP_PROTO_TCP) : FALSE);
  walk_menu_tree_for_selected_packet(&tap_menu_tree_root, cf->current_frame,
      cf->edt);
}

/* Enable or disable menu items based on whether a tree row is selected
   and, if so, on the properties of the tree row. */
static gboolean
walk_menu_tree_for_selected_tree_row(menu_item_t *node, field_info *fi)
{
	gboolean is_enabled;
	menu_item_t *child;

	/*
	 * Is this a leaf node or an interior node?
	 */
	if (node->children == NULL) {
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
		if (node->selected_tree_row_enabled != NULL)
			node->enabled = node->selected_tree_row_enabled(fi);
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
		for (child = node->children; child != NULL; child =
		    child->next) {
			if (walk_menu_tree_for_selected_tree_row(child, fi))
				is_enabled = TRUE;
		}
		node->enabled = is_enabled;
	}

	/*
	 * The root node doesn't correspond to a menu tree item; it
	 * has a null name pointer.
	 */
	if (node->name != NULL) {
		set_menu_sensitivity(main_menu_factory, node->name,
		    node->enabled);
	}
	return node->enabled;
}

void
set_menus_for_selected_tree_row(capture_file *cf)
{
  gboolean properties;

  if (cf->finfo_selected != NULL) {
	header_field_info *hfinfo = cf->finfo_selected->hfinfo;
	if (hfinfo->parent == -1) {
	  properties = prefs_is_registered_protocol(hfinfo->abbrev);
	} else {
	  properties = prefs_is_registered_protocol(proto_registrar_get_abbrev(hfinfo->parent));
	}
	set_menu_sensitivity(main_menu_factory,
	  "/Tools/Go To Corresponding Frame", hfinfo->type == FT_FRAMENUM);
	set_menu_sensitivity(tree_view_menu_factory,
	  "/Go To Corresponding Frame", hfinfo->type == FT_FRAMENUM);
	set_menu_sensitivity(main_menu_factory, "/Display/Match",
	  proto_can_match_selected(cf->finfo_selected, cf->edt));
	set_menu_sensitivity(tree_view_menu_factory, "/Match",
	  proto_can_match_selected(cf->finfo_selected, cf->edt));
	set_menu_sensitivity(main_menu_factory, "/Display/Prepare",
	  proto_can_match_selected(cf->finfo_selected, cf->edt));
	set_menu_sensitivity(tree_view_menu_factory, "/Prepare",
	  proto_can_match_selected(cf->finfo_selected, cf->edt));
	set_menu_sensitivity(tree_view_menu_factory, "/Protocol Properties...",
	  properties);
  } else {
	set_menu_sensitivity(tree_view_menu_factory,
	    "/Go To Corresponding Frame", FALSE);
	set_menu_sensitivity(main_menu_factory, "/Display/Match", FALSE);
	set_menu_sensitivity(tree_view_menu_factory, "/Match", FALSE);
	set_menu_sensitivity(main_menu_factory, "/Display/Prepare", FALSE);
	set_menu_sensitivity(tree_view_menu_factory, "/Prepare", FALSE);
	set_menu_sensitivity(main_menu_factory,
	    "/Tools/Go To Corresponding Frame", FALSE);
	set_menu_sensitivity(tree_view_menu_factory, "/Protocol Properties...",
	  FALSE);
  }

  walk_menu_tree_for_selected_tree_row(&tap_menu_tree_root, cf->finfo_selected);
}
