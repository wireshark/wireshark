/* menu.c
 * Menu routines
 *
 * $Id: menu.c,v 1.40 2000/08/20 21:55:57 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include <glib.h>

#include <string.h>
#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "../menu.h"

#include "main.h"
#include "menu.h"
#include "packet.h"
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
#include "help_dlg.h"
#include "proto_dlg.h"
#include "keys.h"
#include "plugins.h"

GtkWidget *popup_menu_object;

#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

static void menus_init(void);
static void set_menu_sensitivity (gchar *, gint);

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
               "<CheckItem>"      -> create a check item
               "<ToggleItem>"     -> create a toggle item
               "<RadioItem>"      -> create a radio item
               <path>             -> path of a radio item to link against
               "<Separator>"      -> create a separator
               "<Branch>"         -> create an item to hold sub items (optional)
               "<LastBranch>"     -> create a right justified branch 
    */

/* main menu */
static GtkItemFactoryEntry menu_items[] =
{
  {"/_File", NULL, NULL, 0, "<Branch>" },
  {"/File/_Open...", "<control>O", GTK_MENU_FUNC(file_open_cmd_cb), 0, NULL},
  {"/File/_Close", "<control>W", GTK_MENU_FUNC(file_close_cmd_cb), 0, NULL},
  {"/File/_Save", "<control>S", GTK_MENU_FUNC(file_save_cmd_cb), 0, NULL},
  {"/File/Save _As...", NULL, GTK_MENU_FUNC(file_save_as_cmd_cb), 0, NULL},
  {"/File/_Reload", "<control>R", GTK_MENU_FUNC(file_reload_cmd_cb), 0, NULL},
  {"/File/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/File/_Print...", NULL, GTK_MENU_FUNC(file_print_cmd_cb), 0, NULL},
  {"/File/Print Pac_ket", "<control>P", GTK_MENU_FUNC(file_print_packet_cmd_cb), 0, NULL},
  {"/File/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/File/_Quit", "<control>Q", GTK_MENU_FUNC(file_quit_cmd_cb), 0, NULL},
  {"/_Edit", NULL, NULL, 0, "<Branch>" },
  {"/Edit/Cut", "<control>X", NULL, 0, NULL},
  {"/Edit/Copy", "<control>C", NULL, 0, NULL},
  {"/Edit/Paste", "<control>V", NULL, 0, NULL},
  {"/Edit/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/Edit/_Find Frame...", "<control>F", GTK_MENU_FUNC(find_frame_cb), 0, NULL},
  {"/Edit/_Go To Frame...", "<control>G", GTK_MENU_FUNC(goto_frame_cb), 0, NULL},
  {"/Edit/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/Edit/_Preferences...", NULL, GTK_MENU_FUNC(prefs_cb), 0, NULL},
  {"/Edit/_Filters...", NULL, GTK_MENU_FUNC(filter_dialog_cb), 0, NULL},
  {"/Edit/P_rotocols...", NULL, GTK_MENU_FUNC(proto_cb), 0, NULL},
#ifdef HAVE_LIBPCAP
  {"/_Capture", NULL, NULL, 0, "<Branch>" },
  {"/Capture/_Start...", "<control>K", GTK_MENU_FUNC(capture_prep_cb), 0, NULL},
#endif
  {"/_Display", NULL, NULL, 0, "<Branch>" },
  {"/Display/_Options...", NULL, GTK_MENU_FUNC(display_opt_cb), 0, NULL},
  {"/Display/_Match Selected", NULL, GTK_MENU_FUNC(match_selected_cb), 0, NULL},
  {"/Display/_Colorize Display...", NULL, GTK_MENU_FUNC(color_display_cb), 0, NULL},
  {"/Display/Collapse _All", NULL, GTK_MENU_FUNC(collapse_all_cb), 0, NULL},
  {"/Display/_Expand All", NULL, GTK_MENU_FUNC(expand_all_cb), 0, NULL},
  {"/Display/_Show Packet In New Window", NULL, GTK_MENU_FUNC(new_window_cb), 0, NULL},
  {"/_Tools", NULL, NULL, 0, "<Branch>" },
#ifdef HAVE_PLUGINS
  {"/Tools/_Plugins...", NULL, GTK_MENU_FUNC(tools_plugins_cmd_cb), 0, NULL},
#endif
  {"/Tools/_Follow TCP Stream", NULL, GTK_MENU_FUNC(follow_stream_cb), 0, NULL},
/*  {"/Tools/Graph", NULL, NULL, 0, NULL}, future use */
  {"/Tools/_Summary", NULL, GTK_MENU_FUNC(summary_open_cb), 0, NULL},
  {"/_Help", NULL, NULL, 0, "<LastBranch>" },
  {"/Help/_Help", NULL, GTK_MENU_FUNC(help_cb), 0, NULL},
  {"/Help/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/Help/_About Ethereal...", NULL, GTK_MENU_FUNC(about_ethereal), 0, NULL}
};

/* calculate the number of menu_items */
static int nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

/* packet list popup */
static GtkItemFactoryEntry packet_list_menu_items[] =
{
	{"/Follow TCP Stream", NULL, GTK_MENU_FUNC(follow_stream_cb), 0, NULL},
	{"/Filters...", NULL, GTK_MENU_FUNC(filter_dialog_cb), 0, NULL},
	{"/<separator>", NULL, NULL, 0, "<Separator>"},
	{"/Colorize Display...", NULL, GTK_MENU_FUNC(color_display_cb), 0, NULL},
	{"/Print...", NULL, GTK_MENU_FUNC(file_print_cmd_cb), 0, NULL},
  	{"/Print Packet", NULL, GTK_MENU_FUNC(file_print_packet_cmd_cb), 0, NULL},
  	{"/Show Packet In New Window", NULL, GTK_MENU_FUNC(new_window_cb), 0, NULL}, 
};

static GtkItemFactoryEntry tree_view_menu_items[] =
{
	{"/Follow TCP Stream", NULL, GTK_MENU_FUNC(follow_stream_cb), 0, NULL},
	{"/Filters...", NULL, GTK_MENU_FUNC(filter_dialog_cb), 0, NULL},
	{"/<separator>", NULL, NULL, 0, "<Separator>"},
	{"/Resolve Name", NULL, GTK_MENU_FUNC(resolve_name_cb), 0, NULL},
	{"/Protocol Properties...", NULL, GTK_MENU_FUNC(properties_cb), 0, NULL},
	{"/Match Selected", NULL, GTK_MENU_FUNC(match_selected_cb), 0, NULL},
	{"/<separator>", NULL, NULL, 0, "<Separator>"},
	{"/Collapse All", NULL, GTK_MENU_FUNC(collapse_all_cb), 0, NULL},
	{"/Expand All", NULL, GTK_MENU_FUNC(expand_all_cb), 0, NULL}
};

static GtkItemFactoryEntry hexdump_menu_items[] =
{
	{"/Follow TCP Stream", NULL, GTK_MENU_FUNC(follow_stream_cb), 0, NULL},
	{"/Filters...", NULL, GTK_MENU_FUNC(filter_dialog_cb), 0, NULL}
};

static int initialize = TRUE;
static GtkItemFactory *factory = NULL;
static GtkItemFactory *packet_list_menu_factory = NULL;
static GtkItemFactory *tree_view_menu_factory = NULL;
static GtkItemFactory *hexdump_menu_factory = NULL;

static GSList *popup_menu_list = NULL;

static GtkAccelGroup *grp;

void
get_main_menu(GtkWidget ** menubar, GtkAccelGroup ** table) {

  grp = gtk_accel_group_new();

  if (initialize) {
    popup_menu_object = gtk_widget_new(GTK_TYPE_WIDGET, NULL);
    menus_init();
  }

  if (menubar)
    *menubar = factory->widget;

  if (table)
    *table = grp;
}

static void
menus_init(void) {

  if (initialize) {
    initialize = FALSE;

    /* popup */

    packet_list_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    gtk_item_factory_create_items_ac(packet_list_menu_factory, sizeof(packet_list_menu_items)/sizeof(packet_list_menu_items[0]), packet_list_menu_items, NULL, 2);
    gtk_object_set_data(GTK_OBJECT(popup_menu_object), PM_PACKET_LIST_KEY, packet_list_menu_factory->widget);
    popup_menu_list = g_slist_append((GSList *)popup_menu_list, packet_list_menu_factory);

    tree_view_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    gtk_item_factory_create_items_ac(tree_view_menu_factory, sizeof(tree_view_menu_items)/sizeof(tree_view_menu_items[0]), tree_view_menu_items, NULL, 2);
    gtk_object_set_data(GTK_OBJECT(popup_menu_object), PM_TREE_VIEW_KEY, tree_view_menu_factory->widget);
    popup_menu_list = g_slist_append((GSList *)popup_menu_list, tree_view_menu_factory);

    hexdump_menu_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    gtk_item_factory_create_items_ac(hexdump_menu_factory, sizeof(hexdump_menu_items)/sizeof(hexdump_menu_items[0]), hexdump_menu_items, NULL, 2);
    gtk_object_set_data(GTK_OBJECT(popup_menu_object), PM_HEXDUMP_KEY, hexdump_menu_factory->widget);
    popup_menu_list = g_slist_append((GSList *)popup_menu_list, hexdump_menu_factory);
    
    factory = gtk_item_factory_new(GTK_TYPE_MENU_BAR, "<main>", grp);
    gtk_item_factory_create_items_ac(factory, nmenu_items, menu_items, NULL,2);
    set_menus_for_unsaved_capture_file(FALSE);
    set_menus_for_capture_file(FALSE);
    set_menu_sensitivity("/Edit/Cut", FALSE);
    set_menu_sensitivity("/Edit/Copy", FALSE);
    set_menu_sensitivity("/Edit/Paste", FALSE);
    set_menus_for_captured_packets(FALSE);
    set_menus_for_selected_packet(FALSE);
    set_menus_for_selected_tree_row(FALSE);
  }
}

void
set_menu_sensitivity_meat(GtkItemFactory *ifactory, gchar *path, gint val) {
	GtkWidget *menu = NULL;
	
	if((menu = gtk_item_factory_get_widget(ifactory, path)) != NULL) {
		gtk_widget_set_sensitive(menu,val);
	}
}

static void
set_menu_sensitivity (gchar *path, gint val) {
  GSList *menu_list = popup_menu_list;
  gchar *shortpath = strrchr(path, '/');

  set_menu_sensitivity_meat(factory, path, val);

  while (menu_list != NULL) {
  	set_menu_sensitivity_meat(menu_list->data, shortpath, val);
	menu_list = g_slist_next(menu_list);
  }
  
}

void
set_menu_object_data_meat(GtkItemFactory *ifactory, gchar *path, gchar *key, gpointer data)
{
	GtkWidget *menu = NULL;
	
	if ((menu = gtk_item_factory_get_widget(ifactory, path)) != NULL)
		gtk_object_set_data(GTK_OBJECT(menu), key, data);
}

void
set_menu_object_data (gchar *path, gchar *key, gpointer data) {
  GSList *menu_list = popup_menu_list;
  gchar *shortpath = strrchr(path, '/');
  
  set_menu_object_data_meat(factory, path, key, data);
  while (menu_list != NULL) {
  	set_menu_object_data_meat(menu_list->data, shortpath, key, data);
	menu_list = g_slist_next(menu_list);
  }
}

void
popup_menu_handler(GtkWidget *widget, GdkEvent *event)
{
	GtkWidget *menu = NULL;
	GdkEventButton *event_button = NULL;

	if(widget == NULL || event == NULL) {
		return;
	}
	
	/*
	 * If we ever want to make the menu differ based on what row
	 * and/or column we're above, we'd use "gtk_clist_get_selection_info()"
	 * to find the row and column number for the coordinates; a CTree is,
	 * I guess, like a CList with one column(?) and the expander widget
	 * as a pixmap.
	 */
	menu = widget;
	if(event->type == GDK_BUTTON_PRESS) {
		event_button = (GdkEventButton *) event;
		
		if(event_button->button == 3) {
			gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, event_button->button, event_button->time);
		}
	}
}

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading. */
void
set_menus_for_capture_file(gboolean have_capture_file)
{
  set_menu_sensitivity("/File/Open...", have_capture_file);
  set_menu_sensitivity("/File/Save As...", have_capture_file);
  set_menu_sensitivity("/File/Close", have_capture_file);
  set_menu_sensitivity("/File/Reload", have_capture_file);
}

/* Enable or disable menu items based on whether you have an unsaved
   capture file you've finished reading. */
void
set_menus_for_unsaved_capture_file(gboolean have_unsaved_capture_file)
{
  set_menu_sensitivity("/File/Save", have_unsaved_capture_file);
}

/* Enable or disable menu items based on whether there's a capture in
   progress. */
void
set_menus_for_capture_in_progress(gboolean capture_in_progress)
{
  set_menu_sensitivity("/File/Open...", !capture_in_progress);
  set_menu_sensitivity("/Capture/Start...", !capture_in_progress);
}

/* Enable or disable menu items based on whether you have some captured
   packets. */
void
set_menus_for_captured_packets(gboolean have_captured_packets)
{
  set_menu_sensitivity("/File/Print...", have_captured_packets);
  set_menu_sensitivity("/Edit/Find Frame...", have_captured_packets);
  set_menu_sensitivity("/Edit/Go To Frame...", have_captured_packets);
  set_menu_sensitivity("/Display/Match Selected", have_captured_packets);
  set_menu_sensitivity("/Display/Colorize Display...", have_captured_packets);
  set_menu_sensitivity("/Tools/Summary", have_captured_packets);
}

/* Enable or disable menu items based on whether a packet is selected. */
void
set_menus_for_selected_packet(gboolean have_selected_packet)
{
  set_menu_sensitivity("/File/Print Packet", have_selected_packet);
  set_menu_sensitivity("/Display/Collapse All", have_selected_packet);
  set_menu_sensitivity("/Display/Expand All", have_selected_packet);
  set_menu_sensitivity("/Display/Show Packet In New Window", have_selected_packet);
  set_menu_sensitivity("/Tools/Follow TCP Stream",
      have_selected_packet ? (pi.ipproto == 6) : FALSE);
  set_menu_sensitivity("/Resolve Name", 
      have_selected_packet && !g_resolving_actif);  
}

/* Enable or disable menu items based on whether a tree row is selected. */
void
set_menus_for_selected_tree_row(gboolean have_selected_tree)
{
  gboolean properties = FALSE;
  if (finfo_selected) {
	header_field_info *hfinfo = finfo_selected->hfinfo;
	if (hfinfo->parent == -1) {
	  properties = prefs_is_registered_protocol(hfinfo->abbrev);
	} else {
	  properties = prefs_is_registered_protocol(proto_registrar_get_abbrev(hfinfo->parent));
	}
  }
  set_menu_sensitivity("/Protocol Properties...", have_selected_tree && properties);
}
