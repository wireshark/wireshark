/* menu.c
 * Menu routines
 *
 * $Id: menu.c,v 1.23 1999/07/07 22:51:40 gram Exp $
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

#include <glib.h>

#include <gtk/gtk.h>
#include <pcap.h>	/* for capture.h */

#include <string.h>

#include "ethereal.h"
#include "menu.h"
#include "packet.h"
#include "capture.h"
#include "summary.h"
#include "display.h"
#include "prefs.h"
#include "print.h"
#include "follow.h"

/* Much of this was take from the GTK+ tuturial at http://www.gtk.org */
#ifndef USE_ITEM
static void menus_remove_accel (GtkWidget *, gchar *, gchar *);
static gint menus_install_accel (GtkWidget *, gchar *, gchar, gchar, gchar *);
#endif

#ifdef USE_ITEM
GtkAccelGroup *grp;
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

static GtkItemFactoryEntry menu_items[] =
{
  {"/_File", NULL, NULL, 0, "<Branch>" },
  {"/File/_Open...", "<control>O", GTK_MENU_FUNC(file_open_cmd_cb), 0, NULL},
  {"/File/_Close", "<control>W", GTK_MENU_FUNC(file_close_cmd_cb), 0, NULL},
  {"/File/_Save", "<control>S", GTK_MENU_FUNC(file_save_cmd_cb), 0, NULL},
  {"/File/Save _As...", NULL, GTK_MENU_FUNC(file_save_as_cmd_cb), 0, NULL},
  {"/File/_Reload", "<control>R", GTK_MENU_FUNC(file_reload_cmd_cb), 0, NULL},
  {"/File/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/File/_Print Packet", "<control>P", GTK_MENU_FUNC(file_print_cmd_cb), 0, NULL},
  {"/File/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/File/_Quit", "<control>Q", GTK_MENU_FUNC(file_quit_cmd_cb), 0, NULL},
  {"/_Edit", NULL, NULL, 0, "<Branch>" },
  {"/Edit/Cut", "<control>X", NULL, 0, NULL},
  {"/Edit/Copy", "<control>C", NULL, 0, NULL},
  {"/Edit/Paste", "<control>V", NULL, 0, NULL},
  {"/Edit/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/Edit/Find", "<control>F", NULL, 0, NULL},
  {"/Edit/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/Edit/_Preferences...", NULL, GTK_MENU_FUNC(prefs_cb), E_PR_PG_NONE, NULL},
  {"/_Capture", NULL, NULL, 0, "<Branch>" },
  {"/Capture/_Start...", "<control>K", GTK_MENU_FUNC(capture_prep_cb), 0, NULL},
  {"/_Display", NULL, NULL, 0, "<Branch>" },
  {"/Display/_Options...", NULL, GTK_MENU_FUNC(display_opt_cb), 0, NULL},
  {"/Display/_Match Selected", NULL, GTK_MENU_FUNC(match_selected_cb), 0, NULL},
  {"/_Tools", NULL, NULL, 0, "<Branch>" },
  {"/Tools/_Capture...", NULL, GTK_MENU_FUNC(capture_prep_cb), 0, NULL},
  {"/Tools/_Follow TCP Stream", NULL, GTK_MENU_FUNC(follow_stream_cb), 0, NULL},
/*  {"/Tools/Graph", NULL, NULL, 0, NULL}, future use */
  {"/Tools/Summary", NULL, GTK_MENU_FUNC(summary_prep_cb), 0, NULL},
  {"/_Help", NULL, NULL, 0, "<LastBranch>" },
  {"/Help/_About Ethereal...", NULL, GTK_MENU_FUNC(about_ethereal), 0, NULL}
};
#else
/* this is the GtkMenuEntry structure used to create new menus.  The
 * first member is the menu definition string.  The second, the
 * default accelerator key used to access this menu function with
 * the keyboard.  The third is the callback function to call when
 * this menu item is selected (by the accelerator key, or with the
 * mouse.) The last member is the data to pass to your callback function.
 */
static GtkMenuEntry menu_items[] =
{
  {"<Main>/File/Open...", "<control>O", file_open_cmd_cb, NULL},
  {"<Main>/File/Close", "<control>W", file_close_cmd_cb, NULL},
  {"<Main>/File/Save", "<control>S", file_save_cmd_cb, NULL},
  {"<Main>/File/Save As...", NULL, file_save_as_cmd_cb, NULL},
  {"<Main>/File/Reload", "<control>R", file_reload_cmd_cb, NULL},
  {"<Main>/File/<separator>", NULL, NULL, NULL},
  {"<Main>/File/Print Packet", "<control>P", file_print_cmd_cb, NULL},
  {"<Main>/File/<separator>", NULL, NULL, NULL},
  {"<Main>/File/Quit", "<control>Q", file_quit_cmd_cb, NULL},
  {"<Main>/Edit/Cut", "<control>X", NULL, NULL},
  {"<Main>/Edit/Copy", "<control>C", NULL, NULL},
  {"<Main>/Edit/Paste", "<control>V", NULL, NULL},
  {"<Main>/Edit/<separator>", NULL, NULL, NULL},
  {"<Main>/Edit/Find", "<control>F", NULL, NULL},
  {"<Main>/Edit/<separator>", NULL, NULL, NULL},
  {"<Main>/Edit/Preferences...", NULL, prefs_cb, (gpointer) E_PR_PG_NONE},
  {"<Main>/Capture/Start...", "<control>K", capture_prep_cb, NULL},
  {"<Main>/Display/Options...", NULL, display_opt_cb, NULL},
  {"<Main>/Display/Match Selected", NULL, match_selected_cb, NULL},
  {"<Main>/Tools/Capture...", NULL, capture_prep_cb, NULL},
  {"<Main>/Tools/Follow TCP Stream", NULL, follow_stream_cb, NULL},
/*  {"<Main>/Tools/Graph", NULL, NULL, NULL}, future use */
  {"<Main>/Tools/Summary", NULL, summary_prep_cb, NULL},
  {"<Main>/Help/About Ethereal...", NULL, about_ethereal, NULL}
};
#endif

/* calculate the number of menu_items */
static int nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

static int initialize = TRUE;
#ifdef USE_ITEM
static GtkItemFactory *factory = NULL;
#else
static GtkMenuFactory *factory = NULL;
static GtkMenuFactory *subfactory[1];
static GHashTable *entry_ht = NULL;
#endif

void
#ifdef GTK_HAVE_FEATURES_1_1_0
get_main_menu(GtkWidget ** menubar, GtkAccelGroup ** table) {
#else
get_main_menu(GtkWidget ** menubar, GtkAcceleratorTable ** table) {
#endif

#ifdef USE_ITEM
  grp = gtk_accel_group_new();
#endif

  if (initialize)
    menus_init();

#ifdef USE_ITEM
  if (menubar)
    *menubar = factory->widget;
#else
  if (menubar)
    *menubar = subfactory[0]->widget;
#endif

  if (table)
#ifdef USE_ITEM
    *table = grp;
#else
#ifdef GTK_HAVE_FEATURES_1_1_0
    *table = subfactory[0]->accel_group;
#else
    *table = subfactory[0]->table;
#endif /* GTK 1.1.0 */
#endif /* USE_ITEM */
}

void
menus_init(void) {
#ifndef USE_ITEM
  GtkMenuPath *mp;
#endif

  if (initialize) {
    initialize = FALSE;

#ifdef USE_ITEM
    factory = gtk_item_factory_new(GTK_TYPE_MENU_BAR, "<main>", grp);
    gtk_item_factory_create_items_ac(factory, nmenu_items, menu_items, NULL,2);
    set_menu_sensitivity("/File/Close", FALSE);
    set_menu_sensitivity("/File/Save", FALSE);
    set_menu_sensitivity("/File/Save As...", FALSE);
    set_menu_sensitivity("/File/Reload", FALSE);
    set_menu_sensitivity("/Edit/Cut", FALSE);
    set_menu_sensitivity("/Edit/Copy", FALSE);
    set_menu_sensitivity("/Edit/Paste", FALSE);
    set_menu_sensitivity("/Edit/Find", FALSE);
    set_menu_sensitivity("/Tools/Graph", FALSE);
    set_menu_sensitivity("/Tools/Summary", FALSE);

    set_menu_sensitivity("/Tools/Follow TCP Stream", FALSE);
    set_menu_sensitivity("/Display/Match Selected", FALSE);
    
#else
    factory = gtk_menu_factory_new(GTK_MENU_FACTORY_MENU_BAR);
    subfactory[0] = gtk_menu_factory_new(GTK_MENU_FACTORY_MENU_BAR);

    gtk_menu_factory_add_subfactory(factory, subfactory[0], "<Main>");
    menus_create(menu_items, nmenu_items);

    set_menu_sensitivity("<Main>/File/Close", FALSE);
    set_menu_sensitivity("<Main>/File/Save", FALSE);
    set_menu_sensitivity("<Main>/File/Save As...", FALSE);
    set_menu_sensitivity("<Main>/File/Reload", FALSE);
    set_menu_sensitivity("<Main>/Edit/Cut", FALSE);
    set_menu_sensitivity("<Main>/Edit/Copy", FALSE);
    set_menu_sensitivity("<Main>/Edit/Paste", FALSE);
    set_menu_sensitivity("<Main>/Edit/Find", FALSE);
    set_menu_sensitivity("<Main>/Tools/Graph", FALSE);
    set_menu_sensitivity("<Main>/Tools/Summary", FALSE);

    set_menu_sensitivity("<Main>/Tools/Follow TCP Stream", FALSE);
    set_menu_sensitivity("<Main>/Display/Match Selected", FALSE);

    if ((mp = gtk_menu_factory_find(factory, "<Main>/Help")) != NULL) {
      gtk_menu_item_right_justify((GtkMenuItem *) mp->widget);
    }
#endif
  }
}

void
set_menu_sensitivity (gchar *path, gint val) {
#ifdef USE_ITEM
  GtkWidget *menu;
#else
  GtkMenuPath *mp;
#endif

#ifdef USE_ITEM 
  if ((menu = gtk_item_factory_get_widget(factory, path)) != NULL)
    gtk_widget_set_sensitive(menu, val);
#else
  if ((mp = gtk_menu_factory_find(factory, path)) != NULL)
    gtk_widget_set_sensitive(mp->widget, val);
#endif
}

void
set_menu_object_data (gchar *path, gchar *key, gpointer data) {
#ifdef USE_ITEM
  GtkWidget *menu;
#else
  GtkMenuPath *mp;
#endif
  
#ifdef USE_ITEM 
  if ((menu = gtk_item_factory_get_widget(factory, path)) != NULL)
    gtk_object_set_data(GTK_OBJECT(menu), key, data);
#else
  if ((mp = gtk_menu_factory_find(factory, path)) != NULL)
    gtk_object_set_data(GTK_OBJECT(mp->widget), key, data);
#endif
}

#ifndef USE_ITEM
void
menus_create(GtkMenuEntry * entries, int nmenu_entries) {
  char *accelerator;
  int i;

  if (initialize)
    menus_init();

  if (entry_ht)
    for (i = 0; i < nmenu_entries; i++) {
      accelerator = g_hash_table_lookup(entry_ht, entries[i].path);
      if (accelerator) {
        if (accelerator[0] == '\0')
          entries[i].accelerator = NULL;
        else
          entries[i].accelerator = accelerator;
      }
    }
  gtk_menu_factory_add_entries(factory, entries, nmenu_entries);

  for (i = 0; i < nmenu_entries; i++)
    if (entries[i].widget) {
#ifdef GTK_HAVE_FEATURES_1_1_0
      gtk_signal_connect(GTK_OBJECT(entries[i].widget), "add_accelerator",
         (GtkSignalFunc) menus_install_accel, entries[i].path);
#else
      gtk_signal_connect(GTK_OBJECT(entries[i].widget), "install_accelerator",
         (GtkSignalFunc) menus_install_accel, entries[i].path);
#endif
      gtk_signal_connect(GTK_OBJECT(entries[i].widget), "remove_accelerator",
        (GtkSignalFunc) menus_remove_accel, entries[i].path);
  }
}

static gint
menus_install_accel(GtkWidget * widget, gchar * signal_name, gchar key, gchar modifiers, gchar * path) {
  char accel[64];
  char *t1, t2[2];

  accel[0] = '\0';
  if (modifiers & GDK_CONTROL_MASK)
    strcat(accel, "<control>");
  if (modifiers & GDK_SHIFT_MASK)
    strcat(accel, "<shift>");
  if (modifiers & GDK_MOD1_MASK)
    strcat(accel, "<alt>");

  t2[0] = key;
  t2[1] = '\0';
  strcat(accel, t2);

  if (entry_ht) {
    t1 = g_hash_table_lookup(entry_ht, path);
    g_free(t1);
  } else
    entry_ht = g_hash_table_new(g_str_hash, g_str_equal);

  g_hash_table_insert(entry_ht, path, g_strdup(accel));

  return TRUE;
}

static void
menus_remove_accel(GtkWidget * widget, gchar * signal_name, gchar * path) {
  char *t;

  if (entry_ht) {
    t = g_hash_table_lookup(entry_ht, path);
    g_free(t);

    g_hash_table_insert(entry_ht, path, g_strdup(""));
  }
}
#endif

