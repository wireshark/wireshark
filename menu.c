/* menu.c
 * Menu routines
 *
 * $Id: menu.c,v 1.4 1998/09/25 23:24:00 gerald Exp $
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
#include <pcap.h>

#include <strings.h>

#include "menu.h"
#include "ethereal.h"
#include "capture.h"
#include "filter.h"
#include "packet.h"
#include "print.h"
#include "follow.h"
#include "prefs.h"

/* Much of this was take from the GTK+ tuturial at http://www.gtk.org */

static void menus_remove_accel (GtkWidget *, gchar *, gchar *);
static gint menus_install_accel (GtkWidget *, gchar *, gchar, gchar, gchar *);

/* this is the GtkMenuEntry structure used to create new menus.  The
 * first member is the menu definition string.  The second, the
 * default accelerator key used to access this menu function with
 * the keyboard.  The third is the callback function to call when
 * this menu item is selected (by the accelerator key, or with the
 * mouse.) The last member is the data to pass to your callback function.
 */

static GtkMenuEntry menu_items[] =
{
  {"<Main>/File/Open", "<control>O", file_open_cmd_cb, NULL},
  {"<Main>/File/Close", "<control>W", file_close_cmd_cb, NULL},
  {"<Main>/File/Save", "<control>S", NULL, NULL},
  {"<Main>/File/Save as", NULL, NULL, NULL},
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
  {"<Main>/Edit/Printer Options", NULL, printer_opts_cb, NULL},
  {"<Main>/Edit/<separator>", NULL, NULL, NULL},
  {"<Main>/Edit/Preferences", NULL, prefs_cb, NULL},
  {"<Main>/Tools/Capture", "<control>K", capture_prep_cb, NULL},
  {"<Main>/Tools/Filter", NULL, filter_sel_cb, NULL},
  {"<Main>/Tools/Follow TCP Stream", NULL, follow_stream_cb, NULL},
  {"<Main>/Tools/Graph", NULL, NULL, NULL},
  {"<Main>/Help/About Ethereal", NULL, NULL, NULL}
};

/* calculate the number of menu_items */
static int nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

static int initialize = TRUE;
static GtkMenuFactory *factory = NULL;
static GtkMenuFactory *subfactory[1];
static GHashTable *entry_ht = NULL;

void
get_main_menu(GtkWidget ** menubar, GtkAcceleratorTable ** table) {
  if (initialize)
    menus_init();

  if (menubar)
    *menubar = subfactory[0]->widget;
  if (table)
    *table = subfactory[0]->table;
}

void
menus_init(void) {
  GtkMenuPath *mp;

  if (initialize) {
    initialize = FALSE;

    factory = gtk_menu_factory_new(GTK_MENU_FACTORY_MENU_BAR);
    subfactory[0] = gtk_menu_factory_new(GTK_MENU_FACTORY_MENU_BAR);

    gtk_menu_factory_add_subfactory(factory, subfactory[0], "<Main>");
    menus_create(menu_items, nmenu_items);

    set_menu_sensitivity("<Main>/File/Close", FALSE);
    set_menu_sensitivity("<Main>/File/Save", FALSE);
    set_menu_sensitivity("<Main>/File/Save as", FALSE);
    set_menu_sensitivity("<Main>/Edit/Cut", FALSE);
    set_menu_sensitivity("<Main>/Edit/Copy", FALSE);
    set_menu_sensitivity("<Main>/Edit/Paste", FALSE);
    set_menu_sensitivity("<Main>/Edit/Find", FALSE);
    set_menu_sensitivity("<Main>/Edit/Preferences", FALSE);
    set_menu_sensitivity("<Main>/Tools/Graph", FALSE);
    set_menu_sensitivity("<Main>/Help/About Ethereal", FALSE);
    if ((mp = gtk_menu_factory_find(factory, "<Main>/Help")) != NULL) {
      gtk_menu_item_right_justify((GtkMenuItem *) mp->widget);
    }
  }
}

void
set_menu_sensitivity (gchar *path, gint val) {
  GtkMenuPath *mp;
  
  if ((mp = gtk_menu_factory_find(factory, path)) != NULL) {
    gtk_widget_set_sensitive(mp->widget, val);
  }
}

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
      gtk_signal_connect(GTK_OBJECT(entries[i].widget), "install_accelerator",
         (GtkSignalFunc) menus_install_accel, entries[i].path);
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

void
menus_set_sensitive(char *path, int sensitive) {
  GtkMenuPath *menu_path;

  if (initialize)
    menus_init();

  menu_path = gtk_menu_factory_find(factory, path);
  if (menu_path)
    gtk_widget_set_sensitive(menu_path->widget, sensitive);
  else
    g_warning("Unable to set sensitivity for menu which doesn't exist: %s", path);
}
