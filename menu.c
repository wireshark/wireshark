/* menu.c
 * Menu routines
 *
 * $Id: menu.c,v 1.29 1999/07/27 01:58:43 guy Exp $
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

#include <string.h>
#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "ethereal.h"
#include "menu.h"
#include "packet.h"
#include "capture.h"
#include "summary.h"
#include "display.h"
#include "prefs.h"
#include "print.h"
#include "follow.h"


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
  {"/File/<separator>", NULL, NULL, 0, "<Separator>"},
  {"/File/Print...", NULL, GTK_MENU_FUNC(file_print_cmd_cb), 0, NULL},
  {"/File/Print Pac_ket", "<control>P", GTK_MENU_FUNC(file_print_packet_cmd_cb), 0, NULL},
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
#ifdef HAVE_LIBPCAP
  {"/_Capture", NULL, NULL, 0, "<Branch>" },
  {"/Capture/_Start...", "<control>K", GTK_MENU_FUNC(capture_prep_cb), 0, NULL},
#endif
  {"/_Display", NULL, NULL, 0, "<Branch>" },
  {"/Display/_Options...", NULL, GTK_MENU_FUNC(display_opt_cb), 0, NULL},
  {"/Display/_Match Selected", NULL, GTK_MENU_FUNC(match_selected_cb), 0, NULL},
  {"/_Tools", NULL, NULL, 0, "<Branch>" },
#ifdef HAVE_LIBPCAP
  {"/Tools/_Capture...", NULL, GTK_MENU_FUNC(capture_prep_cb), 0, NULL},
#endif
  {"/Tools/_Follow TCP Stream", NULL, GTK_MENU_FUNC(follow_stream_cb), 0, NULL},
/*  {"/Tools/Graph", NULL, NULL, 0, NULL}, future use */
  {"/Tools/Summary", NULL, GTK_MENU_FUNC(summary_prep_cb), 0, NULL},
  {"/_Help", NULL, NULL, 0, "<LastBranch>" },
  {"/Help/_About Ethereal...", NULL, GTK_MENU_FUNC(about_ethereal), 0, NULL}
};

/* calculate the number of menu_items */
static int nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

static int initialize = TRUE;
static GtkItemFactory *factory = NULL;

void
get_main_menu(GtkWidget ** menubar, GtkAccelGroup ** table) {

  grp = gtk_accel_group_new();

  if (initialize)
    menus_init();

  if (menubar)
    *menubar = factory->widget;

  if (table)
    *table = grp;
}

void
menus_init(void) {

  if (initialize) {
    initialize = FALSE;

    factory = gtk_item_factory_new(GTK_TYPE_MENU_BAR, "<main>", grp);
    gtk_item_factory_create_items_ac(factory, nmenu_items, menu_items, NULL,2);
    set_menu_sensitivity("/File/Close", FALSE);
    set_menu_sensitivity("/File/Save", FALSE);
    set_menu_sensitivity("/File/Save As...", FALSE);
    set_menu_sensitivity("/File/Print...", FALSE);
    set_menu_sensitivity("/File/Print Packet", FALSE);
    set_menu_sensitivity("/Edit/Cut", FALSE);
    set_menu_sensitivity("/Edit/Copy", FALSE);
    set_menu_sensitivity("/Edit/Paste", FALSE);
    set_menu_sensitivity("/Edit/Find", FALSE);
    set_menu_sensitivity("/Tools/Graph", FALSE);
    set_menu_sensitivity("/Tools/Summary", FALSE);

    /*set_menu_sensitivity("/Tools/Follow TCP Stream", FALSE);*/
    set_menu_sensitivity("/Display/Match Selected", FALSE);
  }
}

void
set_menu_sensitivity (gchar *path, gint val) {
  GtkWidget *menu;

  if ((menu = gtk_item_factory_get_widget(factory, path)) != NULL)
    gtk_widget_set_sensitive(menu, val);
}

void
set_menu_object_data (gchar *path, gchar *key, gpointer data) {
  GtkWidget *menu;
  
  if ((menu = gtk_item_factory_get_widget(factory, path)) != NULL)
    gtk_object_set_data(GTK_OBJECT(menu), key, data);
}


