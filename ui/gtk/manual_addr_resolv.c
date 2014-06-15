/* manual_addr_resolv.c
 * Dialog box for manual address resolve
 * Copyright 2010 Stig Bjorlykke <stig@bjorlykke.org>
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

#include <gtk/gtk.h>

#include "epan/addr_resolv.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/main.h"
#include "ui/gtk/menus.h"
#include "ui/gtk/manual_addr_resolv.h"
#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/packet_win.h"

GtkWidget *man_addr_resolv_dlg = NULL;

static void
man_addr_ill_addr_cb(gpointer dialog _U_, gint btn _U_, gpointer data _U_)
{
  gtk_window_present(GTK_WINDOW(man_addr_resolv_dlg));
}

static void
man_addr_resolv_ok(GtkWidget *w _U_, gpointer data _U_)
{
  GtkWidget   *addr_cb, *name_te, *resolv_cb;
  const gchar *name;
  gchar       *addr;
  gboolean     active, redissect = FALSE;

  addr_cb = (GtkWidget *)g_object_get_data(G_OBJECT(man_addr_resolv_dlg), "address");
  name_te = (GtkWidget *)g_object_get_data(G_OBJECT(man_addr_resolv_dlg), "name");

  addr = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(addr_cb));
  name = gtk_entry_get_text(GTK_ENTRY(name_te));

  if (strlen(addr) && strlen(name)) {
    if (!add_ip_name_from_string(addr, name)) {
      GtkWidget *dialog = (GtkWidget *)simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                                        "Illegal IP address: \"%s\".", addr);
      simple_dialog_set_cb(dialog, man_addr_ill_addr_cb, NULL);
      g_free(addr);
      return;
    } else {
      redissect = TRUE;
    }
  }
  g_free(addr);

  resolv_cb = (GtkWidget *)g_object_get_data(G_OBJECT(man_addr_resolv_dlg), "resolv");
  active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(resolv_cb));
  if (!gbl_resolv_flags.network_name && active) {
    /* Name resolution for Network Layer activated */
    gbl_resolv_flags.network_name = TRUE;
    menu_name_resolution_changed();
    redissect = TRUE;
  }

  if (redissect) {
    redissect_packets();
    redissect_all_packet_windows();
  }
  window_destroy(man_addr_resolv_dlg);
  man_addr_resolv_dlg = NULL;
}

static void
changed_cb(GtkWidget *w _U_, GtkWidget *ok_bt)
{
  const gchar *name;
  gchar       *addr;
  GtkWidget   *addr_cb, *name_cb, *resolv_cb;
  gboolean     active;

  name_cb   = (GtkWidget *)g_object_get_data(G_OBJECT(man_addr_resolv_dlg), "name");
  addr_cb   = (GtkWidget *)g_object_get_data(G_OBJECT(man_addr_resolv_dlg), "address");
  resolv_cb = (GtkWidget *)g_object_get_data(G_OBJECT(man_addr_resolv_dlg), "resolv");

  name   = gtk_entry_get_text(GTK_ENTRY(name_cb));
  addr   = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(addr_cb));
  active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(resolv_cb));

  gtk_widget_set_sensitive(ok_bt, strlen(name) > 0 && strlen(addr) && active ? TRUE : FALSE);
  g_free(addr);
}

void
manual_addr_resolv_dlg(GtkWidget *w _U_, gpointer data)
{
  GtkWidget *vbox, *bbox, *grid, *sep;
  GtkWidget *ok_bt, *close_bt, *help_bt;
  GtkWidget *addr_lb, *addr_cb;
  GtkWidget *name_lb, *name_te, *resolv_cb;
  GList     *addr_list = NULL;

  man_addr_resolv_dlg = dlg_window_new("Manual Address Resolve");
  gtk_window_set_default_size(GTK_WINDOW(man_addr_resolv_dlg), 310, 80);

  vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
  gtk_container_add(GTK_CONTAINER(man_addr_resolv_dlg), vbox);
  gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);

  grid = ws_gtk_grid_new();
  gtk_box_pack_start(GTK_BOX(vbox), grid, TRUE, TRUE, 0);

  addr_lb = gtk_label_new("Address:");
  ws_gtk_grid_attach_defaults(GTK_GRID(grid), addr_lb, 0, 0, 1, 1);

  addr_cb = gtk_combo_box_text_new_with_entry();
  if (data) {
    GList *addr_entry;
    addr_list = get_ip_address_list_from_packet_list_row(data);
    for (addr_entry = addr_list; addr_entry != NULL; addr_entry = g_list_next(addr_entry)) {
      gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(addr_cb), (const gchar *)addr_entry->data);
      g_free(addr_entry->data);
    }
    g_list_free(addr_entry);
    gtk_combo_box_set_active(GTK_COMBO_BOX(addr_cb), 0);
  }
  ws_gtk_grid_attach_defaults(GTK_GRID(grid), addr_cb, 1, 0, 1, 1);
  g_object_set_data(G_OBJECT(man_addr_resolv_dlg), "address", addr_cb);

  name_lb = gtk_label_new("Name:");
  ws_gtk_grid_attach_defaults(GTK_GRID(grid), name_lb, 0, 1, 1, 1);

  name_te = gtk_entry_new();
  ws_gtk_grid_attach_defaults(GTK_GRID(grid), name_te, 1, 1, 1, 1);
  g_object_set_data(G_OBJECT(man_addr_resolv_dlg), "name", name_te);

  sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
  gtk_box_pack_start(GTK_BOX(vbox), sep, TRUE, TRUE, 0);

  resolv_cb = gtk_check_button_new_with_mnemonic("Enable network name resolution");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(resolv_cb), gbl_resolv_flags.network_name);
  gtk_widget_set_sensitive(resolv_cb, !gbl_resolv_flags.network_name);

  gtk_widget_set_tooltip_text(resolv_cb, "Perform network layer name resolution.");
  g_object_set_data(G_OBJECT(man_addr_resolv_dlg), "resolv", resolv_cb);
  gtk_box_pack_start(GTK_BOX(vbox), resolv_cb, TRUE, TRUE, 0);

  /* Button row. */
  bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
  gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

  ok_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
  g_signal_connect(ok_bt, "clicked", G_CALLBACK(man_addr_resolv_ok), NULL);
  gtk_widget_set_sensitive(ok_bt, FALSE);

  g_signal_connect(name_te, "changed", G_CALLBACK(changed_cb), ok_bt);
  g_signal_connect(addr_cb, "changed", G_CALLBACK(changed_cb), ok_bt);
  g_signal_connect(resolv_cb, "toggled", G_CALLBACK(changed_cb), ok_bt);
  dlg_set_activate(name_te, ok_bt);

  close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
  window_set_cancel_button(man_addr_resolv_dlg, close_bt, window_cancel_button_cb);

  help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_MANUAL_ADDR_RESOLVE_DIALOG);

  gtk_widget_grab_default(ok_bt);
  g_signal_connect(man_addr_resolv_dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

  if (addr_list) {
    /* We have column data, activate name box */
    gtk_widget_grab_focus(name_te);
  }
  gtk_widget_show_all(man_addr_resolv_dlg);
  window_present(man_addr_resolv_dlg);
}
