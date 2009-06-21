/* main_filter_toolbar.c
 * The filter toolbar
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

/*
 * This file implements the "filter" toolbar for Wireshark.
 */

#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtk/gtk.h>

#include "filter_dlg.h"
#include "filter_autocomplete.h"

#include "epan/prefs.h"

#include "keys.h"
#include "gtkglobals.h"
#include "stock_icons.h"
#include "recent.h"

#include "main.h"
#include "menus.h"
#include "main_toolbar.h"
#include "main_filter_toolbar.h"


GtkWidget   *main_display_filter_widget=NULL;

/* Run the current display filter on the current packet set, and
   redisplay. */
static void
filter_activate_cb(GtkWidget *w _U_, gpointer data)
{
  const char *s;

  s = gtk_entry_get_text(GTK_ENTRY(data));

  main_filter_packets(&cfile, s, FALSE);
}

/* redisplay with no display filter */
static void
filter_reset_cb(GtkWidget *w, gpointer data _U_)
{
  GtkWidget *filter_te = NULL;

  if ((filter_te = g_object_get_data(G_OBJECT(w), E_DFILTER_TE_KEY))) {
    gtk_entry_set_text(GTK_ENTRY(filter_te), "");
  }
  main_filter_packets(&cfile, NULL, FALSE);
}


GtkWidget *filter_toolbar_new()
{
    GtkWidget
              *filter_bt, *filter_cm, *filter_te,
              *filter_add_expr_bt,
              *filter_apply,
              *filter_reset;
    GtkWidget *filter_tb;
    GList         *dfilter_list = NULL;
    GtkTooltips   *tooltips;

    /* Display filter construct dialog has an Apply button, and "OK" not
       only sets our text widget, it activates it (i.e., it causes us to
       filter the capture). */
    static construct_args_t args = {
        "Wireshark: Display Filter",
        TRUE,
        TRUE,
        FALSE
    };

    tooltips = gtk_tooltips_new();

    /* filter toolbar */
    filter_tb = gtk_toolbar_new();
    gtk_toolbar_set_orientation(GTK_TOOLBAR(filter_tb),
                                GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_show(filter_tb);

    /* Create the "Filter:" button */
    filter_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);
    g_signal_connect(filter_bt, "clicked", G_CALLBACK(display_filter_construct_cb), &args);
    gtk_widget_show(filter_bt);
    g_object_set_data(G_OBJECT(top_level), E_FILT_BT_PTR_KEY, filter_bt);

    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_bt,
        "Open the \"Display Filter\" dialog, to edit/apply filters", "Private");

    /* Create the filter combobox */
    filter_cm = gtk_combo_new();
    dfilter_list = NULL;
    gtk_combo_disable_activate(GTK_COMBO(filter_cm));
    gtk_combo_set_case_sensitive(GTK_COMBO(filter_cm), TRUE);
    g_object_set_data(G_OBJECT(filter_cm), E_DFILTER_FL_KEY, dfilter_list);
    filter_te = GTK_COMBO(filter_cm)->entry;
    main_display_filter_widget=filter_te;
    g_object_set_data(G_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
    g_object_set_data(G_OBJECT(filter_te), E_DFILTER_CM_KEY, filter_cm);
    g_object_set_data(G_OBJECT(top_level), E_DFILTER_CM_KEY, filter_cm);
    g_signal_connect(filter_te, "activate", G_CALLBACK(filter_activate_cb), filter_te);
    g_signal_connect(filter_te, "changed", G_CALLBACK(filter_te_syntax_check_cb), NULL);
    g_object_set_data(G_OBJECT(filter_tb), E_FILT_AUTOCOMP_PTR_KEY, NULL);
    g_object_set_data(G_OBJECT(filter_te), E_FILT_FIELD_USE_STATUSBAR_KEY, "");
    g_signal_connect(filter_te, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
    g_signal_connect(filter_tb, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
    gtk_widget_set_size_request(filter_cm, 400, -1);
    gtk_widget_show(filter_cm);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_cm,
        NULL, NULL);
    /* setting a tooltip for a combobox will do nothing, so add it to the corresponding text entry */
    gtk_tooltips_set_tip(tooltips, filter_te,
        "Enter a display filter, or choose one of your recently used filters. "
        "The background color of this field is changed by a continuous syntax check (green is valid, red is invalid, yellow may have unexpected results).",
        NULL);

    /* Create the "Add Expression..." button, to pop up a dialog
       for constructing filter comparison expressions. */
    filter_add_expr_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_ADD_EXPRESSION);
    g_object_set_data(G_OBJECT(filter_tb), E_FILT_FILTER_TE_KEY, filter_te);
    g_signal_connect(filter_add_expr_bt, "clicked", G_CALLBACK(filter_add_expr_bt_cb), filter_tb);
    gtk_widget_show(filter_add_expr_bt);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_add_expr_bt,
        "Add an expression to this filter string", "Private");

    /* Create the "Clear" button */
    filter_reset = gtk_button_new_from_stock(WIRESHARK_STOCK_CLEAR_EXPRESSION);
    g_object_set_data(G_OBJECT(filter_reset), E_DFILTER_TE_KEY, filter_te);
    g_signal_connect(filter_reset, "clicked", G_CALLBACK(filter_reset_cb), NULL);
    gtk_widget_show(filter_reset);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_reset,
        "Clear this filter string and update the display", "Private");

    /* Create the "Apply" button */
    filter_apply = gtk_button_new_from_stock(WIRESHARK_STOCK_APPLY_EXPRESSION);
    g_object_set_data(G_OBJECT(filter_apply), E_DFILTER_CM_KEY, filter_cm);
    g_signal_connect(filter_apply, "clicked", G_CALLBACK(filter_activate_cb), filter_te);
    gtk_widget_show(filter_apply);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_apply,
        "Apply this filter string to the display", "Private");

    /* Sets the text entry widget pointer as the E_DILTER_TE_KEY data
     * of any widget that ends up calling a callback which needs
     * that text entry pointer */
    set_menu_object_data("/File/Open...", E_DFILTER_TE_KEY, filter_te);
    set_menu_object_data("/Edit/Copy/As Filter", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Display Filters...", E_FILT_TE_PTR_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Follow TCP Stream", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Follow UDP Stream", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Follow SSL Stream", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/... and Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/... or Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/... and not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/... or not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/... and Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/... or Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/... and not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/... or not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/Ethernet", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/IP", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/TCP", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/UDP", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/PN-CBA Server", E_DFILTER_TE_KEY,
                         filter_te);
    set_toolbar_object_data(E_DFILTER_TE_KEY, filter_te);
    g_object_set_data(G_OBJECT(popup_menu_object), E_DFILTER_TE_KEY, filter_te);

    return filter_tb;
}

static gint
dfilter_entry_match(gconstpointer a, gconstpointer b)
{
    const char *s1 = a;
    const char *s2 = b;

    return strcmp(s1, s2);
}

/* add a display filter to the combo box */
/* Note: a new filter string will not replace an old identical one */
static gboolean
dfilter_combo_add(GtkWidget *filter_cm, char *s) {
    GList     *dfilter_list = g_object_get_data(G_OBJECT(filter_cm), E_DFILTER_FL_KEY);

    /* GtkCombos don't let us get at their list contents easily, so we maintain
       our own filter list, and feed it to gtk_combo_set_popdown_strings when
       a new filter is added. */
    if (s && strlen(s) > 0 &&
        g_list_length(dfilter_list) < prefs.gui_recent_df_entries_max &&
        g_list_find_custom(dfilter_list, s, dfilter_entry_match) == NULL) {

      dfilter_list = g_list_append(dfilter_list, s);
      s = NULL;
      g_object_set_data(G_OBJECT(filter_cm), E_DFILTER_FL_KEY, dfilter_list);
      gtk_combo_set_popdown_strings(GTK_COMBO(filter_cm), dfilter_list);
      gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(filter_cm)->entry), g_list_first(dfilter_list)->data);
    }

    g_free(s);

    return TRUE;
}


/* write all non empty display filters (until maximum count)
 * of the combo box GList to the user's recent file */
void
dfilter_recent_combo_write_all(FILE *rf) {
  GtkWidget *filter_cm = g_object_get_data(G_OBJECT(top_level), E_DFILTER_CM_KEY);
  GList     *dfilter_list = g_object_get_data(G_OBJECT(filter_cm), E_DFILTER_FL_KEY);
  GList     *li;
  guint      max_count = 0;


  /* write all non empty display filter strings to the recent file (until max count) */
  li = g_list_first(dfilter_list);
  while ( li && (max_count++ < prefs.gui_recent_df_entries_max) ) {
    if (strlen(li->data)) {
      fprintf (rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", (char *)li->data);
    }
    li = li->next;
  }
}

/* empty the combobox entry field */
void
dfilter_combo_add_empty(void) {
  GtkWidget *filter_cm = g_object_get_data(G_OBJECT(top_level), E_DFILTER_CM_KEY);

  gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(filter_cm)->entry), "");
}


/* add a display filter coming from the user's recent file to the dfilter combo box */
gboolean
dfilter_combo_add_recent(gchar *s) {
  GtkWidget *filter_cm = g_object_get_data(G_OBJECT(top_level), E_DFILTER_CM_KEY);
  char      *dup;

  dup = g_strdup(s);

  return dfilter_combo_add(filter_cm, dup);
}

/* call cf_filter_packets() and add this filter string to the recent filter list */
gboolean
main_filter_packets(capture_file *cf, const gchar *dftext, gboolean force)
{
  GtkCombo  *filter_cm = g_object_get_data(G_OBJECT(top_level), E_DFILTER_CM_KEY);
  GList     *dfilter_list = g_object_get_data(G_OBJECT(filter_cm), E_DFILTER_FL_KEY);
  gboolean   free_filter = TRUE;
  char      *s;
  cf_status_t cf_status;

  s = g_strdup(dftext);

  cf_status = cf_filter_packets(cf, s, force);
  if (!s)
    return (cf_status == CF_OK);

  /* GtkCombos don't let us get at their list contents easily, so we maintain
     our own filter list, and feed it to gtk_combo_set_popdown_strings when
     a new filter is added. */
  if (cf_status == CF_OK && strlen(s) > 0) {
    GList *li;

    while ((li = g_list_find_custom(dfilter_list, s, dfilter_entry_match)) != NULL)
      /* Delete old/duplicate entry now. We'll re-add it later */
      dfilter_list = g_list_delete_link(dfilter_list, li);

    /* trim list size first */
    while (g_list_length(dfilter_list) >= prefs.gui_recent_df_entries_max)
      dfilter_list = g_list_delete_link(dfilter_list, g_list_last(dfilter_list));

    free_filter = FALSE;
    /* Push the filter to the front of the list */
    dfilter_list = g_list_prepend(dfilter_list, s);
    g_object_set_data(G_OBJECT(filter_cm), E_DFILTER_FL_KEY, dfilter_list);
    gtk_combo_set_popdown_strings(filter_cm, dfilter_list);
    gtk_entry_set_text(GTK_ENTRY(filter_cm->entry), g_list_first(dfilter_list)->data);
  }

  if (free_filter)
    g_free(s);

  return (cf_status == CF_OK);
}


