/* prefs_taps.c
 * Dialog box for tap/statistics preferences
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
#include "config.h"
#endif
#include <stdlib.h>

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "gtk/prefs_taps.h"
#include "gtk/prefs_dlg.h"
#include "gtk/main.h"

#define TAP_UPDATE_INTERVAL_KEY   "update_interval"

#define RTP_PLAYER_MAX_VISIBLE_KEY   "rtp_player_max_visible"
#define RTP_PLAYER_TABLE_ROWS 6

static char update_interval_str[128] = "";
static char max_visible_str[128] = "";


GtkWidget*
stats_prefs_show(void)
{
        GtkWidget   *main_tb, *main_vb;
        GtkWidget   *tap_update_interval_te;
#ifdef HAVE_LIBPORTAUDIO
        GtkWidget   *rtp_player_max_visible_te;
#endif
        int pos = 0;

        /* Main vertical box */
        main_vb = gtk_vbox_new(FALSE, 7);
        gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);

        /* Main table */
        main_tb = gtk_table_new(RTP_PLAYER_TABLE_ROWS, 2, FALSE);
        gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
        gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
        gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
        gtk_widget_show(main_tb);

        /* Tap update gap in ms */
        tap_update_interval_te = create_preference_entry(main_tb, pos++,
            "Tap update interval in ms:",
            "Determines time between tap updates.", max_visible_str);
        g_snprintf(update_interval_str, sizeof(update_interval_str), "%d", prefs.tap_update_interval);
        gtk_entry_set_text(GTK_ENTRY(tap_update_interval_te), update_interval_str);
        gtk_widget_set_tooltip_text(tap_update_interval_te, "Gap in milliseconds between updates to taps is defined here");
        g_object_set_data(G_OBJECT(main_vb), TAP_UPDATE_INTERVAL_KEY, tap_update_interval_te);

#ifdef HAVE_LIBPORTAUDIO
        /* Max visible channels in RTP Player */
        rtp_player_max_visible_te = create_preference_entry(main_tb, pos++,
            "Max visible channels in RTP Player:",
            "Determines maximum height of RTP Player window.", max_visible_str);
        g_snprintf(max_visible_str, sizeof(max_visible_str), "%d", prefs.rtp_player_max_visible);
        gtk_entry_set_text(GTK_ENTRY(rtp_player_max_visible_te), max_visible_str);
        gtk_widget_set_tooltip_text(rtp_player_max_visible_te, "Maximum height of RTP Player window is defined here.");
        g_object_set_data(G_OBJECT(main_vb), RTP_PLAYER_MAX_VISIBLE_KEY, rtp_player_max_visible_te);
#endif

        /* Show 'em what we got */
        gtk_widget_show_all(main_vb);

        return main_vb;
}

void
stats_prefs_fetch(GtkWidget *w _U_)
{
        GtkWidget *tap_update_interval_te;
#ifdef HAVE_LIBPORTAUDIO
        GtkWidget *rtp_player_max_visible_te;
#endif

        /* Tap update interval */
        tap_update_interval_te = (GtkWidget *)g_object_get_data(G_OBJECT(w), TAP_UPDATE_INTERVAL_KEY);
        prefs.tap_update_interval = strtol(gtk_entry_get_text(
                GTK_ENTRY(tap_update_interval_te)), NULL, 10);

        /* Test for a sane tap update interval */
        if (prefs.tap_update_interval < 100 || prefs.tap_update_interval > 10000) {
                prefs.tap_update_interval = 3000;
        }

#ifdef HAVE_LIBPORTAUDIO
        /* Max RTP channels */
        rtp_player_max_visible_te = (GtkWidget *)g_object_get_data(G_OBJECT(w), RTP_PLAYER_MAX_VISIBLE_KEY);
        prefs.rtp_player_max_visible = strtol(gtk_entry_get_text(
                GTK_ENTRY(rtp_player_max_visible_te)), NULL, 10);

        /* Test for a sane max channels entry */
        if (prefs.rtp_player_max_visible < 1 || prefs.rtp_player_max_visible > 10)
                prefs.rtp_player_max_visible = RTP_PLAYER_DEFAULT_VISIBLE;
#endif
}

void
stats_prefs_apply(GtkWidget *w _U_)
{
        reset_tap_update_timer();
}

void
stats_prefs_destroy(GtkWidget *w _U_)
{
}
