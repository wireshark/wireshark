/* prefs_filter_expressions.c
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
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
#include <epan/uat.h>


#include "ui/gtk/gui_utils.h"
#include "ui/gtk/uat_gui.h"
#include "ui/gtk/prefs_filter_expressions.h"
#include "ui/gtk/stock_icons.h"

/*
 * Create and display the expression filter UAT
 * Called as part of the creation of the Preferences notebook ( Edit ! Preferences )
 */
GtkWidget *
filter_expressions_prefs_show(void) {

	GtkWidget	*filter_window, *main_grid, *expression_lb, *expression_bt;
	int		row = 0;
	const gchar     *tooltips_text;

	/* Main vertical box */
	filter_window = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 7, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(filter_window), 5);

	/* Main grid */
	main_grid = ws_gtk_grid_new();
	gtk_box_pack_start(GTK_BOX(filter_window), main_grid, FALSE, FALSE, 0);
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_set_vexpand(GTK_WIDGET(main_grid), FALSE); /* Ignore VEXPAND requests from children */
#endif
	ws_gtk_grid_set_row_spacing(GTK_GRID(main_grid), 10);
	ws_gtk_grid_set_column_spacing(GTK_GRID(main_grid), 15);
	gtk_widget_show(main_grid);


	/* Interface properties */
	expression_lb = gtk_label_new("Display filter expressions:");
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), expression_lb, 0, row, 1, 1);
	gtk_misc_set_alignment(GTK_MISC(expression_lb), 1.0f, 0.5f);
	gtk_widget_show(expression_lb);

	expression_bt = ws_gtk_button_new_from_stock(WIRESHARK_STOCK_EDIT);
	tooltips_text = "Open a dialog box to configure display filter expression buttons.";
	gtk_widget_set_tooltip_text(expression_lb, tooltips_text);
	gtk_widget_set_tooltip_text(expression_bt, tooltips_text);
	g_signal_connect(expression_bt, "clicked", G_CALLBACK(uat_window_cb), uat_get_table_by_name("Display expressions"));
	ws_gtk_grid_attach_defaults(GTK_GRID(main_grid), expression_bt, 1, row, 1, 1);

	/* Show 'em what we got */
	gtk_widget_show_all(filter_window);

	return(filter_window);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
