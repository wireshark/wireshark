/* filter_expression_save_dlg.c
 * Routines for "Filter Save" window
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
#include <math.h>

#include <gtk/gtk.h>

#include <epan/prefs.h>


#include "ui/preference_utils.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/filter_expression_save_dlg.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/filter_autocomplete.h"
#include "ui/gtk/help_dlg.h"

#include "main.h"


/* Capture callback data keys */
#define E_FILTER_SAVE_EXPR_KEY     "filter_save_offset_expression"
#define E_FILTER_SAVE_LABEL_KEY     "filter_save_offset_label"

static void filter_save_ok_cb(GtkWidget *ok_bt, GtkWindow *parent_w);
static void filter_save_close_cb(GtkWidget *close_bt, gpointer parent_w);
static void filter_save_frame_destroy_cb(GtkWidget *win, gpointer user_data);
static void filter_button_cb(GtkWidget *close_bt, gpointer parent_w);
static int filter_button_add(const char *label, const char *expr, struct filter_expression *newbutton);

/*
 * Keep a static pointer to the current "Filter Save" window, if any, so
 * that if somebody tries to do "Filter Save" while there's already a
 * "Filter Save" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *filter_save_frame_w;

GtkWidget *_filter_tb = NULL;
GtkWidget *_filter_te = NULL;

/*
 * This does do two things:
 * - Keep track of the various elements of the Filter Toolbar which will
 *   be needed later when a new button has to be added.
 * - Since it is called after the preferences are read from the configfile,
 *   this is the one also which creates the initial buttons when the
 *   Filter Toolbar has been created.
 */
void
filter_expression_save_dlg_init(gpointer filter_tb, gpointer filter_te)
{
	struct filter_expression *fe;

	_filter_tb = (GtkWidget *)filter_tb;
	_filter_te = (GtkWidget *)filter_te;

	fe = *pfilter_expression_head;
	while (fe != NULL) {
		filter_button_add(NULL, NULL, fe);
		fe = fe->next;
	}
}

void
filter_expression_reinit(int what)
{
	struct filter_expression *fe, *prevhead;

	if ((what & FILTER_EXPRESSION_REINIT_DESTROY) != 0) {
		fe = *pfilter_expression_head;
		while (fe != NULL) {
			if (fe->button != NULL) {
				gtk_widget_destroy((GtkWidget *)fe->button);
				fe->button = NULL;
			}
			fe = fe->next;
		}
	}
	if (what == FILTER_EXPRESSION_REINIT_DESTROY) {
		filter_expression_free(*pfilter_expression_head);
		*pfilter_expression_head = NULL;
		return;
	}

	if ((what & FILTER_EXPRESSION_REINIT_CREATE) != 0) {
		gint maxindx = -1, indx;
		fe = *pfilter_expression_head;
		while (fe != NULL) {
			maxindx = MAX(maxindx, fe->filter_index);
			fe = fe->next;
		}

		prevhead = *pfilter_expression_head;
		*pfilter_expression_head = NULL;

		/*
		 * The list should be in the order identified by the
		 * index member.
		 */
		for (indx = 0; indx <= maxindx; indx++) {
			if (prevhead != NULL) {
				fe = prevhead;
				while (fe != NULL && fe->filter_index != indx)
					fe = fe->next;
			}
			if (fe == NULL)
				continue;	/* Shouldn't happen */
			if (fe->deleted)
				continue;	/* Could happen */
			filter_expression_new(fe->label, fe->expression,
			    fe->enabled);
		}
		filter_expression_free(prevhead);

		/* Create the buttons again */
		fe = *pfilter_expression_head;
		while (fe != NULL) {
			if (fe->enabled && !fe->deleted)
				filter_button_add(NULL, NULL, fe);
			fe = fe->next;
		}
	}
}

static int
filter_button_add(const char *label, const char *expr, struct filter_expression *newfe)
{
	struct filter_expression *fe;

	/* No duplicate buttons when adding a new one  */
	if (newfe == NULL)
		fe = filter_expression_new(label, expr, TRUE);
	else
		fe = newfe;

	if (fe->enabled == FALSE)
		return(0);

	/* Create the "Label" button */
	fe->button = gtk_tool_button_new(NULL, fe->label);
	g_signal_connect(fe->button, "clicked", G_CALLBACK(filter_button_cb),
	    NULL);
	gtk_widget_set_sensitive(GTK_WIDGET(fe->button), FALSE);
	gtk_widget_show(GTK_WIDGET(fe->button));

	gtk_toolbar_insert(GTK_TOOLBAR(_filter_tb), (GtkToolItem *)fe->button, -1);
	gtk_widget_set_sensitive(GTK_WIDGET(fe->button), TRUE);
	gtk_widget_set_tooltip_text(GTK_WIDGET(fe->button), fe->expression);

	return(0);
}

static void
filter_button_cb(GtkWidget *this_button, gpointer parent_w _U_)
{
	struct filter_expression *fe;

	fe = *pfilter_expression_head;
	while (fe != NULL) {
		if ((void *)fe->button == (void *)this_button) {
			gtk_entry_set_text(GTK_ENTRY(_filter_te),
			    fe->expression);
			main_filter_packets(&cfile, fe->expression, FALSE);
			return;
		}
		fe = fe->next;
	}
	printf("No Callback\n");
}

void
filter_expression_save_dlg(gpointer data)
{
	GtkWidget   *main_vb, *main_filter_save_hb, *filter_save_frame,
		    *filter_save_type_vb, *filter_save_type_hb, *entry_hb,
		    *bbox, *ok_bt, *cancel_bt, *help_bt, *filter_text_box,
		    *label_text_box;

	const char *expr;

	/* The filter requested */
	expr = gtk_entry_get_text(GTK_ENTRY(data));

	if (filter_save_frame_w != NULL) {
		/* There's already a "Filter Save" dialog box; reactivate it. */
		reactivate_window(filter_save_frame_w);
		return;
	}

	filter_save_frame_w = dlg_window_new("Wireshark: Save Filter");

	/* Container for each row of widgets */
	main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
	gtk_container_add(GTK_CONTAINER(filter_save_frame_w), main_vb);
	gtk_widget_show(main_vb);


	/* */
	main_filter_save_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
	gtk_box_pack_start(GTK_BOX (main_vb), main_filter_save_hb, TRUE, TRUE, 0);
	gtk_widget_show(main_filter_save_hb);

	/* Filter Save frame */
	filter_save_frame = gtk_frame_new("Save Filter as...");
	gtk_box_pack_start(GTK_BOX(main_filter_save_hb), filter_save_frame,
	    TRUE, TRUE, 0);
	gtk_widget_show(filter_save_frame);

	filter_save_type_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(filter_save_type_vb), 3);
	gtk_container_add(GTK_CONTAINER(filter_save_frame),
	    filter_save_type_vb);
	gtk_widget_show(filter_save_type_vb);

	/* filter_save type row */
	filter_save_type_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
	gtk_box_pack_start(GTK_BOX (filter_save_type_vb), filter_save_type_hb, TRUE, TRUE, 0);

	gtk_widget_show(filter_save_type_hb);

	/* filter_save row */
	entry_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
	gtk_box_pack_start(GTK_BOX(filter_save_type_vb), entry_hb, FALSE,
	    FALSE, 0);
	gtk_widget_show(entry_hb);

	filter_text_box = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(entry_hb), filter_text_box, TRUE, TRUE, 0);
	g_signal_connect(filter_text_box, "changed", G_CALLBACK(filter_te_syntax_check_cb), NULL);
	g_signal_connect(filter_text_box, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
	g_signal_connect(filter_save_frame_w, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);

	gtk_entry_set_text(GTK_ENTRY(filter_text_box), expr);
	gtk_widget_show(filter_text_box);

	label_text_box = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(entry_hb), label_text_box, TRUE, TRUE, 0);
	gtk_entry_set_text(GTK_ENTRY(label_text_box), "Filter");
	gtk_widget_show(label_text_box);

	/* Button row */
	bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL,
	    GTK_STOCK_HELP, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	ok_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
	g_signal_connect(ok_bt, "clicked", G_CALLBACK(filter_save_ok_cb),
	filter_save_frame_w);

	cancel_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	g_signal_connect(cancel_bt, "clicked", G_CALLBACK(filter_save_close_cb),
	filter_save_frame_w);

	help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
	g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb),
	(gpointer)HELP_FILTER_SAVE_DIALOG);

	g_object_set_data(G_OBJECT(filter_save_frame_w),
	    E_FILTER_SAVE_EXPR_KEY, filter_text_box);
	g_object_set_data(G_OBJECT(filter_save_frame_w),
	    E_FILTER_SAVE_LABEL_KEY, label_text_box);

	dlg_set_activate(label_text_box, ok_bt);

	/* Give the initial focus to the "offset" entry box. */
	gtk_widget_grab_focus(label_text_box);

	g_signal_connect(filter_save_frame_w, "delete_event",
	G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(filter_save_frame_w, "destroy",
	G_CALLBACK(filter_save_frame_destroy_cb), NULL);

	gtk_widget_show(filter_save_frame_w);
	window_present(filter_save_frame_w);
}

static void
filter_save_ok_cb(GtkWidget *ok_bt _U_, GtkWindow *parent_w)
{
	GtkWidget *expr_te, *label_te;
	const char *expr, *label;

	/* The filter requested */
	expr_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
	    E_FILTER_SAVE_EXPR_KEY);
	label_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
	    E_FILTER_SAVE_LABEL_KEY);
	expr = gtk_entry_get_text(GTK_ENTRY(expr_te));
	label = gtk_entry_get_text(GTK_ENTRY(label_te));

	if (filter_button_add(label, expr, NULL) == 0) {
		prefs_main_write();
		filter_save_close_cb(NULL, parent_w);
	}
}

static void
filter_save_close_cb(GtkWidget *close_bt _U_, gpointer parent_w)
{
	gtk_grab_remove(GTK_WIDGET(parent_w));
	window_destroy(GTK_WIDGET(parent_w));
}

static void
filter_save_frame_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
	/* Note that we no longer have a "Filter Save" dialog box. */
	filter_save_frame_w = NULL;
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
