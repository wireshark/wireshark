/* 
 * Copyright 2004, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
 *
 * $Id$
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
#  include <config.h>
#endif

#include <gtk/gtk.h>

#include "globals.h"
#include "epan/filesystem.h"
#include "simple_dialog.h"
#include "stat_menu.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "main.h"
#include "compat_macros.h"

#include "sctp_stat.h"
/*#include "sctp_assoc_analyse.h"*/


static GtkWidget *sctp_error_dlg=NULL;
static GtkWidget *clist = NULL;
static GList *last_list = NULL;
static sctp_error_info_t* selected_packet = NULL;/* current selection */
/*static sctp_assoc_info_t* selected_assoc = NULL; */

#define NUM_COLS 3

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;


static void
dlg_destroy(void)
{
	sctp_error_dlg=NULL;
}

static void add_to_clist(sctp_error_info_t* errinfo)
{
	gint added_row, i;
	gchar *data[NUM_COLS];
	gchar field[NUM_COLS][30];

	for (i=0; i<NUM_COLS; i++)
		data[i]=&field[i][0];

		/*printf("errinfo=%s\n",errinfo->chunk_info);*/

	g_snprintf(field[0], 20, "%u", errinfo->frame_number);
	g_snprintf(field[1], 20, "%s", errinfo->chunk_info);
	g_snprintf(field[2], 20, "%s", errinfo->info_text);

	added_row = gtk_clist_append(GTK_CLIST(clist), data);

	/* set data pointer of last row to point to user data for that row */
	gtk_clist_set_row_data(GTK_CLIST(clist), added_row, errinfo);
}

static void
sctp_error_on_unselect(GtkButton *button _U_, gpointer user_data _U_)
{
	gtk_clist_unselect_all(GTK_CLIST(clist));
}

static void sctp_error_dlg_update(GList *list)
{
	GList *ilist=NULL;

	if (sctp_error_dlg != NULL) 
	{
		gtk_clist_clear(GTK_CLIST(clist));
		ilist=list;

		while (ilist)
		{
			add_to_clist((sctp_error_info_t*)(ilist->data));
			ilist = g_list_next(ilist);
		}

		sctp_error_on_unselect(NULL, NULL);
	}
	last_list = ilist;
}

static void
sctp_error_on_select_row(GtkCList *clist, gint row,gint column _U_, GdkEventButton *event _U_, gpointer user_data _U_)
{
	selected_packet = gtk_clist_get_row_data(GTK_CLIST(clist), row);
}



static void
sctp_error_on_frame (GtkButton *button _U_, gpointer user_data _U_)
{

	if (selected_packet==NULL)
		return;

	if (selected_packet)
		cf_goto_frame(&cfile, selected_packet->frame_number);
}


static void
sctp_error_on_close (GtkButton *button _U_, gpointer user_data _U_)
{
	gtk_grab_remove(sctp_error_dlg);
	gtk_widget_destroy(sctp_error_dlg);
}

static void
gtk_sctperror_dlg(void)
{
	GtkWidget *sctp_error_dlg_w;
	GtkWidget *vbox1;
	GtkWidget *scrolledwindow1;
	GtkWidget *hbuttonbox2;
	GtkWidget *bt_unselect;
	GtkWidget *bt_frame;
	GtkWidget *bt_close;

	const gchar *titles[NUM_COLS] =  {"Framenumber","Chunk Types", "Info"};
	column_arrows *col_arrows;
	GtkStyle *win_style;
	GtkWidget *column_lb;
	int i;

	sctp_error_dlg_w = window_new (GTK_WINDOW_TOPLEVEL, "Ethereal: SCTP Associations");
	gtk_window_set_position (GTK_WINDOW (sctp_error_dlg_w), GTK_WIN_POS_CENTER);
	SIGNAL_CONNECT(sctp_error_dlg_w, "destroy", dlg_destroy,NULL);

	/* Container for each row of widgets */
	vbox1 = gtk_vbox_new(FALSE, 2);
	gtk_container_border_width(GTK_CONTAINER(vbox1), 8);
	gtk_container_add(GTK_CONTAINER(sctp_error_dlg_w), vbox1);
	gtk_widget_show(vbox1);

	scrolledwindow1 = scrolled_window_new (NULL, NULL);
	gtk_widget_show (scrolledwindow1);
	gtk_box_pack_start (GTK_BOX (vbox1), scrolledwindow1, TRUE, TRUE, 0);

	clist = gtk_clist_new (NUM_COLS);
	gtk_widget_show (clist);
	gtk_container_add (GTK_CONTAINER (scrolledwindow1), clist);
	WIDGET_SET_SIZE(clist, 500, 200);

	gtk_clist_set_column_width (GTK_CLIST (clist), 0, 100);
	gtk_clist_set_column_width (GTK_CLIST (clist), 1, 200);
	gtk_clist_set_column_width (GTK_CLIST (clist), 2, 200);

	gtk_clist_set_column_justification(GTK_CLIST(clist), 0, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 1, GTK_JUSTIFY_LEFT);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 2, GTK_JUSTIFY_LEFT);

	gtk_clist_column_titles_show (GTK_CLIST (clist));

	gtk_clist_set_sort_column(GTK_CLIST(clist), 0);
	gtk_clist_set_sort_type(GTK_CLIST(clist), GTK_SORT_ASCENDING);

	gtk_widget_show(sctp_error_dlg_w);

	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_COLS);
	win_style = gtk_widget_get_style(scrolledwindow1);

	for (i=0; i<NUM_COLS; i++) {
		col_arrows[i].table = gtk_table_new(2, 2, FALSE);
		gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
		column_lb = gtk_label_new(titles[i]);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		gtk_widget_show(column_lb);

		gtk_clist_set_column_widget(GTK_CLIST(clist), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}


	hbuttonbox2 = gtk_hbutton_box_new ();
	gtk_widget_show (hbuttonbox2);
	gtk_box_pack_start (GTK_BOX (vbox1), hbuttonbox2, FALSE, FALSE, 0);
	gtk_button_box_set_spacing (GTK_BUTTON_BOX (hbuttonbox2), 5);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox2), GTK_BUTTONBOX_SPREAD);


	bt_unselect = gtk_button_new_with_label ("Unselect");
	gtk_widget_show (bt_unselect);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_unselect);

	bt_frame = gtk_button_new_with_label ("Go to Frame");
	gtk_widget_show (bt_frame);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_frame);

	bt_close = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_widget_show (bt_close);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_close);

	SIGNAL_CONNECT(sctp_error_dlg_w, "destroy", dlg_destroy, NULL);
	SIGNAL_CONNECT(clist, "select_row", sctp_error_on_select_row, NULL);
	SIGNAL_CONNECT(bt_unselect, "clicked", sctp_error_on_unselect, NULL);
	SIGNAL_CONNECT(bt_frame, "clicked", sctp_error_on_frame, NULL);
	SIGNAL_CONNECT(bt_close, "clicked", sctp_error_on_close, NULL);

	sctp_error_dlg = sctp_error_dlg_w;
}


void sctp_error_dlg_show(sctp_assoc_info_t* assoc)
{
	GList *list;

	list =assoc->error_info_list;
	if (list != NULL)
	{
		if (sctp_error_dlg != NULL) {
			/* There's already a dialog box; reactivate it. */
			reactivate_window(sctp_error_dlg);
			/* Another list since last call? */
			if (list != last_list) {
				sctp_error_dlg_update(list);
			}
		}
		else {
			/* Create and show the dialog box */
			gtk_sctperror_dlg();
			sctp_error_dlg_update(list);
		}
	}
	else
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "No errors found!");
}

