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
#include <string.h>

#include "globals.h"
#include "epan/filesystem.h"

#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"

#include "dlg_utils.h"
#include "gui_utils.h"
#include "main.h"
#include "compat_macros.h"

#include "sctp_stat.h"


static GtkWidget *sctp_chunk_stat_dlg=NULL;
static GtkWidget *clist = NULL;
static GList *last_list = NULL;
static sctp_assoc_info_t* selected_stream = NULL;  /* current selection */

#define NUM_COLS   14
#define FRAME_LIMIT 8

enum chunk_types {
	DATA          = 0,
	INIT          = 1,
	INIT_ACK      = 2,
	SACK          = 3,
	HEARTBEAT     = 4,
	HEARTBEAT_ACK = 5,
	ABORT         = 6,
	SHUTDOWN      = 7,
	SHUTDOWN_ACK  = 8,
	SCTP_ERROR    = 9,
	COOKIE_ECHO   = 10,
	COOKIE_ACK    = 11
};

static const char *chunk_name(int type)
{
#define CASE(x) case x: s=#x; break
	const char *s = "unknown";
	switch (type)
	{
		CASE(DATA);
		CASE(INIT);
		CASE(INIT_ACK);
		CASE(SACK);
		CASE(HEARTBEAT);
		CASE(HEARTBEAT_ACK);
		CASE(ABORT);
		CASE(SHUTDOWN);
		CASE(SHUTDOWN_ACK);
		CASE(SCTP_ERROR);
		CASE(COOKIE_ECHO);
		CASE(COOKIE_ACK);
	}
	return s;
}

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;


static void
chunk_dlg_destroy(GtkObject *object _U_, gpointer user_data)
{
	struct sctp_udata *u_data=(struct sctp_udata*)user_data;
	decrease_childcount(u_data->parent);
	remove_child(u_data, u_data->parent);
	g_free(u_data->io);
	g_free(u_data);
}

static void
on_destroy(GtkObject *object _U_, gpointer user_data)
{
	struct sctp_udata *u_data=(struct sctp_udata*)user_data;
	decrease_childcount(u_data->parent);
	remove_child(u_data, u_data->parent);
	g_free(u_data->io);
	g_free(u_data);
}


static void add_to_clist(sctp_addr_chunk* sac)
{
	gint added_row, i;
	gchar *data[NUM_COLS];
	gchar field[NUM_COLS][MAX_ADDRESS_LEN];

	for (i=0; i<NUM_COLS; i++)
		data[i]=&field[i][0];
		
	if (sac->addr->type==AT_IPv4)
	{
		g_snprintf(field[0], MAX_ADDRESS_LEN, "%s", ip_to_str((const guint8 *)(sac->addr->data)));
	}
	else if (sac->addr->type==AT_IPv6)
	{
		g_snprintf(field[0], MAX_ADDRESS_LEN, "%s", ip6_to_str((const struct e_in6_addr *)(sac->addr->data)));
	}

	for (i=1; i<NUM_COLS-1; i++)
		g_snprintf(field[i], MAX_ADDRESS_LEN, "%u", sac->addr_count[i-1]);
	
	g_snprintf(field[NUM_COLS-1], MAX_ADDRESS_LEN, "%u", sac->addr_count[12]);
	added_row = gtk_clist_append(GTK_CLIST(clist), data);
	gtk_clist_set_row_data(GTK_CLIST(clist), added_row, sac);
}

void sctp_chunk_stat_dlg_update(struct sctp_udata* udata, unsigned int direction)
{
	GList *list=NULL;
	sctp_addr_chunk* sac;

	if (udata->io->window != NULL)
	{
		gtk_clist_clear(GTK_CLIST(clist));
		if (udata->assoc->addr_chunk_count!=NULL)
		{
			list = g_list_first(udata->assoc->addr_chunk_count);
	
			while (list)
			{
				sac = (sctp_addr_chunk*)(list->data);
				if (sac->direction==direction)
				{
					add_to_clist(sac);
					list = g_list_next(list);
				}
				else
					list = g_list_next(list);
			}
		}
	}
	last_list = list;
}



static void
sctp_chunk_stat_on_close (GtkButton *button _U_, gpointer         user_data)
{
	struct sctp_udata *udata;

	udata = (struct sctp_udata *)user_data;
	gtk_grab_remove(udata->io->window);
	gtk_widget_destroy(udata->io->window);
}

static void
on_close_dlg (GtkButton *button _U_, gpointer user_data)
{
	struct sctp_udata *udata;

	udata = (struct sctp_udata *)user_data;
	gtk_grab_remove(udata->io->window);
	gtk_widget_destroy(udata->io->window);
}


static void path_window_set_title(struct sctp_udata *u_data, unsigned int direction)
{
	char *title;
	if(!u_data->io->window){
		return;
	}
	title = g_strdup_printf("SCTP Path Chunk Statistics for Endpoint %u: %s Port1 %u  Port2 %u",direction,
	                        cf_get_display_name(&cfile), u_data->assoc->port1, u_data->assoc->port2);
	gtk_window_set_title(GTK_WINDOW(u_data->io->window), title);
	g_free(title);
}

static void
gtk_sctpstat_dlg(struct sctp_udata *u_data, unsigned int direction)
{
	GtkWidget *vbox1;
	GtkWidget *scrolledwindow1;
	GtkWidget *hbuttonbox2;
	GtkWidget *bt_close;

	const gchar *titles[NUM_COLS] =  {"IP Address", "DATA", "INIT", "INIT_ACK", "SACK", "HEARTBEAT", "HEARTBEAT_ACK", "ABORT", "SHUTDOWN", "SHUTDOWN_ACK", "ERROR", "COOKIE_ECHO", "COOKIE_ACK", "Others"};
	column_arrows *col_arrows;
	GdkBitmap *ascend_bm, *descend_bm;
	GdkPixmap *ascend_pm, *descend_pm;
	GtkStyle *win_style;
	GtkWidget *column_lb;
	int i;

	sctp_graph_t* io=g_malloc(sizeof(sctp_graph_t));
	io->window=NULL;
	u_data->io=io;
	u_data->io->window= gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_position (GTK_WINDOW (u_data->io->window), GTK_WIN_POS_CENTER);
	path_window_set_title(u_data, direction);
	SIGNAL_CONNECT(u_data->io->window, "destroy", chunk_dlg_destroy,u_data);

	/* Container for each row of widgets */
	vbox1 = gtk_vbox_new(FALSE, 2);
	gtk_container_border_width(GTK_CONTAINER(vbox1), 8);
	gtk_container_add(GTK_CONTAINER(u_data->io->window), vbox1);
	gtk_widget_show(vbox1);

	scrolledwindow1 = scrolled_window_new (NULL, NULL);
	gtk_widget_show (scrolledwindow1);
	gtk_box_pack_start (GTK_BOX (vbox1), scrolledwindow1, TRUE, TRUE, 0);

	clist = gtk_clist_new (NUM_COLS);
	gtk_widget_show (clist);
	gtk_container_add (GTK_CONTAINER (scrolledwindow1), clist);
	WIDGET_SET_SIZE(clist, 850, 200);

	gtk_clist_set_column_width (GTK_CLIST (clist), 0, 135);
	gtk_clist_set_column_width (GTK_CLIST (clist), 1, 35);
	gtk_clist_set_column_width (GTK_CLIST (clist), 2, 25);
	gtk_clist_set_column_width (GTK_CLIST (clist), 3, 50);
	gtk_clist_set_column_width (GTK_CLIST (clist), 4, 35);
	gtk_clist_set_column_width (GTK_CLIST (clist), 5, 60);
	gtk_clist_set_column_width (GTK_CLIST (clist), 6, 90);
	gtk_clist_set_column_width (GTK_CLIST (clist), 7, 40);
	gtk_clist_set_column_width (GTK_CLIST (clist), 8, 65);
	gtk_clist_set_column_width (GTK_CLIST (clist), 9, 90);
	gtk_clist_set_column_width (GTK_CLIST (clist), 10, 40);
	gtk_clist_set_column_width (GTK_CLIST (clist), 11, 80);
	gtk_clist_set_column_width (GTK_CLIST (clist), 12, 70);
	gtk_clist_set_column_width (GTK_CLIST (clist), 13, 35);

	gtk_clist_set_column_justification(GTK_CLIST(clist), 0, GTK_JUSTIFY_LEFT);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 1, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 2, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 3, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 4, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 5, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 6, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 7, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 8, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 9, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 10, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 11, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 12, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 13, GTK_JUSTIFY_CENTER);
	
	gtk_clist_column_titles_show (GTK_CLIST (clist));

	gtk_widget_show(u_data->io->window);

	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_COLS);
	win_style = gtk_widget_get_style(scrolledwindow1);

	ascend_pm = gdk_pixmap_create_from_xpm_d(scrolledwindow1->window,
	                                         &ascend_bm,
	                                         &win_style->bg[GTK_STATE_NORMAL],
	                                         (gchar **)clist_ascend_xpm);
	descend_pm = gdk_pixmap_create_from_xpm_d(scrolledwindow1->window,
	                                          &descend_bm,
	                                          &win_style->bg[GTK_STATE_NORMAL],
	                                          (gchar **)clist_descend_xpm);
	for (i=0; i<NUM_COLS; i++)
	{
		col_arrows[i].table = gtk_table_new(2, 2, FALSE);
		gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
		column_lb = gtk_label_new(titles[i]);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		gtk_widget_show(column_lb);
		col_arrows[i].ascend_pm = gtk_pixmap_new(ascend_pm, ascend_bm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		col_arrows[i].descend_pm = gtk_pixmap_new(descend_pm, descend_bm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm, 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
		/* make src-ip be the default sort order */
		if (i == 0)
		{
			gtk_widget_show(col_arrows[i].ascend_pm);
		}

		gtk_clist_set_column_widget(GTK_CLIST(clist), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}

	hbuttonbox2 = gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(vbox1), hbuttonbox2, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbuttonbox2), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (hbuttonbox2), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX (hbuttonbox2), 0);
	gtk_button_box_set_child_ipadding(GTK_BUTTON_BOX (hbuttonbox2), 4, 0);
	gtk_widget_show(hbuttonbox2);

	bt_close = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_close);
	gtk_widget_show (bt_close);

	SIGNAL_CONNECT(bt_close, "clicked", sctp_chunk_stat_on_close, u_data);

	cf_retap_packets(&cfile, FALSE);

}


static void chunk_window_set_title(struct sctp_udata *u_data)
{
	char *title;
	if(!u_data->io->window){
		return;
	}
	title = g_strdup_printf("SCTP Association Chunk Statistics: %s Port1 %u  Port2 %u",
	                        cf_get_display_name(&cfile), u_data->assoc->port1, u_data->assoc->port2);
	gtk_window_set_title(GTK_WINDOW(u_data->io->window), title);
	g_free(title);
}

static void sctp_chunk_dlg(struct sctp_udata *u_data)
{
	GtkWidget *main_vb, *table;
	GtkWidget *label, *h_button_box;
	GtkWidget *close_bt;
	gchar label_txt[50];
	int i, row;
	
	sctp_graph_t* io=g_malloc(sizeof(sctp_graph_t));
	io->window=NULL;
	u_data->io=io;
	u_data->io->window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_position (GTK_WINDOW (u_data->io->window), GTK_WIN_POS_CENTER);
	WIDGET_SET_SIZE(u_data->io->window, 500, 400);
	SIGNAL_CONNECT(u_data->io->window, "destroy", on_destroy,u_data);

	/* Container for each row of widgets */
	main_vb = gtk_vbox_new(FALSE, 12);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 12);
	gtk_container_add(GTK_CONTAINER(u_data->io->window), main_vb);
	 
	 /* table */
	table = gtk_table_new(1, 4, FALSE);
	gtk_table_set_col_spacings(GTK_TABLE(table), 6);
	gtk_table_set_row_spacings(GTK_TABLE(table), 3);
	gtk_container_add(GTK_CONTAINER(main_vb), table);
	row = 0;
			
	label = gtk_label_new("ChunkType");
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
	gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, row, row+1);	
	label = gtk_label_new("Association");
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
	gtk_table_attach_defaults(GTK_TABLE(table), label, 1, 2, row, row+1);
	label = gtk_label_new("Endpoint 1");
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
	gtk_table_attach_defaults(GTK_TABLE(table), label, 2, 3, row, row+1);
	label = gtk_label_new("Endpoint 2");
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
	gtk_table_attach_defaults(GTK_TABLE(table), label, 3, 4, row, row+1);
	row ++;
	label = gtk_label_new("");
	gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, row, row+1);	
	label = gtk_label_new("");
	gtk_table_attach_defaults(GTK_TABLE(table), label, 1, 2, row, row+1);
	label = gtk_label_new("");
	gtk_table_attach_defaults(GTK_TABLE(table), label, 2, 3, row, row+1);
	label = gtk_label_new("");
	gtk_table_attach_defaults(GTK_TABLE(table), label, 3, 4, row, row+1);
	row ++;

	for (i=0; i<NUM_CHUNKS-1; i++)
	{
		label = gtk_label_new(chunk_name(i));
		gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
		gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, row, row+1);	
		g_snprintf(label_txt, 10, "%u", selected_stream->chunk_count[i]);
		label = gtk_label_new(label_txt);
		gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
		gtk_table_attach_defaults(GTK_TABLE(table), label, 1, 2, row, row+1);
		g_snprintf(label_txt, 10, "%u", selected_stream->ep1_chunk_count[i]);
		label = gtk_label_new(label_txt);
		gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
		gtk_table_attach_defaults(GTK_TABLE(table), label, 2, 3, row, row+1);
		g_snprintf(label_txt, 10, "%u", selected_stream->ep2_chunk_count[i]);
		label = gtk_label_new(label_txt);
		gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
		gtk_table_attach_defaults(GTK_TABLE(table), label, 3, 4, row, row+1);
		row ++;
	}
	
	label = gtk_label_new("Others");
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
	gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, row, row+1);
	g_snprintf(label_txt, 10, "%u", selected_stream->chunk_count[12]);
	label = gtk_label_new(label_txt);
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
	gtk_table_attach_defaults(GTK_TABLE(table), label, 1, 2, row, row+1);
	g_snprintf(label_txt, 10, "%u", selected_stream->ep1_chunk_count[12]);
	label = gtk_label_new(label_txt);
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
	gtk_table_attach_defaults(GTK_TABLE(table), label, 2, 3, row, row+1);
	g_snprintf(label_txt, 10, "%u", selected_stream->ep2_chunk_count[12]);
	label = gtk_label_new(label_txt);
	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
	gtk_table_attach_defaults(GTK_TABLE(table), label, 3, 4, row, row+1);
	
	h_button_box=gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(main_vb), h_button_box, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(h_button_box), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (h_button_box), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX (h_button_box), 0);
	gtk_button_box_set_child_ipadding(GTK_BUTTON_BOX (h_button_box), 4, 0);
	gtk_widget_show(h_button_box);
	
	close_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_box_pack_start(GTK_BOX(h_button_box), close_bt, FALSE, FALSE, 0);
	gtk_widget_show(close_bt);
	SIGNAL_CONNECT(close_bt, "clicked", on_close_dlg, u_data);
	
	gtk_widget_show_all(u_data->io->window);
	chunk_window_set_title(u_data);
}

void sctp_chunk_dlg_show(struct sctp_analyse* userdata)
{
	gint i;
	struct sctp_udata *u_data;

	u_data=g_malloc(sizeof(struct sctp_udata));
	u_data->assoc=g_malloc(sizeof(sctp_assoc_info_t));
	u_data->assoc=userdata->assoc;
	u_data->io=NULL;
	u_data->parent = userdata;

	if (selected_stream==NULL)
		selected_stream=g_malloc(sizeof(sctp_assoc_info_t));

	selected_stream=u_data->assoc;
	for (i=0; i<NUM_CHUNKS; i++)
	{
		selected_stream->chunk_count[i]=u_data->assoc->chunk_count[i];
	}
	set_child(u_data, u_data->parent);
	increase_childcount(u_data->parent);
	sctp_chunk_dlg(u_data);
}

void sctp_chunk_stat_dlg_show(unsigned int direction, struct sctp_analyse* userdata)
{
	struct sctp_udata *u_data;

	u_data=g_malloc(sizeof(struct sctp_udata));
	u_data->assoc=g_malloc(sizeof(sctp_assoc_info_t));
	u_data->assoc=userdata->assoc;
	u_data->io=NULL;
	u_data->parent = userdata;
	
	if (selected_stream==NULL)
		selected_stream=g_malloc(sizeof(sctp_assoc_info_t));
	selected_stream=u_data->assoc;
	selected_stream->addr_chunk_count=u_data->assoc->addr_chunk_count;

	set_child(u_data, u_data->parent);
	increase_childcount(u_data->parent);
	gtk_sctpstat_dlg(u_data, direction);
	sctp_chunk_stat_dlg_update(u_data,direction);
}

GtkWidget* get_chunk_stat_dlg(void)
{
	return sctp_chunk_stat_dlg;
}
