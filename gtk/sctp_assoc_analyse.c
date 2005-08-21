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
#include <string.h>  /* for memmove */
#include "globals.h"
#include "simple_dialog.h"
#include <epan/epan_dissect.h>
#include "epan/filesystem.h"
#include "register.h"
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "main.h"
#include "compat_macros.h"

#include "sctp_stat.h"

static sctp_assoc_info_t static_assoc;

void
decrease_childcount(struct sctp_analyse *parent)
{
	if (parent->num_children > 0)
		parent->num_children--;
}

void
increase_childcount(struct sctp_analyse *parent)
{
	parent->num_children++;
}

void
set_child(struct sctp_udata *child, struct sctp_analyse *parent)
{
	parent->children = g_list_append(parent->children, child);
}

void
remove_child(struct sctp_udata *child, struct sctp_analyse *parent)
{
	parent->children = g_list_remove(parent->children, child);
}

static void
on_destroy(GtkObject *object _U_, gpointer user_data)
{
	struct sctp_analyse *u_data;
	guint16 i, j;
	GList *list;
	struct sctp_udata *child_data;

	u_data = (struct sctp_analyse*)user_data;

	if (u_data->window)
	{
		gtk_grab_remove(GTK_WIDGET(u_data->window));
		gtk_widget_destroy(GTK_WIDGET(u_data->window));
	}
	if (u_data->num_children>0)
	{
		j = u_data->num_children;
		for (i=0; i<j; i++)
		{
			list = g_list_last(u_data->children);
			child_data = (struct sctp_udata *)list->data;
			gtk_grab_remove(GTK_WIDGET(child_data->io->window));
			gtk_widget_destroy(GTK_WIDGET(child_data->io->window));
			list = g_list_previous(list);
		}
		g_list_free(u_data->children);
		u_data->children = NULL;
	}
	
	g_free(u_data->analyse_nb->page2);
	g_free(u_data->analyse_nb->page3);
	g_free(u_data->analyse_nb);
	if (sctp_stat_get_info()->children != NULL)
	{
		remove_analyse_child(u_data);
		decrease_analyse_childcount();
	}
	g_free(u_data);
}

static void
on_notebook_switch_page(void)
{
}

static void on_chunk_stat_bt(GtkWidget *widget _U_, struct sctp_analyse* u_data)
{
	sctp_assoc_info_t* assinfo = NULL;
	int i;

	assinfo = g_malloc(sizeof(sctp_assoc_info_t));
	assinfo = &static_assoc;
	assinfo->addr_chunk_count = (static_assoc.addr_chunk_count);
	for (i=0; i<NUM_CHUNKS; i++)
	{
		assinfo->chunk_count[i]     = static_assoc.chunk_count[i];
		assinfo->ep1_chunk_count[i] = static_assoc.ep1_chunk_count[i];
		assinfo->ep2_chunk_count[i] = static_assoc.ep2_chunk_count[i];
	}
	u_data->assoc = assinfo;
	sctp_chunk_dlg_show(u_data);
}

static void on_close_dlg(GtkWidget *widget _U_, struct sctp_analyse* u_data)
{

	if (u_data->window)
	{
		gtk_grab_remove(GTK_WIDGET(u_data->window));
		gtk_widget_destroy(GTK_WIDGET(u_data->window));
	}
}

static void on_chunk1_dlg(GtkWidget *widget _U_, struct sctp_analyse* u_data)
{
sctp_assoc_info_t* assinfo = NULL;
	
	assinfo = g_malloc(sizeof(sctp_assoc_info_t));
	assinfo = &static_assoc;
	assinfo->addr_chunk_count = (static_assoc.addr_chunk_count);
	u_data->assoc = assinfo;
	sctp_chunk_stat_dlg_show(1, u_data);
}

static void on_chunk2_dlg(GtkWidget *widget _U_, struct sctp_analyse* u_data)
{
sctp_assoc_info_t* assinfo=NULL;

	assinfo = g_malloc(sizeof(sctp_assoc_info_t));
	assinfo = &static_assoc;
	assinfo->addr_chunk_count = (static_assoc.addr_chunk_count);	
	u_data->assoc = assinfo;
	sctp_chunk_stat_dlg_show(2, u_data);
}

static void on_graph1_dlg(GtkWidget *widget _U_, struct sctp_analyse* u_data)
{
	create_graph(1, u_data);
}

static void on_graph2_dlg(GtkWidget *widget _U_, struct sctp_analyse* u_data)
{
	create_graph(2, u_data);
}

static void on_graph_byte1_dlg(GtkWidget *widget _U_, struct sctp_analyse* u_data)
{
	create_byte_graph(1, u_data);
}

static void on_graph_byte2_dlg(GtkWidget *widget _U_, struct sctp_analyse* u_data)
{
	create_byte_graph(2, u_data);
}

void
update_analyse_dlg(struct sctp_analyse* u_data)
{
	gchar label_txt[50];
	gchar *data[1];
	gchar field[1][MAX_ADDRESS_LEN];
	gint added_row;
	GList *list;
	address *store = NULL;

	if (u_data->assoc == NULL)
		return;

	if (u_data->window != NULL)
	{
		gtk_clist_clear(GTK_CLIST(u_data->analyse_nb->page2->clist));
		gtk_clist_clear(GTK_CLIST(u_data->analyse_nb->page3->clist));
	}


	g_snprintf(label_txt, 50,"Checksum Type: %s",u_data->assoc->checksum_type);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->checktype), label_txt);
	g_snprintf(label_txt, 50,"Checksum Errors: %u",u_data->assoc->n_checksum_errors);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->checksum), label_txt);
	g_snprintf(label_txt, 50,"Bundling Errors: %u",u_data->assoc->n_bundling_errors);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->bundling), label_txt);
	g_snprintf(label_txt, 50,"Padding Errors: %u",u_data->assoc->n_padding_errors);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->padding), label_txt);
	g_snprintf(label_txt, 50,"Length Errors: %u",u_data->assoc->n_length_errors);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->length), label_txt);
	g_snprintf(label_txt, 50,"Value Errors: %u",u_data->assoc->n_value_errors);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->value), label_txt);
	g_snprintf(label_txt, 50,"No of Data Chunks from EP1 to EP2: %u",u_data->assoc->n_data_chunks_ep1);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->chunks_ep1), label_txt);
	g_snprintf(label_txt, 50,"No of Data Bytes from EP1 to EP2: %u",u_data->assoc->n_data_bytes_ep1);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->bytes_ep1), label_txt);
	g_snprintf(label_txt, 50,"No of Data Chunks from EP2 to EP1: %u",u_data->assoc->n_data_chunks_ep2);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->chunks_ep2), label_txt);
	g_snprintf(label_txt, 50,"No of Data Bytes from EP2 to EP1: %u",u_data->assoc->n_data_bytes_ep2);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->bytes_ep2), label_txt);

	if (u_data->assoc->init == TRUE)
		gtk_frame_set_label(GTK_FRAME (u_data->analyse_nb->page2->addr_frame), "Complete list of IP-Addresses as provided in the INIT-Chunk");
	else if (u_data->assoc->initack == TRUE && u_data->assoc->initack_dir == 1)
		gtk_frame_set_label(GTK_FRAME (u_data->analyse_nb->page2->addr_frame), "Complete list of IP-Addresses as provided in the INITACK-Chunk");
	else
		gtk_frame_set_label(GTK_FRAME (u_data->analyse_nb->page2->addr_frame), "List of used IP-Addresses");



	if (u_data->assoc->addr1 != NULL)
	{
		list = g_list_first(u_data->assoc->addr1);
		while (list)
		{
			data[0] = &field[0][0];
			store = (address *) (list->data);
			if (store->type == AT_IPv4)
			{
				g_snprintf(field[0], 30, "%s", ip_to_str((const guint8 *)(store->data)));
			}
			else if (store->type == AT_IPv6)
			{		
				g_snprintf(field[0], 40, "%s", ip6_to_str((const struct e_in6_addr *)(store->data)));
			}
			added_row = gtk_clist_append(GTK_CLIST(u_data->analyse_nb->page2->clist), data);
			gtk_clist_set_row_data(GTK_CLIST(u_data->analyse_nb->page2->clist), added_row, u_data->assoc);
			list = g_list_next(list);
		}
	}
	else
	{
		return;
	}
	g_snprintf(label_txt, 50,"Port: %u",u_data->assoc->port1);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page2->port), label_txt);
	g_snprintf(label_txt, 50,"Sent Verification Tag: 0x%x",u_data->assoc->verification_tag1);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page2->veritag), label_txt);

	if (u_data->assoc->init == TRUE || (u_data->assoc->initack == TRUE && u_data->assoc->initack_dir == 1))
	{
		g_snprintf(label_txt, 50,"Requested Number of Inbound Streams: %u",u_data->assoc->instream1);
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page2->max_in), label_txt);
		g_snprintf(label_txt, 50,"Minimum Number of Inbound Streams: %u",((u_data->assoc->instream1>u_data->assoc->outstream2)?u_data->assoc->outstream2:u_data->assoc->instream1));
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page2->min_in), label_txt);

		g_snprintf(label_txt, 50,"Provided Number of Outbound Streams: %u",u_data->assoc->outstream1);
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page2->max_out), label_txt);
		g_snprintf(label_txt, 50,"Minimum Number of Outbound Streams: %u",((u_data->assoc->outstream1>u_data->assoc->instream2)?u_data->assoc->instream2:u_data->assoc->outstream1));
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page2->max_out), label_txt);
	}
	else
	{
		g_snprintf(label_txt, 50,"Used Number of Inbound Streams: %u",u_data->assoc->instream1);
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page2->max_in), label_txt);
		g_snprintf(label_txt, 50,"Used Number of Outbound Streams: %u",u_data->assoc->outstream1);
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page2->max_out), label_txt);
	}

	if (u_data->assoc->initack == TRUE && u_data->assoc->initack_dir == 2)
		gtk_frame_set_label(GTK_FRAME (u_data->analyse_nb->page3->addr_frame), "Complete list of IP-Addresses as provided in the INITACK-Chunk");
	else
		gtk_frame_set_label(GTK_FRAME (u_data->analyse_nb->page3->addr_frame), "List of used IP-Addresses");


	if (u_data->assoc->addr2 != NULL)
	{

		list = g_list_first(u_data->assoc->addr2);

		while (list)
		{
			data[0] = &field[0][0];
			store = (address *) (list->data);
			if (store->type == AT_IPv4)
			{
				g_snprintf(field[0], 30, "%s", ip_to_str((const guint8 *)(store->data)));
			}
			else if (store->type == AT_IPv6)
			{
				g_snprintf(field[0], 40, "%s", ip6_to_str((const struct e_in6_addr *)(store->data)));
			}
			added_row = gtk_clist_append(GTK_CLIST(u_data->analyse_nb->page3->clist), data);
			gtk_clist_set_row_data(GTK_CLIST(u_data->analyse_nb->page3->clist), added_row, u_data->assoc);
			list = g_list_next(list);
		}
	}
		else
	{
		return;
	}

	g_snprintf(label_txt, 50,"Port: %u",u_data->assoc->port2);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page3->port), label_txt);
	g_snprintf(label_txt, 50,"Sent Verification Tag: 0x%x",u_data->assoc->verification_tag2);
	gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page3->veritag), label_txt);

	if (u_data->assoc->initack == TRUE)
	{
		g_snprintf(label_txt, 50,"Requested Number of Inbound Streams: %u",u_data->assoc->instream2);
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page3->max_in), label_txt);
		g_snprintf(label_txt, 50,"Minimum Number of Inbound Streams: %u",((u_data->assoc->instream2>u_data->assoc->outstream1)?u_data->assoc->outstream1:u_data->assoc->instream2));
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page3->min_in), label_txt);

		g_snprintf(label_txt, 50,"Provided Number of Outbound Streams: %u",u_data->assoc->outstream2);
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page3->max_out), label_txt);
		g_snprintf(label_txt, 50,"Minimum Number of Outbound Streams: %u",((u_data->assoc->outstream2>u_data->assoc->instream1)?u_data->assoc->instream1:u_data->assoc->outstream2));
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page3->min_out), label_txt);
	}
	else
	{
		g_snprintf(label_txt, 50,"Used Number of Inbound Streams: %u",u_data->assoc->instream2);
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page3->max_in), label_txt);
		g_snprintf(label_txt, 50,"Used Number of Outbound Streams: %u",u_data->assoc->outstream2);
		gtk_label_set_text(GTK_LABEL(u_data->analyse_nb->page3->min_out), label_txt);
	}
}

static void analyse_window_set_title(struct sctp_analyse *u_data)
{
	char *title;
	
	if(!u_data->window){
		return;
	}
	title = g_strdup_printf("SCTP Analyse Association: %s Port1 %u  Port2 %u", cf_get_display_name(&cfile), u_data->assoc->port1, u_data->assoc->port2);
	gtk_window_set_title(GTK_WINDOW(u_data->window), title);
	g_free(title);
}

static void create_analyse_window(struct sctp_analyse* u_data)
{
	GtkWidget *window = NULL;
	GtkWidget *notebook;
	GtkWidget *main_vb, *page1, *page2, *page3, *hbox, *vbox_l, *vbox_r, *addr_hb, *stat_fr;
	GtkWidget *hbox_l1, *hbox_l2,*label, *h_button_box;
	GtkWidget *chunk_stat_bt, *close_bt, *graph_bt1, *graph_bt2, *chunk_bt1;

	u_data->analyse_nb = g_malloc(sizeof(struct notes));
	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_position (GTK_WINDOW (window), GTK_WIN_POS_CENTER);
	SIGNAL_CONNECT(window, "destroy", on_destroy,u_data);

	/* Container for each row of widgets */
	main_vb = gtk_vbox_new(FALSE, 2);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 2);
	gtk_container_add(GTK_CONTAINER(window), main_vb);
	gtk_widget_show(main_vb);

	/* Start a notebook for flipping between sets of changes */
	notebook = gtk_notebook_new();
	gtk_container_add(GTK_CONTAINER(main_vb), notebook);
	OBJECT_SET_DATA(window, "notebook", notebook);
	SIGNAL_CONNECT(notebook, "switch_page", on_notebook_switch_page,NULL);

	page1 = gtk_vbox_new(FALSE, 8);
	gtk_container_set_border_width(GTK_CONTAINER(page1), 8);

	u_data->analyse_nb->checktype = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->checktype, TRUE, TRUE, 0);

	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->checktype),0,0);

	u_data->analyse_nb->checksum = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->checksum, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->checksum),0,0);

	u_data->analyse_nb->bundling = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->bundling, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->bundling),0,0);

	u_data->analyse_nb->padding = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->padding, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->padding),0,0);

	u_data->analyse_nb->length = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->length, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->length),0,0);

	u_data->analyse_nb->value = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->value, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->value),0,0);


	u_data->analyse_nb->chunks_ep1 = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->chunks_ep1, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->chunks_ep1),0,0);
	u_data->analyse_nb->bytes_ep1 = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->bytes_ep1, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->bytes_ep1),0,0);
	u_data->analyse_nb->chunks_ep2 = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->chunks_ep2, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->chunks_ep2),0,0);
	u_data->analyse_nb->bytes_ep2 = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(page1), u_data->analyse_nb->bytes_ep2, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->bytes_ep2),0,0);

	hbox = gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(page1), hbox, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (hbox), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX (hbox), 0);
	gtk_button_box_set_child_ipadding(GTK_BUTTON_BOX (hbox), 4, 0);
	gtk_widget_show(hbox);

	chunk_stat_bt = gtk_button_new_with_label ("Chunk Statistics");
	gtk_box_pack_start(GTK_BOX(hbox), chunk_stat_bt, FALSE, FALSE, 0);
	gtk_widget_show(chunk_stat_bt);
	SIGNAL_CONNECT(chunk_stat_bt, "clicked", on_chunk_stat_bt, u_data);


	close_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_box_pack_start(GTK_BOX(hbox), close_bt, FALSE, FALSE, 0);
	gtk_widget_show(close_bt);
	SIGNAL_CONNECT(close_bt, "clicked", on_close_dlg, u_data);

	/* tab */
	label = gtk_label_new(" Statistics ");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page1, label);


	/*  page for endpoint 1 */
	page2 = gtk_vbox_new(FALSE, 8);
	gtk_container_set_border_width(GTK_CONTAINER(page2), 8);

	u_data->analyse_nb->page2 = g_malloc(sizeof(struct page));

	u_data->analyse_nb->page2->addr_frame = gtk_frame_new(NULL);
	gtk_container_add(GTK_CONTAINER(page2), u_data->analyse_nb->page2->addr_frame);

	addr_hb = gtk_hbox_new(FALSE, 3);
	gtk_container_border_width(GTK_CONTAINER(addr_hb), 5);
	gtk_container_add(GTK_CONTAINER(u_data->analyse_nb->page2->addr_frame), addr_hb);

	u_data->analyse_nb->page2->scrolled_window = scrolled_window_new(NULL, NULL);
	WIDGET_SET_SIZE(u_data->analyse_nb->page2->scrolled_window, 560, 100);

	u_data->analyse_nb->page2->clist = gtk_clist_new(1);
	gtk_widget_show(u_data->analyse_nb->page2->clist);

	gtk_clist_set_column_width(GTK_CLIST(u_data->analyse_nb->page2->clist), 0, 200);
	gtk_clist_set_column_justification(GTK_CLIST(u_data->analyse_nb->page2->clist), 0, GTK_JUSTIFY_LEFT);

	gtk_container_add(GTK_CONTAINER(u_data->analyse_nb->page2->scrolled_window), u_data->analyse_nb->page2->clist);

	gtk_box_pack_start(GTK_BOX(addr_hb), u_data->analyse_nb->page2->scrolled_window, TRUE, TRUE, 0);
	gtk_widget_show(u_data->analyse_nb->page2->scrolled_window);

	stat_fr = gtk_frame_new(NULL);
	gtk_container_add(GTK_CONTAINER(page2), stat_fr);

	hbox = gtk_hbox_new(FALSE,3);
	gtk_container_border_width(GTK_CONTAINER(hbox), 5);
	gtk_container_add(GTK_CONTAINER(stat_fr), hbox);

	vbox_l = gtk_vbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(hbox), vbox_l, TRUE, TRUE, 0);



	hbox_l1 = gtk_hbox_new(FALSE,3);
	gtk_box_pack_start(GTK_BOX(vbox_l), hbox_l1, TRUE, TRUE, 0);

	u_data->analyse_nb->page2->port = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(hbox_l1), u_data->analyse_nb->page2->port, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page2->port),0,0);

	hbox_l2 = gtk_hbox_new(FALSE,3);
	gtk_box_pack_start(GTK_BOX(vbox_l), hbox_l2, TRUE, TRUE, 0);


	u_data->analyse_nb->page2->veritag = gtk_label_new("");

	gtk_box_pack_start(GTK_BOX(hbox_l2), u_data->analyse_nb->page2->veritag, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page2->veritag),0,0);
	gtk_widget_show(vbox_l);

	vbox_r = gtk_vbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(hbox), vbox_r, TRUE, TRUE, 0);

	u_data->analyse_nb->page2->max_in = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(vbox_r), u_data->analyse_nb->page2->max_in, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page2->max_in),0,0);
	u_data->analyse_nb->page2->min_in = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(vbox_r), u_data->analyse_nb->page2->min_in, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page2->min_in),0,0);

	u_data->analyse_nb->page2->max_out = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(vbox_r), u_data->analyse_nb->page2->max_out, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page2->max_out),0,0);
	u_data->analyse_nb->page2->min_out = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(vbox_r), u_data->analyse_nb->page2->min_out, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page2->min_out),0,0);


	gtk_widget_show(vbox_r);

	h_button_box=gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(page2), h_button_box, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(h_button_box), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (h_button_box), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX (h_button_box), 0);
	gtk_button_box_set_child_ipadding(GTK_BUTTON_BOX (h_button_box), 4, 0);
	gtk_widget_show(h_button_box);
	
	chunk_bt1 = gtk_button_new_with_label("Chunk Statistics");
	gtk_box_pack_start(GTK_BOX(h_button_box), chunk_bt1, FALSE, FALSE, 0);
	gtk_widget_show(chunk_bt1);
	SIGNAL_CONNECT(chunk_bt1, "clicked", on_chunk1_dlg,u_data);

	graph_bt1 = gtk_button_new_with_label("Graph TSN");
	gtk_box_pack_start(GTK_BOX(h_button_box), graph_bt1, FALSE, FALSE, 0);
	gtk_widget_show(graph_bt1);
	SIGNAL_CONNECT(graph_bt1, "clicked", on_graph1_dlg,u_data);

	graph_bt2 = gtk_button_new_with_label("Graph Bytes");
	gtk_box_pack_start(GTK_BOX(h_button_box), graph_bt2, FALSE, FALSE, 0);
	gtk_widget_show(graph_bt2);
	SIGNAL_CONNECT(graph_bt2, "clicked", on_graph_byte1_dlg,u_data);

	close_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_box_pack_start(GTK_BOX(h_button_box), close_bt, FALSE, FALSE, 0);
	gtk_widget_show(close_bt);
	SIGNAL_CONNECT(close_bt, "clicked", on_close_dlg, u_data);

	label = gtk_label_new(" Endpoint 1 ");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page2, label);

	/* same page for endpoint 2*/

	page3 = gtk_vbox_new(FALSE, 8);
	gtk_container_set_border_width(GTK_CONTAINER(page3), 8);
	u_data->analyse_nb->page3 = g_malloc(sizeof(struct page));
	u_data->analyse_nb->page3->addr_frame = gtk_frame_new(NULL);

	gtk_container_add(GTK_CONTAINER(page3), u_data->analyse_nb->page3->addr_frame);

	addr_hb = gtk_hbox_new(FALSE, 3);
	gtk_container_border_width(GTK_CONTAINER(addr_hb), 5);
	gtk_container_add(GTK_CONTAINER(u_data->analyse_nb->page3->addr_frame), addr_hb);

	u_data->analyse_nb->page3->scrolled_window = scrolled_window_new(NULL, NULL);
	WIDGET_SET_SIZE(u_data->analyse_nb->page3->scrolled_window, 560, 100);

	u_data->analyse_nb->page3->clist = gtk_clist_new(1);
	gtk_widget_show(u_data->analyse_nb->page3->clist);		

	gtk_clist_set_column_width(GTK_CLIST(u_data->analyse_nb->page3->clist), 0, 200);
	gtk_clist_set_column_justification(GTK_CLIST(u_data->analyse_nb->page3->clist), 0, GTK_JUSTIFY_LEFT);

	gtk_container_add(GTK_CONTAINER(u_data->analyse_nb->page3->scrolled_window),
	u_data->analyse_nb->page3->clist);

	gtk_box_pack_start(GTK_BOX(addr_hb), u_data->analyse_nb->page3->scrolled_window, TRUE, TRUE, 0);
	gtk_widget_show(u_data->analyse_nb->page3->scrolled_window);

	stat_fr = gtk_frame_new(NULL);
	gtk_container_add(GTK_CONTAINER(page3), stat_fr);

	hbox = gtk_hbox_new(FALSE,3);
	gtk_container_border_width(GTK_CONTAINER(hbox), 5);
	gtk_container_add(GTK_CONTAINER(stat_fr), hbox);

	vbox_l = gtk_vbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(hbox), vbox_l, TRUE, TRUE, 0);
		
	hbox_l1 = gtk_hbox_new(FALSE,3);
	gtk_box_pack_start(GTK_BOX(vbox_l), hbox_l1, TRUE, TRUE, 0);

	u_data->analyse_nb->page3->port = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(hbox_l1), u_data->analyse_nb->page3->port, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page3->port),0,0);

	hbox_l2 = gtk_hbox_new(FALSE,3);
	gtk_box_pack_start(GTK_BOX(vbox_l), hbox_l2, TRUE, TRUE, 0);


	u_data->analyse_nb->page3->veritag = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(hbox_l2), u_data->analyse_nb->page3->veritag, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page3->veritag),0,0);
	gtk_widget_show(vbox_l);

	vbox_r=gtk_vbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(hbox), vbox_r, TRUE, TRUE, 0);

	u_data->analyse_nb->page3->max_in = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(vbox_r), u_data->analyse_nb->page3->max_in, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page3->max_in),0,0);
	u_data->analyse_nb->page3->min_in = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(vbox_r), u_data->analyse_nb->page3->min_in, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page3->min_in),0,0);		

	u_data->analyse_nb->page3->max_out = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(vbox_r), u_data->analyse_nb->page3->max_out, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page3->max_out),0,0);
	u_data->analyse_nb->page3->min_out = gtk_label_new("");
	gtk_box_pack_start(GTK_BOX(vbox_r), u_data->analyse_nb->page3->min_out, TRUE, TRUE, 0);
	gtk_misc_set_alignment (GTK_MISC(u_data->analyse_nb->page3->min_out),0,0);

	gtk_widget_show(vbox_r);

	h_button_box=gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(page3), h_button_box, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(h_button_box), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (h_button_box), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX (h_button_box), 0);
	gtk_button_box_set_child_ipadding(GTK_BUTTON_BOX (h_button_box), 4, 0);
	gtk_widget_show(h_button_box);
	
	chunk_bt1 = gtk_button_new_with_label("Chunk Statistics");
	gtk_box_pack_start(GTK_BOX(h_button_box), chunk_bt1, FALSE, FALSE, 0);
	gtk_widget_show(chunk_bt1);
	SIGNAL_CONNECT(chunk_bt1, "clicked", on_chunk2_dlg, u_data);
	
	graph_bt1 = gtk_button_new_with_label("Graph TSN");
	gtk_box_pack_start(GTK_BOX(h_button_box), graph_bt1, FALSE, FALSE, 0);
	gtk_widget_show(graph_bt1);
	SIGNAL_CONNECT(graph_bt1, "clicked", on_graph2_dlg, u_data);

	graph_bt2 = gtk_button_new_with_label("Graph Bytes");
	gtk_box_pack_start(GTK_BOX(h_button_box), graph_bt2, FALSE, FALSE, 0);
	gtk_widget_show(graph_bt2);
	SIGNAL_CONNECT(graph_bt2, "clicked", on_graph_byte2_dlg,u_data);


	close_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_box_pack_start(GTK_BOX(h_button_box), close_bt, FALSE, FALSE, 0);
	gtk_widget_show(close_bt);
	SIGNAL_CONNECT(close_bt, "clicked", on_close_dlg, u_data);

	label = gtk_label_new(" Endpoint 2 ");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page3, label);

	/* show all notebooks */
	gtk_widget_show_all(notebook);

	gtk_widget_show(window);

	u_data->window = window;
	analyse_window_set_title(u_data);

	update_analyse_dlg(u_data);
}



void assoc_analyse(sctp_assoc_info_t* assoc)
{
	struct sctp_analyse* u_data;
	int i;

	u_data = g_malloc(sizeof(struct sctp_analyse));
	u_data->assoc = assoc;
	u_data->assoc->addr_chunk_count = assoc->addr_chunk_count;
	u_data->window = NULL;
	u_data->analyse_nb = NULL;
	u_data->children = NULL;
	u_data->num_children = 0;
	static_assoc.addr_chunk_count =assoc->addr_chunk_count;
	static_assoc.port1 = assoc->port1;
	static_assoc.port2 = assoc->port2;
	for (i=0; i<NUM_CHUNKS; i++)
	{
		static_assoc.chunk_count[i]     = assoc->chunk_count[i];
		static_assoc.ep1_chunk_count[i] = assoc->ep1_chunk_count[i];
		static_assoc.ep2_chunk_count[i] = assoc->ep2_chunk_count[i];
	}
	set_analyse_child(u_data);
	increase_analyse_childcount();
	static_assoc.addr_chunk_count = assoc->addr_chunk_count;
	create_analyse_window(u_data);
}


static void sctp_analyse_cb(struct sctp_analyse* u_data)
{
	guint8* ip_src;
	guint16 srcport;
	guint8* ip_dst;
	guint16 dstport;
	GList *list, *srclist, *dstlist;
	dfilter_t *sfcode;
	capture_file *cf;
	epan_dissect_t *edt;
	gint err;
	gchar *err_info;
	gboolean frame_matched;
	frame_data *fdata;
	gchar filter_text[256];
	sctp_assoc_info_t* assoc = NULL;
	address *src, *dst;
	int i;

	strcpy(filter_text,"sctp");
	if (!dfilter_compile(filter_text, &sfcode)) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, dfilter_error_msg);
		return;
	}

	cf = &cfile;
	fdata = cf->current_frame;

	/* we are on the selected frame now */
	if (fdata == NULL)
		return; /* if we exit here it's an error */

	/* dissect the current frame */
	if (!wtap_seek_read(cf->wth, fdata->file_off, &cf->pseudo_header,
	    cf->pd, fdata->cap_len, &err, &err_info)) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			cf_read_error_message(err, err_info), cf->filename);
		return;
	}

	edt = epan_dissect_new(TRUE, FALSE);
	epan_dissect_prime_dfilter(edt, sfcode);
	epan_dissect_run(edt, &cf->pseudo_header, cf->pd, fdata, NULL);
	frame_matched = dfilter_apply_edt(sfcode, edt);

	/* if it is not an sctp frame, show the dialog */

	if (frame_matched != 1) {
		epan_dissect_free(edt);
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Please choose an SCTP packet!");
		return;
	}

	ip_src = g_malloc(edt->pi.src.len);
	memcpy(ip_src, edt->pi.src.data, edt->pi.src.len);
	ip_dst = g_malloc(edt->pi.dst.len);
	memcpy(ip_dst, edt->pi.dst.data, edt->pi.dst.len);
	srcport = edt->pi.srcport;
	dstport = edt->pi.destport;

	list = g_list_first(sctp_stat_get_info()->assoc_info_list);

	while (list)
	{
		assoc = (sctp_assoc_info_t*)(list->data);

		if (assoc->port1 == srcport && assoc->port2 == dstport)
		{	
			srclist = g_list_first(assoc->addr1);
			while(srclist)
			{
				src = (address *)(srclist->data);
				
				if (*src->data == *ip_src)
				{
					dstlist = g_list_first(assoc->addr2);
					while(dstlist)
					{
						dst = (address *)(dstlist->data);
						if (*dst->data == *ip_dst)
						{
							u_data->assoc = assoc;
							u_data->assoc->addr_chunk_count = assoc->addr_chunk_count;
							static_assoc.addr_chunk_count = assoc->addr_chunk_count;
							static_assoc.port1 = assoc->port1;
							static_assoc.port2 = assoc->port2;
							for (i=0; i<NUM_CHUNKS; i++)
							{
								static_assoc.chunk_count[i]     = assoc->chunk_count[i];
								static_assoc.ep1_chunk_count[i] = assoc->ep1_chunk_count[i];
								static_assoc.ep2_chunk_count[i] = assoc->ep2_chunk_count[i];
							}
							create_analyse_window(u_data);
							return;
						}
						else
							dstlist = g_list_next(dstlist);
					}
				}
				else
					srclist = g_list_next(srclist);
			}
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Assoc not found!");
			return;
		}
		else if (assoc->port2 == srcport && assoc->port1 == dstport)
		{
			srclist = g_list_first(assoc->addr2);
			while(srclist)
			{
				src = (address *)(srclist->data);
				if (*src->data == *ip_src)
				{
					dstlist = g_list_first(assoc->addr1);
					while(dstlist)
					{
						dst = (address *)(dstlist->data);
						if (*dst->data == *ip_dst)
						{
							u_data->assoc = assoc;
							u_data->assoc->addr_chunk_count = assoc->addr_chunk_count;
							static_assoc.addr_chunk_count = assoc->addr_chunk_count;
							static_assoc.port1 = assoc->port1;
							static_assoc.port2 = assoc->port2;
							for (i=0; i<NUM_CHUNKS; i++)
							{
								static_assoc.chunk_count[i]     = assoc->chunk_count[i];
								static_assoc.ep1_chunk_count[i] = assoc->ep1_chunk_count[i];
								static_assoc.ep2_chunk_count[i] = assoc->ep2_chunk_count[i];
							}
							create_analyse_window(u_data);
							return;
						}
						else
							dstlist = g_list_next(dstlist);
					}
				}
				else
					srclist = g_list_next(srclist);
			}
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Assoc not found!");
			return;
		}
		else
			list = g_list_next(list);

	}
}


void sctp_analyse_start(GtkWidget *w _U_, gpointer data _U_)
{
	struct sctp_analyse * u_data;

	/* Register the tap listener */
	if (sctp_stat_get_info()->is_registered == FALSE)
		register_tap_listener_sctp_stat();
	/* (redissect all packets) */
	
	sctp_stat_scan();

	u_data = g_malloc(sizeof(struct sctp_analyse));
	u_data->assoc        = NULL;
	u_data->children     = NULL;
	u_data->analyse_nb   = NULL;
	u_data->window       = NULL;
	u_data->num_children = 0;

	cf_retap_packets(&cfile);
	sctp_analyse_cb(u_data);
}


void
register_tap_listener_sctp_analyse(void)
{
	register_stat_menu_item("SCTP/Analyse Association", REGISTER_STAT_GROUP_TELEPHONY,
	                       sctp_analyse_start, NULL, NULL, NULL);
}
