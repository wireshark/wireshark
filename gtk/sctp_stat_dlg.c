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

#include "stat_menu.h"
#include "dlg_utils.h"
#include "ui_util.h"
#include "main.h"
#include "compat_macros.h"

#include "sctp_stat.h"


static GtkWidget *sctp_stat_dlg=NULL;
static GtkWidget *clist = NULL;
static GList *last_list = NULL;
static gchar *filter_string = NULL;
static sctp_assoc_info_t* selected_stream = NULL;  /* current selection */
extern GtkWidget *main_display_filter_widget;
static sctp_allassocs_info_t *sctp_assocs=NULL;
static guint16 n_children=0;
static GtkWidget *bt_afilter = NULL, *bt_unselect=NULL, *bt_analyse=NULL, *bt_filter=NULL;

#define NUM_COLS    7
#define FRAME_LIMIT 8

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;


static void
dlg_destroy(void)
{
	guint32 i, j;
	GList *list;
	struct sctp_analyse *child_data;

	j=n_children;
	for (i=0; i<j; i++)
	{
		list=g_list_last(sctp_assocs->children);
		child_data=(struct sctp_analyse *)list->data;
		gtk_grab_remove(GTK_WIDGET(child_data->window));
		gtk_widget_destroy(GTK_WIDGET(child_data->window));
		list=g_list_previous(list);
	}
	g_list_free(sctp_assocs->children);
	sctp_assocs->children = NULL;
	sctp_stat_dlg = NULL;
}

void
decrease_analyse_childcount()
{
	n_children--;
}

void
increase_analyse_childcount()
{
	n_children++;
}

void
set_analyse_child(struct sctp_analyse *child)
{
	sctp_assocs->children=g_list_append(sctp_assocs->children, child);
}

void
remove_analyse_child(struct sctp_analyse *child)
{
	sctp_assocs->children=g_list_remove(sctp_assocs->children, child);
}


static void add_to_clist(sctp_assoc_info_t* assinfo)
{
	gint added_row, i;
	gchar *data[NUM_COLS];
	gchar field[NUM_COLS][30];

	for (i=0; i<NUM_COLS; i++)
		data[i]=&field[i][0];

	g_snprintf(field[0], 20, "%u", assinfo->port1);
	g_snprintf(field[1], 20, "%u", assinfo->port2);
	g_snprintf(field[2], 20, "%u", assinfo->n_packets);
	g_snprintf(field[3], 20, "%s", assinfo->checksum_type);
	g_snprintf(field[4], 20, "%u", assinfo->n_checksum_errors);
	g_snprintf(field[5], 20, "%u", assinfo->n_data_chunks);
	g_snprintf(field[6], 20, "%u", assinfo->n_data_bytes);

	added_row = gtk_clist_append(GTK_CLIST(clist), data);
	gtk_clist_set_row_data(GTK_CLIST(clist), added_row, assinfo);
}

static void
sctp_stat_on_unselect(GtkButton *button _U_, gpointer user_data _U_)
{
	if (filter_string != NULL) {
		g_free(filter_string);
		filter_string = NULL;
	}

	selected_stream = NULL;
	gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), "");
	gtk_clist_unselect_all(GTK_CLIST(clist));
	gtk_widget_set_sensitive(bt_unselect,FALSE);
	gtk_widget_set_sensitive(bt_filter,FALSE);
	gtk_widget_set_sensitive(bt_analyse,FALSE);
	gtk_widget_set_sensitive(bt_afilter,FALSE);
}

void sctp_stat_dlg_update(void)
{
	GList *list;

	list=(sctp_stat_get_info()->assoc_info_list);
	if (sctp_stat_dlg != NULL)
	{
		gtk_clist_clear(GTK_CLIST(clist));

		list = g_list_first(sctp_stat_get_info()->assoc_info_list);

		while (list)
		{
			add_to_clist((sctp_assoc_info_t*)(list->data));
			list = g_list_next(list);
		}

		sctp_stat_on_unselect(NULL, NULL);
	}
	last_list = list;
}

static void
sctp_stat_on_select_row(GtkCList *clist, gint row, gint column _U_,
                        GdkEventButton *event _U_, gpointer user_data _U_)
{
	gchar *text[1];
	guint16 port1, port2;
	guint32 checksum, data_chunks, data_bytes, packets;
	GList *list;
	sctp_assoc_info_t* assoc;

	selected_stream = gtk_clist_get_row_data(GTK_CLIST(clist), row);

	gtk_clist_get_text(GTK_CLIST(clist), row, 0, text);
	port1=atoi(text[0]);
	gtk_clist_get_text(GTK_CLIST(clist), row, 1, text);
	port2=atoi(text[0]);
	gtk_clist_get_text(GTK_CLIST(clist), row, 2, text);
	packets=atoi(text[0]);
	gtk_clist_get_text(GTK_CLIST(clist), row, 4, text);
	checksum=atoi(text[0]);
	gtk_clist_get_text(GTK_CLIST(clist), row, 5, text);
	data_chunks=atoi(text[0]);

	gtk_clist_get_text(GTK_CLIST(clist), row, 6, text);
	data_bytes=atoi(text[0]);

	list = g_list_first(sctp_assocs->assoc_info_list);

	while (list)
	{
		assoc = (sctp_assoc_info_t*)(list->data);
		if (assoc->port1==port1 && assoc->port2==port2 &&
		assoc->n_packets==packets && assoc->n_checksum_errors==checksum
		&& assoc->n_data_chunks==data_chunks && assoc->n_data_bytes==data_bytes)
		{
			selected_stream=assoc;
			break;
		}
		list=g_list_next(list);
	}
	gtk_widget_set_sensitive(bt_unselect,TRUE);
	gtk_widget_set_sensitive(bt_analyse,TRUE);
	gtk_widget_set_sensitive(bt_filter,TRUE);
}

static void
sctp_stat_on_apply_filter (GtkButton *button _U_, gpointer user_data _U_)
{
	if (filter_string != NULL)
	{
		main_filter_packets(&cfile, filter_string, FALSE);
	}
}

static void
sctp_stat_on_filter (GtkButton *button _U_, gpointer user_data _U_)
{
	gchar *f_string = NULL;
	guint32 framenumber=0;
	GList *list, *srclist, *dstlist;
	gchar *str=NULL;
	GString *gstring=NULL;
	struct sockaddr_in *infosrc=NULL;
	struct sockaddr_in *infodst=NULL;

	if (selected_stream==NULL) {
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), "");
		return;
	}

	if (selected_stream->n_packets>FRAME_LIMIT)
	{
		if (selected_stream->check_address==FALSE)
		{
			f_string = g_strdup_printf("((sctp.srcport==%u && sctp.dstport==%u && ((sctp.verification_tag==0x%x && sctp.verification_tag!=0x0) || "
		                                   "(sctp.verification_tag==0x0 && sctp.initiate_tag==0x%x) || "
		                                   "(sctp.verification_tag==0x%x && (sctp.abort_t_bit==1 || sctp.shutdown_complete_t_bit==1)))) ||"
		                                   "(sctp.srcport==%u && sctp.dstport==%u && ((sctp.verification_tag==0x%x && sctp.verification_tag!=0x0) || "
		                                   "(sctp.verification_tag==0x0 && sctp.initiate_tag==0x%x) ||"
		                                   "(sctp.verification_tag==0x%x && (sctp.abort_t_bit==1 || sctp.shutdown_complete_t_bit==1)))))",
			selected_stream->port1,
			selected_stream->port2,
			selected_stream->verification_tag1,
			selected_stream->verification_tag2,
			selected_stream->verification_tag2,
			selected_stream->port2,
			selected_stream->port1,
			selected_stream->verification_tag2,
			selected_stream->verification_tag1,
			selected_stream->verification_tag1);
			filter_string = f_string;
		}
		else
		{
			srclist = g_list_first(selected_stream->addr1);
			infosrc=(struct sockaddr_in *) (srclist->data);
			gstring = g_string_new(g_strdup_printf("((sctp.srcport==%u && sctp.dstport==%u && (ip.src==%s",
				selected_stream->port1, selected_stream->port2, ip_to_str((const guint8 *)&(infosrc->sin_addr.s_addr))));
			srclist= g_list_next(srclist);

			while (srclist)
			{
				infosrc=(struct sockaddr_in *) (srclist->data);
				str =g_strdup_printf("|| ip.src==%s",ip_to_str((const guint8 *)&(infosrc->sin_addr.s_addr)));
				g_string_append(gstring, str);
				srclist= g_list_next(srclist);
			}

			dstlist = g_list_first(selected_stream->addr2);
			infodst=(struct sockaddr_in *) (dstlist->data);
			str = g_strdup_printf(") && (ip.dst==%s",ip_to_str((const guint8 *)&(infodst->sin_addr.s_addr)));
			g_string_append(gstring, str);
			dstlist= g_list_next(dstlist);
			while (dstlist)
			{
				infodst=(struct sockaddr_in *) (dstlist->data);
				str =g_strdup_printf("|| ip.dst==%s",ip_to_str((const guint8 *)&(infodst->sin_addr.s_addr)));
				g_string_append(gstring, str);
				dstlist= g_list_next(dstlist);
			}

			srclist = g_list_first(selected_stream->addr1);
			infosrc=(struct sockaddr_in *) (srclist->data);
			str = g_strdup_printf(")) || (sctp.dstport==%u && sctp.srcport==%u && (ip.dst==%s",
				selected_stream->port1, selected_stream->port2, ip_to_str((const guint8 *)&(infosrc->sin_addr.s_addr)));
			g_string_append(gstring, str);
			srclist= g_list_next(srclist);

			while (srclist)
			{
				infosrc=(struct sockaddr_in *) (srclist->data);
				str =g_strdup_printf("|| ip.dst==%s",ip_to_str((const guint8 *)&(infosrc->sin_addr.s_addr)));
				g_string_append(gstring, str);
				srclist= g_list_next(srclist);
			}

			dstlist = g_list_first(selected_stream->addr2);
			infodst=(struct sockaddr_in *) (dstlist->data);
			str = g_strdup_printf(") && (ip.src==%s",ip_to_str((const guint8 *)&(infodst->sin_addr.s_addr)));
			g_string_append(gstring, str);
			dstlist= g_list_next(dstlist);
			while (dstlist)
			{
				infodst=(struct sockaddr_in *) (dstlist->data);
				str =g_strdup_printf("|| ip.src==%s",ip_to_str((const guint8 *)&(infodst->sin_addr.s_addr)));
				g_string_append(gstring, str);
				dstlist= g_list_next(dstlist);
			}
			str = g_strdup_printf(")))");
			g_string_append(gstring, str);
			filter_string = gstring->str;
			g_string_free(gstring,FALSE);
		}
	}
	else
	{
		list = g_list_first(selected_stream->frame_numbers);
		framenumber = *((guint32 *)(list->data));
		gstring = g_string_new(g_strdup_printf("frame.number==%u",framenumber));
		list = g_list_next(list);
		while (list)
		{
			framenumber = *((guint32 *)(list->data));
			str =g_strdup_printf(" || frame.number==%u",framenumber);
			g_string_append(gstring, str);
			list = g_list_next(list);
		}
		filter_string = gstring->str;
		g_string_free(gstring,FALSE);
	}
	
	if (filter_string != NULL) {
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), filter_string);
	} else {
		g_assert_not_reached();
	}
	gtk_widget_set_sensitive(bt_afilter,TRUE);
}


static void
sctp_stat_on_close (GtkButton *button _U_, gpointer user_data _U_)
{
	gtk_grab_remove(sctp_stat_dlg);
	gtk_widget_destroy(sctp_stat_dlg);
}

static void
sctp_stat_on_analyse (GtkButton *button _U_, gpointer user_data _U_)
{
	if (selected_stream==NULL)
		return;

	if (selected_stream)
		assoc_analyse(selected_stream);
	gtk_widget_set_sensitive(bt_analyse,FALSE);
}

static gint
clist_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	char *text1 = NULL;
	char *text2 = NULL;
	int i1, i2;

	GtkCListRow *row1 = (GtkCListRow *) ptr1;
	GtkCListRow *row2 = (GtkCListRow *) ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	case 0:
	case 2:
		return strcmp (text1, text2);
	case 1:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
		i1=atoi(text1);
		i2=atoi(text2);
		return i1-i2;
	}
	g_assert_not_reached();
	return 0;
}

static void
clist_click_column_cb(GtkCList *list, gint column, gpointer data)
{
	column_arrows *col_arrows = (column_arrows *) data;
	int i;
	gtk_clist_freeze(list);

	for (i = 0; i < NUM_COLS; i++) {
		gtk_widget_hide(col_arrows[i].ascend_pm);
		gtk_widget_hide(col_arrows[i].descend_pm);
	}

	if (column == list->sort_column) {
		if (list->sort_type == GTK_SORT_ASCENDING) {
			list->sort_type = GTK_SORT_DESCENDING;
			gtk_widget_show(col_arrows[column].descend_pm);
		} else {
			list->sort_type = GTK_SORT_ASCENDING;
			gtk_widget_show(col_arrows[column].ascend_pm);
		}
	} else {
		list->sort_type = GTK_SORT_DESCENDING;
		gtk_widget_show(col_arrows[column].descend_pm);
		gtk_clist_set_sort_column(list, column);
	}
	gtk_clist_thaw(list);

	gtk_clist_sort(list);
}

static void
gtk_sctpstat_dlg(void)
{
	GtkWidget *sctp_stat_dlg_w;
	GtkWidget *vbox1;
	GtkWidget *scrolledwindow1;
	GtkWidget *hbuttonbox2;
	GtkWidget *bt_close;

	const gchar *titles[NUM_COLS] =  {"Port 1","Port 2", "No of Packets", "Checksum", "No of Errors", "Data Chunks", "Data Bytes"};
	column_arrows *col_arrows;
	GdkBitmap *ascend_bm, *descend_bm;
	GdkPixmap *ascend_pm, *descend_pm;
	GtkStyle *win_style;
	GtkWidget *column_lb;
	gint i;

	sctp_stat_dlg_w = window_new (GTK_WINDOW_TOPLEVEL, "Ethereal: SCTP Associations");
	gtk_window_set_position (GTK_WINDOW (sctp_stat_dlg_w), GTK_WIN_POS_CENTER);
	SIGNAL_CONNECT(sctp_stat_dlg_w, "destroy", dlg_destroy,NULL);

	/* Container for each row of widgets */
	vbox1 = gtk_vbox_new(FALSE, 2);
	gtk_container_border_width(GTK_CONTAINER(vbox1), 8);
	gtk_container_add(GTK_CONTAINER(sctp_stat_dlg_w), vbox1);
	gtk_widget_show(vbox1);

	scrolledwindow1 = scrolled_window_new (NULL, NULL);
	gtk_widget_show (scrolledwindow1);
	gtk_box_pack_start (GTK_BOX (vbox1), scrolledwindow1, TRUE, TRUE, 0);

	clist = gtk_clist_new (NUM_COLS);
	gtk_widget_show (clist);
	gtk_container_add (GTK_CONTAINER (scrolledwindow1), clist);
	WIDGET_SET_SIZE(clist, 700, 200);

	gtk_clist_set_column_width (GTK_CLIST (clist), 0, 50);
	gtk_clist_set_column_width (GTK_CLIST (clist), 1, 50);
	gtk_clist_set_column_width (GTK_CLIST (clist), 2, 100);
	gtk_clist_set_column_width (GTK_CLIST (clist), 3, 100);
	gtk_clist_set_column_width (GTK_CLIST (clist), 4, 100);
	gtk_clist_set_column_width (GTK_CLIST (clist), 5, 100);
	gtk_clist_set_column_width (GTK_CLIST (clist), 6, 100);


	gtk_clist_set_column_justification(GTK_CLIST(clist), 0, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 1, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 2, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 3, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 4, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 5, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 6, GTK_JUSTIFY_CENTER);
	gtk_clist_column_titles_show (GTK_CLIST (clist));

	gtk_clist_set_compare_func(GTK_CLIST(clist), clist_sort_column);
	gtk_clist_set_sort_column(GTK_CLIST(clist), 0);
	gtk_clist_set_sort_type(GTK_CLIST(clist), GTK_SORT_ASCENDING);

	gtk_widget_show(sctp_stat_dlg_w);

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

	SIGNAL_CONNECT(clist, "click-column", clist_click_column_cb, col_arrows);

	hbuttonbox2 = gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(vbox1), hbuttonbox2, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbuttonbox2), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (hbuttonbox2), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX (hbuttonbox2), 0);
	gtk_button_box_set_child_ipadding(GTK_BUTTON_BOX (hbuttonbox2), 4, 0);
	gtk_widget_show(hbuttonbox2);

	bt_unselect = gtk_button_new_with_label ("Unselect");
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_unselect);
	gtk_widget_show (bt_unselect);
	gtk_widget_set_sensitive(bt_unselect,FALSE);

	bt_filter = gtk_button_new_with_label ("Set filter");
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_filter);
	gtk_widget_show (bt_filter);
	gtk_widget_set_sensitive(bt_filter,FALSE);

	bt_afilter = gtk_button_new_with_label ("Apply filter");
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_afilter);
	gtk_widget_show (bt_afilter);
	gtk_widget_set_sensitive(bt_afilter,FALSE);

	bt_analyse = gtk_button_new_with_label ("Analyse");
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_analyse);
	gtk_widget_show (bt_analyse);
	gtk_widget_set_sensitive(bt_analyse,FALSE);

	bt_close = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_close);
	gtk_widget_show (bt_close);

	SIGNAL_CONNECT(sctp_stat_dlg_w, "destroy", dlg_destroy, NULL);
	SIGNAL_CONNECT(clist, "select_row", sctp_stat_on_select_row, NULL);
	SIGNAL_CONNECT(bt_unselect, "clicked", sctp_stat_on_unselect, NULL);
	SIGNAL_CONNECT(bt_filter, "clicked", sctp_stat_on_filter, NULL);
	SIGNAL_CONNECT(bt_afilter, "clicked", sctp_stat_on_apply_filter, NULL);
	SIGNAL_CONNECT(bt_analyse, "clicked", sctp_stat_on_analyse, NULL);
	SIGNAL_CONNECT(bt_close, "clicked", sctp_stat_on_close, NULL);

	sctp_stat_dlg = sctp_stat_dlg_w;
	cf_retap_packets(&cfile);

}

void sctp_stat_dlg_show(void)
{
	if (sctp_stat_dlg != NULL)
	{
		/* There's already a dialog box; reactivate it. */
		reactivate_window(sctp_stat_dlg);
		/* Another list since last call? */
		if ((sctp_stat_get_info()->assoc_info_list) != last_list)
			sctp_stat_dlg_update();
	}
	else
	{
		/* Create and show the dialog box */
		gtk_sctpstat_dlg();
		sctp_stat_dlg_update();
	}
}


void sctp_stat_start(GtkWidget *w _U_, gpointer data _U_)
{

	sctp_assocs = g_malloc(sizeof(sctp_allassocs_info_t));
	sctp_assocs = (sctp_allassocs_info_t*)sctp_stat_get_info();
	/* Register the tap listener */
	if (sctp_stat_get_info()->is_registered==FALSE)
	register_tap_listener_sctp_stat();
	/*  (redissect all packets) */
	sctp_stat_scan();

	/* Show the dialog box with the list of streams */
	/* sctp_stat_dlg_show(sctp_stat_get_info()->assoc_info_list); */
	sctp_stat_dlg_show();
}

/****************************************************************************/
void
register_tap_listener_sctp_stat_dlg(void)
{
	register_stat_menu_item("SCTP/Show All Associations...", REGISTER_STAT_GROUP_TELEPHONY,
	    sctp_stat_start, NULL, NULL, NULL);
}


GtkWidget* get_stat_dlg(void)
{
	return sctp_stat_dlg;
}
