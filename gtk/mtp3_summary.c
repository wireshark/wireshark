/* mtp3_summary.c
 * Routines for MTP3 Statictics summary window
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Modified from gsm_map_summary.c
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
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <string.h>

#include <wtap.h>

#include "epan/packet_info.h"
#include "epan/epan.h"
#include "epan/value_string.h"
#include "stat_menu.h"
#include "globals.h"
#include "file.h"
#include "summary.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"
#include <epan/tap.h>

#include <epan/dissectors/packet-mtp3.h>
#include "mtp3_stat.h"

#define SUM_STR_MAX 1024

typedef struct column_arrows {
    GtkWidget		*table;
    GtkWidget		*ascend_pm;
    GtkWidget		*descend_pm;
} column_arrows;

#define	MTP3_SUM_INIT_TABLE_NUM_COLUMNS		6

typedef struct _my_columns_t {
    guint32		value;
    const gchar		*strptr;
    GtkJustification	just;
} my_columns_t;

static my_columns_t columns[MTP3_SUM_INIT_TABLE_NUM_COLUMNS] = {
    { 110,	"SI",			GTK_JUSTIFY_LEFT },
    { 100,	"Num MSUs",		GTK_JUSTIFY_RIGHT },
    { 100,	"MSUs/sec",		GTK_JUSTIFY_RIGHT },
    { 100,	"Num Bytes",		GTK_JUSTIFY_RIGHT },
    { 100,	"Bytes/MSU",		GTK_JUSTIFY_RIGHT },
    { 100,	"Bytes/sec",		GTK_JUSTIFY_RIGHT }
};


static void
add_string_to_box(gchar *str, GtkWidget *box)
{
  GtkWidget *lb;
  lb = gtk_label_new(str);
  gtk_misc_set_alignment(GTK_MISC(lb), 0.0, 0.5);
  gtk_box_pack_start(GTK_BOX(box), lb,FALSE,FALSE, 0);
  gtk_widget_show(lb);
}


static void
mtp3_sum_gtk_click_column_cb(
    GtkCList		*clist,
    gint		column,
    gpointer		data)
{
    column_arrows	*col_arrows = (column_arrows *) data;
    int			i;


    gtk_clist_freeze(clist);

    for (i=0; i < MTP3_SUM_INIT_TABLE_NUM_COLUMNS; i++)
    {
	gtk_widget_hide(col_arrows[i].ascend_pm);
	gtk_widget_hide(col_arrows[i].descend_pm);
    }

    if (column == clist->sort_column)
    {
	if (clist->sort_type == GTK_SORT_ASCENDING)
	{
	    clist->sort_type = GTK_SORT_DESCENDING;
	    gtk_widget_show(col_arrows[column].descend_pm);
	}
	else
	{
	    clist->sort_type = GTK_SORT_ASCENDING;
	    gtk_widget_show(col_arrows[column].ascend_pm);
	}
    }
    else
    {
	/*
	 * Columns 0 sorted in descending order by default
	 */
	if (column == 0)
	{
	    clist->sort_type = GTK_SORT_ASCENDING;
	    gtk_widget_show(col_arrows[column].ascend_pm);
	}
	else
	{
	    clist->sort_type = GTK_SORT_DESCENDING;
	    gtk_widget_show(col_arrows[column].descend_pm);
	}

	gtk_clist_set_sort_column(clist, column);
    }

    gtk_clist_thaw(clist);
    gtk_clist_sort(clist);
}


static gint
mtp3_sum_gtk_sort_column(
    GtkCList		*clist,
    gconstpointer	ptr1,
    gconstpointer	ptr2)
{
    const GtkCListRow	*row1 = ptr1;
    const GtkCListRow	*row2 = ptr2;
    char		*text1 = NULL;
    char		*text2 = NULL;
    int			i1, i2;

    text1 = GTK_CELL_TEXT(row1->cell[clist->sort_column])->text;
    text2 = GTK_CELL_TEXT(row2->cell[clist->sort_column])->text;

    switch (clist->sort_column)
    {
    case 0:
	/* text columns */
	return(strcmp(text1, text2));

    default:
	/* number columns */
	i1 = strtol(text1, NULL, 0);
	i2 = strtol(text2, NULL, 0);
	return(i1 - i2);
    }

    g_assert_not_reached();

    return(0);
}

static void
mtp3_sum_draw(
    GtkWidget		*table,
    double		seconds,
    int			*tot_num_msus_p,
    double		*tot_num_bytes_p)
{
    const char		*entries[MTP3_SUM_INIT_TABLE_NUM_COLUMNS];
    int			i, j;
    int			num_msus;
    double		num_bytes;

    *tot_num_msus_p = 0;
    *tot_num_bytes_p = 0;

    for (i=0; i < MTP3_NUM_SI_CODE; i++)
    {
	entries[0] = g_strdup(mtp3_service_indicator_code_short_vals[i].strptr);

	j = 0;
	num_msus = 0;
	num_bytes = 0;

	while (j < mtp3_num_used)
	{
	    num_msus += mtp3_stat[j].si_code[i].num_msus;
	    num_bytes += mtp3_stat[j].si_code[i].size;

	    j++;
	}

	*tot_num_msus_p += num_msus;
	*tot_num_bytes_p += num_bytes;

	entries[1] = g_strdup_printf("%u", num_msus);

	entries[2] = (seconds) ? g_strdup_printf("%.2f", num_msus/seconds) : "N/A";
	
	entries[3] = g_strdup_printf("%.0f", num_bytes);

	entries[4] = (num_msus) ? g_strdup_printf("%.2f", num_bytes/num_msus) : "N/A";

	entries[5] = (seconds) ? g_strdup_printf("%.2f", num_bytes/seconds) : "N/A";

	gtk_clist_insert(GTK_CLIST(table), i, (gchar **) entries);
    }

    gtk_clist_sort(GTK_CLIST(table));
}


static void
mtp3_sum_gtk_sum_cb(GtkWidget *w _U_, gpointer d _U_)
{
  summary_tally summary;
  GtkWidget     *sum_open_w,
                *main_vb, *file_fr, *data_fr, *file_box,
		*data_box, *bbox, *close_bt,
		*tot_fr, *tot_box,
		*table, *column_lb, *table_fr;
  column_arrows	*col_arrows;

  gchar			string_buff[SUM_STR_MAX];
  const char *  file_type;
  double		seconds;
  int			tot_num_msus;
  double		tot_num_bytes;
  int			i;

  /* initialize the tally */
  summary_fill_in(&cfile, &summary);

  /* initial compututations */
  seconds = summary.stop_time - summary.start_time;

  sum_open_w = window_new(GTK_WINDOW_TOPLEVEL, "MTP3 Statistics: Summary");

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(sum_open_w), main_vb);
  gtk_widget_show(main_vb);

  /* File frame */
  file_fr = gtk_frame_new("File");
  gtk_container_add(GTK_CONTAINER(main_vb), file_fr);
  gtk_widget_show(file_fr);

  file_box = gtk_vbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_fr), file_box);
  gtk_widget_show(file_box);

  /* filename */
  g_snprintf(string_buff, SUM_STR_MAX, "Name: %s", ((summary.filename) ? summary.filename : "None"));
  add_string_to_box(string_buff, file_box);

  /* length */
  g_snprintf(string_buff, SUM_STR_MAX, "Length: %lu", summary.file_length);
  add_string_to_box(string_buff, file_box);

  /* format */
  file_type = wtap_file_type_string(summary.encap_type);
  g_snprintf(string_buff, SUM_STR_MAX, "Format: %s", (file_type ? file_type : "N/A"));
  add_string_to_box(string_buff, file_box);

  if (summary.has_snap) {
    /* snapshot length */
    g_snprintf(string_buff, SUM_STR_MAX, "Snapshot length: %u", summary.snap);
    add_string_to_box(string_buff, file_box);
  }

  /* Data frame */
  data_fr = gtk_frame_new("Data");
  gtk_container_add(GTK_CONTAINER(main_vb), data_fr);
  gtk_widget_show(data_fr);

  data_box = gtk_vbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(data_fr), data_box);
  gtk_widget_show(data_box);

  /* seconds */
  g_snprintf(string_buff, SUM_STR_MAX, "Elapsed time: %.3f seconds", summary.elapsed_time);
  add_string_to_box(string_buff, data_box);

  g_snprintf(string_buff, SUM_STR_MAX, "Between first and last packet: %.3f seconds", seconds);
  add_string_to_box(string_buff, data_box);

  /* Packet count */
  g_snprintf(string_buff, SUM_STR_MAX, "Packet count: %i", summary.packet_count);
  add_string_to_box(string_buff, data_box);

  /* MTP3 SPECIFIC */
  table_fr = gtk_frame_new("Service Indicator (SI) Totals");
  gtk_container_add(GTK_CONTAINER(main_vb), table_fr);
  gtk_widget_show(table_fr);

  table = gtk_clist_new(MTP3_SUM_INIT_TABLE_NUM_COLUMNS);
  gtk_container_add(GTK_CONTAINER(table_fr), table);
  gtk_widget_show(table);

  col_arrows =
      (column_arrows *) g_malloc(sizeof(column_arrows) * MTP3_SUM_INIT_TABLE_NUM_COLUMNS);

  for (i = 0; i < MTP3_SUM_INIT_TABLE_NUM_COLUMNS; i++)
  {
      col_arrows[i].table = gtk_table_new(2, 2, FALSE);

      gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);

      column_lb = gtk_label_new(columns[i].strptr);

      gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb,
	  0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);

      gtk_widget_show(column_lb);

      col_arrows[i].ascend_pm = xpm_to_widget(clist_ascend_xpm);

      gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm,
	  1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);

      col_arrows[i].descend_pm = xpm_to_widget(clist_descend_xpm);

      gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm,
	  1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);

      if (i == 0)
      {
	  /* default column sorting */
	  gtk_widget_show(col_arrows[i].ascend_pm);
      }

      gtk_clist_set_column_justification(GTK_CLIST(table), i, columns[i].just);

      gtk_clist_set_column_widget(GTK_CLIST(table), i, col_arrows[i].table);
      gtk_widget_show(col_arrows[i].table);
  }
  gtk_clist_column_titles_show(GTK_CLIST(table));

  gtk_clist_set_compare_func(GTK_CLIST(table), mtp3_sum_gtk_sort_column);
  gtk_clist_set_sort_column(GTK_CLIST(table), 0);
  gtk_clist_set_sort_type(GTK_CLIST(table), GTK_SORT_ASCENDING);

  for (i = 0; i < MTP3_SUM_INIT_TABLE_NUM_COLUMNS; i++)
  {
      gtk_clist_set_column_width(GTK_CLIST(table), i, columns[i].value);
  }

  gtk_clist_set_shadow_type(GTK_CLIST(table), GTK_SHADOW_IN);
  gtk_clist_column_titles_show(GTK_CLIST(table));

  SIGNAL_CONNECT(table, "click-column", mtp3_sum_gtk_click_column_cb, col_arrows);

  mtp3_sum_draw(table, seconds, &tot_num_msus, &tot_num_bytes);

  /* Totals frame */
  tot_fr = gtk_frame_new("Totals");
  gtk_container_add(GTK_CONTAINER(main_vb), tot_fr);
  gtk_widget_show(tot_fr);

  tot_box = gtk_vbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(tot_fr), tot_box);
  gtk_widget_show(tot_box);

  g_snprintf(string_buff, SUM_STR_MAX, "Total MSUs: %u", tot_num_msus);
  add_string_to_box(string_buff, tot_box);

  if (seconds) {
		g_snprintf(string_buff, SUM_STR_MAX, "MSUs/second: %.2f", tot_num_msus/seconds);
  }
  else {
		g_snprintf(string_buff, SUM_STR_MAX, "MSUs/second: N/A");
  }
  add_string_to_box(string_buff, tot_box);

  g_snprintf(string_buff, SUM_STR_MAX, "Total Bytes: %.0f", tot_num_bytes);
  add_string_to_box(string_buff, tot_box);

  if (tot_num_msus) {
		g_snprintf(string_buff, SUM_STR_MAX, "Average Bytes/MSU: %.2f", tot_num_bytes/tot_num_msus);
  }
  else {
	    g_snprintf(string_buff, SUM_STR_MAX, "Average Bytes/MSU: N/A");
  }
  add_string_to_box(string_buff, tot_box);

  if (seconds) {
	  g_snprintf(string_buff, SUM_STR_MAX, "Bytes/second: %.2f", tot_num_bytes/seconds);
  }
  else {
	  g_snprintf(string_buff, SUM_STR_MAX, "Bytes/second: N/A");
  }
  add_string_to_box(string_buff, tot_box);

  /* Button row. */
  bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
  window_set_cancel_button(sum_open_w, close_bt, window_cancel_button_cb);

  SIGNAL_CONNECT(sum_open_w, "delete_event", window_delete_event_cb, NULL);

  gtk_widget_show_all(sum_open_w);
  window_present(sum_open_w);
}


void
register_tap_listener_gtkmtp3_summary(void)
{
    register_stat_menu_item("MTP3/MSU Summary",  REGISTER_STAT_GROUP_TELEPHONY,
        mtp3_sum_gtk_sum_cb, NULL, NULL, NULL);
}
