/* mtp3_stat.c
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Modified from gsm_map_stat.c
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

/*
 * This TAP provides statistics for MTP3:
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <string.h>

#include "epan/packet_info.h"
#include "epan/epan.h"
#include "epan/value_string.h"
#include <epan/stat_cmd_args.h>
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include <epan/tap.h>
#include <epan/emem.h>
#include "../register.h"
#include "../globals.h"
#include "filter_dlg.h"
#include "compat_macros.h"
#include "gui_utils.h"

#include <epan/dissectors/packet-mtp3.h>
#include "mtp3_stat.h"

typedef struct column_arrows {
    GtkWidget		*table;
    GtkWidget		*ascend_pm;
    GtkWidget		*descend_pm;
} column_arrows;

#define	MTP3_INIT_TABLE_NUM_COLUMNS		6

typedef struct _my_columns_t {
    guint32		value;
    const gchar		*strptr;
    GtkJustification	just;
} my_columns_t;

static my_columns_t columns[MTP3_INIT_TABLE_NUM_COLUMNS] = {
    { 80,	"OPC",			GTK_JUSTIFY_LEFT },
    { 80,	"DPC",			GTK_JUSTIFY_LEFT },
    { 110,	"SI",			GTK_JUSTIFY_LEFT },
    { 80,	"Num MSUs",		GTK_JUSTIFY_RIGHT },
    { 100,	"Num Bytes",		GTK_JUSTIFY_RIGHT },
    { 80,	"Avg Bytes",		GTK_JUSTIFY_RIGHT }
};

typedef struct _mtp3_stat_dlg_t {
    GtkWidget		*win;
    GtkWidget		*scrolled_win;
    GtkWidget		*table;
    char		*entries[MTP3_INIT_TABLE_NUM_COLUMNS];
} mtp3_stat_dlg_t;

static mtp3_stat_dlg_t	dlg;

mtp3_stat_t		mtp3_stat[MTP3_MAX_NUM_OPC_DPC];
guint8			mtp3_num_used;


static void
mtp3_stat_reset(
    void		*tapdata)
{
    mtp3_stat_t		(*stat_p)[MTP3_MAX_NUM_OPC_DPC] = tapdata;

    mtp3_num_used = 0;
    memset(stat_p, 0, MTP3_MAX_NUM_OPC_DPC * sizeof(mtp3_stat_t));

    if (dlg.win != NULL)
    {
	gtk_clist_clear(GTK_CLIST(dlg.table));
    }
}


static int
mtp3_stat_packet(
    void		*tapdata,
    packet_info		*pinfo _U_,
    epan_dissect_t	*edt _U_,
    const void		*data)
{
    mtp3_stat_t		(*stat_p)[MTP3_MAX_NUM_OPC_DPC] = tapdata;
    const mtp3_tap_rec_t	*data_p = data;
    int				i;

    if (data_p->si_code >= MTP3_NUM_SI_CODE)
    {
	/*
	 * we thought this si_code was not used ?
	 * is MTP3_NUM_SI_CODE out of date ?
	 */
	return(0);
    }

    /*
     * look for opc/dpc pair
     */
    i = 0;
    while (i < mtp3_num_used)
    {
	if (memcmp(&data_p->addr_opc, &(*stat_p)[i].addr_opc, sizeof(mtp3_addr_pc_t)) == 0)
	{
	    if (memcmp(&data_p->addr_dpc, &(*stat_p)[i].addr_dpc, sizeof(mtp3_addr_pc_t)) == 0)
	    {
		break;
	    }
	}

	i++;
    }

    if (i == mtp3_num_used)
    {
	if (mtp3_num_used == MTP3_MAX_NUM_OPC_DPC)
	{
	    /*
	     * too many
	     */
	    return(0);
	}

	mtp3_num_used++;
    }

    (*stat_p)[i].addr_opc = data_p->addr_opc;
    (*stat_p)[i].addr_dpc = data_p->addr_dpc;
    (*stat_p)[i].si_code[data_p->si_code].num_msus++;
    (*stat_p)[i].si_code[data_p->si_code].size += data_p->size;

    return(1);
}


static void
mtp3_stat_draw(
    void		*tapdata)
{
    mtp3_stat_t		(*stat_p)[MTP3_MAX_NUM_OPC_DPC] = tapdata;
    int			i, j, row_offset;
    char		*str;

    if (!dlg.win || !tapdata)
    {
	return;
    }

    str=ep_alloc(256);
    i = 0;

    while (i < mtp3_num_used)
    {
	row_offset = i * MTP3_NUM_SI_CODE;

	mtp3_addr_to_str_buf((guint8 *) &(*stat_p)[i].addr_opc, str, 256);
	dlg.entries[0] = g_strdup(str);

	mtp3_addr_to_str_buf((guint8 *) &(*stat_p)[i].addr_dpc, str, 256);
	dlg.entries[1] = g_strdup(str);

	for (j=0; j < MTP3_NUM_SI_CODE; j++)
	{
	    dlg.entries[2] = g_strdup(mtp3_service_indicator_code_short_vals[j].strptr);

	    dlg.entries[3] = g_strdup_printf("%u", (*stat_p)[i].si_code[j].num_msus);

	    dlg.entries[4] = g_strdup_printf("%.0f", (*stat_p)[i].si_code[j].size);

	    dlg.entries[5] =
		g_strdup_printf("%.2f",
		    (*stat_p)[i].si_code[j].size/(*stat_p)[i].si_code[j].num_msus);

	    gtk_clist_insert(GTK_CLIST(dlg.table), row_offset + j, dlg.entries);
	}

	i++;
    }

    gtk_clist_sort(GTK_CLIST(dlg.table));
}


static void
mtp3_stat_gtk_click_column_cb(
    GtkCList		*clist,
    gint		column,
    gpointer		data)
{
    column_arrows	*col_arrows = (column_arrows *) data;
    int			i;


    gtk_clist_freeze(clist);

    for (i=0; i < MTP3_INIT_TABLE_NUM_COLUMNS; i++)
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
	 * Columns 0-1 sorted in descending order by default
	 */
	if (column <= 1)
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
mtp3_stat_gtk_sort_column(
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
    case 1:
    case 2:
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
mtp3_stat_gtk_win_destroy_cb(
    GtkWindow		*win _U_,
    gpointer		user_data _U_)
{
    memset((void *) user_data, 0, sizeof(mtp3_stat_dlg_t));
}


static void
mtp3_stat_gtk_win_create(
    mtp3_stat_dlg_t	*dlg_p,
    const char		*title)
{
    int			i;
    column_arrows	*col_arrows;
    GtkWidget		*column_lb;
    GtkWidget		*vbox;
    GtkWidget		*bt_close;
    GtkWidget		*bbox;


    dlg_p->win = window_new(GTK_WINDOW_TOPLEVEL, title);
    gtk_window_set_default_size(GTK_WINDOW(dlg_p->win), 640, 390);

    vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(dlg_p->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    dlg_p->scrolled_win = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), dlg_p->scrolled_win, TRUE, TRUE, 0);

    dlg_p->table = gtk_clist_new(MTP3_INIT_TABLE_NUM_COLUMNS);

    col_arrows =
	(column_arrows *) g_malloc(sizeof(column_arrows) * MTP3_INIT_TABLE_NUM_COLUMNS);

    for (i = 0; i < MTP3_INIT_TABLE_NUM_COLUMNS; i++)
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

	gtk_clist_set_column_justification(GTK_CLIST(dlg_p->table), i, columns[i].just);

	gtk_clist_set_column_widget(GTK_CLIST(dlg_p->table), i, col_arrows[i].table);
	gtk_widget_show(col_arrows[i].table);
    }
    gtk_clist_column_titles_show(GTK_CLIST(dlg_p->table));

    gtk_clist_set_compare_func(GTK_CLIST(dlg_p->table), mtp3_stat_gtk_sort_column);
    gtk_clist_set_sort_column(GTK_CLIST(dlg_p->table), 0);
    gtk_clist_set_sort_type(GTK_CLIST(dlg_p->table), GTK_SORT_ASCENDING);

    for (i = 0; i < MTP3_INIT_TABLE_NUM_COLUMNS; i++)
    {
	gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), i, columns[i].value);
    }

    gtk_clist_set_shadow_type(GTK_CLIST(dlg_p->table), GTK_SHADOW_IN);
    gtk_clist_column_titles_show(GTK_CLIST(dlg_p->table));
    gtk_container_add(GTK_CONTAINER(dlg_p->scrolled_win), dlg_p->table);

    SIGNAL_CONNECT(dlg_p->table, "click-column", mtp3_stat_gtk_click_column_cb, col_arrows);

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    bt_close = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(dlg_p->win, bt_close, window_cancel_button_cb);

    SIGNAL_CONNECT(dlg_p->win, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(dlg_p->win, "destroy", mtp3_stat_gtk_win_destroy_cb, dlg_p);

    gtk_widget_show_all(dlg_p->win);
    window_present(dlg_p->win);
}


static void
mtp3_stat_gtk_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{

    /*
     * if the window is already open, bring it to front
     */
    if (dlg.win)
    {
	gdk_window_raise(dlg.win->window);
	return;
    }

    mtp3_stat_gtk_win_create(&dlg, "MTP3 Statistics");

    mtp3_stat_draw(NULL);
}


static void
mtp3_stat_gtk_init(
    const char		*optarg _U_)
{
    mtp3_stat_gtk_cb(NULL, NULL);
}


void
register_tap_listener_gtkmtp3_stat(void)
{
    GString		*err_p;


    memset((void *) &mtp3_stat, 0, sizeof(mtp3_stat_t));

    err_p =
	register_tap_listener("mtp3", &mtp3_stat, NULL,
	    mtp3_stat_reset,
	    mtp3_stat_packet,
	    mtp3_stat_draw);

    if (err_p != NULL)
    {
	simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, err_p->str);
	g_string_free(err_p, TRUE);

	exit(1);
    }

    register_stat_menu_item("MTP3/MSUs",  REGISTER_STAT_GROUP_TELEPHONY,
        mtp3_stat_gtk_cb, NULL, NULL, NULL);
    register_stat_cmd_arg("mtp3,msus", mtp3_stat_gtk_init);
}
