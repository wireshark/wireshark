/* ansi_map_stat.c
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * MUCH code modified from service_response_time_table.c.
 *
 * $Id: ansi_map_stat.c,v 1.8 2004/01/03 18:05:55 sharpe Exp $
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
 * This TAP provides statistics for ANSI MAP:
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "epan/packet_info.h"
#include "epan/epan.h"
#include "epan/value_string.h"
#include "menu.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "tap.h"
#include "../register.h"
#include "../globals.h"
#include "filter_prefs.h"
#include "compat_macros.h"

#include "packet-ansi_map.h"

typedef struct column_arrows {
    GtkWidget		*table;
    GtkWidget		*ascend_pm;
    GtkWidget		*descend_pm;
} column_arrows;

typedef struct _ansi_map_stat_dlg_t {
    GtkWidget		*win;
    GtkWidget		*scrolled_win;
    GtkWidget		*table;
    char		*entries[3];
} ansi_map_stat_dlg_t;

#define N_MESSAGE_TYPES	256

typedef struct _ansi_map_stat_t {
    int			message_type[N_MESSAGE_TYPES];
} ansi_map_stat_t;

static ansi_map_stat_dlg_t	dlg;
static ansi_map_stat_t		stat;


static void
ansi_map_stat_reset(
    void		*tapdata)
{
    tapdata = tapdata;

    memset((void *) &stat, 0, sizeof(ansi_map_stat_t));
}


static int
ansi_map_stat_packet(
    void		*tapdata,
    packet_info		*pinfo,
    epan_dissect_t	*edt _U_,
    void		*data)
{
    ansi_map_tap_rec_t	*data_p = data;


    tapdata = tapdata;
    pinfo = pinfo;

    if (data_p->message_type > N_MESSAGE_TYPES)
    {
	/*
	 * unknown PDU type !!!
	 */
	return(0);
    }

    stat.message_type[data_p->message_type]++;

    return(1);
}


static void
ansi_map_stat_draw(
    void		*tapdata)
{
    int			i, j;
    char		str[256], *strp;


    tapdata = tapdata;

    if (dlg.win != NULL)
    {
	i = 0;

	while (ansi_map_opr_code_strings[i].strptr)
	{
	    j = gtk_clist_find_row_from_data(GTK_CLIST(dlg.table), (gpointer) i);

	    sprintf(str, "%d",
		stat.message_type[ansi_map_opr_code_strings[i].value]);
	    strp = g_strdup(str);
	    gtk_clist_set_text(GTK_CLIST(dlg.table), j, 2, strp);
	    g_free(strp);

	    i++;
	}

	gtk_clist_sort(GTK_CLIST(dlg.table));
    }
}


static void
ansi_map_stat_gtk_click_column_cb(
    GtkCList		*clist,
    gint		column,
    gpointer		data)
{
    column_arrows	*col_arrows = (column_arrows *) data;
    int			i;


    gtk_clist_freeze(clist);

    for (i=0; i < 3; i++)
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
	 * Columns 2 sorted in ascending order by default
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
ansi_map_stat_gtk_sort_column(
    GtkCList		*clist,
    gconstpointer	ptr1,
    gconstpointer	ptr2)
{
    GtkCListRow		*row1 = (GtkCListRow *) ptr1;
    GtkCListRow		*row2 = (GtkCListRow *) ptr2;
    char		*text1 = NULL;
    char		*text2 = NULL;
    int			i1, i2;

    text1 = GTK_CELL_TEXT(row1->cell[clist->sort_column])->text;
    text2 = GTK_CELL_TEXT(row2->cell[clist->sort_column])->text;

    switch (clist->sort_column)
    {
    case 0:
	/* FALLTHRU */

    case 2:
	i1 = strtol(text1, NULL, 0);
	i2 = strtol(text2, NULL, 0);
	return(i1 - i2);

    case 1:
	return(strcmp(text1, text2));
    }

    g_assert_not_reached();

    return(0);
}


static void
ansi_map_stat_gtk_dlg_close_cb(
    GtkButton		*button _U_,
    gpointer		user_data _U_)
{
    ansi_map_stat_dlg_t	*dlg_p = user_data;

    gtk_grab_remove(GTK_WIDGET(dlg_p->win));
    gtk_widget_destroy(GTK_WIDGET(dlg_p->win));
}


static void
ansi_map_stat_gtk_win_destroy_cb(
    GtkWindow		*win _U_,
    gpointer		user_data _U_)
{
    memset((void *) user_data, 0, sizeof(ansi_map_stat_dlg_t));
}


static void
ansi_map_stat_gtk_win_create(
    ansi_map_stat_dlg_t	*dlg_p,
    char		*title)
{
#define	INIT_TABLE_NUM_COLUMNS	3
    char		*default_titles[] = { "Op Code", "Operation Name", "Count" };
    int			i;
    column_arrows	*col_arrows;
    GdkBitmap		*ascend_bm, *descend_bm;
    GdkPixmap		*ascend_pm, *descend_pm;
    GtkStyle		*win_style;
    GtkWidget		*column_lb;
    GtkWidget		*vbox;
    GtkWidget		*bt_close;
    GtkWidget		*hbuttonbox;
    GtkWidget		*dialog_vbox;
    GtkWidget		*dialog_action_area;


    dlg_p->win = gtk_dialog_new();
    gtk_window_set_default_size(GTK_WINDOW(dlg_p->win), 500, 450);
    gtk_window_set_title(GTK_WINDOW(dlg_p->win), title);
    SIGNAL_CONNECT(dlg_p->win, "destroy", ansi_map_stat_gtk_win_destroy_cb, dlg_p);

    dialog_vbox = GTK_DIALOG(dlg_p->win)->vbox;
    gtk_widget_show(dialog_vbox);

    dialog_action_area = GTK_DIALOG(dlg_p->win)->action_area;
    gtk_widget_show(dialog_action_area);
    gtk_container_set_border_width(GTK_CONTAINER(dialog_action_area), 10);

    hbuttonbox = gtk_hbutton_box_new();
    gtk_widget_ref(hbuttonbox);
    OBJECT_SET_DATA_FULL(dlg_p->win, "hbuttonbox", hbuttonbox,
                         gtk_widget_unref);
    gtk_widget_show(hbuttonbox);
    gtk_box_pack_start(GTK_BOX(dialog_action_area), hbuttonbox, FALSE, FALSE, 0);
    gtk_button_box_set_layout(GTK_BUTTON_BOX(hbuttonbox), GTK_BUTTONBOX_END);
    gtk_button_box_set_spacing(GTK_BUTTON_BOX(hbuttonbox), 0);

    bt_close = gtk_button_new_with_label("Close");
    gtk_widget_ref(bt_close);
    OBJECT_SET_DATA_FULL(dlg_p->win, "bt_close", bt_close, gtk_widget_unref);
    gtk_widget_show(bt_close);
    gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_close);
    GTK_WIDGET_SET_FLAGS(bt_close, GTK_CAN_DEFAULT);
    SIGNAL_CONNECT(bt_close, "clicked", ansi_map_stat_gtk_dlg_close_cb, dlg_p);

    vbox = gtk_vbox_new(FALSE, 0);
    gtk_widget_ref(vbox);
    OBJECT_SET_DATA_FULL(dlg_p->win, "vbox", vbox, gtk_widget_unref);
    gtk_widget_show(vbox);
    gtk_box_pack_start(GTK_BOX(dialog_vbox), vbox, TRUE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);

    dlg_p->scrolled_win = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_ref(dlg_p->scrolled_win);
    OBJECT_SET_DATA_FULL(dlg_p->win, "scrolled_win", dlg_p->scrolled_win,
                         gtk_widget_unref);
    gtk_widget_show(dlg_p->scrolled_win);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(dlg_p->scrolled_win),
	GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
    gtk_box_pack_start(GTK_BOX(vbox), dlg_p->scrolled_win, TRUE, TRUE, 0);

    dlg_p->table = gtk_clist_new(INIT_TABLE_NUM_COLUMNS);
    gtk_widget_ref(dlg_p->table);
    OBJECT_SET_DATA_FULL(dlg_p->win, "table", dlg_p->table, gtk_widget_unref);
    gtk_widget_show(dlg_p->table);

    gtk_widget_show(dlg_p->win);

    col_arrows =
	(column_arrows *) g_malloc(sizeof(column_arrows) * INIT_TABLE_NUM_COLUMNS);

    win_style =
	gtk_widget_get_style(dlg_p->scrolled_win);

    ascend_pm =
	gdk_pixmap_create_from_xpm_d(dlg_p->scrolled_win->window,
	    &ascend_bm,
	    &win_style->bg[GTK_STATE_NORMAL],
	    (gchar **) clist_ascend_xpm);

    descend_pm =
	gdk_pixmap_create_from_xpm_d(dlg_p->scrolled_win->window,
	    &descend_bm,
	    &win_style->bg[GTK_STATE_NORMAL],
	    (gchar **)clist_descend_xpm);

    for (i = 0; i < INIT_TABLE_NUM_COLUMNS; i++)
    {
	col_arrows[i].table = gtk_table_new(2, 2, FALSE);

	gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);

	column_lb = gtk_label_new(default_titles[i]);

	gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb,
	    0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);

	gtk_widget_show(column_lb);

	col_arrows[i].ascend_pm =
	    gtk_pixmap_new(ascend_pm, ascend_bm);

	gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm,
	    1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);

	col_arrows[i].descend_pm =
	    gtk_pixmap_new(descend_pm, descend_bm);

	gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm,
	    1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);

	if (i == 0)
	{
	    /* default column sorting */
	    gtk_widget_show(col_arrows[i].ascend_pm);
	}

	gtk_clist_set_column_widget(GTK_CLIST(dlg_p->table), i, col_arrows[i].table);
	gtk_widget_show(col_arrows[i].table);
    }
    gtk_clist_column_titles_show(GTK_CLIST(dlg_p->table));

    gtk_clist_set_compare_func(GTK_CLIST(dlg_p->table), ansi_map_stat_gtk_sort_column);
    gtk_clist_set_sort_column(GTK_CLIST(dlg_p->table), 0);
    gtk_clist_set_sort_type(GTK_CLIST(dlg_p->table), GTK_SORT_ASCENDING);

    gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), 0, 60);
    gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), 1, 290);
    gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), 2, 50);

    gtk_clist_set_shadow_type(GTK_CLIST(dlg_p->table), GTK_SHADOW_IN);
    gtk_clist_column_titles_show(GTK_CLIST(dlg_p->table));
    gtk_container_add(GTK_CONTAINER(dlg_p->scrolled_win), dlg_p->table);

    SIGNAL_CONNECT(dlg_p->table, "click-column", ansi_map_stat_gtk_click_column_cb, col_arrows);
}


/*
 * Never gets called ?
 */
static void
ansi_map_stat_gtk_init(
    char		*optarg)
{
    /* does not appear to be called */

    optarg = optarg;
}


static void
ansi_map_stat_gtk_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    int			i;
    char		str[100];


    /*
     * if the window is already open, bring it to front
     */
    if (dlg.win)
    {
	gdk_window_raise(dlg.win->window);
	return;
    }

    ansi_map_stat_gtk_win_create(&dlg, "ANSI MAP Operation Statistics");

    i = 0;
    while (ansi_map_opr_code_strings[i].strptr)
    {
	sprintf(str, "0x%02x", ansi_map_opr_code_strings[i].value);
	dlg.entries[0] = g_strdup(str);

	dlg.entries[1] = g_strdup(ansi_map_opr_code_strings[i].strptr);

	dlg.entries[2] = g_strdup("0");

	gtk_clist_insert(GTK_CLIST(dlg.table), i, dlg.entries);
	gtk_clist_set_row_data(GTK_CLIST(dlg.table), i, (gpointer) i);

	i++;
    }

    ansi_map_stat_draw(NULL);
}


void
register_tap_listener_gtkansi_map_stat(void)
{
    GString		*err_p;


    register_ethereal_tap("ansi_map,", ansi_map_stat_gtk_init);

    memset((void *) &stat, 0, sizeof(ansi_map_stat_t));

    err_p =
	register_tap_listener("ansi_map", NULL, NULL,
	    ansi_map_stat_reset,
	    ansi_map_stat_packet,
	    ansi_map_stat_draw);

    if (err_p != NULL)
    {
	simple_dialog(ESD_TYPE_WARN, NULL, err_p->str);
	g_string_free(err_p, TRUE);

	exit(1);
    }
}


void
register_tap_menu_gtkansi_map_stat(void)
{
    register_tap_menu_item("_Statistics/ANSI MAP Operation", ansi_map_stat_gtk_cb, NULL, NULL, NULL);
}
