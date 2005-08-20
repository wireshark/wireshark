/* ansi_a_stat.c
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * MUCH code modified from service_response_time_table.c.
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
 * This TAP provides statistics for the ANSI A-Interface:
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
#include "stat_menu.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include <epan/tap.h>
#include "../register.h"
#include <epan/dissectors/packet-bssap.h>
#include <epan/dissectors/packet-ansi_a.h>
#include "../globals.h"
#include "filter_dlg.h"
#include "compat_macros.h"
#include "gui_utils.h"


typedef struct column_arrows {
    GtkWidget		*table;
    GtkWidget		*ascend_pm;
    GtkWidget		*descend_pm;
} column_arrows;

typedef struct _ansi_a_stat_dlg_t {
    GtkWidget		*win;
    GtkWidget		*scrolled_win;
    GtkWidget		*table;
    char		*entries[3];
} ansi_a_stat_dlg_t;

typedef struct _ansi_a_stat_t {
    int			bsmap_message_type[0xff];
    int			dtap_message_type[0xff];
} ansi_a_stat_t;


static ansi_a_stat_dlg_t	dlg_bsmap;
static ansi_a_stat_dlg_t	dlg_dtap;
static ansi_a_stat_t		stat;


static void
ansi_a_stat_reset(
    void		*tapdata)
{
    ansi_a_stat_t	*stat_p = tapdata;

    memset(stat_p, 0, sizeof(ansi_a_stat_t));
}


static int
ansi_a_stat_packet(
    void		*tapdata,
    packet_info		*pinfo _U_,
    epan_dissect_t	*edt _U_,
    const void		*data)
{
    ansi_a_stat_t	*stat_p = tapdata;
    const ansi_a_tap_rec_t	*data_p = data;

    switch (data_p->pdu_type)
    {
    case BSSAP_PDU_TYPE_BSMAP:
	stat_p->bsmap_message_type[data_p->message_type]++;
	break;

    case BSSAP_PDU_TYPE_DTAP:
	stat_p->dtap_message_type[data_p->message_type]++;
	break;

    default:
	/*
	 * unknown PDU type !!!
	 */
	return(0);
    }

    return(1);
}


static void
ansi_a_stat_draw(
    void		*tapdata)
{
    ansi_a_stat_t	*stat_p = tapdata;
    int			i, j;
    char		*strp;

    if (dlg_bsmap.win && tapdata)
    {
	i = 0;

	while (ansi_a_ios401_bsmap_strings[i].strptr)
	{
	    j = gtk_clist_find_row_from_data(GTK_CLIST(dlg_bsmap.table), (gpointer) i);

	    strp = g_strdup_printf("%d",
		    stat_p->bsmap_message_type[ansi_a_ios401_bsmap_strings[i].value]);
	    gtk_clist_set_text(GTK_CLIST(dlg_bsmap.table), j, 2, strp);
	    g_free(strp);

	    i++;
	}

	gtk_clist_sort(GTK_CLIST(dlg_bsmap.table));
    }

    if (dlg_dtap.win && tapdata)
    {
	i = 0;

	while (ansi_a_ios401_dtap_strings[i].strptr)
	{
	    j = gtk_clist_find_row_from_data(GTK_CLIST(dlg_dtap.table), (gpointer) i);

	    strp = g_strdup_printf("%d",
		    stat_p->dtap_message_type[ansi_a_ios401_dtap_strings[i].value]);
	    gtk_clist_set_text(GTK_CLIST(dlg_dtap.table), j, 2, strp);
	    g_free(strp);

	    i++;
	}

	gtk_clist_sort(GTK_CLIST(dlg_dtap.table));
    }
}


static void
ansi_a_stat_gtk_click_column_cb(
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
ansi_a_stat_gtk_sort_column(
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
ansi_a_stat_gtk_win_destroy_cb(
    GtkWindow		*win _U_,
    gpointer		user_data _U_)
{
    memset((void *) user_data, 0, sizeof(ansi_a_stat_dlg_t));
}


static void
ansi_a_stat_gtk_win_create(
    ansi_a_stat_dlg_t	*dlg_p,
    const char		*title)
{
#define	INIT_TABLE_NUM_COLUMNS	3
    const char		*default_titles[] = { "IEI", "Message Name", "Count" };
    int			i;
    column_arrows	*col_arrows;
    GtkWidget		*column_lb;
    GtkWidget		*vbox;
    GtkWidget		*bt_close;
    GtkWidget		*bbox;


    dlg_p->win = window_new(GTK_WINDOW_TOPLEVEL, title);
    gtk_window_set_default_size(GTK_WINDOW(dlg_p->win), 480, 450);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(dlg_p->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    dlg_p->scrolled_win = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), dlg_p->scrolled_win, TRUE, TRUE, 0);

    dlg_p->table = gtk_clist_new(INIT_TABLE_NUM_COLUMNS);

    col_arrows =
	(column_arrows *) g_malloc(sizeof(column_arrows) * INIT_TABLE_NUM_COLUMNS);

    for (i = 0; i < INIT_TABLE_NUM_COLUMNS; i++)
    {
        col_arrows[i].table = gtk_table_new(2, 2, FALSE);

        gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);

        column_lb = gtk_label_new(default_titles[i]);

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

        gtk_clist_set_column_widget(GTK_CLIST(dlg_p->table), i, col_arrows[i].table);
        gtk_widget_show(col_arrows[i].table);
    }
    gtk_clist_column_titles_show(GTK_CLIST(dlg_p->table));

    gtk_clist_set_compare_func(GTK_CLIST(dlg_p->table), ansi_a_stat_gtk_sort_column);
    gtk_clist_set_sort_column(GTK_CLIST(dlg_p->table), 0);
    gtk_clist_set_sort_type(GTK_CLIST(dlg_p->table), GTK_SORT_ASCENDING);

    gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), 0, 50);
    gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), 1, 280);
    gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), 2, 50);

    gtk_clist_set_shadow_type(GTK_CLIST(dlg_p->table), GTK_SHADOW_IN);
    gtk_clist_column_titles_show(GTK_CLIST(dlg_p->table));
    gtk_container_add(GTK_CONTAINER(dlg_p->scrolled_win), dlg_p->table);

    SIGNAL_CONNECT(dlg_p->table, "click-column", ansi_a_stat_gtk_click_column_cb, col_arrows);

	/* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    bt_close = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(dlg_p->win, bt_close, window_cancel_button_cb);

    SIGNAL_CONNECT(dlg_p->win, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(dlg_p->win, "destroy", ansi_a_stat_gtk_win_destroy_cb, dlg_p);

    gtk_widget_show_all(dlg_p->win);
    window_present(dlg_p->win);
}


/*
 * Never gets called ?
 */
static void
ansi_a_stat_gtk_init(
    const char		*optarg _U_)
{
    /* does not appear to be called */
}


static void
ansi_a_stat_gtk_bsmap_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    int			i;
    char		str[100];


    /*
     * if the window is already open, bring it to front
     */
    if (dlg_bsmap.win)
    {
	gdk_window_raise(dlg_bsmap.win->window);
	return;
    }

    ansi_a_stat_gtk_win_create(&dlg_bsmap, "ANSI A-I/F BSMAP Statistics");

    i = 0;
    while (ansi_a_ios401_bsmap_strings[i].strptr)
    {
	g_snprintf(str, 100, "0x%02x", ansi_a_ios401_bsmap_strings[i].value);
	dlg_bsmap.entries[0] = g_strdup(str);

	dlg_bsmap.entries[1] = g_strdup(ansi_a_ios401_bsmap_strings[i].strptr);

	dlg_bsmap.entries[2] = g_strdup("0");

	gtk_clist_insert(GTK_CLIST(dlg_bsmap.table), i, dlg_bsmap.entries);
	gtk_clist_set_row_data(GTK_CLIST(dlg_bsmap.table), i, (gpointer) i);

	i++;
    }

    ansi_a_stat_draw(&stat);
}


static void
ansi_a_stat_gtk_dtap_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    int			i;
    char		str[100];


    /*
     * if the window is already open, bring it to front
     */
    if (dlg_dtap.win)
    {
	gdk_window_raise(dlg_dtap.win->window);
	return;
    }

    ansi_a_stat_gtk_win_create(&dlg_dtap, "ANSI A-I/F DTAP Statistics");

    i = 0;
    while (ansi_a_ios401_dtap_strings[i].strptr)
    {
	g_snprintf(str, 100, "0x%02x", ansi_a_ios401_dtap_strings[i].value);
	dlg_dtap.entries[0] = g_strdup(str);

	dlg_dtap.entries[1] = g_strdup(ansi_a_ios401_dtap_strings[i].strptr);

	dlg_dtap.entries[2] = g_strdup("0");

	gtk_clist_insert(GTK_CLIST(dlg_dtap.table), i, dlg_dtap.entries);
	gtk_clist_set_row_data(GTK_CLIST(dlg_dtap.table), i, (gpointer) i);

	i++;
    }

    ansi_a_stat_draw(&stat);
}


void
register_tap_listener_gtkansi_a_stat(void)
{
    GString		*err_p;


    register_stat_cmd_arg("ansi_a,", ansi_a_stat_gtk_init);

    memset((void *) &stat, 0, sizeof(ansi_a_stat_t));

    err_p =
	register_tap_listener("ansi_a", &stat, NULL,
	    ansi_a_stat_reset,
	    ansi_a_stat_packet,
	    ansi_a_stat_draw);

    if (err_p != NULL)
    {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, err_p->str);
	g_string_free(err_p, TRUE);

	exit(1);
    }

    register_stat_menu_item("ANSI/A-Interface BSMAP", REGISTER_STAT_GROUP_TELEPHONY, 
        ansi_a_stat_gtk_bsmap_cb, NULL, NULL ,NULL);
    register_stat_menu_item("ANSI/A-Interface DTAP", REGISTER_STAT_GROUP_TELEPHONY,
        ansi_a_stat_gtk_dtap_cb, NULL, NULL ,NULL);
}
