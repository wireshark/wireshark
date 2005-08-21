/* gsm_a_stat.c
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
 * This TAP provides statistics for the GSM A-Interface:
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
#include "gtk_stat_menu.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include <epan/tap.h>
#include "../register.h"
#include <epan/dissectors/packet-bssap.h>
#include <epan/dissectors/packet-gsm_a.h>
#include "../globals.h"
#include "filter_dlg.h"
#include "compat_macros.h"
#include "gui_utils.h"


typedef struct column_arrows {
    GtkWidget		*table;
    GtkWidget		*ascend_pm;
    GtkWidget		*descend_pm;
} column_arrows;

typedef struct _gsm_a_stat_dlg_t {
    GtkWidget		*win;
    GtkWidget		*scrolled_win;
    GtkWidget		*table;
    char		*entries[3];
} gsm_a_stat_dlg_t;

typedef struct _gsm_a_stat_t {
    int		bssmap_message_type[0xff];
    int		dtap_mm_message_type[0xff];
    int		dtap_rr_message_type[0xff];
    int		dtap_cc_message_type[0xff];
    int		dtap_gmm_message_type[0xff];
    int		dtap_sms_message_type[0xff];
    int		dtap_sm_message_type[0xff];
    int		dtap_ss_message_type[0xff];
} gsm_a_stat_t;


static gsm_a_stat_dlg_t		dlg_bssmap;
static gsm_a_stat_dlg_t		dlg_dtap_mm;
static gsm_a_stat_dlg_t		dlg_dtap_rr;
static gsm_a_stat_dlg_t		dlg_dtap_cc;
static gsm_a_stat_dlg_t		dlg_dtap_gmm;
static gsm_a_stat_dlg_t		dlg_dtap_sms;
static gsm_a_stat_dlg_t		dlg_dtap_sm;
static gsm_a_stat_dlg_t		dlg_dtap_ss;
static gsm_a_stat_t		stat;


static void
gsm_a_stat_reset(
    void		*tapdata)
{
    gsm_a_stat_t	*stat_p = tapdata;

    memset(stat_p, 0, sizeof(gsm_a_stat_t));
}


static int
gsm_a_stat_packet(
    void		*tapdata,
    packet_info		*pinfo _U_,
    epan_dissect_t	*edt _U_,
    const void		*data)
{
    gsm_a_stat_t	*stat_p = tapdata;
    const gsm_a_tap_rec_t	*data_p = data;

    switch (data_p->pdu_type)
    {
    case BSSAP_PDU_TYPE_BSSMAP:
	stat_p->bssmap_message_type[data_p->message_type]++;
	break;

    case BSSAP_PDU_TYPE_DTAP:
	switch (data_p->protocol_disc)
	{
	case PD_CC:
	    stat_p->dtap_cc_message_type[data_p->message_type]++;
	    break;
	case PD_MM:
	    stat_p->dtap_mm_message_type[data_p->message_type]++;
	    break;
	case PD_RR:
	    stat_p->dtap_rr_message_type[data_p->message_type]++;
	    break;
	case PD_GMM:
	    stat_p->dtap_gmm_message_type[data_p->message_type]++;
	    break;
	case PD_SMS:
	    stat_p->dtap_sms_message_type[data_p->message_type]++;
	    break;
	case PD_SM:
	    stat_p->dtap_sm_message_type[data_p->message_type]++;
	    break;
	case PD_SS:
	    stat_p->dtap_ss_message_type[data_p->message_type]++;
	    break;
	default:
	    /*
	     * unsupported PD
	     */
	    return(0);
	}
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
gsm_a_stat_draw_aux(
    gsm_a_stat_dlg_t	*dlg_p,
    int			*message_count,
    const value_string	*msg_strings)
{
    int			i, j;
    char		*strp;


    if (dlg_p->win != NULL)
    {
	i = 0;

	while (msg_strings[i].strptr)
	{
	    j = gtk_clist_find_row_from_data(GTK_CLIST(dlg_p->table), (gpointer) i);

	    strp = g_strdup_printf("%d", message_count[msg_strings[i].value]);
	    gtk_clist_set_text(GTK_CLIST(dlg_p->table), j, 2, strp);
	    g_free(strp);

	    i++;
	}

	gtk_clist_sort(GTK_CLIST(dlg_p->table));
    }
}

static void
gsm_a_stat_draw(
    void		*tapdata)
{
    gsm_a_stat_t	*stat_p = tapdata;

	if (!tapdata) return;

    if (dlg_bssmap.win != NULL)
    {
	gsm_a_stat_draw_aux(&dlg_bssmap,
	    stat_p->bssmap_message_type,
	    gsm_a_bssmap_msg_strings);
    }

    if (dlg_dtap_mm.win != NULL)
    {
	gsm_a_stat_draw_aux(&dlg_dtap_mm,
	    stat_p->dtap_mm_message_type,
	    gsm_a_dtap_msg_mm_strings);
    }

    if (dlg_dtap_rr.win != NULL)
    {
	gsm_a_stat_draw_aux(&dlg_dtap_rr,
	    stat_p->dtap_rr_message_type,
	    gsm_a_dtap_msg_rr_strings);
    }

    if (dlg_dtap_cc.win != NULL)
    {
	gsm_a_stat_draw_aux(&dlg_dtap_cc,
	    stat_p->dtap_cc_message_type,
	    gsm_a_dtap_msg_cc_strings);
    }

    if (dlg_dtap_gmm.win != NULL)
    {
	gsm_a_stat_draw_aux(&dlg_dtap_gmm,
	    stat_p->dtap_gmm_message_type,
	    gsm_a_dtap_msg_gmm_strings);
    }

    if (dlg_dtap_sms.win != NULL)
    {
	gsm_a_stat_draw_aux(&dlg_dtap_sms,
	    stat_p->dtap_sms_message_type,
	    gsm_a_dtap_msg_sms_strings);
    }

    if (dlg_dtap_sm.win != NULL)
    {
	gsm_a_stat_draw_aux(&dlg_dtap_sm,
	    stat_p->dtap_sm_message_type,
	    gsm_a_dtap_msg_sm_strings);
    }

    if (dlg_dtap_ss.win != NULL)
    {
	gsm_a_stat_draw_aux(&dlg_dtap_ss,
	    stat_p->dtap_ss_message_type,
	    gsm_a_dtap_msg_ss_strings);
    }
}


static void
gsm_a_stat_gtk_click_column_cb(
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
gsm_a_stat_gtk_sort_column(
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
gsm_a_stat_gtk_win_destroy_cb(
    GtkWindow		*win _U_,
    gpointer		user_data _U_)
{
    memset((void *) user_data, 0, sizeof(gsm_a_stat_dlg_t));
}


static void
gsm_a_stat_gtk_win_create(
    gsm_a_stat_dlg_t	*dlg_p,
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
    gtk_window_set_default_size(GTK_WINDOW(dlg_p->win), 490, 500);

    vbox = gtk_vbox_new(FALSE, 3);
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

    gtk_clist_set_compare_func(GTK_CLIST(dlg_p->table), gsm_a_stat_gtk_sort_column);
    gtk_clist_set_sort_column(GTK_CLIST(dlg_p->table), 0);
    gtk_clist_set_sort_type(GTK_CLIST(dlg_p->table), GTK_SORT_ASCENDING);

    gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), 0, 50);
    gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), 1, 330);
    gtk_clist_set_column_width(GTK_CLIST(dlg_p->table), 2, 50);

    gtk_clist_set_shadow_type(GTK_CLIST(dlg_p->table), GTK_SHADOW_IN);
    gtk_clist_column_titles_show(GTK_CLIST(dlg_p->table));
    gtk_container_add(GTK_CONTAINER(dlg_p->scrolled_win), dlg_p->table);

    SIGNAL_CONNECT(dlg_p->table, "click-column", gsm_a_stat_gtk_click_column_cb, col_arrows);

	/* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    bt_close = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(dlg_p->win, bt_close, window_cancel_button_cb);

    SIGNAL_CONNECT(dlg_p->win, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(dlg_p->win, "destroy", gsm_a_stat_gtk_win_destroy_cb, dlg_p);

    gtk_widget_show_all(dlg_p->win);
    window_present(dlg_p->win);
}


static void
gsm_a_stat_gtk_bssmap_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    int			i;


    /*
     * if the window is already open, bring it to front
     */
    if (dlg_bssmap.win)
    {
	gdk_window_raise(dlg_bssmap.win->window);
	return;
    }

    gsm_a_stat_gtk_win_create(&dlg_bssmap, "GSM A-I/F BSSMAP Statistics");

    i = 0;
    while (gsm_a_bssmap_msg_strings[i].strptr)
    {
	dlg_bssmap.entries[0] = g_strdup_printf("0x%02x",
						gsm_a_bssmap_msg_strings[i].value);

	dlg_bssmap.entries[1] = g_strdup(gsm_a_bssmap_msg_strings[i].strptr);

	dlg_bssmap.entries[2] = g_strdup("0");

	gtk_clist_insert(GTK_CLIST(dlg_bssmap.table), i, dlg_bssmap.entries);
	gtk_clist_set_row_data(GTK_CLIST(dlg_bssmap.table), i, (gpointer) i);

	i++;
    }

    gsm_a_stat_draw(&stat);
}


static void
gsm_a_stat_gtk_bssmap_init(
    const char		*optarg _U_)
{
    gsm_a_stat_gtk_bssmap_cb(NULL, NULL);
}


static void
gsm_a_stat_gtk_dtap_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_,
    gsm_a_stat_dlg_t	*dlg_dtap_p,
    const char		*title,
    const value_string	*dtap_msg_strings)
{
    int			i;


    /*
     * if the window is already open, bring it to front
     */
    if (dlg_dtap_p->win)
    {
	gdk_window_raise(dlg_dtap_p->win->window);
	return;
    }

    gsm_a_stat_gtk_win_create(dlg_dtap_p, title);

    i = 0;
    while (dtap_msg_strings[i].strptr)
    {
	dlg_dtap_p->entries[0] = g_strdup_printf("0x%02x",
						 dtap_msg_strings[i].value);

	dlg_dtap_p->entries[1] = g_strdup(dtap_msg_strings[i].strptr);

	dlg_dtap_p->entries[2] = g_strdup("0");

	gtk_clist_insert(GTK_CLIST(dlg_dtap_p->table), i, dlg_dtap_p->entries);
	gtk_clist_set_row_data(GTK_CLIST(dlg_dtap_p->table), i, (gpointer) i);

	i++;
    }

    gsm_a_stat_draw(&stat);
}

static void
gsm_a_stat_gtk_dtap_mm_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_mm,
	"GSM A-I/F DTAP Mobility Management Statistics",
	gsm_a_dtap_msg_mm_strings);
}

static void
gsm_a_stat_gtk_dtap_mm_init(
    const char		*optarg _U_)
{
    gsm_a_stat_gtk_dtap_mm_cb(NULL, NULL);
}

static void
gsm_a_stat_gtk_dtap_rr_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_rr,
	"GSM A-I/F DTAP Radio Resource Management Statistics",
	gsm_a_dtap_msg_rr_strings);
}

static void
gsm_a_stat_gtk_dtap_rr_init(
    const char		*optarg _U_)
{
    gsm_a_stat_gtk_dtap_rr_cb(NULL, NULL);
}

static void
gsm_a_stat_gtk_dtap_cc_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_cc,
	"GSM A-I/F DTAP Call Control Statistics",
	gsm_a_dtap_msg_cc_strings);
}

static void
gsm_a_stat_gtk_dtap_cc_init(
    const char		*optarg _U_)
{
    gsm_a_stat_gtk_dtap_cc_cb(NULL, NULL);
}

static void
gsm_a_stat_gtk_dtap_gmm_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_gmm,
	"GSM A-I/F DTAP GPRS Mobility Management Statistics",
	gsm_a_dtap_msg_gmm_strings);
}

static void
gsm_a_stat_gtk_dtap_gmm_init(
    const char		*optarg _U_)
{
    gsm_a_stat_gtk_dtap_gmm_cb(NULL, NULL);
}

static void
gsm_a_stat_gtk_dtap_sms_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_sms,
	"GSM A-I/F DTAP Short Message Service Statistics",
	gsm_a_dtap_msg_sms_strings);
}

static void
gsm_a_stat_gtk_dtap_sms_init(
    const char		*optarg _U_)
{
    gsm_a_stat_gtk_dtap_sms_cb(NULL, NULL);
}

static void
gsm_a_stat_gtk_dtap_sm_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_sm,
	"GSM A-I/F DTAP GPRS Session Management Statistics",
	gsm_a_dtap_msg_sm_strings);
}

static void
gsm_a_stat_gtk_dtap_sm_init(
    const char		*optarg _U_)
{
    gsm_a_stat_gtk_dtap_sm_cb(NULL, NULL);
}

static void
gsm_a_stat_gtk_dtap_ss_cb(
    GtkWidget		*w _U_,
    gpointer		d _U_)
{
    gsm_a_stat_gtk_dtap_cb(w, d, &dlg_dtap_ss,
	"GSM A-I/F DTAP Supplementary Services Statistics",
	gsm_a_dtap_msg_ss_strings);
}

static void
gsm_a_stat_gtk_dtap_ss_init(
    const char		*optarg _U_)
{
    gsm_a_stat_gtk_dtap_ss_cb(NULL, NULL);
}


void
register_tap_listener_gtkgsm_a_stat(void)
{
    GString		*err_p;


    memset((void *) &stat, 0, sizeof(gsm_a_stat_t));

    err_p =
	register_tap_listener("gsm_a", &stat, NULL,
	    gsm_a_stat_reset,
	    gsm_a_stat_packet,
	    gsm_a_stat_draw);

    if (err_p != NULL)
    {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, err_p->str);
	g_string_free(err_p, TRUE);

	exit(1);
    }

    register_stat_menu_item("GSM/A-Interface BSSMAP", REGISTER_STAT_GROUP_TELEPHONY,
	gsm_a_stat_gtk_bssmap_cb, NULL, NULL, NULL);
    register_stat_cmd_arg("gsm_a,bssmap", gsm_a_stat_gtk_bssmap_init);

    register_stat_menu_item("GSM/A-Interface DTAP/Mobility Management", REGISTER_STAT_GROUP_TELEPHONY,
	gsm_a_stat_gtk_dtap_mm_cb, NULL, NULL, NULL);
    register_stat_cmd_arg("gsm_a,dtap_mm", gsm_a_stat_gtk_dtap_mm_init);

    register_stat_menu_item("GSM/A-Interface DTAP/Radio Resource Management", REGISTER_STAT_GROUP_TELEPHONY,
	gsm_a_stat_gtk_dtap_rr_cb, NULL, NULL, NULL);
    register_stat_cmd_arg("gsm_a,dtap_rr", gsm_a_stat_gtk_dtap_rr_init);

    register_stat_menu_item("GSM/A-Interface DTAP/Call Control", REGISTER_STAT_GROUP_TELEPHONY,
	gsm_a_stat_gtk_dtap_cc_cb, NULL, NULL, NULL);
    register_stat_cmd_arg("gsm_a,dtap_cc", gsm_a_stat_gtk_dtap_cc_init);

    register_stat_menu_item("GSM/A-Interface DTAP/GPRS Mobility Management", REGISTER_STAT_GROUP_TELEPHONY,
	gsm_a_stat_gtk_dtap_gmm_cb, NULL, NULL, NULL);
    register_stat_cmd_arg("gsm_a,dtap_gmm", gsm_a_stat_gtk_dtap_gmm_init);

    register_stat_menu_item("GSM/A-Interface DTAP/Short Message Service", REGISTER_STAT_GROUP_TELEPHONY,
	gsm_a_stat_gtk_dtap_sms_cb, NULL, NULL, NULL);
    register_stat_cmd_arg("gsm_a,dtap_sms", gsm_a_stat_gtk_dtap_sms_init);

    register_stat_menu_item("GSM/A-Interface DTAP/GPRS Session Management", REGISTER_STAT_GROUP_TELEPHONY,
	gsm_a_stat_gtk_dtap_sm_cb, NULL, NULL, NULL);
    register_stat_cmd_arg("gsm_a,dtap_sm", gsm_a_stat_gtk_dtap_sm_init);

    register_stat_menu_item("GSM/A-Interface DTAP/Supplementary Services", REGISTER_STAT_GROUP_TELEPHONY,
	gsm_a_stat_gtk_dtap_ss_cb, NULL, NULL, NULL);
    register_stat_cmd_arg("gsm_a,dtap_ss", gsm_a_stat_gtk_dtap_ss_init);
}
