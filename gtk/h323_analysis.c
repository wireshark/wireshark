/* h323_analysis.c
 * H323 analysis addition for ethereal
 *
 * $Id$
 *
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*do not define this symbol. will be added soon*/
/*#define USE_CONVERSATION_GRAPH 1*/

#include "h323_analysis.h"
#include "h323_conversations.h"
#include "h323_conversations_dlg.h"

#include <epan/epan_dissect.h>
#include <epan/filesystem.h>

#include "globals.h"

#include "util.h"
#include <epan/tap.h>

#include <epan/dissectors/packet-h225.h>
#include <epan/dissectors/packet-h245.h>

/* in /gtk ... */
#include "dlg_utils.h"
#include "ui_util.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include "tap_menu.h"
#include "main.h"
#include "progress_dlg.h"
#include "compat_macros.h"

#include <string.h>

/****************************************************************************/
/* structure that holds general information about the connection */
typedef struct _user_data_t {
        /* tap associated data*/
        guint32 ip_src;
        guint16 port_src;
        guint32 ip_dst;
        guint16 port_dst;
        guint32 ip_src_h245;
        guint16 port_src_h245;
        guint16 transport;

	GtkWidget *window;
	GtkCList *clist1;
	GtkWidget *label_stats;
	GtkCList *selected_clist1;
	gint selected_row;

} user_data_t;

/* Column titles. */
static gchar *titles[7] =  {
	"Packet",
	"Time",
	"Delay",
	"             Side A",
	"Direction",
	"             Side B",
	"Comment"
};

typedef const guint8 * ip_addr_p;

static gint32 last_sec = 0, last_usec = 0;


/****************************************************************************/
/* TAP FUNCTIONS */

/****************************************************************************/
/* when there is a [re]reading of packet's */
static void
h225_reset(void *user_data_arg _U_)
{
	last_sec = 0;
	last_usec = 0;
	return;
}

/****************************************************************************/
/* here we can redraw the output */
/* not used yet */
static void h225_draw(void *prs _U_)
{
	return;
}


static const GdkColor COLOR_DEFAULT = {0, 0xffff, 0xffff, 0xffff};
static const GdkColor COLOR_ERROR = {0, 0xffff, 0xbfff, 0xbfff};
static const GdkColor COLOR_WARNING = {0, 0xffff, 0xdfff, 0xbfff};
static const GdkColor COLOR_CN = {0, 0xbfff, 0xbfff, 0xffff};

/****************************************************************************/
/* append a line to clist1 */
static void add_to_clist1(GtkCList *clist1, guint32 number, gchar *time,
                         double delay, gchar *sideA, gboolean direction, gchar *sideB,
                         gchar *comment, GdkColor *color)
{
        guint added_row;
        gchar *data[7];
        gchar field[7][32];

        data[0]=&field[0][0];
        data[1]=&field[1][0];
        data[2]=&field[2][0];
        data[3]=&field[3][0];
        data[4]=&field[4][0];
        data[5]=&field[5][0];
        data[6]=&field[6][0];

        g_snprintf(field[0], 32, "%u", number);
        g_snprintf(field[1], 32, "%s", time);
        g_snprintf(field[2], 32, "%f", delay);
        g_snprintf(field[3], 32, "%s", sideA);
        g_snprintf(field[4], 20, "%s", direction? "---->" : "<----");
        g_snprintf(field[5], 32, "%s", sideB);
        g_snprintf(field[6], 32, "%s", comment);

        added_row = gtk_clist_append(GTK_CLIST(clist1), data);
        gtk_clist_set_row_data(GTK_CLIST(clist1), added_row, GUINT_TO_POINTER(number));
        gtk_clist_set_background(GTK_CLIST(clist1), added_row, color);
}


/****************************************************************************/
/* whenever a h225 packet is seen by the tap listener */
static int h225_packet(void *user_data_arg, packet_info *pinfo, epan_dissect_t *edt _U_, void *h225info_arg)
{
	user_data_t *user_data = user_data_arg;
	h225_packet_info *h225ptr_info = h225info_arg;	
	GdkColor color = COLOR_DEFAULT;

        gchar timeStr[32];
        gchar message[32];
	guint32 src, dst;
	double delay;
	gint32 delay_sec, delay_usec;

	/* time since beginning of capture */
        g_snprintf(timeStr, sizeof(timeStr), "%d.%06d", pinfo->fd->rel_secs, pinfo->fd->rel_usecs);

	/* time since previous packet seen in tap listener */
	delay_sec = pinfo->fd->rel_secs - last_sec;
	delay_usec = pinfo->fd->rel_usecs - last_usec;
	
	delay = (double)delay_sec + ((double)delay_usec)/1000000;

	last_sec = pinfo->fd->rel_secs;
	last_usec = pinfo->fd->rel_usecs;

	switch (h225ptr_info->cs_type) {
		
		case H225_SETUP:
			g_snprintf(message, sizeof(message),"H225 Setup");
			break;
		case H225_CALL_PROCEDING:
			g_snprintf(message, sizeof(message),"H225 Call Proceding");
			break;
		case H225_ALERTING:
			g_snprintf(message, sizeof(message),"H225 Alerting");
			break;
		case H225_CONNECT:
			g_snprintf(message, sizeof(message),"H225 Connect");
			break;
		case H225_RELEASE_COMPLET:
			g_snprintf(message, sizeof(message),"H225 Release Complet");
			break;
		case H225_OTHER:
			g_snprintf(message, sizeof(message),"H225 Other");
		}

	g_memmove(&src, pinfo->src.data, 4);
        g_memmove(&dst, pinfo->dst.data, 4);

	if (src == user_data->ip_src)
		add_to_clist1(user_data->clist1,pinfo->fd->num,timeStr,delay,message, 1, "", "", &color);
	else
		add_to_clist1(user_data->clist1, pinfo->fd->num, timeStr,delay, "", 0, message, "", &color);

	return 0;
}


/****************************************************************************/
/* whenever a h245 packet is seen by the tap listener */
static int h245_packet(void *user_data_arg, packet_info *pinfo, epan_dissect_t *edt _U_, void *h245info_arg)
{

	user_data_t *user_data = user_data_arg;
	h245_packet_info *h245ptr_info = h245info_arg;	
	GdkColor color = COLOR_DEFAULT;

        gchar timeStr[32];
        gchar message[32];
	guint32 src, dst;
	double delay;
	gint32 delay_sec, delay_usec;

	/* time since beginning of capture */
        g_snprintf(timeStr, sizeof(timeStr), "%d.%06d", pinfo->fd->rel_secs, pinfo->fd->rel_usecs);

	/* time since previous packet seen in tap listener */
	delay_sec = pinfo->fd->rel_secs - last_sec;
	delay_usec = pinfo->fd->rel_usecs - last_usec;
	
	delay = (double)delay_sec + ((double)delay_usec)/1000000;

	last_sec = pinfo->fd->rel_secs;
	last_usec = pinfo->fd->rel_usecs;

	switch (h245ptr_info->msg_type) {
		
		case H245_TermCapSet:
			g_snprintf(message, sizeof(message),"H245 TermCapSet");
			break;
		case H245_TermCapSetAck:
			g_snprintf(message, sizeof(message),"H245_TermCapSetAck");
			break;
		case H245_TermCapSetRjc:
			g_snprintf(message, sizeof(message),"H245_TermCapSetRjc");
			break;
		case H245_TermCapSetRls:
			g_snprintf(message, sizeof(message),"H245_TermCapSetRls");
			break;
		case H245_OpenLogChn:
			g_snprintf(message, sizeof(message),"H245_OpenLogChn");
			break;
		case H245_OpenLogChnCnf:
			g_snprintf(message, sizeof(message),"H245_OpenLogChnCnf");
			break;
		case H245_OpenLogChnAck:
			g_snprintf(message, sizeof(message),"H245_OpenLogChnAck");
			break;
		case H245_OpenLogChnRjc:
			g_snprintf(message, sizeof(message),"H245_OpenLogChnRjc");
			break;
		case H245_CloseLogChn:
			g_snprintf(message, sizeof(message),"H245_CloseLogChn");
			break;
		case H245_CloseLogChnAck:
			g_snprintf(message, sizeof(message),"H245_CloseLogChnAck");
			break;
		case H245_MastSlvDet:
			g_snprintf(message, sizeof(message),"H245_MastSlvDet");
			break;
		case H245_MastSlvDetAck:
			g_snprintf(message, sizeof(message),"H245_MastSlvDetAck");
			break;
		case H245_MastSlvDetRjc:
			g_snprintf(message, sizeof(message),"H245_MastSlvDetRjc");
			break;
		case H245_MastSlvDetRls:
			g_snprintf(message, sizeof(message),"H245_MastSlvDetRls");
			break;
		case H245_OTHER:
			g_snprintf(message, sizeof(message),"H225 Other");
		}

	g_memmove(&src, pinfo->src.data, 4);
        g_memmove(&dst, pinfo->dst.data, 4);

	if (src == user_data->ip_src)
		add_to_clist1(user_data->clist1,pinfo->fd->num,timeStr,delay,message, 1, "", "", &color);
	else
		add_to_clist1(user_data->clist1, pinfo->fd->num, timeStr,delay, "", 0, message, "", &color);

	return 0;
}


/**************** Callbacks *************************************************/
/****************************************************************************/
/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);


/****************************************************************************/
/* close the dialog window and remove the tap listener */
static void on_destroy(GtkWidget *win _U_, user_data_t *user_data _U_)
{
        g_free(user_data);
}

/****************************************************************************/
static void on_clist_select_row(GtkCList        *clist1 _U_,
                                gint             row _U_,
                                gint             column _U_,
                                GdkEvent        *event _U_,
                                user_data_t     *user_data _U_)
{
        user_data->selected_clist1 = clist1;
        user_data->selected_row = row;
}

/****************************************************************************/
static void on_goto_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
        guint fnumber;

        if (user_data->selected_clist1!=NULL) {
                fnumber = GPOINTER_TO_UINT(gtk_clist_get_row_data(
                        GTK_CLIST(user_data->selected_clist1), user_data->selected_row) );
               goto_frame(&cfile, fnumber);
        }
}


/****************************************************************************/
/* re-dissects all packets */
static void on_refresh_bt_clicked(GtkWidget *bt _U_, user_data_t *user_data _U_)
{
        gchar filter_text_h225[256];
        gchar filter_text_h245[256];
        /*gchar filter_text_rtp[256];*/
        dfilter_t *sfcode;
        GString *error_string;

        /* clear the dialog box clists */
        gtk_clist_clear(GTK_CLIST(user_data->clist1));

        /* try to compile the filter for h225 */
	g_snprintf(filter_text_h225,sizeof(filter_text_h225),
        "h225 && (( ip.src==%s && %s.srcport==%u && ip.dst==%s && %s.dstport==%u ) || ( ip.src==%s && %s.srcport==%u && ip.dst==%s && %s.dstport==%u ))",
                ip_to_str((ip_addr_p)&(user_data->ip_src)),
				transport_prot_name[user_data->transport],
                user_data->port_src,
                ip_to_str((ip_addr_p)&(user_data->ip_dst)),
				transport_prot_name[user_data->transport],
                user_data->port_dst,
                ip_to_str((ip_addr_p)&(user_data->ip_dst)),
				transport_prot_name[user_data->transport],
                user_data->port_dst,
                ip_to_str((ip_addr_p)&(user_data->ip_src)),
				transport_prot_name[user_data->transport],
                user_data->port_src
                );

        if (!dfilter_compile(filter_text_h225, &sfcode)) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, dfilter_error_msg);
                return;
        }

        /* try to compile the filter for h245 */
	g_snprintf(filter_text_h245,sizeof(filter_text_h245), 
        "h245 && (( ip.src==%s && %s.srcport==%u ) || ( ip.dst==%s && %s.dstport==%u ))",
                ip_to_str((ip_addr_p)&(user_data->ip_src_h245)),
				transport_prot_name[user_data->transport],
                user_data->port_src_h245,
                ip_to_str((ip_addr_p)&(user_data->ip_src_h245)),
				transport_prot_name[user_data->transport],
                user_data->port_src_h245
                );

        if (!dfilter_compile(filter_text_h245, &sfcode)) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, dfilter_error_msg);
                return;
        }

	/* register tap h225 listener */
        error_string = register_tap_listener("h225", user_data, filter_text_h225,
                h225_reset, h225_packet, h225_draw);
        if (error_string != NULL) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
                        g_string_free(error_string, TRUE);
                return;
        }

	/* register tap h245 listener */
        error_string = register_tap_listener("h245", user_data, filter_text_h245,
                NULL, h245_packet, NULL);
        if (error_string != NULL) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
                        g_string_free(error_string, TRUE);
                return;
        }

        /* retap all packets */
        retap_packets(&cfile);

        /* remove tap listener again */
        protect_thread_critical_region();
        remove_tap_listener(user_data);
        remove_tap_listener(user_data);
        unprotect_thread_critical_region();

}


/************************************************************************************/
/************** Create the dialog box with all widgets ******************************/
void create_h225_dialog(user_data_t* user_data)
{
        GtkWidget *window = NULL;
        GtkWidget *clist_h225;
        /*GtkWidget *label_stats;*/

        GtkWidget *main_vb;
        GtkWidget *label;
        GtkWidget *scrolled_window;
        GtkWidget *box4, *goto_bt, *close_bt, *refresh_bt;
        GtkTooltips *tooltips = gtk_tooltips_new();

        gchar label_forward[150];

        gchar str_ip_src[16];
        gchar str_ip_dst[16];

        /* as multiple analysis windows can be opened, 
         * don't use window_new_with_geom(), as that will place them on top of each other! */
	window = window_new(GTK_WINDOW_TOPLEVEL, "Ethereal: H.323 VoIP Analysis");
        gtk_window_set_default_size(GTK_WINDOW(window), 700, 350);

        /* Container for each row of widgets */
        main_vb = gtk_vbox_new(FALSE, 2);
        gtk_container_add(GTK_CONTAINER(window), main_vb);
        gtk_container_set_border_width(GTK_CONTAINER(main_vb), 2);
        gtk_widget_show(main_vb);

        strcpy(str_ip_src, ip_to_str((ip_addr_p)&user_data->ip_src));
        strcpy(str_ip_dst, ip_to_str((ip_addr_p)&user_data->ip_dst));

        g_snprintf(label_forward, 149,
                "\nAnalysing H.323 Call between  %s port %u (Side A) and  %s port %u (Side B)\n",
                str_ip_src, user_data->port_src, str_ip_dst, user_data->port_dst);

        /* label */
        label = gtk_label_new(label_forward);
        gtk_box_pack_start (GTK_BOX (main_vb), label, FALSE, FALSE, 0);

        /* scrolled window */
        scrolled_window = scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                        GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
        gtk_box_pack_start (GTK_BOX (main_vb), scrolled_window, TRUE, TRUE, 0);

        /* place for some statistics */
        /*label_stats = gtk_label_new("\n");*/
        /*gtk_box_pack_start(GTK_BOX(main_vb), label_stats, FALSE, FALSE, 0);*/

        /* packet clist */
	clist_h225 = gtk_clist_new_with_titles(7, titles);
        gtk_container_add(GTK_CONTAINER(scrolled_window), clist_h225);
        gtk_widget_show(clist_h225);
	SIGNAL_CONNECT(clist_h225, "select_row", on_clist_select_row, user_data);

        /* column widths and justification */
        gtk_clist_set_column_width(GTK_CLIST(clist_h225), 0, 45);
        gtk_clist_set_column_width(GTK_CLIST(clist_h225), 1, 90);
        gtk_clist_set_column_width(GTK_CLIST(clist_h225), 2, 90);
        gtk_clist_set_column_width(GTK_CLIST(clist_h225), 3, 140);
        gtk_clist_set_column_width(GTK_CLIST(clist_h225), 4, 60);
        gtk_clist_set_column_width(GTK_CLIST(clist_h225), 5, 140);
        gtk_clist_set_column_justification(GTK_CLIST(clist_h225), 0, GTK_JUSTIFY_CENTER);
        gtk_clist_set_column_justification(GTK_CLIST(clist_h225), 1, GTK_JUSTIFY_CENTER);
        gtk_clist_set_column_justification(GTK_CLIST(clist_h225), 2, GTK_JUSTIFY_CENTER);
        gtk_clist_set_column_justification(GTK_CLIST(clist_h225), 3, GTK_JUSTIFY_LEFT);
        gtk_clist_set_column_justification(GTK_CLIST(clist_h225), 4, GTK_JUSTIFY_CENTER);
        gtk_clist_set_column_justification(GTK_CLIST(clist_h225), 5, GTK_JUSTIFY_LEFT);
        gtk_clist_set_column_justification(GTK_CLIST(clist_h225), 6, GTK_JUSTIFY_CENTER);

        gtk_widget_show(scrolled_window);

        /* buttons */
        box4 = gtk_hbutton_box_new();
        gtk_box_pack_start(GTK_BOX(main_vb), box4, FALSE, FALSE, 0);
        gtk_container_set_border_width(GTK_CONTAINER(box4), 10);
        gtk_button_box_set_layout(GTK_BUTTON_BOX (box4), GTK_BUTTONBOX_END);
        gtk_button_box_set_spacing(GTK_BUTTON_BOX (box4), 10);
        gtk_button_box_set_child_ipadding(GTK_BUTTON_BOX (box4), 4, 0);
        gtk_widget_show(box4);

	refresh_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_REFRESH);
        gtk_container_add(GTK_CONTAINER(box4), refresh_bt);
        gtk_widget_show(refresh_bt);
        SIGNAL_CONNECT(refresh_bt, "clicked", on_refresh_bt_clicked, user_data);
        gtk_tooltips_set_tip (tooltips, refresh_bt, "Refresh data", NULL);

	goto_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_JUMP_TO);
        gtk_container_add(GTK_CONTAINER(box4), goto_bt);
        gtk_widget_show(goto_bt);
        SIGNAL_CONNECT(goto_bt, "clicked", on_goto_bt_clicked, user_data);
        gtk_tooltips_set_tip (tooltips, goto_bt, "Jump to the selected packet", NULL);

        close_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
        gtk_container_add(GTK_CONTAINER(box4), close_bt);
	GTK_WIDGET_SET_FLAGS(close_bt, GTK_CAN_DEFAULT);
        gtk_widget_show(close_bt);
        gtk_tooltips_set_tip (tooltips, close_bt, "Close this dialog", NULL);
	window_set_cancel_button(window, close_bt, window_cancel_button_cb);

	SIGNAL_CONNECT(window, "delete_event", window_delete_event_cb, NULL);
        SIGNAL_CONNECT(window, "destroy", on_destroy, user_data);

	gtk_widget_show_all(window);
	window_present(window);

	/* some widget references need to be saved for outside use */
	user_data->window = window;
        user_data->clist1 = GTK_CLIST(clist_h225);
        user_data->label_stats = label;
        user_data->selected_clist1 = GTK_CLIST(clist_h225);
        user_data->selected_row = 0;
}


/****************************************************************************/
void h323_analysis(
                guint32 ip_src,
                guint16 port_src,
                guint32 ip_dst,
                guint16 port_dst,
                guint32 ip_src_h245,
                guint16 port_src_h245,
                guint16 transport
                )
{
        user_data_t *user_data;

        /* init */
        user_data = g_malloc(sizeof(user_data_t));

        user_data->ip_src = ip_src;
        user_data->port_src = port_src;
        user_data->ip_dst = ip_dst;
        user_data->port_dst = port_dst;
        user_data->ip_src_h245 = ip_src_h245;
        user_data->port_src_h245 = port_src_h245;
        user_data->transport = transport;

	/* create the dialog box */
        create_h225_dialog(user_data);

	/* proceed as if the Refresh button would have been pressed */
        on_refresh_bt_clicked(NULL, user_data);
}


