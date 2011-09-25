/* gtp_stat.c
 * gtp_stat   2008 Kari Tiirikainen
 * Largely based on ldap_stat by Ronnie Sahlberg, all mistakes added by KTi
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/value_string.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-gtp.h>

#include "../timestats.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../stat_menu.h"

#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/service_response_time_table.h"
#include "gtk/tap_param_dlg.h"
#include "gtk/gtkglobals.h"
#include "gtk/main.h"

#include "gtk/old-gtk-compat.h"

/* used to keep track of the statistics for an entire program interface */
typedef struct _gtpstat_t {
	GtkWidget *win;
	srt_stat_table gtp_srt_table;
} gtpstat_t;

static void
gtpstat_set_title(gtpstat_t *gtp)
{
	char		*title;

	title = g_strdup_printf("GTP Control Plane  Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(gtp->win), title);
	g_free(title);
}

static void
gtpstat_reset(void *pgtp)
{
	gtpstat_t *gtp=(gtpstat_t *)pgtp;

	reset_srt_table_data(&gtp->gtp_srt_table);
	gtpstat_set_title(gtp);
}

static int
gtpstat_packet(void *pgtp, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	const gtp_msg_hash_t *gtp=psi;
	gtpstat_t *fs=(gtpstat_t *)pgtp;
	int idx=0;

	/* we are only interested in reply packets */
	if(gtp->is_request){
		return 0;
	}
	/* if we have not seen the request, just ignore it */
	if(!gtp->req_frame){
		return 0;
	}

	/* Only use the commands we know how to handle, this is not a comprehensive list */
	/* Redoing the message indexing is bit reduntant,                    */
	/*  but using message type as such would yield a long gtp_srt_table. */
	/*  Only a fraction of the messages are matchable req/resp pairs,    */
	/*  it just doesn't feel feasible.                                   */

	switch(gtp->msgtype){
 	case GTP_MSG_ECHO_REQ: idx=0;
		break;
 	case GTP_MSG_CREATE_PDP_REQ: idx=1;
		break;
	case GTP_MSG_UPDATE_PDP_REQ: idx=2;
		break;
	case GTP_MSG_DELETE_PDP_REQ: idx=3;
		break;
	default:
		return 0;
	}

	add_srt_table_data(&fs->gtp_srt_table, idx, &gtp->req_time, pinfo);

	return 1;
}



static void
gtpstat_draw(void *pgtp)
{
	gtpstat_t *gtp=(gtpstat_t *)pgtp;

	draw_srt_table_data(&gtp->gtp_srt_table);
}


static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	gtpstat_t *gtp=(gtpstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(gtp);
	unprotect_thread_critical_region();

	free_srt_table_data(&gtp->gtp_srt_table);
	g_free(gtp);
}


static void
gtk_gtpstat_init(const char *optarg, void *userdata _U_)
{
	gtpstat_t *gtp;
	const char *filter=NULL;
	GtkWidget *label;
	char *filter_string;
	GString *error_string;
	GtkWidget *vbox;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	if(!strncmp(optarg,"gtp,",4)){
		filter=optarg+4;
	} else {
		filter="gtp"; /*NULL doesn't work here like in LDAP. Too little time/lazy to find out why ?*/
	}

	gtp=g_malloc(sizeof(gtpstat_t));

	gtp->win = dlg_window_new("gtp-stat");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(gtp->win), TRUE);

	gtk_window_set_default_size(GTK_WINDOW(gtp->win), 550, 400);
	gtpstat_set_title(gtp);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(gtp->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	label=gtk_label_new("GTP Service Response Time statistics");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	filter_string = g_strdup_printf("Filter: %s", filter ? filter : "");
	label=gtk_label_new(filter_string);
	g_free(filter_string);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	label=gtk_label_new("GTP Requests");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(gtp->win);

	init_srt_table(&gtp->gtp_srt_table, 4, vbox, NULL);
	init_srt_table_row(&gtp->gtp_srt_table, 0, "Echo");
	init_srt_table_row(&gtp->gtp_srt_table, 1, "Create PDP context");
	init_srt_table_row(&gtp->gtp_srt_table, 2, "Update PDP context");
	init_srt_table_row(&gtp->gtp_srt_table, 3, "Delete PDP context");

	error_string=register_tap_listener("gtp", gtp, filter, 0, gtpstat_reset, gtpstat_packet, gtpstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		g_free(gtp);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(gtp->win, close_bt, window_cancel_button_cb);

	g_signal_connect(gtp->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(gtp->win, "destroy", G_CALLBACK(win_destroy_cb), gtp);

	gtk_widget_show_all(gtp->win);
	window_present(gtp->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(gtp->win));
}

static tap_param gtp_stat_params[] = {
	{ PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg gtp_stat_dlg = {
	"GTP Control Plane Response Time Statistics",
	"gtp",
	gtk_gtpstat_init,
	-1,
	G_N_ELEMENTS(gtp_stat_params),
	gtp_stat_params
};

void
register_tap_listener_gtkgtpstat(void)
{
	register_dfilter_stat(&gtp_stat_dlg, "GTP",
	    REGISTER_STAT_GROUP_RESPONSE_TIME);
}

void gtp_srt_cb(GtkAction *action, gpointer user_data _U_)
{
	tap_param_dlg_cb(action, &gtp_stat_dlg);
}

