/* fc_stat.c
 * fc_stat   2003 Ronnie Sahlberg
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
#include <epan/conversation.h>
#include <epan/dissectors/packet-fc.h>
#include "../register.h"
#include "../timestats.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "../file.h"
#include "../globals.h"
#include "filter_dlg.h"
#include "service_response_time_table.h"
#include "../stat_menu.h"
#include "../tap_dfilter_dlg.h"
#include "gtkglobals.h"


/* used to keep track of the statistics for an entire program interface */
typedef struct _fcstat_t {
	GtkWidget *win;
	srt_stat_table fc_srt_table;
} fcstat_t;

static void
fcstat_set_title(fcstat_t *fc)
{
	char		*title;

	title = g_strdup_printf("Fibre Channel Service Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(fc->win), title);
	g_free(title);
}

static void
fcstat_reset(void *pfc)
{
	fcstat_t *fc=(fcstat_t *)pfc;

	reset_srt_table_data(&fc->fc_srt_table);
	fcstat_set_title(fc);
}

static int
fcstat_packet(void *pfc, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	const fc_hdr *fc=psi;
	fcstat_t *fs=(fcstat_t *)pfc;

	/* we are only interested in reply packets */
	if(!(fc->fctl&FC_FCTL_EXCHANGE_RESPONDER)){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if( (!fc->itlq) || (fc->itlq->first_exchange_frame==0) ){
		return 0;
	}

	add_srt_table_data(&fs->fc_srt_table, fc->type, &fc->itlq->fc_time, pinfo);

	return 1;
}



static void
fcstat_draw(void *pfc)
{
	fcstat_t *fc=(fcstat_t *)pfc;

	draw_srt_table_data(&fc->fc_srt_table);
}


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	fcstat_t *fc=(fcstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(fc);
	unprotect_thread_critical_region();

	free_srt_table_data(&fc->fc_srt_table);
	g_free(fc);
}


static void
gtk_fcstat_init(const char *optarg, void *userdata _U_)
{
	fcstat_t *fc;
	const char *filter=NULL;
	GtkWidget *label;
	char filter_string[256];
	GString *error_string;
	int i;
	GtkWidget *vbox;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	if(!strncmp(optarg,"fc,srt,",7)){
		filter=optarg+7;
	} else {
		filter=NULL;
	}

	fc=g_malloc(sizeof(fcstat_t));

	fc->win=window_new(GTK_WINDOW_TOPLEVEL, "fc-stat");
	gtk_window_set_default_size(GTK_WINDOW(fc->win), 550, 400);
	fcstat_set_title(fc);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(fc->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	label=gtk_label_new("Fibre Channel Service Response Time statistics");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	g_snprintf(filter_string,255,"Filter:%s",filter?filter:"");
	label=gtk_label_new(filter_string);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	label=gtk_label_new("Fibre Channel Types");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(fc->win);

	init_srt_table(&fc->fc_srt_table, 256, vbox, NULL);
	for(i=0;i<256;i++){
		init_srt_table_row(&fc->fc_srt_table, i, val_to_str(i, fc_fc4_val, "Unknown(0x%02x)"));
	}


	error_string=register_tap_listener("fc", fc, filter, fcstat_reset, fcstat_packet, fcstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(fc);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button(fc->win, close_bt, window_cancel_button_cb);

	SIGNAL_CONNECT(fc->win, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(fc->win, "destroy", win_destroy_cb, fc);

	gtk_widget_show_all(fc->win);
	window_present(fc->win);

	cf_retap_packets(&cfile, FALSE);
}

static tap_dfilter_dlg fc_stat_dlg = {
	"Fibre Channel Service Response Time statistics",
	"fc,srt",
	gtk_fcstat_init,
	-1
};

void
register_tap_listener_gtkfcstat(void)
{
	register_dfilter_stat(&fc_stat_dlg, "Fibre Channel",
	    REGISTER_STAT_GROUP_RESPONSE_TIME);
}
