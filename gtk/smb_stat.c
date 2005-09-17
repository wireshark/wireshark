/* smb_stat.c
 * smb_stat   2003 Ronnie Sahlberg
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/value_string.h>

#include <epan/tap.h>
#include <epan/dissectors/packet-smb.h>
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
typedef struct _smbstat_t {
	GtkWidget *win;
	srt_stat_table smb_srt_table;
	srt_stat_table trans2_srt_table;
	srt_stat_table nt_trans_srt_table;
} smbstat_t;

static void
smbstat_set_title(smbstat_t *ss)
{
	char *title;

	title = g_strdup_printf("SMB Service Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(ss->win), title);
	g_free(title);
}

static void
smbstat_reset(void *pss)
{
	smbstat_t *ss=(smbstat_t *)pss;

	reset_srt_table_data(&ss->smb_srt_table);
	reset_srt_table_data(&ss->trans2_srt_table);
	reset_srt_table_data(&ss->nt_trans_srt_table);
	smbstat_set_title(ss);
}

static int
smbstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	smbstat_t *ss=(smbstat_t *)pss;
	const smb_info_t *si=psi;

	/* we are only interested in reply packets */
	if(si->request){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if(!si->sip){
		return 0;
	}

	add_srt_table_data(&ss->smb_srt_table, si->cmd, &si->sip->req_time, pinfo);

	if(si->cmd==0xA0 && si->sip->extra_info_type == SMB_EI_NTI){
		smb_nt_transact_info_t *sti=(smb_nt_transact_info_t *)si->sip->extra_info;

		if(sti){
			add_srt_table_data(&ss->nt_trans_srt_table, sti->subcmd, &si->sip->req_time, pinfo);
		}
	} else if(si->cmd==0x32 && si->sip->extra_info_type == SMB_EI_T2I){
		smb_transact2_info_t *st2i=(smb_transact2_info_t *)si->sip->extra_info;

		if(st2i){
			add_srt_table_data(&ss->trans2_srt_table, st2i->subcmd, &si->sip->req_time, pinfo);
		}
	}

	return 1;
}



static void
smbstat_draw(void *pss)
{
	smbstat_t *ss=(smbstat_t *)pss;

	draw_srt_table_data(&ss->smb_srt_table);
	draw_srt_table_data(&ss->trans2_srt_table);
	draw_srt_table_data(&ss->nt_trans_srt_table);
}


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	smbstat_t *ss=(smbstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ss);
	unprotect_thread_critical_region();

	free_srt_table_data(&ss->smb_srt_table);
	free_srt_table_data(&ss->trans2_srt_table);
	free_srt_table_data(&ss->nt_trans_srt_table);
	g_free(ss);
}


static void
gtk_smbstat_init(const char *optarg)
{
	smbstat_t *ss;
	const char *filter=NULL;
	GtkWidget *label;
	char filter_string[256];
	GString *error_string;
	int i;
	GtkWidget *vbox;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	if(!strncmp(optarg,"smb,srt,",8)){
		filter=optarg+8;
	} else {
		filter=NULL;
	}

	ss=g_malloc(sizeof(smbstat_t));

	ss->win=window_new(GTK_WINDOW_TOPLEVEL, "smb-stat");
	gtk_window_set_default_size(GTK_WINDOW(ss->win), 550, 600);
	smbstat_set_title(ss);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(ss->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	label=gtk_label_new("SMB Service Response Time statistics");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	g_snprintf(filter_string,255,"Filter:%s",filter?filter:"");
	label=gtk_label_new(filter_string);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	label=gtk_label_new("SMB Commands");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(ss->win);

	init_srt_table(&ss->smb_srt_table, 256, vbox, "smb.cmd");
	for(i=0;i<256;i++){
		init_srt_table_row(&ss->smb_srt_table, i, val_to_str(i, smb_cmd_vals, "Unknown(0x%02x)"));
	}


	label=gtk_label_new("Transaction2 Sub-Commands");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	init_srt_table(&ss->trans2_srt_table, 256, vbox, "smb.trans2.cmd");
	for(i=0;i<256;i++){
		init_srt_table_row(&ss->trans2_srt_table, i, val_to_str(i, trans2_cmd_vals, "Unknown(0x%02x)"));
	}


	label=gtk_label_new("NT Transaction Sub-Commands");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	init_srt_table(&ss->nt_trans_srt_table, 256, vbox, "smb.nt.function");
	for(i=0;i<256;i++){
		init_srt_table_row(&ss->nt_trans_srt_table, i, val_to_str(i, nt_cmd_vals, "Unknown(0x%02x)"));
	}


	error_string=register_tap_listener("smb", ss, filter, smbstat_reset, smbstat_packet, smbstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ss);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button(ss->win, close_bt, window_cancel_button_cb);

	SIGNAL_CONNECT(ss->win, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(ss->win, "destroy", win_destroy_cb, ss);

	gtk_widget_show_all(ss->win);
	window_present(ss->win);
	
	cf_retap_packets(&cfile, FALSE);
}

static tap_dfilter_dlg smb_stat_dlg = {
	"SMB SRT Statistics",
	"smb,srt",
	gtk_smbstat_init,
	-1
};

void
register_tap_listener_gtksmbstat(void)
{
	register_dfilter_stat(&smb_stat_dlg, "SMB",
	    REGISTER_STAT_GROUP_RESPONSE_TIME);
}
