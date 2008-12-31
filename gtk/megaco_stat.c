/* megaco_stat.c
 * megaco-statistics for Wireshark
 * Copyright 2003 Lars Roland
 * Copyright 2008  Balint Reczey <balint.reczey@ericsson.com>
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
#include "epan/gcp.h"

#include "../register.h"
#include "../timestats.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../globals.h"
#include "../stat_menu.h"

#include "gtk/gui_stat_util.h"
#include "gtk/dlg_utils.h"
#include "gtk/tap_dfilter_dlg.h"
#include "gtk/gui_utils.h"
#include "gtk/main.h"


#define NUM_TIMESTATS 11

#define GCP_CMD_REPLY_CASE \
        case GCP_CMD_ADD_REPLY: \
        case GCP_CMD_MOVE_REPLY: \
        case GCP_CMD_MOD_REPLY: \
        case GCP_CMD_SUB_REPLY: \
        case GCP_CMD_AUDITCAP_REPLY: \
        case GCP_CMD_AUDITVAL_REPLY: \
        case GCP_CMD_NOTIFY_REPLY: \
        case GCP_CMD_SVCCHG_REPLY: \
        case GCP_CMD_TOPOLOGY_REPLY: \
        case GCP_CMD_REPLY: 

#define GCP_CMD_REQ_CASE \
        case GCP_CMD_ADD_REQ: \
        case GCP_CMD_MOVE_REQ: \
        case GCP_CMD_MOD_REQ: \
        case GCP_CMD_SUB_REQ: \
        case GCP_CMD_AUDITCAP_REQ: \
        case GCP_CMD_AUDITVAL_REQ: \
        case GCP_CMD_NOTIFY_REQ: \
        case GCP_CMD_SVCCHG_REQ: \
        case GCP_CMD_TOPOLOGY_REQ: \
        case GCP_CMD_CTX_ATTR_AUDIT_REQ: \
        case GCP_CMD_OTHER_REQ:

/* used to keep track of the statistics for an entire program interface */
typedef struct _megacostat_t {
	GtkWidget *win;
	GtkWidget *vbox;
	char *filter;
	GtkWidget *scrolled_window;
	GtkCList *table;
        timestat_t rtd[NUM_TIMESTATS];
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
} megacostat_t;

static const value_string megaco_message_type[] = {
  {  0,	"ADD "},
  {  1,	"MOVE"},
  {  2,	"MDFY"},
  {  3,	"SUBT"},
  {  4,	"AUCP"},
  {  5,	"AUVL"},
  {  6,	"NTFY"},
  {  7, "SVCC"},
  {  8, "TOPO"},
  {  9, "NONE"},
  {  0, NULL}
};

static void
megacostat_reset(void *pms)
{
	megacostat_t *ms=(megacostat_t *)pms;
	int i;

	for(i=0;i<NUM_TIMESTATS;i++) {
		ms->rtd[i].num=0;
		ms->rtd[i].min_num=0;
		ms->rtd[i].max_num=0;
		ms->rtd[i].min.secs=0;
        	ms->rtd[i].min.nsecs=0;
        	ms->rtd[i].max.secs=0;
        	ms->rtd[i].max.nsecs=0;
        	ms->rtd[i].tot.secs=0;
        	ms->rtd[i].tot.nsecs=0;
	}

	ms->open_req_num=0;
	ms->disc_rsp_num=0;
	ms->req_dup_num=0;
	ms->rsp_dup_num=0;
}

static gboolean
megacostat_is_duplicate_reply(const gcp_cmd_t* cmd)
{
	switch (cmd->type) {

        GCP_CMD_REPLY_CASE
		{
			gcp_cmd_msg_t *cmd_msg;
			/* cycle through commands to find same command in the transaction */
			for (cmd_msg = cmd->trx->cmds; cmd_msg->cmd->msg->framenum != cmd->msg->framenum &&
					cmd_msg != NULL; cmd_msg = cmd_msg->next) {
				if (cmd_msg->cmd->type == cmd->type)
					return TRUE;
			}
				
			return FALSE;
		}
		break;
	default:
		return FALSE;
		break;
	}

	
}

static gboolean
megacostat_had_request(const gcp_cmd_t* cmd)
{
	switch (cmd->type) {

        GCP_CMD_REPLY_CASE
		{
			gcp_cmd_msg_t *cmd_msg;
			/* cycle through commands to find a request in the transaction */
			for (cmd_msg = cmd->trx->cmds; cmd_msg->cmd->msg->framenum != cmd->msg->framenum &&
					cmd_msg != NULL; cmd_msg = cmd_msg->next) {
				
				switch (cmd_msg->cmd->type) {

        			GCP_CMD_REQ_CASE
					return TRUE;
					break;
				default:
					return FALSE;
					break;
				}
			}
				
			return FALSE;
		}
		break;
	default:
		return FALSE;
		break;
	}
}

static int
megacostat_packet(void *pms, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pmi)
{
	megacostat_t *ms=(megacostat_t *)pms;
	const gcp_cmd_t *mi=(gcp_cmd_t*)pmi;
	nstime_t delta;
	int ret = 0;

	switch (mi->type) {

        GCP_CMD_REQ_CASE
		if(mi->trx->initial->framenum != mi->msg->framenum){
			/* Duplicate is ignored */
			ms->req_dup_num++;
		}
		else {
			ms->open_req_num++;
		}
		break;

        GCP_CMD_REPLY_CASE
		if(megacostat_is_duplicate_reply(mi)){
			/* Duplicate is ignored */
			ms->rsp_dup_num++;
		}
		else if (!megacostat_had_request(mi)) {
			/* no request was seen */
			ms->disc_rsp_num++;
		}
		else {
			ms->open_req_num--;
			/* calculate time delta between request and response */
			nstime_delta(&delta, &pinfo->fd->abs_ts, &mi->trx->initial->time);

			switch(mi->type) {
			
			case GCP_CMD_ADD_REPLY:
				time_stat_update(&(ms->rtd[0]),&delta, pinfo);
				break;
			case GCP_CMD_MOVE_REPLY:
				time_stat_update(&(ms->rtd[1]),&delta, pinfo);
				break;
			case GCP_CMD_MOD_REPLY:
				time_stat_update(&(ms->rtd[2]),&delta, pinfo);
				break;
			case GCP_CMD_SUB_REPLY:
				time_stat_update(&(ms->rtd[3]),&delta, pinfo);
				break;
			case GCP_CMD_AUDITCAP_REPLY:
				time_stat_update(&(ms->rtd[4]),&delta, pinfo);
				break;
			case GCP_CMD_AUDITVAL_REPLY:
				time_stat_update(&(ms->rtd[5]),&delta, pinfo);
				break;
			case GCP_CMD_NOTIFY_REPLY:
				time_stat_update(&(ms->rtd[6]),&delta, pinfo);
				break;
			case GCP_CMD_SVCCHG_REPLY:
				time_stat_update(&(ms->rtd[7]),&delta, pinfo);
				break;
			case GCP_CMD_TOPOLOGY_REPLY:
				time_stat_update(&(ms->rtd[8]),&delta, pinfo);
				break;
			case GCP_CMD_REPLY:
				time_stat_update(&(ms->rtd[9]),&delta, pinfo);
				break;
			default:
				time_stat_update(&(ms->rtd[10]),&delta, pinfo);
			}

			ret = 1;
		}
		break;

	default:
		break;
	}

	return ret;
}

static void
megacostat_draw(void *pms)
{
	megacostat_t *ms=(megacostat_t *)pms;
	int i;
	char *str[7];

	for(i=0;i<7;i++) {
		str[i]=g_malloc(sizeof(char[256]));
	}

	/* clear list before printing */
	gtk_clist_clear(ms->table);

	for(i=0;i<NUM_TIMESTATS;i++) {
		/* nothing seen, nothing to do */
		if(ms->rtd[i].num==0){
			continue;
		}

		g_snprintf(str[0], 256, "%s", val_to_str(i,megaco_message_type,"Other"));
		g_snprintf(str[1], 256, "%d", ms->rtd[i].num);
		g_snprintf(str[2], 256, "%8.2f msec", nstime_to_msec(&(ms->rtd[i].min)));
		g_snprintf(str[3], 256, "%8.2f msec", nstime_to_msec(&(ms->rtd[i].max)));
		g_snprintf(str[4], 256, "%8.2f msec", get_average(&(ms->rtd[i].tot), ms->rtd[i].num));
		g_snprintf(str[5], 256, "%6u", ms->rtd[i].min_num);
		g_snprintf(str[6], 256, "%6u", ms->rtd[i].max_num);
		gtk_clist_append(ms->table, str);
	}

	gtk_widget_show(GTK_WIDGET(ms->table));
	for(i=0;i<7;i++) {
		g_free(str[i]);
	}
}

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	megacostat_t *ms=(megacostat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ms);
	unprotect_thread_critical_region();

	if(ms->filter){
		g_free(ms->filter);
		ms->filter=NULL;
	}
	g_free(ms);
}

static const gchar *titles[]={
			"Type",
			"Messages",
			"Min SRT",
			"Max SRT",
			"Avg SRT",
			"Min in Frame",
			"Max in Frame" };

static void
gtk_megacostat_init(const char *optarg, void *userdata _U_)
{
	megacostat_t *ms;
	const char *filter=NULL;
	GString *error_string;
	GtkWidget *bt_close;
	GtkWidget *bbox;

	if(strncmp(optarg,"megaco,srt,",11) == 0){
		filter=optarg+11;
	} else {
		filter="";
	}

	ms=g_malloc(sizeof(megacostat_t));
	ms->filter=g_strdup(filter);

	megacostat_reset(ms);

	ms->win=window_new(GTK_WINDOW_TOPLEVEL, "MEGACO SRT");
	gtk_window_set_default_size(GTK_WINDOW(ms->win), 550, 150);

	ms->vbox=gtk_vbox_new(FALSE, 3);

	init_main_stat_window(ms->win, ms->vbox, "MEGACO Service Response Time (SRT) Statistics", filter);

	/* init a scrolled window*/
	ms->scrolled_window = scrolled_window_new(NULL, NULL);

	ms->table = create_stat_table(ms->scrolled_window, ms->vbox, 7, titles);

	error_string=register_tap_listener("megaco", ms, filter, megacostat_reset, megacostat_packet, megacostat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ms->filter);
		g_free(ms);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(ms->vbox), bbox, FALSE, FALSE, 0);

	bt_close = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(ms->win, bt_close, window_cancel_button_cb);

	g_signal_connect(ms->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(ms->win, "destroy", G_CALLBACK(win_destroy_cb), ms);

	gtk_widget_show_all(ms->win);
	window_present(ms->win);

	cf_retap_packets(&cfile, FALSE);
	gdk_window_raise(ms->win->window);
}

static tap_dfilter_dlg megaco_srt_dlg = {
	"MEGACO Service Response Time (SRT) Statistics",
	"megaco,srt",
	gtk_megacostat_init,
	-1
};

void
register_tap_listener_gtkmegacostat(void)
{
	/* We don't register this tap, if we don't have the megaco plugin loaded.*/
	if (find_tap_id("megaco")) {
		register_dfilter_stat(&megaco_srt_dlg, "MEGACO",
		    REGISTER_STAT_GROUP_RESPONSE_TIME);
	}
}
