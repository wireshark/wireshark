/* mgcp_stat.c
 * mgcp-statistics for ethereal
 * Copyright 2003 Lars Roland
 *
 * $Id: mgcp_stat.c,v 1.1 2003/04/16 07:24:06 guy Exp $
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <string.h>
#include "../epan/packet_info.h"
#include "../tap.h"
#include "../epan/value_string.h"
#include "../register.h"
#include "../plugins/mgcp/packet-mgcp.h"
#include "../timestats.h"
#include "mgcp_stat.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../globals.h"

#define NUM_TIMESTATS 11

/* used to keep track of the statistics for an entire program interface */
typedef struct _mgcpstat_t {
	GtkWidget *win;
	GtkWidget *vbox;
	char *filter;
	GtkWidget *table;
	int table_height;
        timestat_t rtd[NUM_TIMESTATS];
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
} mgcpstat_t;

static const value_string mgcp_mesage_type[] = {
  {  0,	"Overall"},
  {  1,	"EPCF"},
  {  2,	"CRCX"},
  {  3,	"MDCX"},
  {  4,	"DLCX"},
  {  5,	"RQNT"},
  {  6,	"NTFY"},
  {  7,	"AUEP"},
  {  8, "AUCX"},
  {  9, "RSIP"},
};

static void
add_table_entry(mgcpstat_t *ss, char *str, int x, int y)
{
	GtkWidget *tmp;

	if(y>=ss->table_height){
		ss->table_height=y+1;
		gtk_table_resize(GTK_TABLE(ss->table), ss->table_height, 7);
	}
	tmp=gtk_label_new(str);
	gtk_table_attach_defaults(GTK_TABLE(ss->table), tmp, x, x+1, y, y+1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
	gtk_widget_show(tmp);
}


static void
mgcpstat_reset(void *pms)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
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


static int
mgcpstat_packet(void *pms, packet_info *pinfo, epan_dissect_t *edt _U_, void *pmi)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
	mgcp_info_t *mi=pmi;
	nstime_t delta;

	switch (mi->mgcp_type) {

	case MGCP_REQUEST:
		if(mi->is_duplicate){
			/* Duplicate is ignored */
			ms->req_dup_num++;
			return 0;
		}
		else {
			ms->open_req_num++;
			return 0;
		}
	break;

	case MGCP_RESPONSE:
		if(mi->is_duplicate){
			/* Duplicate is ignored */
			ms->rsp_dup_num++;
			return 0;
		}
		else if (!mi->request_available) {
			/* no request was seen */
			ms->disc_rsp_num++;
			return 0;
		}
		else {
			ms->open_req_num--;
			/* calculate time delta between request and response */
			delta.secs=pinfo->fd->abs_secs-mi->req_time.secs;
			delta.nsecs=pinfo->fd->abs_usecs*1000-mi->req_time.nsecs;
			if(delta.nsecs<0){
				delta.nsecs+=1000000000;
				delta.secs--;
			}

			time_stat_update(&(ms->rtd[0]),&delta, pinfo);

			if (strncasecmp(mi->code, "EPCF", 4) == 0 ) {
				time_stat_update(&(ms->rtd[1]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "CRCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[2]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "MDCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[3]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "DLCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[4]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "RQNT", 4) == 0 ) {
				time_stat_update(&(ms->rtd[5]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "NTFY", 4) == 0 ) {
				time_stat_update(&(ms->rtd[6]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "AUEP", 4) == 0 ) {
				time_stat_update(&(ms->rtd[7]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "AUCX", 4) == 0 ) {
				time_stat_update(&(ms->rtd[8]),&delta, pinfo);
			}
			else if (strncasecmp(mi->code, "RSIP", 4) == 0 ) {
				time_stat_update(&(ms->rtd[9]),&delta, pinfo);
			}
			else {
				time_stat_update(&(ms->rtd[10]),&delta, pinfo);
			}

			return 1;
		}
	break;

	default:
		return 0;
	break;
	}
}

static void
mgcpstat_draw(void *pms)
{
	mgcpstat_t *ms=(mgcpstat_t *)pms;
	int i;
	int pos;
	char str[256];

	gtk_widget_destroy(ms->table);
	ms->table_height=5;
	ms->table=gtk_table_new(ms->table_height, 7, TRUE);
	gtk_container_add(GTK_CONTAINER(ms->vbox), ms->table);

	pos=0;

	add_table_entry(ms, "Type", 0, pos);
	add_table_entry(ms, "Messages", 1, pos);
	add_table_entry(ms, "Min RTD", 2, pos);
	add_table_entry(ms, "Max RTD", 3, pos);
	add_table_entry(ms, "Avg RTD", 4, pos);
	add_table_entry(ms, "Min in Frame", 5, pos);
	add_table_entry(ms, "Max in Frame", 6, pos);
	pos++;

	for(i=0;i<NUM_TIMESTATS;i++) {
		/* nothing seen, nothing to do */
		if(ms->rtd[i].num==0){
			continue;
		}

		sprintf(str, "%s", val_to_str(i,mgcp_mesage_type,"Other"));
		add_table_entry(ms, str, 0, pos);
		sprintf(str, "%d", ms->rtd[i].num);
		add_table_entry(ms, str, 1, pos);
		sprintf(str, "%8.2f msec", nstime_to_msec(&(ms->rtd[i].min)));
		add_table_entry(ms, str, 2, pos);
		sprintf(str, "%8.2f msec", nstime_to_msec(&(ms->rtd[i].max)));
		add_table_entry(ms, str, 3, pos);
		sprintf(str, "%8.2f msec", get_average(&(ms->rtd[i].tot), ms->rtd[i].num));
		add_table_entry(ms, str, 4, pos);
		sprintf(str, "%6u", ms->rtd[i].min_num);
		add_table_entry(ms, str, 5, pos);
		sprintf(str, "%6u", ms->rtd[i].max_num);
		add_table_entry(ms, str, 6, pos);
		pos++;
	}

	gtk_widget_show(ms->table);
}

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	mgcpstat_t *ms=(mgcpstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ms);
	unprotect_thread_critical_region();

	if(ms->filter){
		g_free(ms->filter);
		ms->filter=NULL;
	}
	g_free(ms);
}

void
gtk_mgcpstat_init(char *optarg)
{
	mgcpstat_t *ms;
	char *filter=NULL;
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	char filter_string[256];

	if(!strncmp(optarg,"mgcp,rtd,",9)){
		filter=optarg+9;
	} else {
		filter=g_malloc(1);
		*filter='\0';
	}

	ms=g_malloc(sizeof(mgcpstat_t));
	ms->filter=g_malloc(strlen(filter)+1);
	strcpy(ms->filter, filter);

	mgcpstat_reset(ms);

	ms->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(ms->win), "MGCP Response Time Delay (RTD) Statistics");
	SIGNAL_CONNECT(ms->win, "destroy", win_destroy_cb, ms);

	ms->vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(ms->win), ms->vbox);
	gtk_container_set_border_width(GTK_CONTAINER(ms->vbox), 10);
	gtk_widget_show(ms->vbox);

	stat_label=gtk_label_new("MGCP Response Time Delay (RTD) Statistics");
	gtk_box_pack_start(GTK_BOX(ms->vbox), stat_label, FALSE, FALSE, 0);
	gtk_widget_show(stat_label);

	snprintf(filter_string,255,"Filter:%s",filter?filter:"");
	filter_label=gtk_label_new(filter_string);
	gtk_box_pack_start(GTK_BOX(ms->vbox), filter_label, FALSE, FALSE, 0);
	gtk_widget_show(filter_label);

	ms->table_height=5;
	ms->table=gtk_table_new(ms->table_height, 7, TRUE);
	gtk_container_add(GTK_CONTAINER(ms->vbox), ms->table);

	add_table_entry(ms, "Type", 0, 0);
	add_table_entry(ms, "Messages", 1, 0);
	add_table_entry(ms, "Min RTD", 2, 0);
	add_table_entry(ms, "Max RTD", 3, 0);
	add_table_entry(ms, "Avg RTD", 4, 0);
	add_table_entry(ms, "Min in Frame", 5, 0);
	add_table_entry(ms, "Max in Frame", 6, 0);

	gtk_widget_show(ms->table);

	if(register_tap_listener("mgcp", ms, filter, mgcpstat_reset, mgcpstat_packet, mgcpstat_draw)){
		char str[256];
		/* error, we failed to attach to the tap. clean up */
		snprintf(str,255,"Could not attach to tap using filter:%s",filter?filter:"");
		simple_dialog(ESD_TYPE_WARN, NULL, str);
		g_free(ms->filter);
		g_free(ms);
		return;
	}

	gtk_widget_show_all(ms->win);
	redissect_packets(&cfile);
}

void
register_tap_listener_gtkmgcpstat(void)
{
	register_ethereal_tap("mgcp,rtd", gtk_mgcpstat_init, NULL, NULL);
}


void
gtk_mgcpstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_mgcpstat_init("mgcp,rtd");
}
