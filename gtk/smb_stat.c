/* smb_stat.c
 * smb_stat   2003 Ronnie Sahlberg
 *
 * $Id: smb_stat.c,v 1.4 2003/04/23 05:37:23 guy Exp $
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
#include "menu.h"
#include "../epan/packet_info.h"
#include "../tap.h"
#include "../epan/value_string.h"
#include "../smb.h"
#include "../register.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../globals.h"

typedef struct _smb_procedure_t {
	int num;
	nstime_t min;
	nstime_t max;
	nstime_t tot;
} smb_procedure_t;

/* used to keep track of the statistics for an entire program interface */
typedef struct _smbstat_t {
	GtkWidget *win;
	GtkWidget *vbox;
	char *filter;
	GtkWidget *table;
	int table_height;
	GtkWidget *table_widgets[768];
	smb_procedure_t proc[256];
	smb_procedure_t trans2[256];
	smb_procedure_t nt_trans[256];
} smbstat_t;




static void
add_table_entry(smbstat_t *ss, char *str, int x, int y)
{
	GtkWidget *tmp;

	if(y>=ss->table_height){
		ss->table_height=y+1;
		gtk_table_resize(GTK_TABLE(ss->table), ss->table_height, 5);
	}
	tmp=gtk_label_new(str);
	gtk_table_attach_defaults(GTK_TABLE(ss->table), tmp, x, x+1, y, y+1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
	gtk_widget_show(tmp);
}


static void
smbstat_reset(void *pss)
{
	smbstat_t *ss=(smbstat_t *)pss;
	guint32 i;

	for(i=0;i<256;i++){
		ss->proc[i].num=0;	
		ss->proc[i].min.secs=0;
		ss->proc[i].min.nsecs=0;
		ss->proc[i].max.secs=0;
		ss->proc[i].max.nsecs=0;
		ss->proc[i].tot.secs=0;
		ss->proc[i].tot.nsecs=0;
		
		ss->trans2[i].num=0;	
		ss->trans2[i].min.secs=0;
		ss->trans2[i].min.nsecs=0;
		ss->trans2[i].max.secs=0;
		ss->trans2[i].max.nsecs=0;
		ss->trans2[i].tot.secs=0;
		ss->trans2[i].tot.nsecs=0;

		ss->nt_trans[i].num=0;	
		ss->nt_trans[i].min.secs=0;
		ss->nt_trans[i].min.nsecs=0;
		ss->nt_trans[i].max.secs=0;
		ss->nt_trans[i].max.nsecs=0;
		ss->nt_trans[i].tot.secs=0;
		ss->nt_trans[i].tot.nsecs=0;
	}
}

static int
smbstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, void *psi)
{
	smbstat_t *ss=(smbstat_t *)pss;
	smb_info_t *si=psi;
	nstime_t delta;
	smb_procedure_t *sp;

	/* we are only interested in reply packets */
	if(si->request){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if(!si->sip){
		return 0;
	}

	if(si->cmd==0xA0){
		smb_nt_transact_info_t *sti=(smb_nt_transact_info_t *)si->sip->extra_info;

		/*nt transaction*/
		sp=&(ss->nt_trans[sti->subcmd]);
	} else if(si->cmd==0x32){
		smb_transact2_info_t *st2i=(smb_transact2_info_t *)si->sip->extra_info;

		/*transaction2*/
		sp=&(ss->trans2[st2i->subcmd]);
	} else {
		sp=&(ss->proc[si->cmd]);
	}

	/* calculate time delta between request and reply */
	delta.secs=pinfo->fd->abs_secs-si->sip->req_time.secs;
	delta.nsecs=pinfo->fd->abs_usecs*1000-si->sip->req_time.nsecs;
	if(delta.nsecs<0){
		delta.nsecs+=1000000000;
		delta.secs--;
	}

	if((sp->max.secs==0)
	&& (sp->max.nsecs==0) ){
		sp->max.secs=delta.secs;
		sp->max.nsecs=delta.nsecs;
	}

	if((sp->min.secs==0)
	&& (sp->min.nsecs==0) ){
		sp->min.secs=delta.secs;
		sp->min.nsecs=delta.nsecs;
	}

	if( (delta.secs<sp->min.secs)
	||( (delta.secs==sp->min.secs)
	  &&(delta.nsecs<sp->min.nsecs) ) ){
		sp->min.secs=delta.secs;
		sp->min.nsecs=delta.nsecs;
	}

	if( (delta.secs>sp->max.secs)
	||( (delta.secs==sp->max.secs)
	  &&(delta.nsecs>sp->max.nsecs) ) ){
		sp->max.secs=delta.secs;
		sp->max.nsecs=delta.nsecs;
	}
	
	sp->tot.secs += delta.secs;
	sp->tot.nsecs += delta.nsecs;
	if(sp->tot.nsecs>1000000000){
		sp->tot.nsecs-=1000000000;
		sp->tot.secs++;
	}
	sp->num++;

	return 1;
}

static void
smbstat_draw(void *pss)
{
	smbstat_t *ss=(smbstat_t *)pss;
	guint32 i;
	int pos;
	char str[256];
#ifdef G_HAVE_UINT64
	guint64 td;
#else
	guint32 td;
#endif

	gtk_widget_destroy(ss->table);
	ss->table_height=5;
	ss->table=gtk_table_new(ss->table_height, 5, TRUE);
	gtk_container_add(GTK_CONTAINER(ss->vbox), ss->table);

	pos=0;
	add_table_entry(ss, "Command", 0, pos);
	add_table_entry(ss, "Calls", 1, pos);
	add_table_entry(ss, "Min RTT", 2, pos);
	add_table_entry(ss, "Max RTT", 3, pos);
	add_table_entry(ss, "Avg RTT", 4, pos);
	pos++;

	for(i=0;i<256;i++){
		/* nothing seen, nothing to do */
		if(ss->proc[i].num==0){
			continue;
		}

		/* we deal with transaction2 later */
		if(i==0x32){
			continue;
		}

		/* we deal with nt transaction later */
		if(i==0xA0){
			continue;
		}

		/* scale it to units of 10us.*/
		/* for long captures with a large tot time, this can overflow on 32bit */
		td=(int)ss->proc[i].tot.secs;
		td=td*100000+(int)ss->proc[i].tot.nsecs/10000;
		if(ss->proc[i].num){
			td/=ss->proc[i].num;
		} else {
			td=0;
		}

		sprintf(str, "%s", val_to_str(i, smb_cmd_vals, "Unknown (0x%02x)"));
		add_table_entry(ss, str, 0, pos);
		sprintf(str, "%d", ss->proc[i].num);
		add_table_entry(ss, str, 1, pos);
		sprintf(str, "%3d.%05d", (int)ss->proc[i].min.secs,ss->proc[i].min.nsecs/10000);
		add_table_entry(ss, str, 2, pos);
		sprintf(str, "%3d.%05d", (int)ss->proc[i].max.secs,ss->proc[i].max.nsecs/10000);
		add_table_entry(ss, str, 3, pos);
		sprintf(str, "%3d.%05d", td/100000, td%100000);
		add_table_entry(ss, str, 4, pos);
		pos++;
	}


	add_table_entry(ss, "", 0, pos);
	add_table_entry(ss, "", 1, pos);
	add_table_entry(ss, "", 2, pos);
	add_table_entry(ss, "", 3, pos);
	add_table_entry(ss, "", 4, pos);
	pos++;

	add_table_entry(ss, "Transaction2 Command", 0, pos);
	add_table_entry(ss, "Calls", 1, pos);
	add_table_entry(ss, "Min RTT", 2, pos);
	add_table_entry(ss, "Max RTT", 3, pos);
	add_table_entry(ss, "Avg RTT", 4, pos);
	pos++;

	for(i=0;i<256;i++){
		/* nothing seen, nothing to do */
		if(ss->trans2[i].num==0){
			continue;
		}

		/* scale it to units of 10us.*/
		/* for long captures with a large tot time, this can overflow on 32bit */
		td=(int)ss->trans2[i].tot.secs;
		td=td*100000+(int)ss->trans2[i].tot.nsecs/10000;
		if(ss->trans2[i].num){
			td/=ss->trans2[i].num;
		} else {
			td=0;
		}

		sprintf(str, "%s", val_to_str(i, trans2_cmd_vals, "Unknown (0x%02x)"));
		add_table_entry(ss, str, 0, pos);
		sprintf(str, "%d", ss->trans2[i].num);
		add_table_entry(ss, str, 1, pos);
		sprintf(str, "%3d.%05d", (int)ss->trans2[i].min.secs,ss->trans2[i].min.nsecs/10000);
		add_table_entry(ss, str, 2, pos);
		sprintf(str, "%3d.%05d", (int)ss->trans2[i].max.secs,ss->trans2[i].max.nsecs/10000);
		add_table_entry(ss, str, 3, pos);
		sprintf(str, "%3d.%05d", td/100000, td%100000);
		add_table_entry(ss, str, 4, pos);
		pos++;
	}

	add_table_entry(ss, "", 0, pos);
	add_table_entry(ss, "", 1, pos);
	add_table_entry(ss, "", 2, pos);
	add_table_entry(ss, "", 3, pos);
	add_table_entry(ss, "", 4, pos);
	pos++;

	add_table_entry(ss, "NT Transaction Command", 0, pos);
	add_table_entry(ss, "Calls", 1, pos);
	add_table_entry(ss, "Min RTT", 2, pos);
	add_table_entry(ss, "Max RTT", 3, pos);
	add_table_entry(ss, "Avg RTT", 4, pos);
	pos++;

	for(i=0;i<256;i++){
		/* nothing seen, nothing to do */
		if(ss->nt_trans[i].num==0){
			continue;
		}

		/* scale it to units of 10us.*/
		/* for long captures with a large tot time, this can overflow on 32bit */
		td=(int)ss->nt_trans[i].tot.secs;
		td=td*100000+(int)ss->nt_trans[i].tot.nsecs/10000;
		if(ss->nt_trans[i].num){
			td/=ss->nt_trans[i].num;
		} else {
			td=0;
		}

		sprintf(str, "%s", val_to_str(i, nt_cmd_vals, "Unknown (0x%02x)"));
		add_table_entry(ss, str, 0, pos);
		sprintf(str, "%d", ss->nt_trans[i].num);
		add_table_entry(ss, str, 1, pos);
		sprintf(str, "%3d.%05d", (int)ss->nt_trans[i].min.secs,ss->nt_trans[i].min.nsecs/10000);
		add_table_entry(ss, str, 2, pos);
		sprintf(str, "%3d.%05d", (int)ss->nt_trans[i].max.secs,ss->nt_trans[i].max.nsecs/10000);
		add_table_entry(ss, str, 3, pos);
		sprintf(str, "%3d.%05d", td/100000, td%100000);
		add_table_entry(ss, str, 4, pos);
		pos++;
	}
	gtk_widget_show(ss->table);
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

	if(ss->filter){
		g_free(ss->filter);
		ss->filter=NULL;
	}
	g_free(ss);
}


static void
gtk_smbstat_init(char *optarg)
{
	smbstat_t *ss;
	guint32 i;
	char *filter=NULL;
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	char filter_string[256];

	if(!strncmp(optarg,"smb,rtt,",8)){
		filter=optarg+8;
	} else {
		filter=NULL;
	}

	ss=g_malloc(sizeof(smbstat_t));
	if(filter){
		ss->filter=g_malloc(strlen(filter)+1);
		strcpy(ss->filter, filter);
	} else {
		ss->filter=NULL;
	}

	for(i=0;i<256;i++){
		ss->proc[i].num=0;	
		ss->proc[i].min.secs=0;
		ss->proc[i].min.nsecs=0;
		ss->proc[i].max.secs=0;
		ss->proc[i].max.nsecs=0;
		ss->proc[i].tot.secs=0;
		ss->proc[i].tot.nsecs=0;
		
		ss->trans2[i].num=0;	
		ss->trans2[i].min.secs=0;
		ss->trans2[i].min.nsecs=0;
		ss->trans2[i].max.secs=0;
		ss->trans2[i].max.nsecs=0;
		ss->trans2[i].tot.secs=0;
		ss->trans2[i].tot.nsecs=0;

		ss->nt_trans[i].num=0;	
		ss->nt_trans[i].min.secs=0;
		ss->nt_trans[i].min.nsecs=0;
		ss->nt_trans[i].max.secs=0;
		ss->nt_trans[i].max.nsecs=0;
		ss->nt_trans[i].tot.secs=0;
		ss->nt_trans[i].tot.nsecs=0;
	}

	ss->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(ss->win), "SMB RTT Statistics");
	SIGNAL_CONNECT(ss->win, "destroy", win_destroy_cb, ss);

	ss->vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(ss->win), ss->vbox);
	gtk_container_set_border_width(GTK_CONTAINER(ss->vbox), 10);
	gtk_widget_show(ss->vbox);

	stat_label=gtk_label_new("SMB RTT Statistics");
	gtk_box_pack_start(GTK_BOX(ss->vbox), stat_label, FALSE, FALSE, 0);
	gtk_widget_show(stat_label);

	snprintf(filter_string,255,"Filter:%s",filter?filter:"");
	filter_label=gtk_label_new(filter_string);
	gtk_box_pack_start(GTK_BOX(ss->vbox), filter_label, FALSE, FALSE, 0);
	gtk_widget_show(filter_label);


	ss->table_height=5;
	ss->table=gtk_table_new(ss->table_height, 5, TRUE);
	gtk_container_add(GTK_CONTAINER(ss->vbox), ss->table);

	add_table_entry(ss, "Command", 0, 0);
	add_table_entry(ss, "Calls", 1, 0);
	add_table_entry(ss, "Min RTT", 2, 0);
	add_table_entry(ss, "Max RTT", 3, 0);
	add_table_entry(ss, "Avg RTT", 4, 0);

	add_table_entry(ss, "", 0, 1);
	add_table_entry(ss, "", 1, 1);
	add_table_entry(ss, "", 2, 1);
	add_table_entry(ss, "", 3, 1);
	add_table_entry(ss, "", 4, 1);

	add_table_entry(ss, "Transaction2 Commands", 0, 2);
	add_table_entry(ss, "Calls", 1, 2);
	add_table_entry(ss, "Min RTT", 2, 2);
	add_table_entry(ss, "Max RTT", 3, 2);
	add_table_entry(ss, "Avg RTT", 4, 2);

	add_table_entry(ss, "", 0, 3);
	add_table_entry(ss, "", 1, 3);
	add_table_entry(ss, "", 2, 3);
	add_table_entry(ss, "", 3, 3);
	add_table_entry(ss, "", 4, 3);

	add_table_entry(ss, "NT Transaction Commands", 0, 4);
	add_table_entry(ss, "Calls", 1, 4);
	add_table_entry(ss, "Min RTT", 2, 4);
	add_table_entry(ss, "Max RTT", 3, 4);
	add_table_entry(ss, "Avg RTT", 4, 4);

	gtk_widget_show(ss->table);

	if(register_tap_listener("smb", ss, filter, smbstat_reset, smbstat_packet, smbstat_draw)){
		char str[256];
		/* error, we failed to attach to the tap. clean up */
		snprintf(str,255,"Could not attach to tap using filter:%s\nMaybe the filter string is invalid?",filter?filter:"");
		simple_dialog(ESD_TYPE_WARN, NULL, str);
		g_free(ss->filter);
		g_free(ss);
		return;
	}

	gtk_widget_show_all(ss->win);
	redissect_packets(&cfile);
}



static GtkWidget *dlg=NULL, *dlg_box;
static GtkWidget *filter_box;
static GtkWidget *filter_label, *filter_entry;
static GtkWidget *start_button;

static void
dlg_destroy_cb(void)
{
	dlg=NULL;
}

static void
smbstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	char *filter;
	char str[256];

	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]==0){
		gtk_smbstat_init("smb,rtt");
	} else {
		sprintf(str,"smb,rtt,%s", filter);
		gtk_smbstat_init(str);
	}
}

static void
gtk_smbstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	dlg=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(dlg), "SMB RTT Statistics");
	SIGNAL_CONNECT(dlg, "destroy", dlg_destroy_cb, NULL);
	dlg_box=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);


	/* filter box */
	filter_box=gtk_hbox_new(FALSE, 10);
	/* Filter label */
	gtk_container_set_border_width(GTK_CONTAINER(filter_box), 10);
	filter_label=gtk_label_new("Filter:");
	gtk_box_pack_start(GTK_BOX(filter_box), filter_label, FALSE, FALSE, 0);
	gtk_widget_show(filter_label);

	filter_entry=gtk_entry_new_with_max_length(250);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_entry, FALSE, FALSE, 0);
	gtk_widget_show(filter_entry);
	
	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);


	/* the start button */
	start_button=gtk_button_new_with_label("Create Stat");
        SIGNAL_CONNECT_OBJECT(start_button, "clicked",
                              smbstat_start_button_clicked, NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), start_button, TRUE, TRUE, 0);
	gtk_widget_show(start_button);

	gtk_widget_show_all(dlg);
}

void
register_tap_listener_gtksmbstat(void)
{
	register_ethereal_tap("smb,rtt", gtk_smbstat_init);
}

void
register_tap_menu_gtksmbstat(void)
{
	register_tap_menu_item("SMB/RTT", gtk_smbstat_cb);
}
