/* rpc_stat.c
 * rpc_stat   2002 Ronnie Sahlberg
 *
 * $Id: rpc_stat.c,v 1.3 2002/10/23 23:12:38 guy Exp $
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

/* This module provides rpc call/reply RTT statistics to tethereal.
 * It is only used by tethereal and not ethereal
 *
 * It serves as an example on how to use the tap api.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include "epan/packet_info.h"
#include "simple_dialog.h"
#include "tap.h"
#include "rpc_stat.h"
#include "packet-rpc.h"


/* used to keep track of statistics for a specific procedure */
typedef struct _rpc_procedure_t {
	GtkWidget *wnum;
	GtkWidget *wmin;
	GtkWidget *wmax;
	GtkWidget *wavg;
	gchar snum[8];
	gchar smin[16];
	gchar smax[16];
	gchar savg[16];
	int num;
	nstime_t min;
	nstime_t max;
	nstime_t tot;
} rpc_procedure_t;

/* used to keep track of the statistics for an entire program interface */
typedef struct _rpcstat_t {
	GtkWidget *win;
	GtkWidget *table;
	char *prog;
	guint32 program;
	guint32 version;
	guint32 num_procedures;
	rpc_procedure_t *procedures;
} rpcstat_t;




static void
rpcstat_reset(rpcstat_t *rs)
{
	guint32 i;

	for(i=0;i<rs->num_procedures;i++){
		rs->procedures[i].num=0;	
		rs->procedures[i].min.secs=0;
		rs->procedures[i].min.nsecs=0;
		rs->procedures[i].max.secs=0;
		rs->procedures[i].max.nsecs=0;
		rs->procedures[i].tot.secs=0;
		rs->procedures[i].tot.nsecs=0;
	}
}


static int
rpcstat_packet(rpcstat_t *rs, packet_info *pinfo, epan_dissect_t *edt _U_, rpc_call_info_value *ri)
{
	nstime_t delta;
	rpc_procedure_t *rp;

	if(ri->proc>=rs->num_procedures){
		/* dont handle this since its outside of known table */
		return 0;
	}
	/* we are only interested in reply packets */
	if(ri->request){
		return 0;
	}
	/* we are only interested in certain program/versions */
	if( (ri->prog!=rs->program) || (ri->vers!=rs->version) ){
		return 0;
	}

	rp=&(rs->procedures[ri->proc]);

	/* calculate time delta between request and reply */
	delta.secs=pinfo->fd->abs_secs-ri->req_time.secs;
	delta.nsecs=pinfo->fd->abs_usecs*1000-ri->req_time.nsecs;
	if(delta.nsecs<0){
		delta.nsecs+=1000000000;
		delta.secs--;
	}

	if((rp->max.secs==0)
	&& (rp->max.nsecs==0) ){
		rp->max.secs=delta.secs;
		rp->max.nsecs=delta.nsecs;
	}

	if((rp->min.secs==0)
	&& (rp->min.nsecs==0) ){
		rp->min.secs=delta.secs;
		rp->min.nsecs=delta.nsecs;
	}

	if( (delta.secs<rp->min.secs)
	||( (delta.secs==rp->min.secs)
	  &&(delta.nsecs<rp->min.nsecs) ) ){
		rp->min.secs=delta.secs;
		rp->min.nsecs=delta.nsecs;
	}

	if( (delta.secs>rp->max.secs)
	||( (delta.secs==rp->max.secs)
	  &&(delta.nsecs>rp->max.nsecs) ) ){
		rp->max.secs=delta.secs;
		rp->max.nsecs=delta.nsecs;
	}
	
	rp->tot.secs += delta.secs;
	rp->tot.nsecs += delta.nsecs;
	if(rp->tot.nsecs>1000000000){
		rp->tot.nsecs-=1000000000;
		rp->tot.secs++;
	}
	rp->num++;

	return 1;
}

static void
rpcstat_draw(rpcstat_t *rs)
{
	guint32 i;
#ifdef G_HAVE_UINT64
	guint64 td;
#else
	guint32 td;
#endif

	for(i=0;i<rs->num_procedures;i++){
		/* scale it to units of 10us.*/
		/* for long captures with a large tot time, this can overflow on 32bit */
		td=(int)rs->procedures[i].tot.secs;
		td=td*100000+(int)rs->procedures[i].tot.nsecs/10000;
		if(rs->procedures[i].num){
			td/=rs->procedures[i].num;
		} else {
			td=0;
		}

		sprintf(rs->procedures[i].snum,"%d", rs->procedures[i].num);
		gtk_label_set_text(GTK_LABEL(rs->procedures[i].wnum), rs->procedures[i].snum);

		sprintf(rs->procedures[i].smin,"%3d.%05d", (int)rs->procedures[i].min.secs,rs->procedures[i].min.nsecs/10000);
		gtk_label_set_text(GTK_LABEL(rs->procedures[i].wmin), rs->procedures[i].smin);

		sprintf(rs->procedures[i].smax,"%3d.%05d", (int)rs->procedures[i].max.secs,rs->procedures[i].max.nsecs/10000);
		gtk_label_set_text(GTK_LABEL(rs->procedures[i].wmax), rs->procedures[i].smax);

		sprintf(rs->procedures[i].savg,"%3d.%05d", td/100000, td%100000);
		gtk_label_set_text(GTK_LABEL(rs->procedures[i].wavg), rs->procedures[i].savg);

	}
}



static guint32 rpc_program=0;
static guint32 rpc_version=0;
static gint32 rpc_min_vers=-1;
static gint32 rpc_max_vers=-1;
static gint32 rpc_min_proc=-1;
static gint32 rpc_max_proc=-1;

static void *
rpcstat_find_procs(gpointer *key, gpointer *value _U_, gpointer *user_data _U_)
{
	rpc_proc_info_key *k=(rpc_proc_info_key *)key;

	if(k->prog!=rpc_program){
		return NULL;
	}
	if(k->vers!=rpc_version){
		return NULL;
	}
	if(rpc_min_proc==-1){
		rpc_min_proc=k->proc;
		rpc_max_proc=k->proc;
	}
	if((gint32)k->proc<rpc_min_proc){
		rpc_min_proc=k->proc;
	}
	if((gint32)k->proc>rpc_max_proc){
		rpc_max_proc=k->proc;
	}

	return NULL;
}

static void *
rpcstat_find_vers(gpointer *key, gpointer *value _U_, gpointer *user_data _U_)
{
	rpc_proc_info_key *k=(rpc_proc_info_key *)key;

	if(k->prog!=rpc_program){
		return NULL;
	}
	if(rpc_min_vers==-1){
		rpc_min_vers=k->vers;
		rpc_max_vers=k->vers;
	}
	if((gint32)k->vers<rpc_min_vers){
		rpc_min_vers=k->vers;
	}
	if((gint32)k->vers>rpc_max_vers){
		rpc_max_vers=k->vers;
	}

	return NULL;
}

/* since the gtk2 implementation of tap is multithreaded we must protect
 * remove_tap_listener() from modifying the list while draw_tap_listener()
 * is running.  the other protected block is in main.c
 *
 * there should not be any other critical regions in gtk2
 */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	rpcstat_t *rs=(rpcstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(rs);
	unprotect_thread_critical_region();

	g_free(rs->procedures);
	g_free(rs);
}

/* When called, this function will create a new instance of gtk2-rpcstat.
 */
void
gtk_rpcstat_init(guint32 program, guint32 version, char *filter)
{
	rpcstat_t *rs;
	guint32 i;
	char title_string[60];
	char filter_string[256];
	GtkWidget *vbox;
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	GtkWidget *tmp;

	rpc_program=program;
	rpc_version=version;
	rs=g_malloc(sizeof(rpcstat_t));
	rs->prog=rpc_prog_name(rpc_program);
	rs->program=rpc_program;
	rs->version=rpc_version;

	rs->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	sprintf(title_string,"ONC-RPC RTT Stat for %s version %d", rs->prog, rs->version);
	gtk_window_set_title(GTK_WINDOW(rs->win), title_string);
	gtk_signal_connect(GTK_OBJECT(rs->win), "destroy", GTK_SIGNAL_FUNC(win_destroy_cb), rs);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(rs->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	stat_label=gtk_label_new(title_string);
	gtk_box_pack_start(GTK_BOX(vbox), stat_label, FALSE, FALSE, 0);
	gtk_widget_show(stat_label);

	snprintf(filter_string,255,"Filter:%s",filter?filter:"");
	filter_label=gtk_label_new(filter_string);
	gtk_box_pack_start(GTK_BOX(vbox), filter_label, FALSE, FALSE, 0);
	gtk_widget_show(filter_label);


	rpc_min_proc=-1;
	rpc_max_proc=-1;
	g_hash_table_foreach(rpc_procs, (GHFunc)rpcstat_find_procs, NULL);
	rs->num_procedures=rpc_max_proc+1;

	rs->table=gtk_table_new(rs->num_procedures+1, 5, TRUE);
	gtk_container_add(GTK_CONTAINER(vbox), rs->table);

	tmp=gtk_label_new("Procedure");
	gtk_table_attach_defaults(GTK_TABLE(rs->table), tmp, 0,1,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
	gtk_widget_show(tmp);

	tmp=gtk_label_new("Calls");
	gtk_table_attach_defaults(GTK_TABLE(rs->table), tmp, 1,2,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_RIGHT);
	gtk_widget_show(tmp);

	tmp=gtk_label_new("Min RTT");
	gtk_table_attach_defaults(GTK_TABLE(rs->table), tmp, 2,3,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_RIGHT);
	gtk_widget_show(tmp);

	tmp=gtk_label_new("Max RTT");
	gtk_table_attach_defaults(GTK_TABLE(rs->table), tmp, 3,4,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_RIGHT);
	gtk_widget_show(tmp);

	tmp=gtk_label_new("Avg RTT");
	gtk_table_attach_defaults(GTK_TABLE(rs->table), tmp, 4,5,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_RIGHT);
	gtk_widget_show(tmp);

	
	rs->procedures=g_malloc(sizeof(rpc_procedure_t)*(rs->num_procedures+1));
	for(i=0;i<rs->num_procedures;i++){
		GtkWidget *tmp;
		
		tmp=gtk_label_new(rpc_proc_name(rpc_program, rpc_version, i));
		gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
		gtk_table_attach_defaults(GTK_TABLE(rs->table), tmp, 0,1,i+1,i+2);
		gtk_widget_show(tmp);

		rs->procedures[i].wnum=gtk_label_new("0");
		gtk_table_attach_defaults(GTK_TABLE(rs->table), rs->procedures[i].wnum, 1,2,i+1,i+2);
		gtk_label_set_justify(GTK_LABEL(rs->procedures[i].wnum), GTK_JUSTIFY_RIGHT);
		gtk_widget_show(rs->procedures[i].wnum);

		rs->procedures[i].wmin=gtk_label_new("0");
		gtk_table_attach_defaults(GTK_TABLE(rs->table), rs->procedures[i].wmin, 2,3,i+1,i+2);
		gtk_label_set_justify(GTK_LABEL(rs->procedures[i].wmin), GTK_JUSTIFY_RIGHT);
		gtk_widget_show(rs->procedures[i].wmin);

		rs->procedures[i].wmax=gtk_label_new("0");
		gtk_table_attach_defaults(GTK_TABLE(rs->table), rs->procedures[i].wmax, 3,4,i+1,i+2);
		gtk_label_set_justify(GTK_LABEL(rs->procedures[i].wmax), GTK_JUSTIFY_RIGHT);
		gtk_widget_show(rs->procedures[i].wmax);

		rs->procedures[i].wavg=gtk_label_new("0");
		gtk_table_attach_defaults(GTK_TABLE(rs->table), rs->procedures[i].wavg, 4,5,i+1,i+2);
		gtk_label_set_justify(GTK_LABEL(rs->procedures[i].wavg), GTK_JUSTIFY_RIGHT);
		gtk_widget_show(rs->procedures[i].wavg);

		rs->procedures[i].num=0;	
		rs->procedures[i].min.secs=0;
		rs->procedures[i].min.nsecs=0;
		rs->procedures[i].max.secs=0;
		rs->procedures[i].max.nsecs=0;
		rs->procedures[i].tot.secs=0;
		rs->procedures[i].tot.nsecs=0;
	}

	gtk_widget_show(rs->table);

	if(register_tap_listener("rpc", rs, filter, (void*)rpcstat_reset, (void*)rpcstat_packet, (void*)rpcstat_draw)){
		char str[256];
		/* error, we failed to attach to the tap. clean up */
		snprintf(str,255,"Could not attach to tap using filter:%s",filter?filter:"");
		simple_dialog(ESD_TYPE_WARN, NULL, str);
		g_free(rs->procedures);
		g_free(rs);
		return;
	}


	gtk_widget_show_all(rs->win);
}



static GtkWidget *dlg=NULL, *dlg_box;
static GtkWidget *prog_box;
static GtkWidget *prog_label, *prog_opt, *prog_menu;
static GtkWidget *vers_label, *vers_opt, *vers_menu;
static GtkWidget *filter_box;
static GtkWidget *filter_label, *filter_entry;
static GtkWidget *start_button;



static void
rpcstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	char *filter;

	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]==0){
		filter=NULL;
	}
	gtk_rpcstat_init(rpc_program, rpc_version, filter);
}

static void
rpcstat_version_select(GtkWidget *item _U_, gpointer key)
{
	int vers=(int)key;

	rpc_version=vers;
}



static void
rpcstat_program_select(GtkWidget *item _U_, gpointer key)
{
	rpc_prog_info_key *k=(rpc_prog_info_key *)key;
	int i;

	rpc_program=k->prog;

	/* change version menu */
	rpc_version=0;
	gtk_object_destroy(GTK_OBJECT(vers_menu));
	vers_menu=gtk_menu_new();
	rpc_min_vers=-1;
	rpc_max_vers=-1;
	g_hash_table_foreach(rpc_procs, (GHFunc)rpcstat_find_vers, NULL);
	rpc_version=rpc_min_vers;
	for(i=rpc_min_vers;i<=rpc_max_vers;i++){
		GtkWidget *menu_item;
		char vs[5];
		sprintf(vs,"%d",i);
		menu_item=gtk_menu_item_new_with_label(vs);
		gtk_signal_connect(GTK_OBJECT(menu_item), "activate", 
				GTK_SIGNAL_FUNC(rpcstat_version_select), (gpointer)i);

		gtk_widget_show(menu_item);
		gtk_menu_append(GTK_MENU(vers_menu), menu_item);
	}
	gtk_option_menu_set_menu(GTK_OPTION_MENU(vers_opt), vers_menu);
}

static void *
rpcstat_list_programs(gpointer *key, gpointer *value, gpointer *user_data _U_)
{
	rpc_prog_info_key *k=(rpc_prog_info_key *)key;
	rpc_prog_info_value *v=(rpc_prog_info_value *)value;
	GtkWidget *menu_item;

	menu_item=gtk_menu_item_new_with_label(v->progname);
	gtk_signal_connect(GTK_OBJECT(menu_item), "activate", 
			GTK_SIGNAL_FUNC(rpcstat_program_select), (gpointer)k);

	gtk_widget_show(menu_item);
	gtk_menu_append(GTK_MENU(prog_menu), menu_item);

	if(!rpc_program){
		rpc_program=k->prog;
	}

	return NULL;
}

static void
dlg_destroy_cb(void)
{
	dlg=NULL;
}

void
gtk_rpcstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	int i;

	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	dlg=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(dlg), "ONC-RPC RTT Statistics");
	gtk_signal_connect(GTK_OBJECT(dlg), "destroy", GTK_SIGNAL_FUNC(dlg_destroy_cb), NULL);
	dlg_box=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);


	prog_box=gtk_hbox_new(FALSE, 10);
	/* Program label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	prog_label=gtk_label_new("Program:");
	gtk_box_pack_start(GTK_BOX(prog_box), prog_label, FALSE, FALSE, 0);
	gtk_widget_show(prog_label);

	/* Program menu */
	prog_opt=gtk_option_menu_new();
	prog_menu=gtk_menu_new();
	g_hash_table_foreach(rpc_progs, (GHFunc)rpcstat_list_programs, NULL);
	gtk_option_menu_set_menu(GTK_OPTION_MENU(prog_opt), prog_menu);
	gtk_box_pack_start(GTK_BOX(prog_box), prog_opt, TRUE, TRUE, 0);
	gtk_widget_show(prog_opt);

	/* Version label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	vers_label=gtk_label_new("Version:");
	gtk_box_pack_start(GTK_BOX(prog_box), vers_label, FALSE, FALSE, 0);
	gtk_widget_show(vers_label);

	/* Version menu */
	vers_opt=gtk_option_menu_new();
	vers_menu=gtk_menu_new();
	rpc_min_vers=-1;
	rpc_max_vers=-1;
	g_hash_table_foreach(rpc_procs, (GHFunc)rpcstat_find_vers, NULL);
	rpc_version=rpc_min_vers;
	for(i=rpc_min_vers;i<=rpc_max_vers;i++){
		GtkWidget *menu_item;
		char vs[5];
		sprintf(vs,"%d",i);
		menu_item=gtk_menu_item_new_with_label(vs);
		gtk_signal_connect(GTK_OBJECT(menu_item), "activate", 
				GTK_SIGNAL_FUNC(rpcstat_version_select), (gpointer)i);

		gtk_widget_show(menu_item);
		gtk_menu_append(GTK_MENU(vers_menu), menu_item);
	}

	gtk_option_menu_set_menu(GTK_OPTION_MENU(vers_opt), vers_menu);
	gtk_box_pack_start(GTK_BOX(prog_box), vers_opt, TRUE, TRUE, 0);
	gtk_widget_show(vers_opt);

	gtk_box_pack_start(GTK_BOX(dlg_box), prog_box, TRUE, TRUE, 0);
	gtk_widget_show(prog_box);

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
	gtk_signal_connect_object(GTK_OBJECT(start_button), "clicked", 
			GTK_SIGNAL_FUNC(rpcstat_start_button_clicked),
			NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), start_button, TRUE, TRUE, 0);
	gtk_widget_show(start_button);

	gtk_widget_show_all(dlg);
}


