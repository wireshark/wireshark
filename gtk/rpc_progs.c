/* rpc_progs.c
 * rpc_progs   2002 Ronnie Sahlberg
 *
 * $Id: rpc_progs.c,v 1.2 2002/10/23 23:12:36 guy Exp $
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
#include "tap.h"
#include "rpc_progs.h"
#include "packet-rpc.h"

static GtkWidget *win=NULL;
static GtkWidget *table=NULL;
static int num_progs=0;

/* used to keep track of statistics for a specific program/version */
typedef struct _rpc_program_t {
	struct _rpc_program_t *next;
	guint32 program;
	GtkWidget *wprogram;
	gchar sprogram[24];

	guint32 version;
	GtkWidget *wversion;
	gchar sversion[16];

	int num;
	GtkWidget *wnum;
	gchar snum[16];

	nstime_t min;
	GtkWidget *wmin;
	gchar smin[16];

	nstime_t max;
	GtkWidget *wmax;
	gchar smax[16];

	nstime_t tot;
	GtkWidget *wavg;
	gchar savg[16];
} rpc_program_t;

static rpc_program_t *prog_list=NULL;


static void
rpcprogs_reset(void *dummy _U_)
{
	rpc_program_t *rp;

	for(rp=prog_list;rp;rp=rp->next){
		rp->num=0;	
		rp->min.secs=0;
		rp->min.nsecs=0;
		rp->max.secs=0;
		rp->max.nsecs=0;
		rp->tot.secs=0;
		rp->tot.nsecs=0;
	}
}

static void
add_new_program(rpc_program_t *rp)
{
	num_progs++;
	gtk_table_resize(GTK_TABLE(table), num_progs+1, 6);
	rp->wprogram=gtk_label_new("0");
	gtk_table_attach_defaults(GTK_TABLE(table), rp->wprogram, 0,1,num_progs,num_progs+1);
	gtk_widget_show(rp->wprogram);
	rp->wversion=gtk_label_new("0");
	gtk_table_attach_defaults(GTK_TABLE(table), rp->wversion, 1,2,num_progs,num_progs+1);
	gtk_widget_show(rp->wversion);
	rp->wnum=gtk_label_new("0");
	gtk_table_attach_defaults(GTK_TABLE(table), rp->wnum, 2,3,num_progs,num_progs+1);
	gtk_widget_show(rp->wnum);
	rp->wmin=gtk_label_new("0");
	gtk_table_attach_defaults(GTK_TABLE(table), rp->wmin, 3,4,num_progs,num_progs+1);
	gtk_widget_show(rp->wmin);
	rp->wmax=gtk_label_new("0");
	gtk_table_attach_defaults(GTK_TABLE(table), rp->wmax, 4,5,num_progs,num_progs+1);
	gtk_widget_show(rp->wmax);
	rp->wavg=gtk_label_new("0");
	gtk_table_attach_defaults(GTK_TABLE(table), rp->wavg, 5,6,num_progs,num_progs+1);
	gtk_widget_show(rp->wavg);

	rp->num=0;
	rp->min.secs=0;
	rp->min.nsecs=0;
	rp->max.secs=0;
	rp->max.nsecs=0;
	rp->tot.secs=0;
	rp->tot.nsecs=0;
}



static int
rpcprogs_packet(void *dummy _U_, packet_info *pinfo, epan_dissect_t *edt _U_, rpc_call_info_value *ri)
{
	nstime_t delta;
	rpc_program_t *rp;

	if(!prog_list){
		/* the list was empty */
		rp=g_malloc(sizeof(rpc_program_t));
		add_new_program(rp);
		rp->next=NULL;
		rp->program=ri->prog;
		rp->version=ri->vers;
		prog_list=rp;
	} else if((ri->prog==prog_list->program)
		&&(ri->vers==prog_list->version)){
		rp=prog_list;
	} else if( (ri->prog<prog_list->program)
		||((ri->prog==prog_list->program)&&(ri->vers<prog_list->version))){
		/* we should be first entry in list */
		rp=g_malloc(sizeof(rpc_program_t));
		add_new_program(rp);
		rp->next=prog_list;
		rp->program=ri->prog;
		rp->version=ri->vers;
		prog_list=rp;
	} else {
		/* we go somewhere else in the list */
		for(rp=prog_list;rp;rp=rp->next){
			if((rp->next)
			&& (rp->next->program==ri->prog)
			&& (rp->next->version==ri->vers)){
				rp=rp->next;
				break;
			}
			if((!rp->next)
			|| (rp->next->program>ri->prog)
			|| (  (rp->next->program==ri->prog)
			    &&(rp->next->version>ri->vers))){
				rpc_program_t *trp;
				trp=g_malloc(sizeof(rpc_program_t));
				add_new_program(trp);
				trp->next=rp->next;
				trp->program=ri->prog;
				trp->version=ri->vers;
				rp->next=trp;
				rp=trp;
				break;
			}
		}
	}

	
	/* we are only interested in reply packets */
	if(ri->request){
		return 0;
	}

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
rpcprogs_draw(void *dummy _U_)
{
	rpc_program_t *rp;
	int i;
#ifdef G_HAVE_UINT64
	guint64 td;
#else
	guint32 td;
#endif

	for(rp=prog_list,i=1;rp;rp=rp->next,i++){
		/* scale it to units of 10us.*/
		/* for long captures with a large tot time, this can overflow on 32bit */
		td=(int)rp->tot.secs;
		td=td*100000+(int)rp->tot.nsecs/10000;
		if(rp->num){
			td/=rp->num;
		} else {
			td=0;
		}

		sprintf(rp->sprogram,"%s",rpc_prog_name(rp->program));
		gtk_label_set_text(GTK_LABEL(rp->wprogram), rp->sprogram);

		sprintf(rp->sversion,"%d",rp->version);
		gtk_label_set_text(GTK_LABEL(rp->wversion), rp->sversion);

		sprintf(rp->snum,"%d",rp->num);
		gtk_label_set_text(GTK_LABEL(rp->wnum), rp->snum);

		sprintf(rp->smin,"%3d.%05d",(int)rp->min.secs,(int)rp->min.nsecs/10000);
		gtk_label_set_text(GTK_LABEL(rp->wmin), rp->smin);

		sprintf(rp->smax,"%3d.%05d",(int)rp->max.secs,(int)rp->max.nsecs/10000);
		gtk_label_set_text(GTK_LABEL(rp->wmax), rp->smax);

		sprintf(rp->savg,"%3d.%05d",(int)td/100000,(int)td%100000);
		gtk_label_set_text(GTK_LABEL(rp->wavg), rp->savg);

	}
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
win_destroy_cb(void *dummy _U_, gpointer data _U_)
{
	rpc_program_t *rp, *rp2;

	protect_thread_critical_region();
	remove_tap_listener(win);
	unprotect_thread_critical_region();

	win=NULL;
	for(rp=prog_list;rp;){
		rp2=rp->next;
		g_free(rp);
		rp=rp2;
	}
	prog_list=NULL;
}


/* When called, this function will start rpcprogs
 */
void
gtk_rpcprogs_init(void)
{
	char title_string[60];
	GtkWidget *vbox;
	GtkWidget *stat_label;
	GtkWidget *tmp;

	if(win){
		gdk_window_raise(win->window);
		return;
	}

	win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	sprintf(title_string,"ONC-RPC Program Statistics");
	gtk_window_set_title(GTK_WINDOW(win), title_string);
	gtk_signal_connect(GTK_OBJECT(win), "destroy", GTK_SIGNAL_FUNC(win_destroy_cb), win);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	stat_label=gtk_label_new(title_string);
	gtk_box_pack_start(GTK_BOX(vbox), stat_label, FALSE, FALSE, 0);
	gtk_widget_show(stat_label);


	table=gtk_table_new(1, 5, TRUE);
	gtk_container_add(GTK_CONTAINER(vbox), table);

	tmp=gtk_label_new("Program");
	gtk_table_attach_defaults(GTK_TABLE(table), tmp, 0,1,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
	gtk_widget_show(tmp);

	tmp=gtk_label_new("Version");
	gtk_table_attach_defaults(GTK_TABLE(table), tmp, 1,2,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_RIGHT);
	gtk_widget_show(tmp);

	tmp=gtk_label_new("Calls");
	gtk_table_attach_defaults(GTK_TABLE(table), tmp, 2,3,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_RIGHT);
	gtk_widget_show(tmp);

	tmp=gtk_label_new("Min RTT");
	gtk_table_attach_defaults(GTK_TABLE(table), tmp, 3,4,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_RIGHT);
	gtk_widget_show(tmp);

	tmp=gtk_label_new("Max RTT");
	gtk_table_attach_defaults(GTK_TABLE(table), tmp, 4,5,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_RIGHT);
	gtk_widget_show(tmp);

	tmp=gtk_label_new("Avg RTT");
	gtk_table_attach_defaults(GTK_TABLE(table), tmp, 5,6,0,1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_RIGHT);
	gtk_widget_show(tmp);

	
	gtk_widget_show(table);

	if(register_tap_listener("rpc", win, NULL, (void*)rpcprogs_reset, (void*)rpcprogs_packet, (void*)rpcprogs_draw)){
		fprintf(stderr, "ethereal: gtk_rpcprogs_init() failed to register tap\n");
		exit(1);
	}


	gtk_widget_show_all(win);
}

