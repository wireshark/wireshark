/* dcerpc_stat.c
 * dcerpc_stat   2002 Ronnie Sahlberg
 *
 * $Id: dcerpc_stat.c,v 1.4 2003/04/23 03:51:02 guy Exp $
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
#include "../register.h"
#include "packet-dcerpc.h"
#include "dcerpc_stat.h"
#include "../globals.h"
#include "compat_macros.h"

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
	e_uuid_t uuid;
	guint16 ver;
	guint32 num_procedures;
	rpc_procedure_t *procedures;
} rpcstat_t;


static int
uuid_equal(e_uuid_t *uuid1, e_uuid_t *uuid2)
{
	if( (uuid1->Data1!=uuid2->Data1)
	  ||(uuid1->Data2!=uuid2->Data2)
	  ||(uuid1->Data3!=uuid2->Data3)
	  ||(uuid1->Data4[0]!=uuid2->Data4[0])
	  ||(uuid1->Data4[1]!=uuid2->Data4[1])
	  ||(uuid1->Data4[2]!=uuid2->Data4[2])
	  ||(uuid1->Data4[3]!=uuid2->Data4[3])
	  ||(uuid1->Data4[4]!=uuid2->Data4[4])
	  ||(uuid1->Data4[5]!=uuid2->Data4[5])
	  ||(uuid1->Data4[6]!=uuid2->Data4[6])
	  ||(uuid1->Data4[7]!=uuid2->Data4[7]) ){
		return 0;
	}
	return 1;
}
	

static void
dcerpcstat_reset(rpcstat_t *rs)
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
dcerpcstat_packet(rpcstat_t *rs, packet_info *pinfo, epan_dissect_t *edt _U_, dcerpc_info *ri)
{
	nstime_t delta;
	rpc_procedure_t *rp;

	if(!ri->call_data){
		return 0;
	}
	if(!ri->call_data->req_frame){
		/* we have not seen the request so we dont know the delta*/
		return 0;
	}
	if(ri->call_data->opnum>=rs->num_procedures){
		/* dont handle this since its outside of known table */
		return 0;
	}

	/* we are only interested in reply packets */
	if(ri->request){
		return 0;
	}

	/* we are only interested in certain program/versions */
	if( (!uuid_equal( (&ri->call_data->uuid), (&rs->uuid)))
	  ||(ri->call_data->ver!=rs->ver)){
		return 0;
	}

	rp=&(rs->procedures[ri->call_data->opnum]);

	/* calculate time delta between request and reply */
	delta.secs=pinfo->fd->abs_secs-ri->call_data->req_time.secs;
	delta.nsecs=pinfo->fd->abs_usecs*1000-ri->call_data->req_time.nsecs;
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
dcerpcstat_draw(rpcstat_t *rs)
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



/* When called, this function will create a new instance of gtk-dcerpcstat.
 */
static void
gtk_dcerpcstat_init(char *optarg)
{
	rpcstat_t *rs;
	guint32 i, max_procs;
	char title_string[60];
	char filter_string[256];
	GtkWidget *vbox;
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	GtkWidget *tmp;
	dcerpc_sub_dissector *procs;
	e_uuid_t uuid;
	int d1,d2,d3,d40,d41,d42,d43,d44,d45,d46,d47;
	int major, minor;
	int pos=0;
        char *filter=NULL;

	if(sscanf(optarg,"dcerpc,rtt,%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%d.%d%n", &d1,&d2,&d3,&d40,&d41,&d42,&d43,&d44,&d45,&d46,&d47,&major,&minor,&pos)==13){
		uuid.Data1=d1;
		uuid.Data2=d2;
		uuid.Data3=d3;
		uuid.Data4[0]=d40;
		uuid.Data4[1]=d41;
		uuid.Data4[2]=d42;
		uuid.Data4[3]=d43;
		uuid.Data4[4]=d44;
		uuid.Data4[5]=d45;
		uuid.Data4[6]=d46;
		uuid.Data4[7]=d47;
		if(pos){
			filter=optarg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "tethereal: invalid \"-z dcerpc,rtt,<uuid>,<major version>.<minor version>[,<filter>]\" argument\n");
		exit(1);
	}


	rs=g_malloc(sizeof(rpcstat_t));
	rs->prog=dcerpc_get_proto_name(&uuid, (minor<<8)|(major&0xff) );
	if(!rs->prog){
		g_free(rs);
		fprintf(stderr,"tethereal: dcerpcstat_init() Protocol with uuid:%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x v%d.%d not supported\n",uuid.Data1,uuid.Data2,uuid.Data3,uuid.Data4[0],uuid.Data4[1],uuid.Data4[2],uuid.Data4[3],uuid.Data4[4],uuid.Data4[5],uuid.Data4[6],uuid.Data4[7],major,minor);
		exit(1);
	}
	procs=dcerpc_get_proto_sub_dissector(&uuid, (minor<<8)|(major&0xff) );
	rs->uuid=uuid;
	rs->ver=(minor<<8)|(major&0xff);

	rs->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	sprintf(title_string,"DCE-RPC RTT Stat for %s version %d.%d", rs->prog, rs->ver&0xff,rs->ver>>8);
	gtk_window_set_title(GTK_WINDOW(rs->win), title_string);
	SIGNAL_CONNECT(rs->win, "destroy", win_destroy_cb, rs);

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


	for(i=0,max_procs=0;procs[i].name;i++){
		if(procs[i].num>max_procs){
			max_procs=procs[i].num;
		}
	}
	rs->num_procedures=max_procs+1;
	rs->procedures=g_malloc(sizeof(rpc_procedure_t)*(rs->num_procedures+1));

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

       	for(i=0;i<rs->num_procedures;i++){
		GtkWidget *tmp;
		int j;
		char *proc_name;

		proc_name="unknown";
		for(j=0;procs[j].name;j++){
			if(procs[j].num==i){
				proc_name=procs[j].name;
			}
		}

		tmp=gtk_label_new(proc_name);
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


	if(register_tap_listener("dcerpc", rs, filter, (void*)dcerpcstat_reset, (void*)dcerpcstat_packet, (void*)dcerpcstat_draw)){
		char str[256];
		/* error, we failed to attach to the tap. clean up */
		snprintf(str,255,"Could not attach to tap using filter:%s",filter?filter:"");
		simple_dialog(ESD_TYPE_WARN, NULL, str);
		g_free(rs->procedures);
		g_free(rs);
		return;
	}


	gtk_widget_show_all(rs->win);
	redissect_packets(&cfile);
}



static e_uuid_t *dcerpc_uuid_program=NULL;
static guint16 dcerpc_version;
static GtkWidget *dlg=NULL, *dlg_box;
static GtkWidget *prog_box;
static GtkWidget *prog_label, *prog_opt, *prog_menu;
static GtkWidget *vers_label, *vers_opt, *vers_menu;
static GtkWidget *filter_box;
static GtkWidget *filter_label, *filter_entry;
static GtkWidget *start_button;


static void
dcerpcstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	char *filter;
	char str[256];

	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]==0){
		sprintf(str, "dcerpc,rtt,%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%d.%d",dcerpc_uuid_program->Data1,dcerpc_uuid_program->Data2,dcerpc_uuid_program->Data3,dcerpc_uuid_program->Data4[0],dcerpc_uuid_program->Data4[1],dcerpc_uuid_program->Data4[2],dcerpc_uuid_program->Data4[3],dcerpc_uuid_program->Data4[4],dcerpc_uuid_program->Data4[5],dcerpc_uuid_program->Data4[6],dcerpc_uuid_program->Data4[7],dcerpc_version&0xff,dcerpc_version>>8);

	} else {
		sprintf(str, "dcerpc,rtt,%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%d.%d,%s",dcerpc_uuid_program->Data1,dcerpc_uuid_program->Data2,dcerpc_uuid_program->Data3,dcerpc_uuid_program->Data4[0],dcerpc_uuid_program->Data4[1],dcerpc_uuid_program->Data4[2],dcerpc_uuid_program->Data4[3],dcerpc_uuid_program->Data4[4],dcerpc_uuid_program->Data4[5],dcerpc_uuid_program->Data4[6],dcerpc_uuid_program->Data4[7],dcerpc_version&0xff,dcerpc_version>>8, filter);
	}

	gtk_dcerpcstat_init(str);
}


static void
dcerpcstat_version_select(GtkWidget *item _U_, gpointer key)
{
	int vers=(int)key;

	dcerpc_version=vers;
}




static void *
dcerpcstat_find_vers(gpointer *key, gpointer *value _U_, gpointer *user_data _U_)
{
	dcerpc_uuid_key *k=(dcerpc_uuid_key *)key;
	GtkWidget *menu_item;
	char vs[5];

	if(!uuid_equal((&k->uuid), dcerpc_uuid_program)){
		return NULL;
	}

	sprintf(vs,"%d.%d",k->ver&0xff,k->ver>>8);
	menu_item=gtk_menu_item_new_with_label(vs);
	SIGNAL_CONNECT(menu_item, "activate", dcerpcstat_version_select,
                       ((int)k->ver));
	gtk_widget_show(menu_item);
	gtk_menu_append(GTK_MENU(vers_menu), menu_item);

	if(dcerpc_version==0xffff){
		dcerpc_version=k->ver;
	}

	return NULL;
}


static void
dcerpcstat_program_select(GtkWidget *item _U_, gpointer key)
{
	dcerpc_uuid_key *k=(dcerpc_uuid_key *)key;

	dcerpc_uuid_program=&k->uuid;

	/* change version menu */
	dcerpc_version=0xffff;
	gtk_object_destroy(GTK_OBJECT(vers_menu));
	vers_menu=gtk_menu_new();
	g_hash_table_foreach(dcerpc_uuids, (GHFunc)dcerpcstat_find_vers, NULL);
	gtk_option_menu_set_menu(GTK_OPTION_MENU(vers_opt), vers_menu);
}


static void *
dcerpcstat_list_programs(gpointer *key, gpointer *value, gpointer *user_data _U_)
{
	dcerpc_uuid_key *k=(dcerpc_uuid_key *)key;
	dcerpc_uuid_value *v=(dcerpc_uuid_value *)value;
	GtkWidget *menu_item;

	menu_item=gtk_menu_item_new_with_label(v->name);
	SIGNAL_CONNECT(menu_item, "activate", dcerpcstat_program_select, k);

	gtk_widget_show(menu_item);
	gtk_menu_append(GTK_MENU(prog_menu), menu_item);

	if(!dcerpc_uuid_program){
		dcerpc_uuid_program=&k->uuid;
	}

	return NULL;
}


static void
dlg_destroy_cb(void)
{
	dlg=NULL;
}


void
gtk_dcerpcstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	dlg=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(dlg), "DCE-RPC RTT Statistics");
	SIGNAL_CONNECT(dlg, "destroy", dlg_destroy_cb, NULL);
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
	g_hash_table_foreach(dcerpc_uuids, (GHFunc)dcerpcstat_list_programs, NULL);
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
	dcerpc_version=0xffff;
	g_hash_table_foreach(dcerpc_uuids, (GHFunc)dcerpcstat_find_vers, NULL);
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
	SIGNAL_CONNECT_OBJECT(start_button, "clicked", 
                              dcerpcstat_start_button_clicked, NULL);

	gtk_box_pack_start(GTK_BOX(dlg_box), start_button, TRUE, TRUE, 0);
	gtk_widget_show(start_button);

	gtk_widget_show_all(dlg);
}

void
register_tap_listener_gtkdcerpcstat(void)
{
	register_ethereal_tap("dcerpc,rtt,", gtk_dcerpcstat_init);
}
