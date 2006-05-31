/* dcerpc_stat.c
 * dcerpc_stat   2002 Ronnie Sahlberg
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

/* This module provides rpc call/reply SRT statistics to Wireshark,
 * and displays them graphically.
 * It is only used by Wireshark and not tshark
 *
 * It serves as an example on how to use the tap api.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/epan.h>

#include <epan/stat_cmd_args.h>
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include <epan/tap.h>
#include "../register.h"
#include <epan/dissectors/packet-dcerpc.h>
#include "../globals.h"
#include "filter_dlg.h"
#include "compat_macros.h"
#include "service_response_time_table.h"
#include "gtkglobals.h"


/* used to keep track of the statistics for an entire program interface */
typedef struct _rpcstat_t {
	GtkWidget *win;
	srt_stat_table srt_table;
	const char *prog;
	e_uuid_t uuid;
	guint16 ver;
	int num_procedures;
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

static char *
dcerpcstat_gen_title(rpcstat_t *rs)
{
	char *title;

	title = g_strdup_printf("DCE-RPC Service Response Time statistics for %s major version %u: %s", rs->prog, rs->ver, cf_get_display_name(&cfile));
	return title;
}

static void
dcerpcstat_set_title(rpcstat_t *rs)
{
	char *title;

	title = dcerpcstat_gen_title(rs);
	gtk_window_set_title(GTK_WINDOW(rs->win), title);
	g_free(title);
}

static void
dcerpcstat_reset(void *rs_arg)
{
	rpcstat_t *rs = rs_arg;

	reset_srt_table_data(&rs->srt_table);
	dcerpcstat_set_title(rs);
}


static int
dcerpcstat_packet(void *rs_arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *ri_arg)
{
	rpcstat_t *rs = rs_arg;
	const dcerpc_info *ri = ri_arg;

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
	if(ri->ptype != PDU_RESP){
		return 0;
	}

	/* we are only interested in certain program/versions */
	if( (!uuid_equal( (&ri->call_data->uuid), (&rs->uuid)))
	  ||(ri->call_data->ver!=rs->ver)){
		return 0;
	}


	add_srt_table_data(&rs->srt_table, ri->call_data->opnum, &ri->call_data->req_time, pinfo);


	return 1;
}

static void
dcerpcstat_draw(void *rs_arg)
{
	rpcstat_t *rs = rs_arg;

	draw_srt_table_data(&rs->srt_table);
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

	free_srt_table_data(&rs->srt_table);
	g_free(rs);
}



/* When called, this function will create a new instance of gtk-dcerpcstat.
 */
static void
gtk_dcerpcstat_init(const char *optarg, void* userdata _U_)
{
	rpcstat_t *rs;
	guint32 i, max_procs;
	char *title_string;
	char filter_string[256];
	GtkWidget *vbox;
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	GtkWidget *bbox;
	GtkWidget *close_bt;
	dcerpc_sub_dissector *procs;
	e_uuid_t uuid;
	guint d1,d2,d3,d40,d41,d42,d43,d44,d45,d46,d47;
	int major, minor;
	guint16 ver;
	int pos=0;
        const char *filter=NULL;
        GString *error_string;
	int hf_opnum;

	/*
	 * XXX - DCE RPC statistics are maintained only by major version,
	 * not by major and minor version, so the minor version number is
	 * ignored.
	 *
	 * Should we just stop supporting minor version numbers here?
	 * Or should we allow it to be omitted?  Or should we keep
	 * separate statistics for different minor version numbers,
	 * and allow the minor version number to be omitted, and
	 * report aggregate statistics for all minor version numbers
	 * if it's omitted?
	 */
	if(sscanf(optarg,"dcerpc,srt,%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%d.%d,%n", &d1,&d2,&d3,&d40,&d41,&d42,&d43,&d44,&d45,&d46,&d47,&major,&minor,&pos)==13){
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
		fprintf(stderr, "wireshark: invalid \"-z dcerpc,srt,<uuid>,<major version>.<minor version>[,<filter>]\" argument\n");
		exit(1);
	}
	if (major < 0 || major > 65535) {
		fprintf(stderr,"wireshark: dcerpcstat_init() Major version number %d is invalid - must be positive and <= 65535\n", major);
		exit(1);
	}
	if (minor < 0 || minor > 65535) {
		fprintf(stderr,"wireshark: dcerpcstat_init() Minor version number %d is invalid - must be positive and <= 65535\n", minor);
		exit(1);
	}
	ver = major;

	rs=g_malloc(sizeof(rpcstat_t));
	rs->prog=dcerpc_get_proto_name(&uuid, ver);
	if(!rs->prog){
		g_free(rs);
		fprintf(stderr,"wireshark: dcerpcstat_init() Protocol with uuid:%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x v%u not supported\n",uuid.Data1,uuid.Data2,uuid.Data3,uuid.Data4[0],uuid.Data4[1],uuid.Data4[2],uuid.Data4[3],uuid.Data4[4],uuid.Data4[5],uuid.Data4[6],uuid.Data4[7],ver);
		exit(1);
	}
	hf_opnum=dcerpc_get_proto_hf_opnum(&uuid, ver);
	procs=dcerpc_get_proto_sub_dissector(&uuid, ver);
	rs->uuid=uuid;
	rs->ver=ver;

	rs->win=window_new(GTK_WINDOW_TOPLEVEL, "dcerpc-stat");
	dcerpcstat_set_title(rs);
	gtk_window_set_default_size(GTK_WINDOW(rs->win), 550, 400);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(rs->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	title_string=dcerpcstat_gen_title(rs);
	stat_label=gtk_label_new(title_string);
	g_free(title_string);
	gtk_box_pack_start(GTK_BOX(vbox), stat_label, FALSE, FALSE, 0);

	g_snprintf(filter_string,255,"Filter:%s",filter?filter:"");
	filter_label=gtk_label_new(filter_string);
	gtk_box_pack_start(GTK_BOX(vbox), filter_label, FALSE, FALSE, 0);

	for(i=0,max_procs=0;procs[i].name;i++){
		if(procs[i].num>max_procs){
			max_procs=procs[i].num;
		}
	}
	rs->num_procedures=max_procs+1;

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(rs->win);

	if(hf_opnum!=-1){
		init_srt_table(&rs->srt_table, max_procs+1, vbox, proto_registrar_get_nth(hf_opnum)->abbrev);
	} else {
		init_srt_table(&rs->srt_table, max_procs+1, vbox, NULL);
	}

       	for(i=0;i<(max_procs+1);i++){
		int j;
		const char *proc_name;

		proc_name="unknown";
		for(j=0;procs[j].name;j++){
			if(procs[j].num==i){
				proc_name=procs[j].name;
			}
		}

		init_srt_table_row(&rs->srt_table, i, proc_name);
	}


	error_string=register_tap_listener("dcerpc", rs, filter, dcerpcstat_reset, dcerpcstat_packet, dcerpcstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free(error_string, TRUE);
		free_srt_table_data(&rs->srt_table);
		g_free(rs);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button(rs->win, close_bt, window_cancel_button_cb);

	SIGNAL_CONNECT(rs->win, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(rs->win, "destroy", win_destroy_cb, rs);

	gtk_widget_show_all(rs->win);
	window_present(rs->win);

	cf_retap_packets(&cfile, FALSE);
}



static e_uuid_t *dcerpc_uuid_program=NULL;
static guint16 dcerpc_version;
static GtkWidget *dlg=NULL;
static GtkWidget *prog_menu;
static GtkWidget *vers_opt, *vers_menu;
static GtkWidget *filter_entry;
static dcerpc_uuid_key *current_uuid_key=NULL;
static dcerpc_uuid_value *current_uuid_value=NULL;
static dcerpc_uuid_key *new_uuid_key=NULL;
static dcerpc_uuid_value *new_uuid_value=NULL;


static void
dcerpcstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	GString *str;
	const char *filter;

	str = g_string_new("dcerpc,srt");
	g_string_sprintfa(str,
	    ",%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%u.%u",
	    dcerpc_uuid_program->Data1, dcerpc_uuid_program->Data2,
	    dcerpc_uuid_program->Data3,
	    dcerpc_uuid_program->Data4[0], dcerpc_uuid_program->Data4[1],
	    dcerpc_uuid_program->Data4[2], dcerpc_uuid_program->Data4[3],
	    dcerpc_uuid_program->Data4[4], dcerpc_uuid_program->Data4[5],
	    dcerpc_uuid_program->Data4[6], dcerpc_uuid_program->Data4[7],
	    dcerpc_version, 0);
	filter=gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]!=0){
		g_string_sprintfa(str, ",%s", filter);
	}

	gtk_dcerpcstat_init(str->str,NULL);
	g_string_free(str, TRUE);
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

	g_snprintf(vs, 5, "%u",k->ver);
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


static GtkWidget *program_submenu_menu;
static GtkWidget *program_submenu_item;
static GtkWidget *program_submenu_label;
static int program_subitem_index;
static const char *first_menu_name;
static void 
dcerpcstat_add_program_to_menu(dcerpc_uuid_key *k, dcerpc_uuid_value *v)
{
	GtkWidget *program_menu_item;
	GtkWidget *box;
	char str[64];

	switch(program_subitem_index%15){
	case 0:

		first_menu_name=v->name;
		g_snprintf(str,63,"%s ...",v->name);
		program_submenu_item=gtk_menu_item_new();
		box=gtk_hbox_new(TRUE,0);
		gtk_container_add(GTK_CONTAINER(program_submenu_item), box);
		
		program_submenu_label=gtk_label_new(str);
		gtk_box_pack_start(GTK_BOX(box), program_submenu_label, TRUE, TRUE, 0);
		gtk_widget_show(program_submenu_label);
		gtk_widget_show(box);

		gtk_menu_append(GTK_MENU(prog_menu), program_submenu_item);
		gtk_widget_show(program_submenu_item);

		program_submenu_menu=gtk_menu_new();
		gtk_menu_item_set_submenu(GTK_MENU_ITEM(program_submenu_item), program_submenu_menu);
		break;
	case 14:
		g_snprintf(str,63,"%s - %s",first_menu_name,v->name);
		gtk_label_set_text(GTK_LABEL(program_submenu_label), str);
		break;
/*qqq*/
	}
	program_subitem_index++;		

	program_menu_item=gtk_menu_item_new_with_label(v->name);
	SIGNAL_CONNECT(program_menu_item, "activate", dcerpcstat_program_select, k);

	gtk_widget_show(program_menu_item);
	gtk_menu_append(GTK_MENU(program_submenu_menu), program_menu_item);

	if(!dcerpc_uuid_program){
		dcerpc_uuid_program=&k->uuid;
	}

	return;
}

static void *
dcerpcstat_find_next_program(gpointer *key, gpointer *value, gpointer *user_data _U_)
{
	dcerpc_uuid_key *k=(dcerpc_uuid_key *)key;
	dcerpc_uuid_value *v=(dcerpc_uuid_value *)value;

	/* first time called, just set new_uuid to this one */
	if((current_uuid_key==NULL)&&(new_uuid_key==NULL)){
		new_uuid_key=k;
		new_uuid_value=v;
		return NULL;
	}

	/* if we havent got a current one yet, just check the new
	   and scan for the first one alphabetically  */
	if(current_uuid_key==NULL){
		if(strcmp(new_uuid_value->name, v->name)>0){
			new_uuid_key=k;
			new_uuid_value=v;
			return NULL;
		}
		return NULL;
	}

	/* searching for the next one we are only interested in those
	   that sorts alphabetically after the current one */
	if(strcmp(current_uuid_value->name, v->name)>=0){
		/* this one doesnt so just skip it */
		return NULL;
	}

	/* is it the first potential new entry? */
	if(new_uuid_key==NULL){
		new_uuid_key=k;
		new_uuid_value=v;
		return NULL;
	}

	/* does it sort before the current new one? */
	if(strcmp(new_uuid_value->name, v->name)>0){
		new_uuid_key=k;
		new_uuid_value=v;
		return NULL;
	}

	return NULL;
}


static void
dlg_destroy_cb(void)
{
	dlg=NULL;
}


static void
gtk_dcerpcstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	GtkWidget *dlg_box;
	GtkWidget *prog_box, *prog_label, *prog_opt;
	GtkWidget *vers_label;
	GtkWidget *filter_box, *filter_bt;
	GtkWidget *bbox, *start_button, *cancel_button;
	const char *filter;
	static construct_args_t args = {
	  "Service Response Time Statistics Filter",
	  FALSE,
	  FALSE,
      FALSE
	};

	/* if the window is already open, bring it to front and
	   un-minimize it, as necessary */
	if(dlg){
		reactivate_window(dlg);
		return;
	}

	dlg=dlg_window_new("Wireshark: Compute DCE-RPC SRT statistics");
	gtk_window_set_default_size(GTK_WINDOW(dlg), 400, -1);

	dlg_box=gtk_vbox_new(FALSE, 10);
	gtk_container_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Program box */
	prog_box=gtk_hbox_new(FALSE, 3);

	/* Program label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	prog_label=gtk_label_new("Program:");
	gtk_box_pack_start(GTK_BOX(prog_box), prog_label, FALSE, FALSE, 0);
	gtk_widget_show(prog_label);

	/* Program menu */
	prog_opt=gtk_option_menu_new();
	prog_menu=gtk_menu_new();
	current_uuid_key=NULL;
	current_uuid_value=NULL;
/*qqq*/
	program_submenu_item=NULL;
	program_submenu_menu=NULL;
	program_subitem_index=0;
	do {
		new_uuid_key=NULL;
		new_uuid_value=NULL;
		g_hash_table_foreach(dcerpc_uuids, (GHFunc)dcerpcstat_find_next_program, NULL);
		if(new_uuid_key){
			dcerpcstat_add_program_to_menu(new_uuid_key, new_uuid_value);
		}
		current_uuid_key=new_uuid_key;
		current_uuid_value=new_uuid_value;
	} while(new_uuid_key!=NULL);

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

	/* Filter box */
	filter_box=gtk_hbox_new(FALSE, 3);

	/* Filter label */
	filter_bt=BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);
	SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_bt, FALSE, FALSE, 0);
	gtk_widget_show(filter_bt);

	/* Filter entry */
	filter_entry=gtk_entry_new();
    SIGNAL_CONNECT(filter_entry, "changed", filter_te_syntax_check_cb, NULL);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_entry, TRUE, TRUE, 0);
	filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	if(filter){
		gtk_entry_set_text(GTK_ENTRY(filter_entry), filter);
	}
	gtk_widget_show(filter_entry);
	
	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);

	OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_entry);

	/* button box */
    bbox = dlg_button_row_new(WIRESHARK_STOCK_CREATE_STAT, GTK_STOCK_CANCEL, NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    start_button = OBJECT_GET_DATA(bbox, WIRESHARK_STOCK_CREATE_STAT);
	SIGNAL_CONNECT_OBJECT(start_button, "clicked", 
                              dcerpcstat_start_button_clicked, NULL);

    cancel_button = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
    window_set_cancel_button(dlg, cancel_button, window_cancel_button_cb);

    SIGNAL_CONNECT(dlg, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(dlg, "destroy", dlg_destroy_cb, NULL);

	/* Catch the "activate" signal on the filter text entry, so that
	   if the user types Return there, we act as if the "Create Stat"
	   button had been selected, as happens if Return is typed if some
	   widget that *doesn't* handle the Return key has the input
	   focus. */
	dlg_set_activate(filter_entry, start_button);

    gtk_widget_grab_default(start_button );

	/* Give the initial focus to the "Filter" entry box. */
	gtk_widget_grab_focus(filter_entry);

	gtk_widget_show_all(dlg);
    window_present(dlg);
}

void
register_tap_listener_gtkdcerpcstat(void)
{
	register_stat_cmd_arg("dcerpc,srt,", gtk_dcerpcstat_init,NULL);

	register_stat_menu_item("DCE-RPC...", REGISTER_STAT_GROUP_RESPONSE_TIME,
	    gtk_dcerpcstat_cb, NULL, NULL, NULL);
}
