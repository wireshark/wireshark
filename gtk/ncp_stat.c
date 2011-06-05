/* ncp_stat.c
 * ncp_stat   2005 Greg Morris
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
#include <epan/dissectors/packet-ncp-int.h>

#include "../timestats.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../stat_menu.h"

#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/filter_dlg.h"
#include "gtk/service_response_time_table.h"
#include "gtk/tap_param_dlg.h"
#include "gtk/gtkglobals.h"
#include "gtk/main.h"


/* used to keep track of the statistics for an entire program interface */
typedef struct _ncpstat_t {
	GtkWidget *win;
	srt_stat_table ncp_srt_table;
    srt_stat_table nds_srt_table;
    srt_stat_table func_srt_table;
    srt_stat_table sss_srt_table;
    srt_stat_table nmas_srt_table;
    srt_stat_table sub_17_srt_table;
    srt_stat_table sub_21_srt_table;
    srt_stat_table sub_22_srt_table;
    srt_stat_table sub_23_srt_table;
    srt_stat_table sub_32_srt_table;
    srt_stat_table sub_34_srt_table;
    srt_stat_table sub_35_srt_table;
    srt_stat_table sub_36_srt_table;
    srt_stat_table sub_86_srt_table;
    srt_stat_table sub_87_srt_table;
    srt_stat_table sub_89_srt_table;
    srt_stat_table sub_90_srt_table;
    srt_stat_table sub_92_srt_table;
    srt_stat_table sub_94_srt_table;
    srt_stat_table sub_104_srt_table;
    srt_stat_table sub_111_srt_table;
    srt_stat_table sub_114_srt_table;
    srt_stat_table sub_123_srt_table;
    srt_stat_table sub_131_srt_table;
} ncpstat_t;

static const value_string ncp_group_vals[] = {
	{ 0, "Synchronization" },
	{ 1, "Print" },
	{ 2, "File System" },
	{ 3, "Connection" },
	{ 4, "File Server Environment" },
	{ 5, "Message" },
	{ 6, "Bindery" },
	{ 7, "Queue Management System (QMS)" },
	{ 8, "Accounting" },
	{ 9, "Transaction Tracking" },
	{ 10, "AFP" },
	{ 11, "NCP Extension" },
	{ 12, "Extended Attribute" },
	{ 13, "Auditing" },
	{ 14, "Enhanced File System" },
	{ 15, "Migration" },
	{ 16, "Novell Modular Authentication Services (NMAS)" },
	{ 17, "Secret Store Services (SSS)" },
	{ 18, "Packet Burst" },
	{ 19, "Novell Directory Services (NDS)" },
	{ 20, "Time Synchronization" },
	{ 21, "Server Statistics" },
	{ 22, "Remote" },
	{ 0,  NULL}
};

static const value_string sss_verb_enum[] = {
	{ 0x00000000, "Query Server" },
	{ 0x00000001, "Read App Secrets" },
	{ 0x00000002, "Write App Secrets" },
	{ 0x00000003, "Add Secret ID" },
	{ 0x00000004, "Remove Secret ID" },
	{ 0x00000005, "Remove SecretStore" },
	{ 0x00000006, "Enumerate Secret IDs" },
	{ 0x00000007, "Unlock Store" },
	{ 0x00000008, "Set Master Password" },
	{ 0x00000009, "Get Service Information" },
	{ 0x000000ff, "Fragment"},
	{ 0x00000000, NULL}
};

static const value_string nmas_subverb_enum[] = {
	{ 0, "Fragmented Ping" },
	{ 2, "Client Put Data" },
	{ 4, "Client Get Data" },
	{ 6, "Client Get User NDS Credentials" },
	{ 8, "Login Store Management" },
	{ 10, "Writable Object Check" },
	{ 1242, "Message Handler" },
	{ 0,  NULL}
};

static const value_string ncp_nds_verb_vals[] = {
	{ 1, "Resolve Name" },
	{ 2, "Read Entry Information" },
	{ 3, "Read" },
	{ 4, "Compare" },
	{ 5, "List" },
	{ 6, "Search Entries" },
	{ 7, "Add Entry" },
	{ 8, "Remove Entry" },
	{ 9, "Modify Entry" },
	{ 10, "Modify RDN" },
	{ 11, "Create Attribute" },
	{ 12, "Read Attribute Definition" },
	{ 13, "Remove Attribute Definition" },
	{ 14, "Define Class" },
	{ 15, "Read Class Definition" },
	{ 16, "Modify Class Definition" },
	{ 17, "Remove Class Definition" },
	{ 18, "List Containable Classes" },
	{ 19, "Get Effective Rights" },
	{ 20, "Add Partition" },
	{ 21, "Remove Partition" },
	{ 22, "List Partitions" },
	{ 23, "Split Partition" },
	{ 24, "Join Partitions" },
	{ 25, "Add Replica" },
	{ 26, "Remove Replica" },
	{ 27, "Open Stream" },
	{ 28, "Search Filter" },
	{ 29, "Create Subordinate Reference" },
	{ 30, "Link Replica" },
	{ 31, "Change Replica Type" },
	{ 32, "Start Update Schema" },
	{ 33, "End Update Schema" },
	{ 34, "Update Schema" },
	{ 35, "Start Update Replica" },
	{ 36, "End Update Replica" },
	{ 37, "Update Replica" },
	{ 38, "Synchronize Partition" },
	{ 39, "Synchronize Schema" },
	{ 40, "Read Syntaxes" },
	{ 41, "Get Replica Root ID" },
	{ 42, "Begin Move Entry" },
	{ 43, "Finish Move Entry" },
	{ 44, "Release Moved Entry" },
	{ 45, "Backup Entry" },
	{ 46, "Restore Entry" },
	{ 47, "Save DIB (Obsolete)" },
	{ 48, "Control" },
	{ 49, "Remove Backlink" },
	{ 50, "Close Iteration" },
	{ 51, "Mutate Entry" },
	{ 52, "Audit Skulking" },
	{ 53, "Get Server Address" },
	{ 54, "Set Keys" },
	{ 55, "Change Password" },
	{ 56, "Verify Password" },
	{ 57, "Begin Login" },
	{ 58, "Finish Login" },
	{ 59, "Begin Authentication" },
	{ 60, "Finish Authentication" },
	{ 61, "Logout" },
	{ 62, "Repair Ring (Obsolete)" },
	{ 63, "Repair Timestamps" },
	{ 64, "Create Back Link" },
	{ 65, "Delete External Reference" },
	{ 66, "Rename External Reference" },
	{ 67, "Create Queue Entry Directory" },
	{ 68, "Remove Queue Entry Directory" },
	{ 69, "Merge Entries" },
	{ 70, "Change Tree Name" },
	{ 71, "Partition Entry Count" },
	{ 72, "Check Login Restrictions" },
	{ 73, "Start Join" },
	{ 74, "Low Level Split" },
	{ 75, "Low Level Join" },
	{ 76, "Abort Partition Operation" },
	{ 77, "Get All Servers" },
	{ 78, "Partition Function" },
	{ 79, "Read References" },
	{ 80, "Inspect Entry" },
	{ 81, "Get Remote Entry ID" },
	{ 82, "Change Security" },
	{ 83, "Check Console Operator" },
	{ 84, "Start Move Tree" },
	{ 85, "Move Tree" },
	{ 86, "End Move Tree" },
	{ 87, "Low Level Abort Join" },
	{ 88, "Check Security Equivalence" },
	{ 89, "Merge Tree" },
	{ 90, "Sync External Reference" },
	{ 91, "Resend Entry" },
	{ 92, "New Schema Epoch" },
	{ 93, "Statistics" },
	{ 94, "Ping" },
	{ 95, "Get Bindery Contexts" },
	{ 96, "Monitor Connection" },
	{ 97, "Get DS Statistics" },
	{ 98, "Reset DS Counters" },
	{ 99, "Console" },
	{ 100, "Read Stream" },
	{ 101, "Write Stream" },
	{ 102, "Create Orphan Partition" },
	{ 103, "Remove Orphan Partition" },
	{ 104, "Link Orphan Partition" },
	{ 105, "Set Distributed Reference Link (DRL)" },
	{ 106, "Available" },
	{ 107, "Available" },
	{ 108, "Verify Distributed Reference Link (DRL)" },
	{ 109, "Verify Partition" },
	{ 110, "Iterator" },
	{ 111, "Available" },
	{ 112, "Close Stream" },
	{ 113, "Available" },
	{ 114, "Read Status" },
	{ 115, "Partition Sync Status" },
	{ 116, "Read Reference Data" },
	{ 117, "Write Reference Data" },
	{ 118, "Resource Event" },
	{ 119, "DIB Request (obsolete)" },
	{ 120, "Set Replication Filter" },
	{ 121, "Get Replication Filter" },
	{ 122, "Change Attribute Definition" },
	{ 123, "Schema in Use" },
	{ 124, "Remove Keys" },
	{ 125, "Clone" },
	{ 126, "Multiple Operations Transaction" },
	{ 240, "Ping" },
	{ 255, "EDirectory Call" },
	{ 0,  NULL }
};

static void
ncpstat_set_title(ncpstat_t *ss)
{
	char *title;

	title = g_strdup_printf("NCP Service Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(ss->win), title);
	g_free(title);
}

static void
ncpstat_reset(void *pss)
{
	ncpstat_t *ss=(ncpstat_t *)pss;

	reset_srt_table_data(&ss->ncp_srt_table);
	reset_srt_table_data(&ss->func_srt_table);
	reset_srt_table_data(&ss->nds_srt_table);
	reset_srt_table_data(&ss->sss_srt_table);
	reset_srt_table_data(&ss->nmas_srt_table);
	reset_srt_table_data(&ss->sub_17_srt_table);
	reset_srt_table_data(&ss->sub_21_srt_table);
	reset_srt_table_data(&ss->sub_22_srt_table);
	reset_srt_table_data(&ss->sub_23_srt_table);
	reset_srt_table_data(&ss->sub_32_srt_table);
	reset_srt_table_data(&ss->sub_34_srt_table);
	reset_srt_table_data(&ss->sub_35_srt_table);
	reset_srt_table_data(&ss->sub_36_srt_table);
	reset_srt_table_data(&ss->sub_86_srt_table);
	reset_srt_table_data(&ss->sub_87_srt_table);
	reset_srt_table_data(&ss->sub_89_srt_table);
	reset_srt_table_data(&ss->sub_90_srt_table);
	reset_srt_table_data(&ss->sub_92_srt_table);
	reset_srt_table_data(&ss->sub_94_srt_table);
	reset_srt_table_data(&ss->sub_104_srt_table);
	reset_srt_table_data(&ss->sub_111_srt_table);
	reset_srt_table_data(&ss->sub_114_srt_table);
	reset_srt_table_data(&ss->sub_123_srt_table);
	reset_srt_table_data(&ss->sub_131_srt_table);
	ncpstat_set_title(ss);
}

static int
ncpstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv)
{
	ncpstat_t *ss=(ncpstat_t *)pss;
    const ncp_req_hash_value *request_val=prv;

	/* if we havent seen the request, just ignore it */
	if(!request_val || request_val->ncp_rec==0){
		return 0;
	}
    /* By Group */
    init_srt_table_row(&ss->ncp_srt_table, request_val->ncp_rec->group, val_to_str(request_val->ncp_rec->group, ncp_group_vals, "Unknown(%u)"));
    add_srt_table_data(&ss->ncp_srt_table, request_val->ncp_rec->group, &request_val->req_frame_time, pinfo);
    /* By NCP number without subfunction*/
    if (request_val->ncp_rec->subfunc==0) {
        init_srt_table_row(&ss->func_srt_table, request_val->ncp_rec->func, request_val->ncp_rec->name);
        add_srt_table_data(&ss->func_srt_table, request_val->ncp_rec->func, &request_val->req_frame_time, pinfo);
    }
    /* By Subfunction number */
	if(request_val->ncp_rec->subfunc!=0){
        if (request_val->ncp_rec->func==17) {
            init_srt_table_row(&ss->sub_17_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_17_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==21) {
            init_srt_table_row(&ss->sub_21_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_21_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==22) {
            init_srt_table_row(&ss->sub_22_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_22_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==23) {
            init_srt_table_row(&ss->sub_23_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_23_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==32) {
            init_srt_table_row(&ss->sub_32_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_32_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==34) {
            init_srt_table_row(&ss->sub_34_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_34_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==35) {
            init_srt_table_row(&ss->sub_35_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_35_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==36) {
            init_srt_table_row(&ss->sub_36_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_36_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==86) {
            init_srt_table_row(&ss->sub_86_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_86_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==87) {
            init_srt_table_row(&ss->sub_87_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_87_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==89) {
            init_srt_table_row(&ss->sub_89_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_89_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==90) {
            init_srt_table_row(&ss->sub_90_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_90_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==92) {
            init_srt_table_row(&ss->sub_92_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_92_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==94) {
            init_srt_table_row(&ss->sub_94_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_94_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==104) {
            init_srt_table_row(&ss->sub_104_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_104_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==111) {
            init_srt_table_row(&ss->sub_111_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_111_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==114) {
            init_srt_table_row(&ss->sub_114_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_114_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==123) {
            init_srt_table_row(&ss->sub_123_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_123_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
        if (request_val->ncp_rec->func==131) {
            init_srt_table_row(&ss->sub_131_srt_table, (request_val->ncp_rec->subfunc), request_val->ncp_rec->name);
            add_srt_table_data(&ss->sub_131_srt_table, (request_val->ncp_rec->subfunc), &request_val->req_frame_time, pinfo);
        }
	}
    /* By NDS verb */
    if (request_val->ncp_rec->func==0x68) {
        init_srt_table_row(&ss->nds_srt_table, (request_val->nds_request_verb), val_to_str(request_val->nds_request_verb, ncp_nds_verb_vals, "Unknown(%u)"));
        add_srt_table_data(&ss->nds_srt_table, (request_val->nds_request_verb), &request_val->req_frame_time, pinfo);
    }
    if (request_val->ncp_rec->func==0x5c) {
        init_srt_table_row(&ss->sss_srt_table, (request_val->req_nds_flags), val_to_str(request_val->req_nds_flags, sss_verb_enum, "Unknown(%u)"));
        add_srt_table_data(&ss->sss_srt_table, (request_val->req_nds_flags), &request_val->req_frame_time, pinfo);
    }
    if (request_val->ncp_rec->func==0x5e) {
        init_srt_table_row(&ss->nmas_srt_table, (request_val->req_nds_flags), val_to_str(request_val->req_nds_flags, nmas_subverb_enum, "Unknown(%u)"));
        add_srt_table_data(&ss->nmas_srt_table, (request_val->req_nds_flags), &request_val->req_frame_time, pinfo);
    }
    return 1;
}



static void
ncpstat_draw(void *pss)
{
	ncpstat_t *ss=(ncpstat_t *)pss;

	draw_srt_table_data(&ss->ncp_srt_table);
	draw_srt_table_data(&ss->func_srt_table);
	draw_srt_table_data(&ss->nds_srt_table);
	draw_srt_table_data(&ss->sss_srt_table);
	draw_srt_table_data(&ss->nmas_srt_table);
	draw_srt_table_data(&ss->sub_17_srt_table);
	draw_srt_table_data(&ss->sub_21_srt_table);
	draw_srt_table_data(&ss->sub_22_srt_table);
	draw_srt_table_data(&ss->sub_23_srt_table);
	draw_srt_table_data(&ss->sub_32_srt_table);
	draw_srt_table_data(&ss->sub_34_srt_table);
	draw_srt_table_data(&ss->sub_35_srt_table);
	draw_srt_table_data(&ss->sub_36_srt_table);
	draw_srt_table_data(&ss->sub_86_srt_table);
	draw_srt_table_data(&ss->sub_87_srt_table);
	draw_srt_table_data(&ss->sub_89_srt_table);
	draw_srt_table_data(&ss->sub_90_srt_table);
	draw_srt_table_data(&ss->sub_92_srt_table);
	draw_srt_table_data(&ss->sub_94_srt_table);
	draw_srt_table_data(&ss->sub_104_srt_table);
	draw_srt_table_data(&ss->sub_111_srt_table);
	draw_srt_table_data(&ss->sub_114_srt_table);
	draw_srt_table_data(&ss->sub_123_srt_table);
	draw_srt_table_data(&ss->sub_131_srt_table);
}

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	ncpstat_t *ss=(ncpstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ss);
	unprotect_thread_critical_region();


	free_srt_table_data(&ss->ncp_srt_table);
	free_srt_table_data(&ss->func_srt_table);
	free_srt_table_data(&ss->nds_srt_table);
	free_srt_table_data(&ss->sss_srt_table);
	free_srt_table_data(&ss->nmas_srt_table);
	free_srt_table_data(&ss->sub_17_srt_table);
	free_srt_table_data(&ss->sub_21_srt_table);
	free_srt_table_data(&ss->sub_22_srt_table);
	free_srt_table_data(&ss->sub_23_srt_table);
	free_srt_table_data(&ss->sub_32_srt_table);
	free_srt_table_data(&ss->sub_34_srt_table);
	free_srt_table_data(&ss->sub_35_srt_table);
	free_srt_table_data(&ss->sub_36_srt_table);
	free_srt_table_data(&ss->sub_86_srt_table);
	free_srt_table_data(&ss->sub_87_srt_table);
	free_srt_table_data(&ss->sub_89_srt_table);
	free_srt_table_data(&ss->sub_90_srt_table);
	free_srt_table_data(&ss->sub_92_srt_table);
	free_srt_table_data(&ss->sub_94_srt_table);
	free_srt_table_data(&ss->sub_104_srt_table);
	free_srt_table_data(&ss->sub_111_srt_table);
	free_srt_table_data(&ss->sub_114_srt_table);
	free_srt_table_data(&ss->sub_123_srt_table);
	free_srt_table_data(&ss->sub_131_srt_table);
	g_free(ss);
}


static void
gtk_ncpstat_init(const char *optarg, void *userdata _U_)
{
    ncpstat_t *ss;
    const char *filter=NULL;
    GtkWidget *label;
    char *filter_string;
    GString *error_string;
    GtkWidget *temp_page;
    GtkWidget *main_nb;
    GtkWidget *vbox;
    GtkWidget *bbox;
    GtkWidget *close_bt;

    if(!strncmp(optarg,"ncp,srt,",8)){
        filter=optarg+8;
    } else {
        filter=NULL;
    }

    ss=g_malloc(sizeof(ncpstat_t));

	ss->win = dlg_window_new("ncp-stat");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(ss->win), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(ss->win), 300, 400);

    ncpstat_set_title(ss);

    vbox=gtk_vbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(ss->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    label=gtk_label_new("NCP Service Response Time Statistics");
    gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, TRUE, 0);

    filter_string = g_strdup_printf("Filter: %s",filter ? filter : "");
    label=gtk_label_new(filter_string);
    g_free(filter_string);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    main_nb = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), main_nb, TRUE, TRUE, 0);
    temp_page = gtk_vbox_new(FALSE, 6);
    label = gtk_label_new("Groups");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);

    /* NCP Groups */
    /* We must display TOP LEVEL Widget before calling init_srt_table() */
    gtk_widget_show_all(ss->win);
    label=gtk_label_new("NCP by Group Type");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->ncp_srt_table, 256, temp_page, "ncp.group");

    /* NCP Functions */
    temp_page = gtk_vbox_new(FALSE, 6);
    label = gtk_label_new("Functions");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("NCP Functions without Subfunctions");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->func_srt_table, 256, temp_page, "ncp.func");

    /* NCP Subfunctions */

    temp_page = gtk_vbox_new(FALSE, 6);
    label = gtk_label_new("17");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 17");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_17_srt_table, 256, temp_page, "ncp.func==17 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("21");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 21");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_21_srt_table, 256, temp_page, "ncp.func==21 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("22");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 22");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_22_srt_table, 256, temp_page, "ncp.func==22 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("23");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 23");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_23_srt_table, 256, temp_page, "ncp.func==23 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("32");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 32");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_32_srt_table, 256, temp_page, "ncp.func==32 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("34");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 34");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_34_srt_table, 256, temp_page, "ncp.func==34 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("35");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 35");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_35_srt_table, 256, temp_page, "ncp.func==35 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("36");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 36");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_36_srt_table, 256, temp_page, "ncp.func==36 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("86");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 86");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_86_srt_table, 256, temp_page, "ncp.func==86 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("87");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 87");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_87_srt_table, 256, temp_page, "ncp.func==87 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("89");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 89 (Extended NCP's with UTF8 Support)");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_89_srt_table, 256, temp_page, "ncp.func==89 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("90");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 90");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_90_srt_table, 256, temp_page, "ncp.func==90 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("92");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 92 (Secret Store Services)");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_92_srt_table, 256, temp_page, "ncp.func==92 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("94");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 94 (Novell Modular Authentication Services)");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_94_srt_table, 256, temp_page, "ncp.func==94 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("104");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 104");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_104_srt_table, 256, temp_page, "ncp.func==104 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("111");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 111");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_111_srt_table, 256, temp_page, "ncp.func==111 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("114");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 114");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_114_srt_table, 256, temp_page, "ncp.func==114 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("123");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 123");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_123_srt_table, 256, temp_page, "ncp.func==123 && ncp.subfunc");
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("131");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Subfunctions for NCP 131");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sub_131_srt_table, 256, temp_page, "ncp.func==131 && ncp.subfunc");

    /* NDS Verbs */
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("NDS");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("NDS Verbs");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->nds_srt_table, 256, temp_page, "ncp.ndsverb");
    /* Secret Store Verbs */
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("SSS");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("Secret Store Verbs");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->sss_srt_table, 256, temp_page, "sss.subverb");
    /* NMAS Verbs */
    temp_page = gtk_vbox_new(FALSE, 6);
    label=gtk_label_new("NMAS");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, label);
    label=gtk_label_new("NMAS Verbs");
    gtk_box_pack_start(GTK_BOX(temp_page), label, FALSE, FALSE, 0);
    init_srt_table(&ss->nmas_srt_table, 256, temp_page, "nmas.subverb");

    /* Register the tap listener */
    error_string=register_tap_listener("ncp_srt", ss, filter, 0, ncpstat_reset, ncpstat_packet, ncpstat_draw);
    if(error_string){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        g_free(ss);
        return;
    }

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(ss->win, close_bt, window_cancel_button_cb);

    g_signal_connect(ss->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(ss->win, "destroy", G_CALLBACK(win_destroy_cb), ss);

    gtk_widget_show_all(ss->win);
    window_present(ss->win);

    cf_redissect_packets(&cfile);
}

static tap_param ncp_stat_params[] = {
	{ PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg ncp_stat_dlg = {
	"NCP SRT Statistics",
	"ncp,srt",
	gtk_ncpstat_init,
	-1,
	G_N_ELEMENTS(ncp_stat_params),
	ncp_stat_params
};

void
register_tap_listener_gtkncpstat(void)
{
	register_dfilter_stat(&ncp_stat_dlg, "NCP",
	    REGISTER_STAT_GROUP_RESPONSE_TIME);
}
