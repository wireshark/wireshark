/* ldap_stat.c
 * ldap_stat   2003 Ronnie Sahlberg
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
#include <epan/dissectors/packet-ldap.h>

#include "../timestats.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../stat_menu.h"

#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/service_response_time_table.h"
#include "gtk/tap_param_dlg.h"
#include "gtk/gtkglobals.h"
#include "gtk/main.h"


/* used to keep track of the statistics for an entire program interface */
typedef struct _ldapstat_t {
	GtkWidget *win;
	srt_stat_table ldap_srt_table;
} ldapstat_t;

static void
ldapstat_set_title(ldapstat_t *ldap)
{
	char		*title;

	title = g_strdup_printf("LDAP Service Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(ldap->win), title);
	g_free(title);
}

static void
ldapstat_reset(void *pldap)
{
	ldapstat_t *ldap=(ldapstat_t *)pldap;

	reset_srt_table_data(&ldap->ldap_srt_table);
	ldapstat_set_title(ldap);
}

static int
ldapstat_packet(void *pldap, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
	const ldap_call_response_t *ldap=psi;
	ldapstat_t *fs=(ldapstat_t *)pldap;

	/* we are only interested in reply packets */
	if(ldap->is_request){
		return 0;
	}
	/* if we havnt seen the request, just ignore it */
	if(!ldap->req_frame){
		return 0;
	}

	/* only use the commands we know how to handle */
	switch(ldap->protocolOpTag){
	case LDAP_REQ_BIND:
	case LDAP_REQ_SEARCH:
	case LDAP_REQ_MODIFY:
	case LDAP_REQ_ADD:
	case LDAP_REQ_DELETE:
	case LDAP_REQ_MODRDN:
	case LDAP_REQ_COMPARE:
	case LDAP_REQ_EXTENDED:
		break;
	default:
		return 0;
	}

	add_srt_table_data(&fs->ldap_srt_table, ldap->protocolOpTag, &ldap->req_time, pinfo);

	return 1;
}



static void
ldapstat_draw(void *pldap)
{
	ldapstat_t *ldap=(ldapstat_t *)pldap;

	draw_srt_table_data(&ldap->ldap_srt_table);
}


static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	ldapstat_t *ldap=(ldapstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ldap);
	unprotect_thread_critical_region();

	free_srt_table_data(&ldap->ldap_srt_table);
	g_free(ldap);
}


static void
gtk_ldapstat_init(const char *optarg, void *userdata _U_)
{
	ldapstat_t *ldap;
	const char *filter=NULL;
	GtkWidget *label;
	char *filter_string;
	GString *error_string;
	GtkWidget *vbox;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	if(!strncmp(optarg,"ldap,srt,",9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	ldap=g_malloc(sizeof(ldapstat_t));

	ldap->win = dlg_window_new("ldap-stat");
	gtk_window_set_destroy_with_parent (GTK_WINDOW(ldap->win), TRUE);
	gtk_window_set_default_size(GTK_WINDOW(ldap->win), 550, 400);
	ldapstat_set_title(ldap);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(ldap->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	label=gtk_label_new("LDAP Service Response Time statistics");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	filter_string = g_strdup_printf("Filter: %s", filter ? filter : "");
	label=gtk_label_new(filter_string);
	g_free(filter_string);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	label=gtk_label_new("LDAP Commands");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(ldap->win);

	init_srt_table(&ldap->ldap_srt_table, 24, vbox, NULL);
	init_srt_table_row(&ldap->ldap_srt_table, 0, "Bind");
	init_srt_table_row(&ldap->ldap_srt_table, 1, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 2, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 3, "Search");
	init_srt_table_row(&ldap->ldap_srt_table, 4, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 5, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 6, "Modify");
	init_srt_table_row(&ldap->ldap_srt_table, 7, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 8, "Add");
	init_srt_table_row(&ldap->ldap_srt_table, 9, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 10, "Delete");
	init_srt_table_row(&ldap->ldap_srt_table, 11, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 12, "Modrdn");
	init_srt_table_row(&ldap->ldap_srt_table, 13, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 14, "Compare");
	init_srt_table_row(&ldap->ldap_srt_table, 15, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 16, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 17, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 18, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 19, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 20, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 21, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 22, "<unknown>");
	init_srt_table_row(&ldap->ldap_srt_table, 23, "Extended");


	error_string=register_tap_listener("ldap", ldap, filter, 0, ldapstat_reset, ldapstat_packet, ldapstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ldap);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(ldap->win, close_bt, window_cancel_button_cb);

	g_signal_connect(ldap->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(ldap->win, "destroy", G_CALLBACK(win_destroy_cb), ldap);

	gtk_widget_show_all(ldap->win);
	window_present(ldap->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(ldap->win->window);
}

static tap_param ldap_stat_params[] = {
	{ PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg ldap_stat_dlg = {
	"LDAP Service Response Time Statistics",
	"ldap,srt",
	gtk_ldapstat_init,
	-1,
	G_N_ELEMENTS(ldap_stat_params),
	ldap_stat_params
};

void
register_tap_listener_gtkldapstat(void)
{
	register_dfilter_stat(&ldap_stat_dlg, "LDAP",
	    REGISTER_STAT_GROUP_RESPONSE_TIME);
}
