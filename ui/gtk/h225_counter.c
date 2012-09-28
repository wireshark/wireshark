/* h225_counter.c
 * H.225 message counter for Wireshark
 * Copyright 2003 Lars Roland
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/value_string.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-h225.h>

#include "ui/simple_dialog.h"
#include "../file.h"
#include "../stat_menu.h"

#include "ui/gtk/gui_stat_util.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/tap_param_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/main.h"

#include "ui/gtk/old-gtk-compat.h"

static void gtk_h225counter_init(const char *optarg, void *userdata);

static tap_param h225_counter_params[] = {
	{ PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg h225_counter_dlg = {
	"H.225 Messages and Message Reasons",
	"h225,counter",
	gtk_h225counter_init,
	-1,
	G_N_ELEMENTS(h225_counter_params),
	h225_counter_params
};

/* following values represent the size of their valuestring arrays */

#define RAS_MSG_TYPES 33
#define CS_MSG_TYPES 13

#define GRJ_REASONS 8
#define RRJ_REASONS 18
#define URQ_REASONS 6
#define URJ_REASONS 6
#define ARJ_REASONS 22
#define BRJ_REASONS 8
#define DRQ_REASONS 3
#define DRJ_REASONS 4
#define LRJ_REASONS 16
#define IRQNAK_REASONS 4
#define REL_CMP_REASONS 26
#define FACILITY_REASONS 11


/* used to keep track of the statistics for an entire program interface */
typedef struct _h225counter_t {
	GtkWidget *win;
	GtkWidget *vbox;
	char *filter;
	GtkWidget *scrolled_window;
	GtkTreeView *table;
	guint32 ras_msg[RAS_MSG_TYPES + 1];
        guint32 cs_msg[CS_MSG_TYPES + 1];
        guint32 grj_reason[GRJ_REASONS + 1];
        guint32 rrj_reason[RRJ_REASONS + 1];
        guint32 urq_reason[URQ_REASONS + 1];
        guint32 urj_reason[URJ_REASONS + 1];
        guint32 arj_reason[ARJ_REASONS + 1];
        guint32 brj_reason[BRJ_REASONS + 1];
        guint32 drq_reason[DRQ_REASONS + 1];
        guint32 drj_reason[DRJ_REASONS + 1];
        guint32 lrj_reason[LRJ_REASONS + 1];
        guint32 irqnak_reason[IRQNAK_REASONS + 1];
        guint32 rel_cmp_reason[REL_CMP_REASONS + 1];
        guint32 facility_reason[FACILITY_REASONS + 1];
} h225counter_t;


static void
h225counter_reset(void *phs)
{
	h225counter_t *hs=(h225counter_t *)phs;
	int i;

	for(i=0;i<=RAS_MSG_TYPES;i++) {
		hs->ras_msg[i] = 0;
	}
	for(i=0;i<=CS_MSG_TYPES;i++) {
		hs->cs_msg[i] = 0;
	}
	for(i=0;i<=GRJ_REASONS;i++) {
		hs->grj_reason[i] = 0;
	}
	for(i=0;i<=RRJ_REASONS;i++) {
		hs->rrj_reason[i] = 0;
	}
	for(i=0;i<=URQ_REASONS;i++) {
		hs->urq_reason[i] = 0;
	}
	for(i=0;i<=URJ_REASONS;i++) {
		hs->urj_reason[i] = 0;
	}
	for(i=0;i<=ARJ_REASONS;i++) {
		hs->arj_reason[i] = 0;
	}
	for(i=0;i<=BRJ_REASONS;i++) {
		hs->brj_reason[i] = 0;
	}
	for(i=0;i<=DRQ_REASONS;i++) {
		hs->drq_reason[i] = 0;
	}
	for(i=0;i<=DRJ_REASONS;i++) {
		hs->drj_reason[i] = 0;
	}
	for(i=0;i<=LRJ_REASONS;i++) {
		hs->lrj_reason[i] = 0;
	}
	for(i=0;i<=IRQNAK_REASONS;i++) {
		hs->irqnak_reason[i] = 0;
	}
	for(i=0;i<=REL_CMP_REASONS;i++) {
		hs->rel_cmp_reason[i] = 0;
	}
	for(i=0;i<=FACILITY_REASONS;i++) {
		hs->facility_reason[i] = 0;
	}
}

static int
h225counter_packet(void *phs, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *phi)
{
	h225counter_t *hs=(h225counter_t *)phs;
	const h225_packet_info *pi=phi;

	switch (pi->msg_type) {

	case H225_RAS:
		if(pi->msg_tag==-1) { /* uninitialized */
			return 0;
		}
		else if (pi->msg_tag >= RAS_MSG_TYPES) { /* unknown */
			hs->ras_msg[RAS_MSG_TYPES]++;
		}
		else {
			hs->ras_msg[pi->msg_tag]++;
		}

		/* Look for reason tag */
		if(pi->reason==-1) { /* uninitialized */
			break;
		}

		switch(pi->msg_tag) {

		case 2:	/* GRJ */
			if(pi->reason < GRJ_REASONS)
				hs->grj_reason[pi->reason]++;
			else
				hs->grj_reason[GRJ_REASONS]++;
			break;
		case 5:	/* RRJ */
			if(pi->reason < RRJ_REASONS)
				hs->rrj_reason[pi->reason]++;
			else
				hs->rrj_reason[RRJ_REASONS]++;
			break;
		case 6:	/* URQ */
			if(pi->reason < URQ_REASONS)
				hs->urq_reason[pi->reason]++;
			else
				hs->urq_reason[URQ_REASONS]++;
			break;
		case 8:	/* URJ */
			if(pi->reason < URJ_REASONS)
				hs->urj_reason[pi->reason]++;
			else
				hs->urj_reason[URJ_REASONS]++;
			break;
		case 11: /* ARJ */
			if(pi->reason < ARJ_REASONS)
				hs->arj_reason[pi->reason]++;
			else
				hs->arj_reason[ARJ_REASONS]++;
			break;
		case 14: /* BRJ */
			if(pi->reason < BRJ_REASONS)
				hs->brj_reason[pi->reason]++;
			else
				hs->brj_reason[BRJ_REASONS]++;
			break;
		case 15: /* DRQ */
			if(pi->reason < DRQ_REASONS)
				hs->drq_reason[pi->reason]++;
			else
				hs->drq_reason[DRQ_REASONS]++;
			break;
		case 17: /* DRJ */
			if(pi->reason < DRJ_REASONS)
				hs->drj_reason[pi->reason]++;
			else
				hs->drj_reason[DRJ_REASONS]++;
			break;
		case 20: /* LRJ */
			if(pi->reason < LRJ_REASONS)
				hs->lrj_reason[pi->reason]++;
			else
				hs->lrj_reason[LRJ_REASONS]++;
			break;
		case 29: /* IRQ Nak */
			if(pi->reason < IRQNAK_REASONS)
				hs->irqnak_reason[pi->reason]++;
			else
				hs->irqnak_reason[IRQNAK_REASONS]++;
			break;

		default:
			/* do nothing */
			break;
		}

		break;

	case H225_CS:
		if(pi->msg_tag==-1) { /* uninitialized */
			return 0;
		}
		else if (pi->msg_tag >= CS_MSG_TYPES) { /* unknown */
			hs->cs_msg[CS_MSG_TYPES]++;
		}
		else {
			hs->cs_msg[pi->msg_tag]++;
		}

		/* Look for reason tag */
		if(pi->reason==-1) { /* uninitialized */
			break;
		}

		switch(pi->msg_tag) {

		case 5:	/* ReleaseComplete */
			if(pi->reason < REL_CMP_REASONS)
				hs->rel_cmp_reason[pi->reason]++;
			else
				hs->rel_cmp_reason[REL_CMP_REASONS]++;
			break;
		case 6:	/* Facility */
			if(pi->reason < FACILITY_REASONS)
				hs->facility_reason[pi->reason]++;
			else
				hs->facility_reason[FACILITY_REASONS]++;
			break;
		default:
			/* do nothing */
			break;
		}

		break;

	default:
		return 0;
	}

	return 1;
}

static void
h225counter_draw(void *phs)
{
	h225counter_t *hs=(h225counter_t *)phs;
	int i,j;
	char str[256];
	GtkListStore *store;
	GtkTreeIter iter;

	/* Now print Message and Reason Counter Table */
	/* clear list before printing */
  	store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->table));
  	gtk_list_store_clear(store);

	for(i=0;i<=RAS_MSG_TYPES;i++) {
		if(hs->ras_msg[i]!=0) {
			g_snprintf(str, 256, "%s", val_to_str(i,h225_RasMessage_vals,"unknown ras-messages"));
			gtk_list_store_append(store, &iter);
			gtk_list_store_set(store, &iter,
				   0, val_to_str(i,h225_RasMessage_vals,"unknown ras-messages"),
				   1, hs->ras_msg[i], -1);

			/* reason counter */
			switch(i) {
			case 2: /* GRJ */
				for(j=0;j<=GRJ_REASONS;j++) {
					if(hs->grj_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,GatekeeperRejectReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->grj_reason[j], -1);
					}
				}
				break;
			case 5: /* RRJ */
				for(j=0;j<=RRJ_REASONS;j++) {
					if(hs->rrj_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,RegistrationRejectReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->rrj_reason[j], -1);
					}
				}
				break;
			case 6: /* URQ */
				for(j=0;j<=URQ_REASONS;j++) {
					if(hs->urq_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,UnregRequestReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->urq_reason[j], -1);
					}
				}
				break;
			case 8: /* URJ */
				for(j=0;j<=URJ_REASONS;j++) {
					if(hs->urj_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,UnregRejectReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->urj_reason[j], -1);
					}
				}
				break;
			case 11: /* ARJ */
				for(j=0;j<=ARJ_REASONS;j++) {
					if(hs->arj_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,AdmissionRejectReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->arj_reason[j], -1);
					}
				}
				break;
			case 14: /* BRJ */
				for(j=0;j<=BRJ_REASONS;j++) {
					if(hs->brj_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,BandRejectReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->brj_reason[j], -1);
					}
				}
				break;
			case 15: /* DRQ */
				for(j=0;j<=DRQ_REASONS;j++) {
					if(hs->drq_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,DisengageReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->drq_reason[j], -1);
					}
				}
				break;
			case 17: /* DRJ */
				for(j=0;j<=DRJ_REASONS;j++) {
					if(hs->drj_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,DisengageRejectReason_vals,"unknown reason"));
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->drj_reason[j], -1);
					}
				}
				break;
			case 20: /* LRJ */
				for(j=0;j<=LRJ_REASONS;j++) {
					if(hs->lrj_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,LocationRejectReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->lrj_reason[j], -1);
					}
				}
				break;
			case 29: /* IRQNak */
				for(j=0;j<=IRQNAK_REASONS;j++) {
					if(hs->irqnak_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,InfoRequestNakReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->irqnak_reason[j], -1);
					}
				}
				break;
			default:
				break;
			}
			/* end of reason counter*/
		}
	}

	for(i=0;i<=CS_MSG_TYPES;i++) {
		if(hs->cs_msg[i]!=0) {
			gtk_list_store_append(store, &iter);
			gtk_list_store_set(store, &iter,
				   0, val_to_str(i,T_h323_message_body_vals,"unknown cs-messages"),
				   1, hs->cs_msg[i], -1);

			/* reason counter */
			switch(i) {
			case 5: /* ReleaseComplete */
				for(j=0;j<=REL_CMP_REASONS;j++) {
					if(hs->rel_cmp_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,h225_ReleaseCompleteReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->rel_cmp_reason[j], -1);
					}
				}
				break;
			case 6: /* Facility */
				for(j=0;j<=FACILITY_REASONS;j++) {
					if(hs->facility_reason[j]!=0) {
						g_snprintf(str, 256,"    %s",
								val_to_str(j,FacilityReason_vals,"unknown reason"));
						gtk_list_store_append(store, &iter);
						gtk_list_store_set(store, &iter,
							0, str,
							1, hs->facility_reason[j], -1);
					}
				}
				break;
			default:
				break;
			}
		}
	}
}

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	h225counter_t *hs=(h225counter_t *)data;

	remove_tap_listener(hs);

	if(hs->filter){
		g_free(hs->filter);
		hs->filter=NULL;
	}
	g_free(hs);
}

static const stat_column titles[]={
  {G_TYPE_STRING, LEFT, "Message Type or Reason"},
  {G_TYPE_UINT, RIGHT, "Count" }
};

static void
gtk_h225counter_init(const char *optarg, void *userdata _U_)
{
	h225counter_t *hs;
	GString *error_string;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	hs=g_malloc(sizeof(h225counter_t));

	if(strncmp(optarg,"h225,counter,",13) == 0){
		hs->filter=g_strdup(optarg+13);
	} else {
		hs->filter=NULL;
	}

	h225counter_reset(hs);

	hs->win = dlg_window_new("Wireshark: H.225 counters");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(hs->win), TRUE);

	gtk_window_set_default_size(GTK_WINDOW(hs->win), 400, 200);

	hs->vbox=ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(hs->vbox), 12);

	init_main_stat_window(hs->win, hs->vbox, "H.225 Message and Message Reason Counter", hs->filter);

        /* init a scrolled window*/
	hs->scrolled_window = scrolled_window_new(NULL, NULL);

	hs->table = create_stat_table(hs->scrolled_window, hs->vbox, 2, titles);

	error_string=register_tap_listener("h225", hs, hs->filter, 0, h225counter_reset, h225counter_packet, h225counter_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		g_free(hs->filter);
		g_free(hs);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(hs->vbox), bbox, FALSE, FALSE, 0);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(hs->win, close_bt, window_cancel_button_cb);

	g_signal_connect(hs->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(hs->win, "destroy", G_CALLBACK(win_destroy_cb), hs);

	gtk_widget_show_all(hs->win);
	window_present(hs->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(hs->win));
}

void
register_tap_listener_gtk_h225counter(void)
{
	register_dfilter_stat(&h225_counter_dlg, "_H.225",
	    REGISTER_STAT_GROUP_TELEPHONY);
}

void h225_counter_cb(GtkAction *action, gpointer user_data _U_)
{
	tap_param_dlg_cb(action, &h225_counter_dlg);
}
