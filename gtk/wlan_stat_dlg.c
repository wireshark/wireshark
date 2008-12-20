/* wlan_stat_dlg.c
 * Copyright 2008 Stig Bjorlykke <stig@bjorlykke.org>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/addr_resolv.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-ieee80211.h>
#include <epan/strutil.h>

#include "../register.h"
#include "../simple_dialog.h"
#include "../globals.h"
#include "../stat_menu.h"
#include "../isprint.h"

#include "gtk/gtkglobals.h"
#include "gtk/dlg_utils.h"
#include "gtk/filter_utils.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/gui_utils.h"
#include "gtk/recent.h"
#include "gtk/help_dlg.h"
#include "gtk/main.h"

enum {
	BSSID_COLUMN,
	CHANNEL_COLUMN,
	SSID_COLUMN,
	PERCENT_COLUMN,
	BEACONS_COLUMN,
	DATA_COLUMN,
	PROBE_REQ_COLUMN,
	PROBE_RESP_COLUMN,
	AUTH_COLUMN,
	DEAUTH_COLUMN,
	OTHER_COLUMN,
	PROTECTION_COLUMN,
	PERCENT_VALUE_COLUMN,
	TABLE_COLUMN,
	NUM_COLUMNS
};

static const gchar *titles[] = { "BSSID", "Ch.", "SSID", "% Packets", "Beacons", "Data Packets",
				 "Probe Req", "Probe Resp", "Auth", "Deauth", "Other", "Protection" };

enum {
	ADDRESS_COLUMN,
	PERCENT_2_COLUMN,
	DATA_SENT_COLUMN,
	DATA_REC_COLUMN,
	PROBE_REQ_2_COLUMN,
	PROBE_RESP_2_COLUMN,
	AUTH_2_COLUMN,
	DEAUTH_2_COLUMN,
	OTHER_2_COLUMN,
	COMMENT_COLUMN,
	PERCENT_VALUE_2_COLUMN,
	DETAILS_COLUMN,
	NUM_DETAIL_COLUMNS
};

static const gchar *detail_titles[] = { "Address", "% Packets", "Data Sent", "Data Received",
					"Probe Req", "Probe Resp", "Auth", "Deauth", "Other", "Comment" };

typedef struct wlan_details_ep {
	struct wlan_details_ep *next;
	address address;
	guint32 probe_req;
	guint32 probe_rsp;
	guint32 auth;
	guint32 deauth;
	guint32 data_sent;
	guint32 data_received;
	guint32 other;
	guint32 number_of_packets;
	GtkTreeIter iter;
	gboolean iter_valid;
} wlan_details_ep_t;

typedef struct wlan_ep {
	struct wlan_ep* next;
	address bssid;
	struct _wlan_stats stats;
	guint32 type[256];
	guint32 number_of_packets;
	GtkTreeIter iter;
	gboolean iter_valid;
	gboolean probe_req_searched;
	struct wlan_details_ep *details;
} wlan_ep_t;

static GtkWidget  *wlanstat_dlg_w = NULL;
static GtkWidget  *wlanstat_pane = NULL;
static GtkWidget  *wlanstat_name_lb = NULL;

/* used to keep track of the statistics for an entire program interface */
typedef struct _wlan_stat_t {
	GtkTreeView  *table;
	GtkTreeView  *details;
	GtkWidget  *menu;
	GtkWidget  *details_menu;
	guint32    number_of_packets;
	guint32    num_entries;
	guint32    num_details;
	gboolean   resolve_names;
	gboolean   use_dfilter;
	gboolean   show_only_existing;
	wlan_ep_t* ep_list;
} wlanstat_t;

static void
dealloc_wlan_details_ep (wlan_details_ep_t *details)
{
	wlan_details_ep_t *tmp;

	while (details) {
		tmp = details;
		details = details->next;
		g_free (tmp);
	}
}

static void
wlanstat_reset (void *phs)
{
	wlanstat_t* wlan_stat = (wlanstat_t *)phs;
	wlan_ep_t* list = wlan_stat->ep_list;
	wlan_ep_t* tmp = NULL;
	char title[256];
	GString *error_string;
	GtkListStore *store;
	const char *filter = NULL;

	if (wlanstat_dlg_w != NULL) {
		g_snprintf (title, 255, "Wireshark: WLAN Traffic Statistics: %s",
			    cf_get_display_name(&cfile));
		gtk_window_set_title(GTK_WINDOW(wlanstat_dlg_w), title);
	}

	if (wlan_stat->use_dfilter) {
		filter = gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	}

	error_string = set_tap_dfilter (wlan_stat, filter);
	if (error_string) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		return;
	}

	if (wlan_stat->use_dfilter) {
		if (filter && strlen(filter)) {
			g_snprintf(title, 255, "Network Overview - Filter: %s", filter);
		} else {
			g_snprintf(title, 255, "Network Overview - No Filter");
		}
	} else {
		g_snprintf(title, 255, "Network Overview");
	}
	gtk_frame_set_label(GTK_FRAME(wlanstat_name_lb), title);

	/* remove all entries from the list */
	store = GTK_LIST_STORE(gtk_tree_view_get_model(wlan_stat->table));
	gtk_list_store_clear(store);
	store = GTK_LIST_STORE(gtk_tree_view_get_model(wlan_stat->details));
	gtk_list_store_clear(store);

	if (!list)
		return;

	while (list) {
		tmp = list;
		dealloc_wlan_details_ep (tmp->details);
		list = tmp->next;
		g_free (tmp);
	}

	wlan_stat->ep_list = NULL;
	wlan_stat->number_of_packets = 0;
}

static void
invalidate_detail_iters (wlanstat_t *hs)
{
	wlan_ep_t *ep = hs->ep_list;
	wlan_details_ep_t *d_ep;

	while (ep) {
		d_ep = ep->details;
		while (d_ep) {
			d_ep->iter_valid = FALSE;
			d_ep = d_ep->next;
		}
		ep = ep->next;
	}
}

static wlan_ep_t*
alloc_wlan_ep (struct _wlan_hdr *si, packet_info *pinfo _U_)
{
	wlan_ep_t* ep;

	if (!si)
		return NULL;

	if (!(ep = g_malloc (sizeof(wlan_ep_t))))
		return NULL;

	SE_COPY_ADDRESS (&ep->bssid, &si->bssid);
	ep->stats.channel = si->stats.channel;
	memcpy (ep->stats.ssid, si->stats.ssid, MAX_SSID_LEN);
	ep->stats.ssid_len = si->stats.ssid_len;
	g_strlcpy (ep->stats.protection, si->stats.protection, MAX_PROTECT_LEN);
	memset(&ep->type, 0, sizeof (int) * 256);
	ep->number_of_packets = 0;
	ep->details = NULL;
	ep->iter_valid = FALSE;
	ep->probe_req_searched = FALSE;
	ep->next = NULL;

	return ep;
}

static wlan_details_ep_t*
alloc_wlan_details_ep (address *address)
{
	wlan_details_ep_t* d_ep;

	if (!address)
		return NULL;

	if (!(d_ep = g_malloc (sizeof(wlan_details_ep_t))))
		return NULL;

	SE_COPY_ADDRESS (&d_ep->address, address);
	d_ep->probe_req = 0;
	d_ep->probe_rsp = 0;
	d_ep->auth = 0;
	d_ep->deauth = 0;
	d_ep->data_sent = 0;
	d_ep->data_received = 0;
	d_ep->other = 0;
	d_ep->number_of_packets = 0;
	d_ep->iter_valid = FALSE;
	d_ep->next = NULL;

	return d_ep;
}

wlan_details_ep_t *
get_details_ep (wlan_ep_t *te, address *address)
{
	wlan_details_ep_t *tmp, *d_te = NULL;

	if (!te->details) {
		te->details = alloc_wlan_details_ep (address);
		d_te = te->details;
	} else {
		for (tmp = te->details; tmp; tmp = tmp->next) {
			if (!CMP_ADDRESS (&tmp->address, address)) {
				d_te = tmp;
				break;
			}
		}

		if (!d_te) {
			if ((d_te = alloc_wlan_details_ep (address)) != NULL) {
				d_te->next = te->details;
				te->details = d_te;
			}
		}
	}

	g_assert (d_te != NULL);

	return d_te;
}

static void
wlanstat_packet_details (wlan_ep_t *te, guint32 type, address *address, gboolean src)
{
	wlan_details_ep_t *d_te = get_details_ep (te, address);

	switch (type) {
	case 0x04:
		d_te->probe_req++;
		break;
	case 0x05:
		d_te->probe_rsp++;
		break;
	case 0x08:
		/* No counting for beacons */
		break;
	case 0x0B:
		d_te->auth++;
		break;
	case 0x0C:
		d_te->deauth++;
		break;
	case 0x20:
	case 0x21:
	case 0x22:
	case 0x23:
	case 0x28:
	case 0x29:
	case 0x2A:
	case 0x2B:
		if (src) {
			d_te->data_sent++;
		} else {
			d_te->data_received++;
		}
		break;
	default:
		d_te->other++;
		break;
	}

	if (type != 0x08) {
		/* Do not count beacons in details */
		d_te->number_of_packets++;
	}
}

static int
wlanstat_packet (void *phs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *phi)
{

	wlanstat_t *hs = (wlanstat_t *)phs;
	wlan_ep_t *tmp = NULL, *te = NULL;
	struct _wlan_hdr *si = (struct _wlan_hdr *) phi;

	if (!hs)
		return (0);

	hs->number_of_packets++;
	if (!hs->ep_list) {
		hs->ep_list = alloc_wlan_ep (si, pinfo);
		te = hs->ep_list;
	} else {
		for (tmp = hs->ep_list; tmp; tmp = tmp->next) {
			if (((si->type == 0x04) &&
			     (((tmp->stats.ssid_len == 0) && (si->stats.ssid_len == 0) &&
			       (strcmp (get_addr_name(&tmp->bssid), "Broadcast") == 0)) ||
			      (si->stats.ssid_len != 0 &&
			       (tmp->stats.ssid_len == si->stats.ssid_len) &&
			       (memcmp (tmp->stats.ssid, si->stats.ssid, si->stats.ssid_len) == 0)))) ||
			    ((si->type != 0x04) &&
			     (!CMP_ADDRESS (&tmp->bssid, &si->bssid)))) {
				te = tmp;
				break;
			}
		}

		if (!te) {
			if ((te = alloc_wlan_ep (si, pinfo))) {
				te->next = hs->ep_list;
				hs->ep_list = te;
			}
		}

		if (!te->probe_req_searched && (si->type != 0x04) && (te->type[0x04] == 0) &&
		    (si->stats.ssid_len > 1 || si->stats.ssid[0] != 0)) {
			/*
			 * We have found a matching entry without Probe Requests.
			 * Search the rest of the entries for a corresponding entry
			 * matching the SSID and BSSID == Broadcast.
			 *
			 * This is because we can have a hidden SSID or Probe Request
			 * before we have a Beacon, Association Request, etc.
			 */
		 	wlan_ep_t *prev = NULL;
			GtkListStore *store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->table));
			te->probe_req_searched = TRUE;
			for (tmp = hs->ep_list; tmp; tmp = tmp->next) {
				if ((si->stats.ssid_len == tmp->stats.ssid_len) &&
				    (memcmp (si->stats.ssid, tmp->stats.ssid, tmp->stats.ssid_len) == 0) &&
				    (strcmp (get_addr_name(&tmp->bssid), "Broadcast") == 0)) {
					/*
					 * Found a matching entry. Merge with the previous
					 * found entry and remove from list.
					 */
					te->type[0x04] += tmp->type[0x04];
					te->number_of_packets += tmp->number_of_packets;

					if (tmp->details && tmp->details->next) {
						/* Adjust received probe requests */
						wlan_details_ep_t *d_te;
						d_te = get_details_ep (te, &tmp->details->address);
						d_te->probe_req += tmp->type[0x04];
						d_te->number_of_packets += tmp->type[0x04];
						d_te = get_details_ep (te, &tmp->details->next->address);
						d_te->probe_req += tmp->type[0x04];
						d_te->number_of_packets += tmp->type[0x04];
					}
					if (prev) {
						prev->next = tmp->next;
					} else {
						hs->ep_list = tmp->next;
					}
					dealloc_wlan_details_ep (tmp->details);
					if (tmp->iter_valid) {
						gtk_list_store_remove(store, &tmp->iter);
					}
					g_free (tmp);
					break;
				}
				prev = tmp;
			}
		}
	}

	if(!te)
		return (0);

	if (te->stats.channel == 0 && si->stats.channel != 0) {
		te->stats.channel = si->stats.channel;
	}
	if (te->stats.ssid[0] == 0 && si->stats.ssid_len != 0) {
		memcpy (te->stats.ssid, si->stats.ssid, MAX_SSID_LEN);
		te->stats.ssid_len = si->stats.ssid_len;
	}
	if (te->stats.protection[0] == 0 && si->stats.protection[0] != 0) {
		g_strlcpy (te->stats.protection, si->stats.protection, MAX_PROTECT_LEN);
	}
	te->type[si->type]++;
	te->number_of_packets++;

	wlanstat_packet_details (te, si->type, &si->src, TRUE);  /* Register source */
	wlanstat_packet_details (te, si->type, &si->dst, FALSE); /* Register destination */

	return (1);
}

static void
wlanstat_details(wlanstat_t *hs, wlan_ep_t *wlan_ep, gboolean clear)
{
	wlan_details_ep_t *tmp = NULL;
	char address[256], comment[256], percent[256];
	gboolean broadcast, basestation;
	float f;
	GtkListStore *store;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->details));
	if (clear) {
		gtk_list_store_clear(store);
		invalidate_detail_iters(hs);
	}
 	hs->num_details = 0;

	for(tmp = wlan_ep->details; tmp; tmp=tmp->next) {
		broadcast = !(strcmp (get_addr_name(&tmp->address), "Broadcast"));
		basestation = !broadcast && !CMP_ADDRESS(&tmp->address, &wlan_ep->bssid);

		if ((wlan_ep->number_of_packets - wlan_ep->type[0x08]) > 0) {
			f = (float)(((float)tmp->number_of_packets * 100.0) / (wlan_ep->number_of_packets - wlan_ep->type[0x08]));
		} else {
			f = 0.0;
		}

		if (hs->resolve_names) {
			g_snprintf (address, sizeof(address), "%s", get_addr_name(&tmp->address));
		} else {
			g_snprintf (address, sizeof(address), "%s", address_to_str(&tmp->address));
		}
		if (basestation) {
			g_snprintf (comment, sizeof(comment), "Base station");
		} else {
			g_snprintf (comment, sizeof(comment), " ");
		}
		g_snprintf (percent, sizeof(percent), "%.2f %%", f);

		if (!tmp->iter_valid) {
			gtk_list_store_append(store, &tmp->iter);
			tmp->iter_valid = TRUE;
		}
		gtk_list_store_set(store, &tmp->iter,
				   ADDRESS_COLUMN, address,
				   PERCENT_2_COLUMN, percent,
				   DATA_SENT_COLUMN, tmp->data_sent,
				   DATA_REC_COLUMN, tmp->data_received,
				   PROBE_REQ_2_COLUMN, tmp->probe_req,
				   PROBE_RESP_2_COLUMN, tmp->probe_rsp,
				   AUTH_2_COLUMN, tmp->auth,
				   DEAUTH_2_COLUMN, tmp->deauth,
				   OTHER_2_COLUMN, tmp->other,
				   COMMENT_COLUMN, comment,
				   PERCENT_VALUE_2_COLUMN, f,
				   DETAILS_COLUMN, tmp,
				   -1);

		hs->num_details++;
	}
}

static void
wlanstat_draw(void *phs)
{
	wlanstat_t *hs = (wlanstat_t *)phs;
	wlan_ep_t* list = hs->ep_list, *tmp = 0;
	guint32 data = 0, other = 0;
	char bssid[256], channel[256], ssid[256], percent[256];
	gboolean broadcast;
	float f;
	GtkListStore *store;
	GtkTreeSelection *sel;
	GtkTreeModel *model;
	GtkTreeIter iter;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->table));
	hs->num_entries = 0;

	for(tmp = list; tmp; tmp=tmp->next) {
		broadcast = !(strcmp (get_addr_name(&tmp->bssid), "Broadcast"));

		if (hs->show_only_existing && broadcast) {
			if (tmp->iter_valid) {
				gtk_list_store_remove(store, &tmp->iter);
				tmp->iter_valid = FALSE;
			}
			continue;
		}

		data = tmp->type[0x20] + tmp->type[0x21] + tmp->type[0x22] + tmp->type[0x23] +
		  tmp->type[0x28] + tmp->type[0x29] + tmp->type[0x2A] + tmp->type[0x2B];
		other = tmp->number_of_packets - data - tmp->type[0x08] - tmp->type[0x04] -
		  tmp->type[0x05] - tmp->type[0x0B] - tmp->type[0x0C];
		f = (float)(((float)tmp->number_of_packets * 100.0) / hs->number_of_packets);

		if (hs->resolve_names) {
			g_snprintf (bssid, sizeof(bssid), "%s", get_addr_name(&tmp->bssid));
		} else {
			g_snprintf (bssid, sizeof(bssid), "%s", address_to_str(&tmp->bssid));
		}
		if (tmp->stats.channel) {
			g_snprintf (channel, sizeof(channel), "%u", tmp->stats.channel);
		} else {
			channel[0] = '\0';
		}
		if (tmp->stats.ssid_len == 0) {
			g_snprintf (ssid, sizeof(ssid), "<Broadcast>");
		} else if (tmp->stats.ssid_len == 1 && tmp->stats.ssid[0] == 0) {
			g_snprintf (ssid, sizeof(ssid), "<Hidden>");
		} else {
			g_snprintf (ssid, sizeof(ssid), "%s", format_text(tmp->stats.ssid, tmp->stats.ssid_len));
		}
		g_snprintf (percent, sizeof(percent), "%.2f %%", f);

		if (!tmp->iter_valid) {
			gtk_list_store_append(store, &tmp->iter);
			tmp->iter_valid = TRUE;
		}
		gtk_list_store_set (store, &tmp->iter,
				    BSSID_COLUMN, bssid,
				    CHANNEL_COLUMN, channel,
				    SSID_COLUMN, ssid,
				    PERCENT_COLUMN, percent,
				    BEACONS_COLUMN, tmp->type[0x08],
				    DATA_COLUMN, data,
				    PROBE_REQ_COLUMN, tmp->type[0x04],
				    PROBE_RESP_COLUMN, tmp->type[0x05],
				    AUTH_COLUMN, tmp->type[0x0B],
				    DEAUTH_COLUMN, tmp->type[0x0C],
				    OTHER_COLUMN, other,
				    PROTECTION_COLUMN, tmp->stats.protection,
				    PERCENT_VALUE_COLUMN, f,
				    TABLE_COLUMN, tmp,
				    -1);

		hs->num_entries++;
	}

	sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(hs->table));
	if (gtk_tree_selection_get_selected (sel, &model, &iter)) {
		wlan_ep_t *ep;

		gtk_tree_model_get (model, &iter, TABLE_COLUMN, &ep, -1);
		wlanstat_details (hs, ep, FALSE);
	}
}

/* What to do when a list item is selected/unselected */
static void
wlan_select_cb(GtkTreeSelection *sel, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;
	wlan_ep_t *ep;
	GtkTreeModel *model;
	GtkTreeIter iter;

	if (gtk_tree_selection_get_selected (sel, &model, &iter)) {
		gtk_tree_model_get (model, &iter, TABLE_COLUMN, &ep, -1);
		wlanstat_details (hs, ep, TRUE);
	}
}


static void
wlan_resolve_toggle_dest(GtkWidget *widget, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;

	hs->resolve_names = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

	wlanstat_draw(hs);
}

static void
wlan_filter_toggle_dest(GtkWidget *widget, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;

	hs->use_dfilter = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

	cf_retap_packets(&cfile, FALSE);
	gdk_window_raise(wlanstat_dlg_w->window);
}

static void
wlan_existing_toggle_dest(GtkWidget *widget, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;

	hs->show_only_existing = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

	wlanstat_draw(hs);
}

static gboolean
csv_handle(GtkTreeModel *model, GtkTreePath *path _U_, GtkTreeIter *iter,
              gpointer data)
{
	GString *CSV_str = (GString *)data;
	gchar   *table_text;
	gint     table_value;
	int      i;

	for (i=0; i<=PROTECTION_COLUMN; i++) {
		if (i == BSSID_COLUMN || i == CHANNEL_COLUMN || i == SSID_COLUMN ||
		    i == PERCENT_COLUMN || i == PROTECTION_COLUMN) {
			gtk_tree_model_get(model, iter, i, &table_text, -1);
			g_string_append(CSV_str, table_text);
		} else {
			gtk_tree_model_get(model, iter, i, &table_value, -1);
			g_string_append_printf(CSV_str, "%u", table_value);
		}
		if (i != PROTECTION_COLUMN)
			g_string_append(CSV_str,",");
	}
	g_string_append(CSV_str,"\n");

	return FALSE;
}

static void
wlan_copy_as_csv(GtkWindow *win _U_, gpointer data)
{
	int             i;
	GString         *CSV_str = g_string_new("");
	GtkClipboard    *cb;
	GtkTreeView     *tree_view = GTK_TREE_VIEW(data);
	GtkListStore    *store;

	/* Add the column headers to the CSV data */
	for (i=0; i<=PROTECTION_COLUMN; i++) {
		g_string_append(CSV_str, titles[i]);
		if (i != PROTECTION_COLUMN)
			g_string_append(CSV_str, ",");
	}
	g_string_append(CSV_str,"\n");

	/* Add the column values to the CSV data */
	store = GTK_LIST_STORE(gtk_tree_view_get_model(tree_view));
	gtk_tree_model_foreach(GTK_TREE_MODEL(store), csv_handle, CSV_str);

	/* Now that we have the CSV data, copy it into the default clipboard */
	cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
	gtk_clipboard_set_text(cb, CSV_str->str, -1);
	g_string_free(CSV_str, TRUE);
}

static void
win_destroy_cb (GtkWindow *win _U_, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;

	protect_thread_critical_region ();
	remove_tap_listener (hs);
	unprotect_thread_critical_region ();

	if (wlanstat_dlg_w != NULL) {
		window_destroy(wlanstat_dlg_w);
		wlanstat_dlg_w = NULL;
	}
	wlanstat_reset (hs);
	g_free (hs);

	recent.gui_geometry_wlan_stats_pane =
	  gtk_paned_get_position(GTK_PANED(wlanstat_pane));
}

/* Filter value */
#define VALUE_BSSID_ONLY       0
#define VALUE_SSID_ONLY        1
#define VALUE_BSSID_AND_SSID   2
#define VALUE_BSSID_OR_SSID    3

static void
wlan_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
	int value;
	wlanstat_t *hs=(wlanstat_t *)callback_data;
	char *str = NULL;
	wlan_ep_t *ep;
	GtkTreeSelection *sel;
	GtkTreeModel *model;
	GtkTreeIter iter;

	sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(hs->table));
	gtk_tree_selection_get_selected (sel, &model, &iter);
	gtk_tree_model_get (model, &iter, TABLE_COLUMN, &ep, -1);

	value = FILTER_EXTRA(callback_action);

	switch (value) {
	case VALUE_BSSID_ONLY:
		str = g_strdup_printf("wlan.bssid==%s", address_to_str(&ep->bssid));
		break;
	case VALUE_SSID_ONLY:
		str = g_strdup_printf("wlan_mgt.ssid==\"%s\"", format_text(ep->stats.ssid, ep->stats.ssid_len));
		break;
	case VALUE_BSSID_AND_SSID:
		str = g_strdup_printf("wlan.bssid==%s && wlan_mgt.ssid==\"%s\"",
				      address_to_str(&ep->bssid), format_text(ep->stats.ssid, ep->stats.ssid_len));
		break;
	case VALUE_BSSID_OR_SSID:
		str = g_strdup_printf("wlan.bssid==%s || wlan_mgt.ssid==\"%s\"",
				      address_to_str(&ep->bssid), format_text(ep->stats.ssid, ep->stats.ssid_len));
		break;
	}

	apply_selected_filter (callback_action, str);

	g_free (str);
}

static void
wlan_details_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
	wlanstat_t *hs=(wlanstat_t *)callback_data;
	char *str = NULL;
	wlan_details_ep_t *ep;
	GtkTreeSelection *sel;
	GtkTreeModel *model;
	GtkTreeIter iter;

	sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(hs->details));
	gtk_tree_selection_get_selected (sel, &model, &iter);
	gtk_tree_model_get (model, &iter, DETAILS_COLUMN, &ep, -1);

	str = g_strdup_printf("wlan.addr==%s", address_to_str(&ep->address));

	apply_selected_filter (callback_action, str);

	g_free (str);
}

static gint
wlan_show_popup_menu_cb(void *widg _U_, GdkEvent *event, wlanstat_t *et)
{
	GdkEventButton *bevent = (GdkEventButton *)event;
	GtkTreeSelection *sel;
	GtkTreeModel *model;
	GtkTreeIter iter;

	/* To qoute the "Gdk Event Structures" doc:
	 * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
	if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
		/* If this is a right click on one of our columns, popup the context menu */
		sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(et->table));
		if (gtk_tree_selection_get_selected (sel, &model, &iter)) {
			gtk_menu_popup(GTK_MENU(et->menu), NULL, NULL, NULL, NULL,
				       bevent->button, bevent->time);
		}
	}

	return FALSE;
}

static GtkItemFactoryEntry wlan_list_menu_items[] =
{
	/* Match */
	{"/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Apply as Filter/Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Apply as Filter/Not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Not Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/Not Selected/SID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/Not Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Apply as Filter/Not Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Apply as Filter/... and Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/... and Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/... and Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/... and Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Apply as Filter/... and Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Apply as Filter/... or Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/... or Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/... or Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/... or Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Apply as Filter/... or Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Apply as Filter/... and not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/... and not Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Apply as Filter/... or not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/... or not Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},

	/* Prepare */
	{"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Prepare a Filter/Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Prepare a Filter/Not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Not Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/SID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Prepare a Filter/... and Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/... and Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Prepare a Filter/... or Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/... or Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/... and not Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/... or not Selected/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},

	/* Find Frame */
	{"/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Find Frame/Find Frame/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Find Frame/Find Frame/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Find Frame/Find Frame/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	/* Find Next */
	{"/Find Frame/Find Next", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Next/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Find Frame/Find Next/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Find Frame/Find Next/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Find Frame/Find Next/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},
	/* Find Previous */
	{"/Find Frame/Find Previous", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Previous/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Find Frame/Find Previous/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Find Frame/Find Previous/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Find Frame/Find Previous/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},

	/* Colorize */
	{"/Colorize", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Colorize/BSSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, VALUE_BSSID_ONLY), NULL, NULL,},
	{"/Colorize/SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, VALUE_SSID_ONLY), NULL, NULL,},
	{"/Colorize/BSSID and SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, VALUE_BSSID_AND_SSID), NULL, NULL,},
	{"/Colorize/BSSID or SSID", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, VALUE_BSSID_OR_SSID), NULL, NULL,},

};

static void
wlan_create_popup_menu(wlanstat_t *hs)
{
	GtkItemFactory *item_factory;

	item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

	gtk_item_factory_create_items_ac(item_factory, sizeof(wlan_list_menu_items)/sizeof(wlan_list_menu_items[0]), wlan_list_menu_items, hs, 2);

	hs->menu = gtk_item_factory_get_widget(item_factory, "<main>");
	g_signal_connect(hs->table, "button_press_event", G_CALLBACK(wlan_show_popup_menu_cb), hs);
}

static gint
wlan_details_show_popup_menu_cb(void *widg _U_, GdkEvent *event, wlanstat_t *et)
{
	GdkEventButton *bevent = (GdkEventButton *)event;
	GtkTreeSelection *sel;
	GtkTreeModel *model;
	GtkTreeIter iter;

	/* To qoute the "Gdk Event Structures" doc:
	 * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
	if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
		/* if this is a right click on one of our columns, popup the context menu */
		sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(et->details));
		if (gtk_tree_selection_get_selected (sel, &model, &iter)) {
			gtk_menu_popup(GTK_MENU(et->details_menu), NULL, NULL, NULL, NULL,
				       bevent->button, bevent->time);
		}
	}

	return FALSE;
}

static GtkItemFactoryEntry wlan_details_list_menu_items[] =
{
	/* Match */
	{"/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/Not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/... and Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/... or Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, 0), NULL, NULL,},

	/* Prepare */
	{"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/Not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/... and Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/... or Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, 0), NULL, NULL,},

	/* Find Frame */
	{"/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, 0), NULL, NULL,},
	/* Find Next */
	{"/Find Frame/Find Next", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, 0), NULL, NULL,},
	/* Find Previous */
	{"/Find Frame/Find Previous", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, 0), NULL, NULL,},

	/* Colorize WLAN Address */
	{"/Colorize WLAN Address", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, 0), NULL, NULL,}

};

static void
wlan_details_create_popup_menu(wlanstat_t *hs)
{
	GtkItemFactory *item_factory;

	item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

	gtk_item_factory_create_items_ac(item_factory, sizeof(wlan_details_list_menu_items)/sizeof(wlan_details_list_menu_items[0]), wlan_details_list_menu_items, hs, 2);

	hs->details_menu = gtk_item_factory_get_widget(item_factory, "<main>");
	g_signal_connect(hs->details, "button_press_event", G_CALLBACK(wlan_details_show_popup_menu_cb), hs);
}

static void
wlanstat_dlg_create (void)
{
	wlanstat_t    *hs;
	GString       *error_string;
	GtkWidget     *scrolled_window;
	GtkWidget     *bbox;
	GtkWidget     *vbox;
	GtkWidget     *hbox;
	GtkWidget     *frame;
	GtkWidget     *selected_vb;
	GtkWidget     *resolv_cb;
	GtkWidget     *filter_cb;
	GtkWidget     *existing_cb;
	GtkWidget     *close_bt;
	GtkWidget     *help_bt;
	GtkWidget     *copy_bt;
	GtkTooltips   *tooltips = gtk_tooltips_new();
	GtkListStore  *store;
	GtkTreeView       *tree_view;
	GtkCellRenderer   *renderer;
	GtkTreeViewColumn *column;
	GtkTreeSelection  *sel;
	char title[256];
	gint i;

	hs=g_malloc (sizeof(wlanstat_t));
	hs->num_entries = 0;
	hs->ep_list = NULL;
	hs->number_of_packets = 0;
	hs->resolve_names = TRUE;
	hs->use_dfilter = FALSE;
	hs->show_only_existing = FALSE;

	g_snprintf (title, 255, "Wireshark: WLAN Traffic Statistics: %s",
		    cf_get_display_name(&cfile));
	wlanstat_dlg_w = window_new_with_geom (GTK_WINDOW_TOPLEVEL, title, "WLAN Statistics");
	gtk_window_set_default_size (GTK_WINDOW(wlanstat_dlg_w), 750, 400);

	vbox=gtk_vbox_new (FALSE, 3);
	gtk_container_add(GTK_CONTAINER(wlanstat_dlg_w), vbox);
	gtk_container_set_border_width (GTK_CONTAINER(vbox), 6);

	wlanstat_pane = gtk_vpaned_new();
	gtk_box_pack_start (GTK_BOX (vbox), wlanstat_pane, TRUE, TRUE, 0);
	gtk_paned_set_position(GTK_PANED(wlanstat_pane), recent.gui_geometry_wlan_stats_pane);
	gtk_widget_show(wlanstat_pane);

	/* init a scrolled window for overview */
	wlanstat_name_lb = gtk_frame_new("Network Overview");
	gtk_paned_pack1(GTK_PANED(wlanstat_pane), wlanstat_name_lb, FALSE, TRUE);
	selected_vb = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(wlanstat_name_lb), selected_vb);
	gtk_container_set_border_width(GTK_CONTAINER(selected_vb), 5);

	scrolled_window = scrolled_window_new (NULL, NULL);
	gtk_box_pack_start(GTK_BOX(selected_vb), scrolled_window, TRUE, TRUE, 0);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_window),
					    GTK_SHADOW_IN);

	store = gtk_list_store_new(NUM_COLUMNS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
				   G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT,
				   G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT,
				   G_TYPE_STRING, G_TYPE_FLOAT, G_TYPE_POINTER);
	hs->table = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
	gtk_container_add(GTK_CONTAINER (scrolled_window), GTK_WIDGET(hs->table));
	g_object_unref(G_OBJECT(store));

	tree_view = hs->table;
	gtk_tree_view_set_headers_visible(tree_view, TRUE);
	gtk_tree_view_set_headers_clickable(tree_view, TRUE);

	for (i = 0; i <= PROTECTION_COLUMN; i++) {
#if GTK_CHECK_VERSION(2,6,0)
		if (i == PERCENT_COLUMN) {
			renderer = gtk_cell_renderer_progress_new();
			column = gtk_tree_view_column_new_with_attributes(titles[i], renderer,
									  "text", i,
									  "value", PERCENT_VALUE_COLUMN,
									  NULL);
			gtk_tree_view_column_set_expand(column, TRUE);
			gtk_tree_view_column_set_sort_column_id(column, PERCENT_VALUE_COLUMN);
		} else {
#else
		{
#endif
			renderer = gtk_cell_renderer_text_new();
			column = gtk_tree_view_column_new_with_attributes(titles[i], renderer,
									  "text", i,
									  NULL);
			gtk_tree_view_column_set_sort_column_id(column, i);
		}

		if (i != BSSID_COLUMN && i != SSID_COLUMN && i != PROTECTION_COLUMN) {
			/* Align all number columns */
			g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
		}
		gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
		gtk_tree_view_column_set_resizable(column, TRUE);
		gtk_tree_view_append_column(tree_view, column);

		if (i == SSID_COLUMN) {
			/* Sort the SSID column */
			gtk_tree_view_column_clicked(column);
		}
	}

	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->table));
	gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
	g_signal_connect(sel, "changed", G_CALLBACK(wlan_select_cb), hs);

	/* init a scrolled window for details */
	frame = gtk_frame_new("Selected Network");
	gtk_paned_pack2(GTK_PANED(wlanstat_pane), frame, FALSE, TRUE);
	selected_vb = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(frame), selected_vb);
	gtk_container_set_border_width(GTK_CONTAINER(selected_vb), 5);

	scrolled_window = scrolled_window_new (NULL, NULL);
	gtk_box_pack_start(GTK_BOX(selected_vb), scrolled_window, TRUE, TRUE, 0);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_window),
					    GTK_SHADOW_IN);

	store = gtk_list_store_new(NUM_DETAIL_COLUMNS, G_TYPE_STRING, G_TYPE_STRING,
				   G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT,
				   G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_STRING,
				   G_TYPE_FLOAT, G_TYPE_POINTER);
	hs->details = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
	gtk_container_add(GTK_CONTAINER (scrolled_window), GTK_WIDGET(hs->details));
	g_object_unref(G_OBJECT(store));

	tree_view = hs->details;
	gtk_tree_view_set_headers_visible(tree_view, TRUE);
	gtk_tree_view_set_headers_clickable(tree_view, TRUE);

	for (i = 0; i <= COMMENT_COLUMN; i++) {
#if GTK_CHECK_VERSION(2,6,0)
		if (i == PERCENT_2_COLUMN) {
			renderer = gtk_cell_renderer_progress_new();
			column = gtk_tree_view_column_new_with_attributes(detail_titles[i], renderer,
									  "text", i,
									  "value", PERCENT_VALUE_2_COLUMN,
									  NULL);
			gtk_tree_view_column_set_expand(column, TRUE);
			gtk_tree_view_column_set_sort_column_id(column, PERCENT_VALUE_2_COLUMN);
		} else {
#else
		{
#endif
			renderer = gtk_cell_renderer_text_new();
			column = gtk_tree_view_column_new_with_attributes(detail_titles[i], renderer,
									  "text", i,
									  NULL);
			gtk_tree_view_column_set_sort_column_id(column, i);
		}

		if (i != ADDRESS_COLUMN && i != COMMENT_COLUMN) {
			/* Align all number columns */
			g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
		}
		gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
		gtk_tree_view_column_set_resizable(column, TRUE);
		gtk_tree_view_append_column(tree_view, column);

		if (i == ADDRESS_COLUMN) {
			/* Sort the Address column */
			gtk_tree_view_column_clicked(column);
		}
	}

	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->table));
	gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);

	/* create popup menu for this table */
	wlan_create_popup_menu(hs);
	wlan_details_create_popup_menu(hs);

	error_string=register_tap_listener ("wlan", hs, NULL, wlanstat_reset,
					    wlanstat_packet, wlanstat_draw);
	if (error_string) {
		simple_dialog (ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free (error_string, TRUE);
		g_free (hs);
		return;
	}

	hbox = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

	resolv_cb = gtk_check_button_new_with_mnemonic("Name resolution");
	gtk_container_add(GTK_CONTAINER(hbox), resolv_cb);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(resolv_cb), TRUE);
	gtk_tooltips_set_tip(tooltips, resolv_cb, "Show results of name resolutions rather than the \"raw\" values. "
			     "Please note: The corresponding name resolution must be enabled.", NULL);

	g_signal_connect(resolv_cb, "toggled", G_CALLBACK(wlan_resolve_toggle_dest), hs);

	filter_cb = gtk_check_button_new_with_mnemonic("Limit to display filter");
	gtk_container_add(GTK_CONTAINER(hbox), filter_cb);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(filter_cb), FALSE);
	gtk_tooltips_set_tip(tooltips, filter_cb, "Limit the list to entries matching the current display filter.", NULL);
	g_signal_connect(filter_cb, "toggled", G_CALLBACK(wlan_filter_toggle_dest), hs);

	existing_cb = gtk_check_button_new_with_mnemonic("Only show existing networks");
	gtk_container_add(GTK_CONTAINER(hbox), existing_cb);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(existing_cb), FALSE);
	gtk_tooltips_set_tip(tooltips, existing_cb, "This option disables probe requests for "
			     "unknown networks.", NULL);
	g_signal_connect(existing_cb, "toggled", G_CALLBACK(wlan_existing_toggle_dest), hs);

	/* Button row. */
	bbox = dlg_button_row_new (GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);

	gtk_box_pack_end (GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button (wlanstat_dlg_w, close_bt, window_cancel_button_cb);

	copy_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
/* 	gtk_button_set_label(GTK_BUTTON(copy_bt), "Copy Overview"); */
	gtk_tooltips_set_tip(tooltips, copy_bt,
			     "Copy all statistical values of this page to the clipboard in CSV (Comma Separated Values) format.", NULL);
	g_signal_connect(copy_bt, "clicked", G_CALLBACK(wlan_copy_as_csv), hs->table);

	help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
	g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_WLAN_TRAFFIC_DIALOG);

	g_signal_connect (wlanstat_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect (wlanstat_dlg_w, "destroy", G_CALLBACK(win_destroy_cb), hs);

	gtk_widget_show_all (wlanstat_dlg_w);
	window_present (wlanstat_dlg_w);

	cf_retap_packets (&cfile, FALSE);
	gdk_window_raise(wlanstat_dlg_w->window);
}

static void
wlanstat_launch (GtkWidget *w _U_, gpointer data _U_)
{
	if (wlanstat_dlg_w) {
		reactivate_window(wlanstat_dlg_w);
	} else {
		wlanstat_dlg_create ();
	}
}

void
register_tap_listener_wlanstat (void)
{
	register_stat_menu_item ("WLAN Traffic...", REGISTER_STAT_GROUP_UNSORTED,
				 wlanstat_launch, NULL, NULL, NULL);
}
