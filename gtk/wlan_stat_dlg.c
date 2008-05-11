/* wlan_stat_dlg.c
 * Copyright 2008 Stig Bjørlykke <stig@bjorlykke.org>
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

#include "gtk/main.h"
#include "gtk/gtkglobals.h"
#include "gtk/find_dlg.h"
#include "gtk/color_dlg.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/gui_utils.h"
#include "gtk/recent.h"
#include "gtk/help_dlg.h"

#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"

#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

#define NUM_COLS 12
static const gchar *titles[] = { "BSSID", "Channel", "SSID", "Beacons", "Data Packets", "Probe Req", "Probe Resp", "Auth", "Deauth", "Other", "Percent", "Protection" };

#define NUM_DETAIL_COLS 10
static const gchar *detail_titles[] = { "Address", "Data Sent", "Data Received", "Probe Req", "Probe Resp", "Auth", "Deauth", "Other", "Percent", "Comment" };

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;

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
} wlan_details_ep_t;

typedef struct wlan_ep {
	struct wlan_ep* next;
	address bssid;
	struct _wlan_stats stats;
	guint32 type[256];
	guint32 number_of_packets;
	struct wlan_details_ep *details;
} wlan_ep_t;

static GtkWidget  *wlanstat_dlg_w = NULL;
static GtkWidget  *wlanstat_pane = NULL;

/* used to keep track of the statistics for an entire program interface */
typedef struct _wlan_stat_t {
	GtkWidget  *table;
	GtkWidget  *details;
	GtkWidget  *menu;
	GtkWidget  *details_menu;
	guint32    number_of_packets;
	guint32    num_entries;
	guint32    num_details;
	gboolean   resolve_names;
	gboolean   show_only_existing;
	address    selected_bssid;
	gboolean   selected_bssid_valid;
	guint8     selected_ssid_len;
	guchar     selected_ssid[MAX_SSID_LEN];
	gboolean   selected_ssid_valid;
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

	if (wlanstat_dlg_w != NULL) {
		char title[256];
		g_snprintf (title, 255, "Wireshark: WLAN Traffic Statistics: %s", 
			    cf_get_display_name(&cfile));
		gtk_window_set_title(GTK_WINDOW(wlanstat_dlg_w), title);
	}

	/* remove all entries from the clist */
	gtk_clist_clear (GTK_CLIST(wlan_stat->table));
	gtk_clist_clear (GTK_CLIST(wlan_stat->details));

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

		if (te && si->type != 0x04 && te->type[0x04] == 0 && te->stats.ssid_len != 0) {
			/* 
			 * We have found a matching entry without Probe Requests.  
			 * Search the rest of the entries for a corresponding entry 
			 * matching the SSID and BSSID == Broadcast.
			 *
			 * This is because we can have a hidden SSID or Probe Request
			 * before we have a Beacon.
			 */
		 	wlan_ep_t *prev = NULL;

			for (tmp = hs->ep_list; tmp; tmp = tmp->next) {
				if (te->stats.ssid_len &&
				    (te->stats.ssid_len == tmp->stats.ssid_len) &&
				    (memcmp (te->stats.ssid, tmp->stats.ssid, tmp->stats.ssid_len) == 0) &&
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
					g_free (tmp);
					break;
				}
				prev = tmp;
			}
		}

		if (!te) {
			if ((te = alloc_wlan_ep (si, pinfo))) {
				te->next = hs->ep_list;
				hs->ep_list = te;
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
wlan_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
	column_arrows *col_arrows = (column_arrows *) data;
	int i;

	gtk_clist_freeze(clist);

	for (i=0; i<NUM_COLS; i++) {
		gtk_widget_hide(col_arrows[i].ascend_pm);
		gtk_widget_hide(col_arrows[i].descend_pm);
	}

	if (column == clist->sort_column) {
		if (clist->sort_type == GTK_SORT_ASCENDING) {
			clist->sort_type = GTK_SORT_DESCENDING;
			gtk_widget_show(col_arrows[column].descend_pm);
		} else {
			clist->sort_type = GTK_SORT_ASCENDING;
			gtk_widget_show(col_arrows[column].ascend_pm);
		}
	} else {
		clist->sort_type = GTK_SORT_ASCENDING;
		gtk_widget_show(col_arrows[column].ascend_pm);
		gtk_clist_set_sort_column(clist, column);
	}

	gtk_clist_sort(clist);
	gtk_clist_thaw(clist);
}

static void
wlan_detail_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
	column_arrows *col_arrows = (column_arrows *) data;
	int i;

	gtk_clist_freeze(clist);

	for (i=0; i<NUM_DETAIL_COLS; i++) {
		gtk_widget_hide(col_arrows[i].ascend_pm);
		gtk_widget_hide(col_arrows[i].descend_pm);
	}

	if (column == clist->sort_column) {
		if (clist->sort_type == GTK_SORT_ASCENDING) {
			clist->sort_type = GTK_SORT_DESCENDING;
			gtk_widget_show(col_arrows[column].descend_pm);
		} else {
			clist->sort_type = GTK_SORT_ASCENDING;
			gtk_widget_show(col_arrows[column].ascend_pm);
		}
	} else {
		clist->sort_type = GTK_SORT_ASCENDING;
		gtk_widget_show(col_arrows[column].ascend_pm);
		gtk_clist_set_sort_column(clist, column);
	}

	gtk_clist_sort(clist);
	gtk_clist_thaw(clist);
}

static gint
wlan_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	char *text1 = NULL;
	char *text2 = NULL;
	int i1, i2;

	const GtkCListRow *row1 = (const GtkCListRow *) ptr1;
	const GtkCListRow *row2 = (const GtkCListRow *) ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	case 0:
	case 2:
	case 11:
		return g_ascii_strcasecmp (text1, text2);
	case 1:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
		i1=atoi(text1);
		i2=atoi(text2);
		return i1-i2;
	}
	g_assert_not_reached();
	return 0;
}

static gint
wlan_detail_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	char *text1 = NULL;
	char *text2 = NULL;
	int i1, i2;

	const GtkCListRow *row1 = (const GtkCListRow *) ptr1;
	const GtkCListRow *row2 = (const GtkCListRow *) ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	case 0:
	case 9:
		return g_ascii_strcasecmp (text1, text2);
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
		i1=atoi(&text1[(text1[0] == '(' ? 1 : 0)]);
		i2=atoi(&text2[(text2[0] == '(' ? 1 : 0)]);
		return i1-i2;
	}
	g_assert_not_reached();
	return 0;
}

static void
wlanstat_details(wlanstat_t *hs, wlan_ep_t *wlan_ep)
{
	wlan_details_ep_t *tmp = NULL;
	char *str[NUM_DETAIL_COLS];
	gboolean broadcast, basestation;
	float f;
	int row, i=0;

	for (i = 0; i < NUM_DETAIL_COLS; i++) {
		str[i] = g_malloc (sizeof(char[256]));
	}

	/* clear list before printing */
	gtk_clist_freeze(GTK_CLIST(hs->details));
	gtk_clist_clear (GTK_CLIST(hs->details));
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
			g_snprintf (str[0],  sizeof(char[256]),"%s", get_addr_name(&tmp->address));
		} else {
			g_snprintf (str[0],  sizeof(char[256]),"%s", address_to_str(&tmp->address));
		}
		g_snprintf (str[1],  sizeof(char[256]),"%u", tmp->data_sent);
		g_snprintf (str[2],  sizeof(char[256]),"%u", tmp->data_received);
		if (broadcast) {
			g_snprintf (str[3],  sizeof(char[256]),"(%u)", tmp->probe_req);
		} else {
			g_snprintf (str[3],  sizeof(char[256]),"%u", tmp->probe_req);
		}
		if (basestation) {
			g_snprintf (str[4],  sizeof(char[256]),"(%u)", tmp->probe_rsp);
			g_snprintf (str[5],  sizeof(char[256]),"(%u)", tmp->auth);
			g_snprintf (str[6],  sizeof(char[256]),"(%u)", tmp->deauth);
			g_snprintf (str[7],  sizeof(char[256]),"(%u)", tmp->other);
		} else {
			g_snprintf (str[4],  sizeof(char[256]),"%u", tmp->probe_rsp);
			g_snprintf (str[5],  sizeof(char[256]),"%u", tmp->auth);
			g_snprintf (str[6],  sizeof(char[256]),"%u", tmp->deauth);
			g_snprintf (str[7],  sizeof(char[256]),"%u", tmp->other);
		}
		g_snprintf (str[8], sizeof(char[256]),"%.2f%%", f);
		if (basestation) {
			g_snprintf (str[9], sizeof(char[256]),"Base station");
		} else {
			g_snprintf (str[9], sizeof(char[256])," ");
		}
		row = gtk_clist_append (GTK_CLIST(hs->details), str);
		gtk_clist_set_row_data (GTK_CLIST(hs->details), row, tmp);
		hs->num_details++;
	}

	gtk_clist_sort(GTK_CLIST(hs->details));
	gtk_clist_thaw(GTK_CLIST(hs->details));
}

static void
wlanstat_draw(void *phs)
{
	wlanstat_t *hs = (wlanstat_t *)phs;
	wlan_ep_t* list = hs->ep_list, *tmp = 0;
	guint32 data = 0, other = 0;
	char *str[NUM_COLS];
	gboolean broadcast;
	float f;
	int row, selected_row = -1, i;

	for (i = 0; i < NUM_COLS; i++) {
		str[i] = g_malloc (sizeof(char[256]));
	}

	/* clear list before printing */
	gtk_clist_freeze(GTK_CLIST(hs->table));
	gtk_clist_clear (GTK_CLIST(hs->table));
	hs->num_entries = 0;

	for(tmp = list; tmp; tmp=tmp->next) {
		broadcast = !(strcmp (get_addr_name(&tmp->bssid), "Broadcast"));

		if (hs->show_only_existing && broadcast) {
			continue;
		}

		data = tmp->type[0x20] + tmp->type[0x21] + tmp->type[0x22] + tmp->type[0x23] +
		  tmp->type[0x28] + tmp->type[0x29] + tmp->type[0x2A] + tmp->type[0x2B];
		other = tmp->number_of_packets - data - tmp->type[0x08] - tmp->type[0x04] - 
		  tmp->type[0x05] - tmp->type[0x0B] - tmp->type[0x0C];
		f = (float)(((float)tmp->number_of_packets * 100.0) / hs->number_of_packets);

		if (hs->resolve_names) {
			g_snprintf (str[0],  sizeof(char[256]),"%s", get_addr_name(&tmp->bssid));
		} else {
			g_snprintf (str[0],  sizeof(char[256]),"%s", address_to_str(&tmp->bssid));
		}
		if (tmp->stats.channel) {
			g_snprintf (str[1],  sizeof(char[256]),"%u", tmp->stats.channel);
		} else {
			str[1][0] = '\0';
		}
		if (tmp->stats.ssid_len == 0) {
			g_snprintf (str[2],  sizeof(char[256]),"<Broadcast>");
		} else if (tmp->stats.ssid_len == 1 && tmp->stats.ssid[0] == 0) {
			g_snprintf (str[2],  sizeof(char[256]),"<Hidden>");
		} else {
			g_snprintf (str[2],  sizeof(char[256]),"%s", format_text(tmp->stats.ssid, tmp->stats.ssid_len));
		}
		g_snprintf (str[3],  sizeof(char[256]),"%u", tmp->type[0x08]);
		g_snprintf (str[4],  sizeof(char[256]),"%u", data);
		g_snprintf (str[5],  sizeof(char[256]),"%u", tmp->type[0x04]);
		g_snprintf (str[6],  sizeof(char[256]),"%u", tmp->type[0x05]);
		g_snprintf (str[7],  sizeof(char[256]),"%u", tmp->type[0x0B]);
		g_snprintf (str[8],  sizeof(char[256]),"%u", tmp->type[0x0C]);
		g_snprintf (str[9],  sizeof(char[256]),"%u", other);
		g_snprintf (str[10], sizeof(char[256]),"%.2f%%", f);
		g_snprintf (str[11], sizeof(char[256]),"%s", tmp->stats.protection);
		row = gtk_clist_append (GTK_CLIST(hs->table), str);
		if ((hs->selected_ssid_valid && 
		     (hs->selected_ssid_len == tmp->stats.ssid_len) && 
		     (memcmp(hs->selected_ssid, tmp->stats.ssid, tmp->stats.ssid_len) == 0)) ||
		    (hs->selected_bssid_valid && !CMP_ADDRESS(&hs->selected_bssid, &tmp->bssid))) {
			selected_row = row;
		}
		gtk_clist_set_row_data (GTK_CLIST(hs->table), row, tmp);
		hs->num_entries++;
	}

	if (selected_row != -1) {
		wlan_ep_t *ep = gtk_clist_get_row_data (GTK_CLIST(hs->table), selected_row);
		gtk_clist_select_row(GTK_CLIST(hs->table), selected_row, 0);
		wlanstat_details (hs, ep);
	}

	gtk_clist_sort(GTK_CLIST(hs->table));
	gtk_clist_thaw(GTK_CLIST(hs->table));

}

/* What to do when a list item is selected/unselected */
static void
wlan_select_cb(GtkWidget *w, gint row, gint col _U_, GdkEventButton *event _U_, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;
	wlan_ep_t *ep = gtk_clist_get_row_data (GTK_CLIST(w), row);

	if (strcmp (get_addr_name(&ep->bssid), "Broadcast") == 0) {
		memcpy (hs->selected_ssid, ep->stats.ssid, MAX_SSID_LEN);
		hs->selected_ssid_len = ep->stats.ssid_len;
		hs->selected_bssid_valid = FALSE;
		hs->selected_ssid_valid = TRUE;
	} else {
		SE_COPY_ADDRESS (&hs->selected_bssid, &ep->bssid);
		hs->selected_bssid_valid = TRUE;
		hs->selected_ssid_valid = FALSE;
	}

	wlanstat_details (hs, ep);
}

static void
wlan_unselect_cb(GtkWidget *w _U_, gint row _U_, gint col _U_, GdkEventButton *event _U_, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;
	hs->selected_bssid_valid = FALSE;
	hs->selected_ssid_valid = FALSE;

	gtk_clist_clear (GTK_CLIST(hs->details));
}

static void
wlan_resolve_toggle_dest(GtkWidget *widget, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;

	hs->resolve_names = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));
	gtk_clist_clear (GTK_CLIST(hs->details));

	wlanstat_draw(hs);
}

static void
wlan_existing_toggle_dest(GtkWidget *widget, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;

	hs->show_only_existing = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));
	gtk_clist_clear (GTK_CLIST(hs->details));

	wlanstat_draw(hs);
}

static void
wlan_copy_as_csv(GtkWindow *win _U_, gpointer data)
{
	int             i,j;
	gchar           *table_entry;
	GString         *CSV_str = g_string_new("");
	GtkClipboard    *cb;
	GtkCList       *clist = GTK_CLIST(data);

	/* Add the column headers to the CSV data */
	for (j=0; j<NUM_COLS; j++) {
		g_string_append(CSV_str, titles[j]);
		if (j != (NUM_COLS - 1))
			g_string_append(CSV_str, ",");
	}
	g_string_append(CSV_str,"\n");

	/* Add the column values to the CSV data */
	for (i=0; i<clist->rows; i++) {
		for (j=0; j<NUM_COLS; j++) {
			gtk_clist_get_text(clist,i,j,&table_entry);
			g_string_append(CSV_str,table_entry);
			if (j != (NUM_COLS - 1))
				g_string_append(CSV_str,",");
		} 
		g_string_append(CSV_str,"\n");
	}

	/* Now that we have the CSV data, copy it into the default clipboard */
	cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
	gtk_clipboard_set_text(cb, CSV_str->str, -1);
	g_string_free(CSV_str, TRUE);
}

void protect_thread_critical_region (void);
void unprotect_thread_critical_region (void);
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

/* Filter actions */
#define ACTION_MATCH		0
#define ACTION_PREPARE		1
#define ACTION_FIND_FRAME	2
#define ACTION_FIND_NEXT	3
#define ACTION_FIND_PREVIOUS	4
#define ACTION_COLORIZE		5

/* Action type - says what to do with the filter */
#define ACTYPE_SELECTED		0
#define ACTYPE_NOT_SELECTED	1
#define ACTYPE_AND_SELECTED	2
#define ACTYPE_OR_SELECTED	3
#define ACTYPE_AND_NOT_SELECTED	4
#define ACTYPE_OR_NOT_SELECTED	5

/* Encoded callback arguments */
#define CALLBACK_MATCH(type)		((ACTION_MATCH<<8) | (type))
#define CALLBACK_PREPARE(type)		((ACTION_PREPARE<<8) | (type))
#define CALLBACK_FIND_FRAME(type)	((ACTION_FIND_FRAME<<8) | (type))
#define CALLBACK_FIND_NEXT(type)	((ACTION_FIND_NEXT<<8) | (type))
#define CALLBACK_FIND_PREVIOUS(type)	((ACTION_FIND_PREVIOUS<<8) | (type))
#define CALLBACK_COLORIZE(type)		((ACTION_COLORIZE<<8) | (type))

/* Extract components of callback argument */
#define FILTER_ACTION(cb_arg)		(((cb_arg)>>8) & 0xff)
#define FILTER_ACTYPE(cb_arg)		((cb_arg) & 0xff)

static void
wlan_apply_filter (guint callback_action, char *dirstr)
{
 	int action, type;
	char str[256];
	const char *current_filter;

	action = FILTER_ACTION(callback_action);
	type = FILTER_ACTYPE(callback_action);


	current_filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	switch(type){
	case ACTYPE_SELECTED:
		g_snprintf(str, 255, "%s", dirstr);
		break;
	case ACTYPE_NOT_SELECTED:
		g_snprintf(str, 255, "!(%s)", dirstr);
		break;
	case ACTYPE_AND_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			g_snprintf(str, 255, "%s", dirstr);
		else
			g_snprintf(str, 255, "(%s) && (%s)", current_filter, dirstr);
		break;
	case ACTYPE_OR_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			g_snprintf(str, 255, "%s", dirstr);
		else
			g_snprintf(str, 255, "(%s) || (%s)", current_filter, dirstr);
		break;
	case ACTYPE_AND_NOT_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			g_snprintf(str, 255, "!(%s)", dirstr);
		else
			g_snprintf(str, 255, "(%s) && !(%s)", current_filter, dirstr);
		break;
	case ACTYPE_OR_NOT_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			g_snprintf(str, 255, "!(%s)", dirstr);
		else
			g_snprintf(str, 255, "(%s) || !(%s)", current_filter, dirstr);
		break;
	}

	switch(action){
	case ACTION_MATCH:
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
		main_filter_packets(&cfile, str, FALSE);
		gdk_window_raise(top_level->window);
		break;
	case ACTION_PREPARE:
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
		break;
	case ACTION_FIND_FRAME:
		find_frame_with_filter(str);
		break;
	case ACTION_FIND_NEXT:
		find_previous_next_frame_with_filter(str, FALSE);
		break;
	case ACTION_FIND_PREVIOUS:
		find_previous_next_frame_with_filter(str, TRUE);
		break;
	case ACTION_COLORIZE:
		color_display_with_filter(str);
		break;
	}
}

static void
wlan_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
	int selection;
	wlanstat_t *hs=(wlanstat_t *)callback_data;
	char dirstr[128];
	wlan_ep_t *ep;

	selection=GPOINTER_TO_INT(g_list_nth_data(GTK_CLIST(hs->table)->selection, 0));
	if(selection>=(int)hs->num_entries){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No entry selected");
		return;
	}

	ep = gtk_clist_get_row_data (GTK_CLIST(hs->table), selection);

	if (strcmp (get_addr_name(&ep->bssid), "Broadcast") == 0) {
		g_snprintf(dirstr, 127, "wlan_mgt.ssid==\"%s\"", format_text(ep->stats.ssid, ep->stats.ssid_len));
	} else {
		g_snprintf(dirstr, 127, "wlan.bssid==%s", address_to_str(&ep->bssid));
	}

	wlan_apply_filter (callback_action, dirstr);
}

static void
wlan_details_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
	int selection;
	wlanstat_t *hs=(wlanstat_t *)callback_data;
	char dirstr[128];
	wlan_details_ep_t *ep;

	selection=GPOINTER_TO_INT(g_list_nth_data(GTK_CLIST(hs->details)->selection, 0));
	if(selection>=(int)hs->num_details){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No entry selected");
		return;
	}

	ep = gtk_clist_get_row_data (GTK_CLIST(hs->details), selection);

	g_snprintf(dirstr, 127, "wlan.addr==%s", address_to_str(&ep->address));

	wlan_apply_filter (callback_action, dirstr);
}

static gint
wlan_show_popup_menu_cb(void *widg _U_, GdkEvent *event, wlanstat_t *et)
{
	GdkEventButton *bevent = (GdkEventButton *)event;
	gint row;
	gint column;

	/* To qoute the "Gdk Event Structures" doc:
	 * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
	if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
		/* if this is a right click on one of our columns, select it and popup the context menu */
		if(gtk_clist_get_selection_info(GTK_CLIST(et->table),
						(gint) (((GdkEventButton *)event)->x),
						(gint) (((GdkEventButton *)event)->y),
						&row, &column)) {
			gtk_clist_unselect_all(GTK_CLIST(et->table));
			gtk_clist_select_row(GTK_CLIST(et->table), row, -1);
		  
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
	{"/Apply as Filter/Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED), NULL, NULL,},
	{"/Apply as Filter/Not Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... and Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... or Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED), NULL, NULL,},

	/* Prepare */
	{"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/Not Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... and Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... or Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED), NULL, NULL,},

	/* Find Frame */
	{"/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED), NULL, NULL,},
	/* Find Next */
	{"/Find Frame/Find Next", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED), NULL, NULL,},
	/* Find Previous */
	{"/Find Frame/Find Previous", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED), NULL, NULL,},
	/* Colorize Host Traffic */
	{"/Colorize Host Traffic", NULL,
		GTK_MENU_FUNC(wlan_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED), NULL, NULL,}

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
	gint row;
	gint column;

	/* To qoute the "Gdk Event Structures" doc:
	 * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
	if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
		/* if this is a right click on one of our columns, select it and popup the context menu */
		if(gtk_clist_get_selection_info(GTK_CLIST(et->details),
						(gint) (((GdkEventButton *)event)->x),
						(gint) (((GdkEventButton *)event)->y),
						&row, &column)) {
			gtk_clist_unselect_all(GTK_CLIST(et->details));
			gtk_clist_select_row(GTK_CLIST(et->details), row, -1);

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
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED), NULL, NULL,},
	{"/Apply as Filter/Not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... and Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... or Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED), NULL, NULL,},

	/* Prepare */
	{"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/Not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... and Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... or Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED), NULL, NULL,},

	/* Find Frame */
	{"/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED), NULL, NULL,},
	/* Find Next */
	{"/Find Frame/Find Next", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED), NULL, NULL,},
	/* Find Previous */
	{"/Find Frame/Find Previous", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED), NULL, NULL,},
	/* Colorize Host Traffic */
	{"/Colorize Host Traffic", NULL,
		GTK_MENU_FUNC(wlan_details_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED), NULL, NULL,}

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
	wlanstat_t *hs;
	GString *error_string;
	GtkWidget *top_label;
	GtkWidget  *scrolled_window;
	GtkWidget *bbox;
	GtkWidget  *vbox;
	GtkWidget  *hbox;
	GtkWidget *resolv_cb;
	GtkWidget *existing_cb;
	GtkWidget *close_bt;
	GtkWidget *help_bt;
	GtkTooltips *tooltips = gtk_tooltips_new();
	GtkWidget *copy_bt;
	column_arrows *col_arrows;
	GtkWidget *column_lb;
	char title[256];
	int i;

	hs=g_malloc (sizeof(wlanstat_t));
	hs->num_entries = 0;
	hs->ep_list = NULL;
	hs->number_of_packets = 0;
	hs->resolve_names = TRUE;
	hs->show_only_existing = FALSE;

	g_snprintf (title, 255, "Wireshark: WLAN Traffic Statistics: %s", 
		    cf_get_display_name(&cfile));
	wlanstat_dlg_w = window_new_with_geom (GTK_WINDOW_TOPLEVEL, title, "WLAN Statistics");
	gtk_window_set_default_size (GTK_WINDOW(wlanstat_dlg_w), 750, 400);

	vbox=gtk_vbox_new (FALSE, 3);
	gtk_container_add(GTK_CONTAINER(wlanstat_dlg_w), vbox);
	gtk_container_set_border_width (GTK_CONTAINER(vbox), 12);

	top_label = gtk_label_new ("WLAN Traffic Statistics");
	gtk_box_pack_start (GTK_BOX (vbox), top_label, FALSE, FALSE, 0);

	wlanstat_pane = gtk_vpaned_new();
	gtk_box_pack_start (GTK_BOX (vbox), wlanstat_pane, TRUE, TRUE, 0);
	gtk_widget_show(wlanstat_pane);

	/* init a scrolled window for overview */
	scrolled_window = scrolled_window_new (NULL, NULL);
	gtk_paned_pack1(GTK_PANED(wlanstat_pane), scrolled_window, TRUE, TRUE);
	gtk_paned_set_position(GTK_PANED(wlanstat_pane), recent.gui_geometry_wlan_stats_pane);

	hs->table = gtk_clist_new (NUM_COLS);
	gtk_container_add (GTK_CONTAINER (scrolled_window), hs->table);

	gtk_clist_column_titles_show (GTK_CLIST (hs->table));

	gtk_clist_set_compare_func(GTK_CLIST(hs->table), wlan_sort_column);
	gtk_clist_set_sort_column(GTK_CLIST(hs->table), 2);
	gtk_clist_set_sort_type(GTK_CLIST(hs->table), GTK_SORT_ASCENDING);

	/* sort by column feature */
	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_COLS);

	for (i=0; i<NUM_COLS; i++) {
		col_arrows[i].table = gtk_table_new(2, 2, FALSE);
		gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
		column_lb = gtk_label_new(titles[i]);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, 
				 GTK_SHRINK, GTK_SHRINK, 0, 0);
		gtk_widget_show(column_lb);

		col_arrows[i].ascend_pm = xpm_to_widget(clist_ascend_xpm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 
				 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		col_arrows[i].descend_pm = xpm_to_widget(clist_descend_xpm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm, 
				 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
		/* make ssid be the default sort order */
		if (i == 2) {
			gtk_widget_show(col_arrows[i].ascend_pm);
		}
		if (i == 0 || i == 2 || i == 11) {
			gtk_clist_set_column_justification(GTK_CLIST(hs->table), i, GTK_JUSTIFY_LEFT);
		} else {
			gtk_clist_set_column_justification(GTK_CLIST(hs->table), i, GTK_JUSTIFY_RIGHT);
		}
		gtk_clist_set_column_auto_resize(GTK_CLIST(hs->table), i, TRUE);
		gtk_clist_set_column_widget(GTK_CLIST(hs->table), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}

	g_signal_connect(GTK_CLIST(hs->table), "click-column", G_CALLBACK(wlan_click_column_cb), col_arrows);
	g_signal_connect(GTK_CLIST(hs->table), "select-row", G_CALLBACK(wlan_select_cb), hs);
	g_signal_connect(GTK_CLIST(hs->table), "unselect-row", G_CALLBACK(wlan_unselect_cb), hs);

	/* init a scrolled window for details */
	scrolled_window = scrolled_window_new (NULL, NULL);
	gtk_paned_pack2(GTK_PANED(wlanstat_pane), scrolled_window, FALSE, TRUE);

	hs->details = gtk_clist_new (NUM_DETAIL_COLS);
	gtk_container_add (GTK_CONTAINER (scrolled_window), hs->details);

	gtk_clist_column_titles_show (GTK_CLIST (hs->details));

	gtk_clist_set_compare_func(GTK_CLIST(hs->details), wlan_detail_sort_column);
	gtk_clist_set_sort_column(GTK_CLIST(hs->details), 0);
	gtk_clist_set_sort_type(GTK_CLIST(hs->details), GTK_SORT_ASCENDING);

	/* sort by column feature */
	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_DETAIL_COLS);

	for (i=0; i<NUM_DETAIL_COLS; i++) {
		col_arrows[i].table = gtk_table_new(2, 2, FALSE);
		gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
		column_lb = gtk_label_new(detail_titles[i]);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, 
				 GTK_SHRINK, GTK_SHRINK, 0, 0);
		gtk_widget_show(column_lb);

		col_arrows[i].ascend_pm = xpm_to_widget(clist_ascend_xpm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 
				 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		col_arrows[i].descend_pm = xpm_to_widget(clist_descend_xpm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm, 
				 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
		/* make ssid be the default sort order */
		if (i == 0) {
			gtk_widget_show(col_arrows[i].ascend_pm);
		}
		if (i == 0 || i == 9) {
			gtk_clist_set_column_justification(GTK_CLIST(hs->details), i, GTK_JUSTIFY_LEFT);
		} else {
			gtk_clist_set_column_justification(GTK_CLIST(hs->details), i, GTK_JUSTIFY_RIGHT);
		}
		gtk_clist_set_column_auto_resize(GTK_CLIST(hs->details), i, TRUE);
		gtk_clist_set_column_widget(GTK_CLIST(hs->details), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}

	g_signal_connect(GTK_CLIST(hs->details), "click-column", G_CALLBACK(wlan_detail_click_column_cb), col_arrows);

	/* create popup menu for this table */
	wlan_create_popup_menu(hs);
	wlan_details_create_popup_menu(hs);

	error_string=register_tap_listener ("wlan", hs, NULL, wlanstat_reset, 
					    wlanstat_packet, wlanstat_draw);
	if (error_string) {
		simple_dialog (ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free (error_string, TRUE);
		g_free (hs);
		return;
	}

	hbox = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

	resolv_cb = gtk_check_button_new_with_mnemonic("Name resolution");
	gtk_container_add(GTK_CONTAINER(hbox), resolv_cb);
	gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(resolv_cb), TRUE);
	gtk_tooltips_set_tip(tooltips, resolv_cb, "Show results of name resolutions rather than the \"raw\" values. "
			     "Please note: The corresponding name resolution must be enabled.", NULL);

	g_signal_connect(resolv_cb, "toggled", G_CALLBACK(wlan_resolve_toggle_dest), hs);

	existing_cb = gtk_check_button_new_with_mnemonic("Only show existing networks");
	gtk_container_add(GTK_CONTAINER(hbox), existing_cb);
	gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(existing_cb), FALSE);
	gtk_tooltips_set_tip(tooltips, existing_cb, "This option disables probe requests for "
			     "unknown networks.", NULL);
	g_signal_connect(existing_cb, "toggled", G_CALLBACK(wlan_existing_toggle_dest), hs);

	/* Button row. */
	if (topic_available (HELP_STATS_WLAN_TRAFFIC_DIALOG)) {
		bbox = dlg_button_row_new (GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
	} else {
		bbox = dlg_button_row_new (GTK_STOCK_CLOSE, GTK_STOCK_COPY, NULL);
	}

	gtk_box_pack_end (GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button (wlanstat_dlg_w, close_bt, window_cancel_button_cb);

	copy_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
	gtk_tooltips_set_tip(tooltips, copy_bt, 
			     "Copy all statistical values of this page to the clipboard in CSV (Comma Seperated Values) format.", NULL);
	g_signal_connect(copy_bt, "clicked", G_CALLBACK(wlan_copy_as_csv), hs->table);

	if (topic_available (HELP_STATS_WLAN_TRAFFIC_DIALOG)) {
                help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
		g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_WLAN_TRAFFIC_DIALOG);
	}

	g_signal_connect (wlanstat_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect (wlanstat_dlg_w, "destroy", G_CALLBACK(win_destroy_cb), hs);

	gtk_widget_show_all (wlanstat_dlg_w);
	window_present (wlanstat_dlg_w);

	cf_retap_packets (&cfile, FALSE);
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
