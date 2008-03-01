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

#include <epan/packet_info.h>
#include <epan/addr_resolv.h>
#include <epan/tap.h>
#include "../register.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "dlg_utils.h"
#include "../globals.h"
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include "gui_utils.h"
#include <epan/dissectors/packet-ieee80211.h>
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "help_dlg.h"
#include <epan/strutil.h>

#define NUM_COLS 12
static const gchar *titles[] = {"BSSID", "Channel", "SSID", "Beacons", "Data Packets", "Probe Req", "Probe Resp", "Auth", "Deauth", "Other", "Percent", "Protection" };

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;

typedef struct wlan_ep {
	struct wlan_ep* next;
	address bssid;
	struct _wlan_stats stats;
	guint32 type[256];
	guint32 number_of_packets;
} wlan_ep_t;

static GtkWidget  *wlanstat_dlg_w = NULL;

/* used to keep track of the statistics for an entire program interface */
typedef struct _wlan_stat_t {
	GtkWidget  *table;
	guint32    number_of_packets;
	gboolean   resolve_names;
	gboolean   show_only_existing;
	wlan_ep_t* ep_list;
} wlanstat_t;

static void
wlanstat_reset (void *phs)
{
	wlanstat_t* wlan_stat = (wlanstat_t *)phs;
	wlan_ep_t* list = (wlan_ep_t*)wlan_stat->ep_list;
	wlan_ep_t* tmp = NULL;

	if (wlanstat_dlg_w != NULL) {
		char title[256];
		g_snprintf (title, 255, "Wireshark: WLAN Traffic Statistics: %s", 
			    cf_get_display_name(&cfile));
		gtk_window_set_title(GTK_WINDOW(wlanstat_dlg_w), title);
	}

	/* remove all entries from the clist */
	gtk_clist_clear (GTK_CLIST(wlan_stat->table));

	if (!list)
		return;

	while (list) {
		tmp = list;
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
	g_strlcpy (ep->stats.ssid, si->stats.ssid, MAX_SSID_LEN);
	g_strlcpy (ep->stats.protection, si->stats.protection, MAX_PROTECT_LEN);
	memset(&ep->type, 0, sizeof (int) * 256);
	ep->number_of_packets = 0;
	ep->next = NULL;

	return ep;
}

static int
wlanstat_packet (void *phs, packet_info *pinfo, epan_dissect_t *edt _U_, const void *phi)
{

	wlanstat_t *hs = (wlanstat_t *)phs;
	wlan_ep_t *tmp = NULL, *te = NULL;
	struct _wlan_hdr *si = (struct _wlan_hdr *) phi;

	if (!hs)
		return (0);

	if (si->type == 0x04 && si->stats.ssid[0] == 0) {
	  /* Probe request without SSID */
	  return 0;
	}

	hs->number_of_packets++;
	if (!hs->ep_list) {
		hs->ep_list = alloc_wlan_ep (si, pinfo);
		te = hs->ep_list;
	} else {
		for (tmp = hs->ep_list; tmp; tmp = tmp->next) {
			if (((si->type == 0x04) &&
			     (strcmp (tmp->stats.ssid, si->stats.ssid) == 0)) ||
			    ((si->type != 0x04) && 
			     (!CMP_ADDRESS (&tmp->bssid, &si->bssid)))) {
				te = tmp;
				break;
			}
		}

		if (te && si->type != 0x04 && te->type[0x04] == 0 && te->stats.ssid[0] != 0) {
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
				if (te->stats.ssid[0] &&
				    (strcmp (te->stats.ssid, tmp->stats.ssid) == 0) &&
				    (strcmp (get_addr_name(&tmp->bssid), "Broadcast") == 0)) {
					/* 
					 * Found a matching entry. Merge with the previous
					 * found entry and remove from list. 
					 */
					te->type[0x04] += tmp->type[0x04];
					te->number_of_packets += tmp->number_of_packets;
					if (prev) {
						prev->next = tmp->next;
					} else {
						hs->ep_list = tmp->next;
					}
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
	if (te->stats.ssid[0] == 0 && si->stats.ssid[0] != 0) {
		g_strlcpy (te->stats.ssid, si->stats.ssid, MAX_SSID_LEN);
	}
	if (te->stats.protection[0] == 0 && si->stats.protection[0] != 0) {
		g_strlcpy (te->stats.protection, si->stats.protection, MAX_PROTECT_LEN);
	}
	te->type[si->type]++;
	te->number_of_packets++;

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
	gtk_clist_thaw(clist);

	gtk_clist_sort(clist);
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

static void
wlanstat_draw(void *phs)
{
	wlanstat_t *hs = (wlanstat_t *)phs;
	wlan_ep_t* list = hs->ep_list, *tmp = 0;
	guint32 data = 0, other = 0;
	char *str[NUM_COLS];
	float f;
	int i=0;

	for (i = 0; i < NUM_COLS; i++) {
		str[i] = g_malloc (sizeof(char[256]));
	}

	/* clear list before printing */
	gtk_clist_clear (GTK_CLIST(hs->table));
	gtk_clist_freeze(GTK_CLIST(hs->table));

	for(tmp = list; tmp; tmp=tmp->next) {
		if (hs->show_only_existing && strcmp (get_addr_name(&tmp->bssid), "Broadcast") == 0) {
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
		g_snprintf (str[2],  sizeof(char[256]),"%s", tmp->stats.ssid);
		g_snprintf (str[3],  sizeof(char[256]),"%u", tmp->type[0x08]);
		g_snprintf (str[4],  sizeof(char[256]),"%u", data);
		g_snprintf (str[5],  sizeof(char[256]),"%u", tmp->type[0x04]);
		g_snprintf (str[6],  sizeof(char[256]),"%u", tmp->type[0x05]);
		g_snprintf (str[7],  sizeof(char[256]),"%u", tmp->type[0x0B]);
		g_snprintf (str[8],  sizeof(char[256]),"%u", tmp->type[0x0C]);
		g_snprintf (str[9],  sizeof(char[256]),"%u", other);
		g_snprintf (str[10], sizeof(char[256]),"%.2f%%", f);
		g_snprintf (str[11], sizeof(char[256]),"%s", tmp->stats.protection);
		gtk_clist_append (GTK_CLIST(hs->table), str);
	}

	gtk_clist_thaw(GTK_CLIST(hs->table));
	gtk_clist_sort(GTK_CLIST(hs->table));
	gtk_widget_show (GTK_WIDGET(hs->table));
}

static void
wlan_resolve_toggle_dest(GtkWidget *widget, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;

	hs->resolve_names = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

	wlanstat_draw(hs);
}

static void
wlan_existing_toggle_dest(GtkWidget *widget, gpointer data)
{
	wlanstat_t *hs = (wlanstat_t *)data;

	hs->show_only_existing = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

	wlanstat_draw(hs);
}

#if (GTK_MAJOR_VERSION >= 2)
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
#endif

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
#if GTK_MAJOR_VERSION >= 2
	GtkWidget *copy_bt;
#endif
	column_arrows *col_arrows;
	GtkWidget *column_lb;
	char title[256];
	int i;

	hs=g_malloc (sizeof(wlanstat_t));
	hs->ep_list = NULL;
	hs->number_of_packets = 0;
	hs->resolve_names = TRUE;
	hs->show_only_existing = FALSE;

	g_snprintf (title, 255, "Wireshark: WLAN Traffic Statistics: %s", 
		    cf_get_display_name(&cfile));
	wlanstat_dlg_w = window_new (GTK_WINDOW_TOPLEVEL, title);
	gtk_window_set_default_size (GTK_WINDOW(wlanstat_dlg_w), 750, 400);

	vbox=gtk_vbox_new (FALSE, 3);
	gtk_container_add(GTK_CONTAINER(wlanstat_dlg_w), vbox);
	gtk_container_set_border_width (GTK_CONTAINER(vbox), 12);

	top_label = gtk_label_new ("WLAN Traffic Statistics");
	gtk_box_pack_start (GTK_BOX (vbox), top_label, FALSE, FALSE, 0);

	/* init a scrolled window*/
	scrolled_window = scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (vbox), scrolled_window, TRUE, TRUE, 0);

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

	SIGNAL_CONNECT(GTK_CLIST(hs->table), "click-column", wlan_click_column_cb, col_arrows);

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

	resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Name resolution", NULL);
	gtk_container_add(GTK_CONTAINER(hbox), resolv_cb);
	gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(resolv_cb), TRUE);
	gtk_tooltips_set_tip(tooltips, resolv_cb, "Show results of name resolutions rather than the \"raw\" values. "
			     "Please note: The corresponding name resolution must be enabled.", NULL);

	SIGNAL_CONNECT(resolv_cb, "toggled", wlan_resolve_toggle_dest, hs);

	existing_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Only show existing networks", NULL);
	gtk_container_add(GTK_CONTAINER(hbox), existing_cb);
	gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(existing_cb), FALSE);
	gtk_tooltips_set_tip(tooltips, existing_cb, "This option disables probe requests for "
			     "unknown networks.", NULL);
	SIGNAL_CONNECT(existing_cb, "toggled", wlan_existing_toggle_dest, hs);

	/* Button row. */
#if GTK_MAJOR_VERSION >= 2
	if (topic_available (HELP_STATS_WLAN_TRAFFIC_DIALOG)) {
		bbox = dlg_button_row_new (GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
	} else {
		bbox = dlg_button_row_new (GTK_STOCK_CLOSE, GTK_STOCK_COPY, NULL);
	}
#else
	if (topic_available (HELP_STATS_WLAN_TRAFFIC_DIALOG)) {
		bbox = dlg_button_row_new (GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
	} else {
		bbox = dlg_button_row_new (GTK_STOCK_CLOSE, NULL);
	}
#endif

	gtk_box_pack_end (GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = OBJECT_GET_DATA (bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button (wlanstat_dlg_w, close_bt, window_cancel_button_cb);

#if (GTK_MAJOR_VERSION >= 2)
	copy_bt = OBJECT_GET_DATA (bbox, GTK_STOCK_COPY);
	gtk_tooltips_set_tip(tooltips, copy_bt, 
			     "Copy all statistical values of this page to the clipboard in CSV (Comma Seperated Values) format.", NULL);
	SIGNAL_CONNECT(copy_bt, "clicked", wlan_copy_as_csv, hs->table);
#endif                 

	if (topic_available (HELP_STATS_WLAN_TRAFFIC_DIALOG)) {
		help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
		SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_STATS_WLAN_TRAFFIC_DIALOG);
	}

	SIGNAL_CONNECT (wlanstat_dlg_w, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT (wlanstat_dlg_w, "destroy", win_destroy_cb, hs);

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
	register_stat_menu_item ("WLAN Traffic...", REGISTER_STAT_GROUP_NONE, 
				 wlanstat_launch, NULL, NULL, NULL);
}
