/* mem leak   should free the column_arrows when the table is destroyed */

/* conversations_table.c
 * conversations_table   2003 Ronnie Sahlberg
 * Helper routines common to all endpoint conversations tap.
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

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/to_str.h>
#include <epan/address.h>
#include <epan/addr_resolv.h>
#include <epan/tap.h>
#include <epan/nstime.h>

#include "../simple_dialog.h"
#include "../globals.h"
#include "../color.h"

#include "gtk/sat.h"
#include "gtk/conversations_table.h"
#include "gtk/filter_utils.h"
#include "gtk/gtkglobals.h"
#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/help_dlg.h"
#include "gtk/main.h"

#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"


#define NUM_COLS 14
#define COL_STR_LEN 16
#define CONV_PTR_KEY "conversations-pointer"
#define NB_PAGES_KEY "notebook-pages"
#define NO_BPS_STR "N/A"

#define CMP_NUM(n1, n2)	\
	if ((n1) > (n2))	\
		return 1;	\
	else if ((n1) < (n2))	\
		return -1;	\
	else			\
		return 0;

/* convert a port number into a string */
static char *
ct_port_to_str(int port_type, guint32 port)
{
	static int i=0;
	static gchar *strp, str[4][12];

	i++;
	if(i>=4){
		i=0;
	}
	strp=str[i];

	switch(port_type){
	case PT_TCP:
        case PT_UDP:
        case PT_SCTP:
        case PT_NCP:
		g_snprintf(strp, 11, "%d", port);
		return strp;
	}
	return NULL;
}


#define FN_SRC_ADDRESS		0
#define FN_DST_ADDRESS		1
#define FN_ANY_ADDRESS		2
#define FN_SRC_PORT		3
#define FN_DST_PORT		4
#define FN_ANY_PORT		5
/* given an address (to distinguis between ipv4 and ipv6 for tcp/udp
   a port_type and a name_type (FN_...)
   return a string for the filter name

   some addresses, like AT_ETHER may actually be any of multiple types
   of protocols,   either ethernet, tokenring, fddi, wlan etc so we must be
   more specific there  thats why we need specific_addr_type
*/
static const char *
ct_get_filter_name(address *addr, int specific_addr_type, int port_type, int name_type)
{
	switch(name_type){
	case FN_SRC_ADDRESS:
		switch(addr->type){
		case AT_ETHER:
			switch(specific_addr_type){
			case SAT_ETHER:
				return "eth.src";
			case SAT_WLAN:
				return "wlan.sa";
			case SAT_FDDI:
				return "fddi.src";
			case SAT_TOKENRING:
				return "tr.src";
                        default:
                                break;
			}
                        break;
		case AT_IPv4:
			return "ip.src";
		case AT_IPv6:
			return "ipv6.src";
		case AT_IPX:
			return "ipx.src";
		case AT_FC:
			return "fc.s_id";
		case AT_URI:
			switch(specific_addr_type){
			case SAT_JXTA:
				return "jxta.message.src";
                        default:
                                break;
			}
                        break;
		case AT_USB:
			return "usb.sa";
		default:
			break;
		}
                break;
	case FN_DST_ADDRESS:
		switch(addr->type){
		case AT_ETHER:
			switch(specific_addr_type){
			case SAT_ETHER:
				return "eth.dst";
			case SAT_WLAN:
				return "wlan.da";
			case SAT_FDDI:
				return "fddi.dst";
			case SAT_TOKENRING:
				return "tr.dst";
                        default:
                                break;
			}
                        break;
		case AT_IPv4:
			return "ip.dst";
		case AT_IPv6:
			return "ipv6.dst";
		case AT_IPX:
			return "ipx.dst";
		case AT_FC:
			return "fc.d_id";
		case AT_URI:
			switch(specific_addr_type){
			case SAT_JXTA:
				return "jxta.message.dst";
                        default:
                                break;
			}
                        break;
		case AT_USB:
			return "usb.da";
		default:
			break;
		}
                break;
	case FN_ANY_ADDRESS:
		switch(addr->type){
		case AT_ETHER:
			switch(specific_addr_type){
			case SAT_ETHER:
				return "eth.addr";
			case SAT_WLAN:
				return "wlan.addr";
			case SAT_FDDI:
				return "fddi.addr";
			case SAT_TOKENRING:
				return "tr.addr";
                        default:
                            break;
			}
                        break;
		case AT_IPv4:
			return "ip.addr";
		case AT_IPv6:
			return "ipv6.addr";
		case AT_IPX:
			return "ipx.addr";
		case AT_FC:
			return "fc.id";
		case AT_URI:
			switch(specific_addr_type){
			case SAT_JXTA:
				return "jxta.message.address";
                        default:
                                break;
			}
                        break;
		case AT_USB:
			return "usb.addr";
		default:
			break;
		}
                break;
	case FN_SRC_PORT:
		switch(port_type){
		case PT_TCP:
			return "tcp.srcport";
		case PT_UDP:
			return "udp.srcport";
		case PT_SCTP:
			return "sctp.srcport";
		case PT_NCP:
			return "ncp.connection";
		default:
			break;
		}
		break;
	case FN_DST_PORT:
		switch(port_type){
		case PT_TCP:
			return "tcp.dstport";
		case PT_UDP:
			return "udp.dstport";
		case PT_SCTP:
			return "sctp.dstport";
		case PT_NCP:
			return "ncp.connection";
		default:
			break;
		}
		break;
	case FN_ANY_PORT:
		switch(port_type){
		case PT_TCP:
			return "tcp.port";
		case PT_UDP:
			return "udp.port";
		case PT_SCTP:
			return "sctp.port";
		case PT_NCP:
			return "ncp.connection";
		default:
			break;
		}
		break;
	}

	g_assert_not_reached();
	return NULL;
}


typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;



static void
reset_ct_table_data(conversations_table *ct)
{
    guint32 i;
    char title[256];
    GString *error_string;
    const char *filter;

    if (ct->use_dfilter) {
        filter = gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
    } else {
        filter = ct->filter;
    }

    error_string = set_tap_dfilter (ct, filter);
    if (error_string) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
        g_string_free(error_string, TRUE);
        return;
    }

    /* Allow clist to update */
    gtk_clist_thaw(ct->table);

    if(ct->page_lb) {
        g_snprintf(title, 255, "Conversations: %s", cf_get_display_name(&cfile));
        gtk_window_set_title(GTK_WINDOW(ct->win), title);
        g_snprintf(title, 255, "%s", ct->name);
        gtk_label_set_text(GTK_LABEL(ct->page_lb), title);
        gtk_widget_set_sensitive(ct->page_lb, FALSE);

        if (ct->use_dfilter) {
            if (filter && strlen(filter)) {
                g_snprintf(title, 255, "%s Conversations - Filter: %s", ct->name, filter);
            } else {
                g_snprintf(title, 255, "%s Conversations - No Filter", ct->name);
            }
        } else {
            g_snprintf(title, 255, "%s Conversations", ct->name);
        }
        gtk_label_set_text(GTK_LABEL(ct->name_lb), title);
    } else {
        g_snprintf(title, 255, "%s Conversations: %s", ct->name, cf_get_display_name(&cfile));
        gtk_window_set_title(GTK_WINDOW(ct->win), title);
    }

    /* remove all entries from the clist */
    gtk_clist_clear(ct->table);

    /* delete all conversations */
    for(i=0;i<ct->num_conversations;i++){
        g_free((gpointer)ct->conversations[i].src_address.data);
        g_free((gpointer)ct->conversations[i].dst_address.data);
    }
    g_free(ct->conversations);
    ct->conversations=NULL;
    ct->num_conversations=0;
}

static void
reset_ct_table_data_cb(void *arg)
{
    reset_ct_table_data(arg);
}

static void
ct_win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	conversations_table *conversations=(conversations_table *)data;

	protect_thread_critical_region();
	remove_tap_listener(conversations);
	unprotect_thread_critical_region();

	reset_ct_table_data(conversations);
	g_free(conversations);
}



static gint
ct_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	guint32 idx1, idx2;
	conversations_table *ct = g_object_get_data(G_OBJECT(clist), CONV_PTR_KEY);
	conv_t *conv1 = NULL;
	conv_t *conv2 = NULL;
        double duration1, duration2;

	const GtkCListRow *row1 = ptr1;
	const GtkCListRow *row2 = ptr2;

	idx1 = GPOINTER_TO_INT(row1->data);
	idx2 = GPOINTER_TO_INT(row2->data);

	if (!ct || idx1 >= ct->num_conversations || idx2 >= ct->num_conversations)
		return 0;

	conv1 = &ct->conversations[idx1];
	conv2 = &ct->conversations[idx2];

        duration1 = nstime_to_sec(&conv1->stop_time) - nstime_to_sec(&conv1->start_time);
        duration2 = nstime_to_sec(&conv2->stop_time) - nstime_to_sec(&conv2->start_time);

	switch(clist->sort_column){
	case 0: /* Source address */
		return(CMP_ADDRESS(&conv1->src_address, &conv2->src_address));
	case 2: /* Destination address */
		return(CMP_ADDRESS(&conv1->dst_address, &conv2->dst_address));
	case 1: /* Source port */
		CMP_NUM(conv1->src_port, conv2->src_port);
	case 3: /* Destination port */
		CMP_NUM(conv1->dst_port, conv2->dst_port);
	case 4: /* Packets */
		CMP_NUM(conv1->tx_frames+conv1->rx_frames,
			conv2->tx_frames+conv2->rx_frames);
        case 5: /* Bytes */
		CMP_NUM(conv1->tx_bytes+conv1->rx_bytes,
			conv2->tx_bytes+conv2->rx_bytes);
        case 6: /* Packets A->B */
		CMP_NUM(conv1->tx_frames, conv2->tx_frames);
        case 7: /* Bytes A->B */
		CMP_NUM(conv1->tx_bytes, conv2->tx_bytes);
        case 8: /* Packets A<-B */
		CMP_NUM(conv1->rx_frames, conv2->rx_frames);
        case 9: /* Bytes A<-B */
		CMP_NUM(conv1->rx_bytes, conv2->rx_bytes);
        case 10: /* Start time */
		return nstime_cmp(&conv1->start_time, &conv2->start_time);
        case 11: /* Duration */
		CMP_NUM(duration1, duration2);
        case 12: /* bps A->B */
            if (duration1 > 0 && conv1->tx_frames > 1 && duration2 > 0 && conv2->tx_frames > 1) {
                CMP_NUM((gint64) conv1->tx_bytes / duration1, (gint64) conv2->tx_bytes / duration2);
            } else {
                CMP_NUM(conv1->tx_bytes, conv2->tx_bytes);
            }
        case 13: /* bps A<-B */
            if (duration1 > 0 && conv1->rx_frames > 1 && duration2 > 0 && conv2->rx_frames > 1) {
                CMP_NUM((gint64) conv1->rx_bytes / duration1, (gint64) conv2->rx_bytes / duration2);
            } else {
                CMP_NUM(conv1->rx_bytes, conv2->rx_bytes);
            }
	default:
		g_assert_not_reached();
	}

	return 0;
}


static void
ct_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
	column_arrows *col_arrows = (column_arrows *) data;
	int i;

	for (i = 0; i < NUM_COLS; i++) {
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

	/* Allow update of clist */
	gtk_clist_thaw(clist);
	gtk_clist_freeze(clist);

}


/* Filter direction */
#define DIR_A_TO_FROM_B		0
#define DIR_A_TO_B		1
#define DIR_A_FROM_B		2
#define DIR_A_TO_FROM_ANY	3
#define DIR_A_TO_ANY		4
#define DIR_A_FROM_ANY		5
#define DIR_ANY_TO_FROM_B	6
#define DIR_ANY_FROM_B		7
#define DIR_ANY_TO_B		8

static void
ct_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
	int direction;
	int selection;
	conversations_table *ct = (conversations_table *)callback_data;
	char *str = NULL;
	char *sport, *dport;

	direction=FILTER_EXTRA(callback_action);

	selection=GPOINTER_TO_INT(g_list_nth_data(GTK_CLIST(ct->table)->selection, 0));
	if(selection>=(int)ct->num_conversations){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No conversation selected");
		return;
	}
	/* translate it back from row index to index in enndpoint array */
	selection=GPOINTER_TO_INT(gtk_clist_get_row_data(ct->table, selection));

	sport=ct_port_to_str(ct->conversations[selection].port_type, ct->conversations[selection].src_port);
	dport=ct_port_to_str(ct->conversations[selection].port_type, ct->conversations[selection].dst_port);

	switch(direction){
	case DIR_A_TO_FROM_B:
		/* A <-> B */
		str = g_strdup_printf("%s==%s%s%s%s%s && %s==%s%s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_ADDRESS),
			address_to_str(&ct->conversations[selection].src_address),
			sport?" && ":"",
			sport?ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_PORT):"",
			sport?"==":"",
			sport?sport:"",
			ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_ADDRESS),
			address_to_str(&ct->conversations[selection].dst_address),
			dport?" && ":"",
			dport?ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_PORT):"",
			dport?"==":"",
			dport?dport:""
		);
		break;
	case DIR_A_TO_B:
		/* A --> B */
		str = g_strdup_printf("%s==%s%s%s%s%s && %s==%s%s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_ADDRESS),
			address_to_str(&ct->conversations[selection].src_address),
			sport?" && ":"",
			sport?ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_PORT):"",
			sport?"==":"",
			sport?sport:"",
			ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_ADDRESS),
			address_to_str(&ct->conversations[selection].dst_address),
			dport?" && ":"",
			dport?ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_PORT):"",
			dport?"==":"",
			dport?dport:""
		);
		break;
	case DIR_A_FROM_B:
		/* A <-- B */
		str = g_strdup_printf("%s==%s%s%s%s%s && %s==%s%s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_ADDRESS),
			address_to_str(&ct->conversations[selection].src_address),
			sport?" && ":"",
			sport?ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_PORT):"",
			sport?"==":"",
			sport?sport:"",
			ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_ADDRESS),
			address_to_str(&ct->conversations[selection].dst_address),
			dport?" && ":"",
			dport?ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_PORT):"",
			dport?"==":"",
			dport?dport:""
		);
		break;
	case DIR_A_TO_FROM_ANY:
		/* A <-> ANY */
		str = g_strdup_printf("%s==%s%s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_ADDRESS),
			address_to_str(&ct->conversations[selection].src_address),
			sport?" && ":"",
			sport?ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_PORT):"",
			sport?"==":"",
			sport?sport:""
		);
		break;
	case DIR_A_TO_ANY:
		/* A --> ANY */
		str = g_strdup_printf("%s==%s%s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_ADDRESS),
			address_to_str(&ct->conversations[selection].src_address),
			sport?" && ":"",
			sport?ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_PORT):"",
			sport?"==":"",
			sport?sport:""
		);
		break;
	case DIR_A_FROM_ANY:
		/* A <-- ANY */
		str = g_strdup_printf("%s==%s%s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_ADDRESS),
			address_to_str(&ct->conversations[selection].src_address),
			sport?" && ":"",
			sport?ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_PORT):"",
			sport?"==":"",
			sport?sport:""
		);
		break;
	case DIR_ANY_TO_FROM_B:
		/* ANY <-> B */
		str = g_strdup_printf("%s==%s%s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_ADDRESS),
			address_to_str(&ct->conversations[selection].dst_address),
			dport?" && ":"",
			dport?ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_PORT):"",
			dport?"==":"",
			dport?dport:""
		);
		break;
	case DIR_ANY_FROM_B:
		/* ANY <-- B */
		str = g_strdup_printf("%s==%s%s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_ADDRESS),
			address_to_str(&ct->conversations[selection].dst_address),
			dport?" && ":"",
			dport?ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_PORT):"",
			dport?"==":"",
			dport?dport:""
		);
		break;
	case DIR_ANY_TO_B:
		/* ANY --> B */
		str = g_strdup_printf("%s==%s%s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_ADDRESS),
			address_to_str(&ct->conversations[selection].dst_address),
			dport?" && ":"",
			dport?ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_PORT):"",
			dport?"==":"",
			dport?dport:""
		);
		break;
    default:
		g_assert_not_reached();
	}

        apply_selected_filter (callback_action, str);

        g_free (str);
}

static gint
ct_show_popup_menu_cb(void *widg _U_, GdkEvent *event, conversations_table *ct)
{
    GdkEventButton *bevent = (GdkEventButton *)event;
    gint row;
    gint column;


    /* To quote the "Gdk Event Structures" doc:
     * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
    if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
        /* if this is a right click on one of our columns, select it and popup the context menu */
        if(gtk_clist_get_selection_info(ct->table,
                                          (gint) (((GdkEventButton *)event)->x),
                                          (gint) (((GdkEventButton *)event)->y),
                                             &row, &column)) {
            gtk_clist_unselect_all(ct->table);
            gtk_clist_select_row(ct->table, row, -1);

            gtk_menu_popup(GTK_MENU(ct->menu), NULL, NULL, NULL, NULL,
                bevent->button, bevent->time);
        }
    }

    return FALSE;
}

static GtkItemFactoryEntry ct_list_menu_items[] =
{
	/* Match */
	{"/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Apply as Filter/Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Apply as Filter/Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Apply as Filter/Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Apply as Filter/Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	{"/Apply as Filter/Not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Not Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/Not Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Apply as Filter/Not Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Apply as Filter/Not Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/Not Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Apply as Filter/Not Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/Not Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/Not Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Apply as Filter/Not Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, DIR_ANY_TO_B), NULL, NULL,},


	{"/Apply as Filter/... and Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/... and Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... and Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Apply as Filter/... and Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... and Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/... and Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Apply as Filter/... and Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/... and Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... and Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... and Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	{"/Apply as Filter/... or Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/... or Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... or Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Apply as Filter/... or Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... or Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/... or Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Apply as Filter/... or Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/... or Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... or Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... or Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	{"/Apply as Filter/... and not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/... and not Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... and not Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	{"/Apply as Filter/... or not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/... or not Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Apply as Filter/... or not Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	/* Prepare */
	{"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Prepare a Filter/Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Prepare a Filter/Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	{"/Prepare a Filter/Not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Not Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/Not Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	{"/Prepare a Filter/... and Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/... and Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... and Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	{"/Prepare a Filter/... or Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/... or Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... or Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	{"/Prepare a Filter/... and not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/... and not Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	{"/Prepare a Filter/... or not Selected", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/... or not Selected/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	/* Find Packet */
	{"/Find Packet", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Packet/Find Packet", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Packet/Find Packet/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Packet/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Find Packet/Find Packet/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Packet/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Find Packet/Find Packet/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Find Packet/Find Packet/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Find Packet/Find Packet/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Packet/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Packet/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, DIR_ANY_TO_B), NULL, NULL,},
	/* Find Next */
	{"/Find Packet/Find Next", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Packet/Find Next/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Next/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Find Packet/Find Next/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Next/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Find Packet/Find Next/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Find Packet/Find Next/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Find Packet/Find Next/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Next/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Next/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, DIR_ANY_TO_B), NULL, NULL,},
	/* Find Previous */
	{"/Find Packet/Find Previous", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Packet/Find Previous/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Previous/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Find Packet/Find Previous/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Previous/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Find Packet/Find Previous/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Find Packet/Find Previous/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Find Packet/Find Previous/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Previous/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Find Packet/Find Previous/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, DIR_ANY_TO_B), NULL, NULL,},

	/* Colorize Conversation */
	{"/Colorize Conversation", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Colorize Conversation/A <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, DIR_A_TO_FROM_B), NULL, NULL,},
	{"/Colorize Conversation/A --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, DIR_A_TO_B), NULL, NULL,},
	{"/Colorize Conversation/A <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, DIR_A_FROM_B), NULL, NULL,},
	{"/Colorize Conversation/A <-> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, DIR_A_TO_FROM_ANY), NULL, NULL,},
	{"/Colorize Conversation/A --> ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, DIR_A_TO_ANY), NULL, NULL,},
	{"/Colorize Conversation/A <-- ANY", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, DIR_A_FROM_ANY), NULL, NULL,},
	{"/Colorize Conversation/ANY <-> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, DIR_ANY_TO_FROM_B), NULL, NULL,},
	{"/Colorize Conversation/ANY <-- B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, DIR_ANY_FROM_B), NULL, NULL,},
	{"/Colorize Conversation/ANY --> B", NULL,
		GTK_MENU_FUNC(ct_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, DIR_ANY_TO_B), NULL, NULL,}
};

static void
ct_create_popup_menu(conversations_table *ct)
{
	GtkItemFactory *item_factory;

	item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

	gtk_item_factory_create_items_ac(item_factory, sizeof(ct_list_menu_items)/sizeof(ct_list_menu_items[0]), ct_list_menu_items, ct, 2);

	ct->menu = gtk_item_factory_get_widget(item_factory, "<main>");
	g_signal_connect(ct->table, "button_press_event", G_CALLBACK(ct_show_popup_menu_cb), ct);
}

/* Draw/refresh the address fields of a single entry at the specified index */
static void
draw_ct_table_address(conversations_table *ct, int conversation_idx)
{
    const char *entry;
    char *port;
    guint32 pt;
    int rownum;

    rownum=gtk_clist_find_row_from_data(ct->table, (gpointer)(long)conversation_idx);

    if(!ct->resolve_names)
        entry=address_to_str(&ct->conversations[conversation_idx].src_address);
    else {
        entry=get_addr_name(&ct->conversations[conversation_idx].src_address);
    }
    gtk_clist_set_text(ct->table, rownum, 0, entry);

    pt = ct->conversations[conversation_idx].port_type;
    if(!ct->resolve_names) pt = PT_NONE;
    switch(pt) {
    case(PT_TCP):
        entry=get_tcp_port(ct->conversations[conversation_idx].src_port);
        break;
    case(PT_UDP):
        entry=get_udp_port(ct->conversations[conversation_idx].src_port);
        break;
    case(PT_SCTP):
        entry=get_sctp_port(ct->conversations[conversation_idx].src_port);
        break;
    default:
        port=ct_port_to_str(ct->conversations[conversation_idx].port_type, ct->conversations[conversation_idx].src_port);
        entry=port?port:"";
    }
    gtk_clist_set_text(ct->table, rownum, 1, entry);

    if(!ct->resolve_names)
        entry=address_to_str(&ct->conversations[conversation_idx].dst_address);
    else {
        entry=get_addr_name(&ct->conversations[conversation_idx].dst_address);
    }
    gtk_clist_set_text(ct->table, rownum, 2, entry);

    switch(pt) {
    case(PT_TCP):
        entry=get_tcp_port(ct->conversations[conversation_idx].dst_port);
        break;
    case(PT_UDP):
        entry=get_udp_port(ct->conversations[conversation_idx].dst_port);
        break;
    case(PT_SCTP):
        entry=get_sctp_port(ct->conversations[conversation_idx].dst_port);
        break;
    default:
        port=ct_port_to_str(ct->conversations[conversation_idx].port_type, ct->conversations[conversation_idx].dst_port);
        entry=port?port:"";
    }
    gtk_clist_set_text(ct->table, rownum, 3, entry);
}

/* Refresh the address fields of all entries in the list */
static void
draw_ct_table_addresses(conversations_table *ct)
{
    guint32 i;

    for(i=0;i<ct->num_conversations;i++){
        draw_ct_table_address(ct, i);
    }
}


static void
draw_ct_table_data(conversations_table *ct)
{
    guint32 i;
    int j;
    char title[256];
    double duration_s;

    if (ct->page_lb) {
        if(ct->num_conversations) {
            g_snprintf(title, 255, "%s: %u", ct->name, ct->num_conversations);
        } else {
            g_snprintf(title, 255, "%s", ct->name);
        }
        gtk_label_set_text(GTK_LABEL(ct->page_lb), title);
        gtk_widget_set_sensitive(ct->page_lb, ct->num_conversations);
    } else {
        if(ct->num_conversations) {
            g_snprintf(title, 255, "%s Conversations: %u", ct->name, ct->num_conversations);
        } else {
            g_snprintf(title, 255, "%s Conversations", ct->name);
        }
        gtk_label_set_text(GTK_LABEL(ct->name_lb), title);
    }

    for(i=0;i<ct->num_conversations;i++){
        char str[COL_STR_LEN];

        j=gtk_clist_find_row_from_data(ct->table, (gpointer)(unsigned long)i);

        g_snprintf(str, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", ct->conversations[i].tx_frames+ct->conversations[i].rx_frames);
        gtk_clist_set_text(ct->table, j, 4, str);
        g_snprintf(str, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", ct->conversations[i].tx_bytes+ct->conversations[i].rx_bytes);
        gtk_clist_set_text(ct->table, j, 5, str);


        g_snprintf(str, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", ct->conversations[i].tx_frames);
        gtk_clist_set_text(ct->table, j, 6, str);
        g_snprintf(str, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", ct->conversations[i].tx_bytes);
        gtk_clist_set_text(ct->table, j, 7, str);


        g_snprintf(str, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", ct->conversations[i].rx_frames);
        gtk_clist_set_text(ct->table, j, 8, str);
        g_snprintf(str, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", ct->conversations[i].rx_bytes);
        gtk_clist_set_text(ct->table, j, 9, str);

        duration_s = nstime_to_sec(&ct->conversations[i].stop_time) - nstime_to_sec(&ct->conversations[i].start_time);
        g_snprintf(str, COL_STR_LEN, "%s", rel_time_to_secs_str(&ct->conversations[i].start_time));
        gtk_clist_set_text(ct->table, j, 10, str);
        g_snprintf(str, COL_STR_LEN, "%.4f", duration_s);
        gtk_clist_set_text(ct->table, j, 11, str);
        if (duration_s > 0 && ct->conversations[i].tx_frames > 1) {
            /* XXX - The gint64 casts below are needed for MSVC++ 6.0 */
            g_snprintf(str, COL_STR_LEN, "%.2f", (gint64) ct->conversations[i].tx_bytes * 8 / duration_s);
            gtk_clist_set_text(ct->table, j, 12, str);
        } else {
            gtk_clist_set_text(ct->table, j, 12, NO_BPS_STR);
        }
        if (duration_s > 0 && ct->conversations[i].rx_frames > 1) {
            /* XXX - The gint64 casts below are needed for MSVC++ 6.0 */
            g_snprintf(str, COL_STR_LEN, "%.2f", (gint64) ct->conversations[i].rx_bytes * 8 / duration_s);
            gtk_clist_set_text(ct->table, j, 13, str);
        } else {
            gtk_clist_set_text(ct->table, j, 13, NO_BPS_STR);
        }
    }

    draw_ct_table_addresses(ct);

    gtk_clist_sort(ct->table);

    /* Allow table to redraw */
    gtk_clist_thaw(ct->table);
    gtk_clist_freeze(ct->table);
}

static void
draw_ct_table_data_cb(void *arg)
{
    draw_ct_table_data(arg);
}

static void
copy_as_csv_cb(GtkWindow *copy_bt, gpointer data _U_)
{
   guint32         i,j;
   gchar           *table_entry;
   GtkClipboard    *cb;
   GString         *CSV_str = g_string_new("");

   conversations_table *talkers=g_object_get_data(G_OBJECT(copy_bt), CONV_PTR_KEY);
   if (!talkers)
     return;

   /* Add the column headers to the CSV data */
   for(i=0;i<talkers->num_columns;i++){                  /* all columns         */
    if((i==1 || i==3) && !talkers->has_ports) continue;  /* Don't add the port column if it's empty */
     g_string_append(CSV_str,talkers->default_titles[i]);/* add the column heading to the CSV string */
    if(i!=talkers->num_columns-1)
     g_string_append(CSV_str,",");
   }
   g_string_append(CSV_str,"\n");                        /* new row */

   /* Add the column values to the CSV data */
   for(i=0;i<talkers->num_conversations;i++){            /* all rows            */
    for(j=0;j<talkers->num_columns;j++){                 /* all columns         */
     if((j==1 || j==3) && !talkers->has_ports) continue; /* Don't add the port column if it's empty */
     gtk_clist_get_text(talkers->table,i,j,&table_entry);/* copy table item into string */
     g_string_append(CSV_str,table_entry);               /* add the table entry to the CSV string */
    if(j!=talkers->num_columns-1)
     g_string_append(CSV_str,",");
    }
    g_string_append(CSV_str,"\n");                       /* new row */
   }

   /* Now that we have the CSV data, copy it into the default clipboard */
   cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);      /* Get the default clipboard */
   gtk_clipboard_set_text(cb, CSV_str->str, -1);         /* Copy the CSV data into the clipboard */
   g_string_free(CSV_str, TRUE);                         /* Free the memory */
}


static gboolean
init_ct_table_page(conversations_table *conversations, GtkWidget *vbox, gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    int i;
    column_arrows *col_arrows;
    GtkStyle *win_style;
    GtkWidget *column_lb;
    GString *error_string;
    char title[256];

    conversations->page_lb=NULL;
    conversations->resolve_names=TRUE;
    conversations->has_ports=!hide_ports;
    conversations->num_columns=NUM_COLS;
    conversations->default_titles[0]="Address A",
    conversations->default_titles[1]="Port A";
    conversations->default_titles[2]="Address B";
    conversations->default_titles[3]="Port B";
    conversations->default_titles[4]="Packets";
    conversations->default_titles[5]="Bytes";
    conversations->default_titles[6]="Packets A->B";
    conversations->default_titles[7]="Bytes A->B";
    conversations->default_titles[8]="Packets A<-B";
    conversations->default_titles[9]="Bytes A<-B";
    conversations->default_titles[10]="Rel Start";
    conversations->default_titles[11]="Duration";
    conversations->default_titles[12]="bps A->B";
    conversations->default_titles[13]="bps A<-B";
    if (strcmp(table_name, "NCP")==0) {
        conversations->default_titles[1]="Connection A";
        conversations->default_titles[3]="Connection B";
    }

    g_snprintf(title, 255, "%s Conversations", table_name);
    conversations->name_lb=gtk_label_new(title);
    gtk_box_pack_start(GTK_BOX(vbox), conversations->name_lb, FALSE, FALSE, 0);


    conversations->scrolled_window=scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), conversations->scrolled_window, TRUE, TRUE, 0);

    conversations->table=(GtkCList *)gtk_clist_new(NUM_COLS);
    g_object_set_data(G_OBJECT(conversations->table), CONV_PTR_KEY, conversations);

    col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_COLS);
    win_style = gtk_widget_get_style(conversations->scrolled_window);
    for (i = 0; i < NUM_COLS; i++) {
        col_arrows[i].table = gtk_table_new(2, 2, FALSE);
        gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
        column_lb = gtk_label_new(conversations->default_titles[i]);
        gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
        gtk_widget_show(column_lb);

        col_arrows[i].ascend_pm = xpm_to_widget((const char **) clist_ascend_xpm);
        gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
        col_arrows[i].descend_pm = xpm_to_widget((const char **) clist_descend_xpm);
        gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm, 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
        /* make total frames be the default sort order */
        if (i == 4) {
            gtk_widget_show(col_arrows[i].ascend_pm);
        }
        gtk_clist_set_column_widget(GTK_CLIST(conversations->table), i, col_arrows[i].table);
        gtk_widget_show(col_arrows[i].table);
    }
    gtk_clist_column_titles_show(GTK_CLIST(conversations->table));

    gtk_clist_set_compare_func(conversations->table, ct_sort_column);
    gtk_clist_set_sort_column(conversations->table, 4);
    gtk_clist_set_sort_type(conversations->table, GTK_SORT_ASCENDING);


    for (i = 0; i < NUM_COLS; i++) {
        gtk_clist_set_column_auto_resize(conversations->table, i, TRUE);
    }

    gtk_clist_set_shadow_type(conversations->table, GTK_SHADOW_IN);
    gtk_clist_column_titles_show(conversations->table);
    gtk_container_add(GTK_CONTAINER(conversations->scrolled_window), (GtkWidget *)conversations->table);

    g_signal_connect(conversations->table, "click-column", G_CALLBACK(ct_click_column_cb), col_arrows);

    conversations->num_conversations=0;
    conversations->conversations=NULL;

    /* hide srcport and dstport if we don't use ports */
    if(hide_ports){
        gtk_clist_set_column_visibility(conversations->table, 1, FALSE);
        gtk_clist_set_column_visibility(conversations->table, 3, FALSE);
    }

    /* create popup menu for this table */
    ct_create_popup_menu(conversations);

    /* register the tap and rerun the taps on the packet list */
    error_string=register_tap_listener(tap_name, conversations, filter, reset_ct_table_data_cb, packet_func, draw_ct_table_data_cb);
    if(error_string){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
        g_string_free(error_string, TRUE);
        return FALSE;
    }

    return TRUE;
}


void
init_conversation_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    conversations_table *conversations;
    char title[256];
    GtkWidget *vbox;
    GtkWidget *bbox;
    GtkWidget *close_bt, *help_bt;
    gboolean ret;
    GtkWidget *copy_bt;
    GtkTooltips *tooltips = gtk_tooltips_new();

    conversations=g_malloc(sizeof(conversations_table));

    conversations->name=table_name;
    conversations->filter=filter;
    conversations->use_dfilter=FALSE;
    g_snprintf(title, 255, "%s Conversations: %s", table_name, cf_get_display_name(&cfile));
    conversations->win=window_new(GTK_WINDOW_TOPLEVEL, title);

    gtk_window_set_default_size(GTK_WINDOW(conversations->win), 750, 400);

    vbox=gtk_vbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(conversations->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    ret = init_ct_table_page(conversations, vbox, hide_ports, table_name, tap_name, filter, packet_func);
    if(ret == FALSE) {
        g_free(conversations);
        return;
    }

    /* Button row. */
    /* XXX - maybe we want to have a "Copy as CSV" stock button here? */
    /*copy_bt = gtk_button_new_with_label ("Copy content to clipboard as CSV");*/
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(conversations->win, close_bt, window_cancel_button_cb);

    copy_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
    gtk_tooltips_set_tip(tooltips, copy_bt,
        "Copy all statistical values of this page to the clipboard in CSV (Comma Separated Values) format.", NULL);
    g_object_set_data(G_OBJECT(copy_bt), CONV_PTR_KEY, conversations);
    g_signal_connect(copy_bt, "clicked", G_CALLBACK(copy_as_csv_cb), NULL);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_CONVERSATIONS_DIALOG);

    g_signal_connect(conversations->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(conversations->win, "destroy", G_CALLBACK(ct_win_destroy_cb), conversations);

    gtk_widget_show_all(conversations->win);
    window_present(conversations->win);

    cf_retap_packets(&cfile, FALSE);


    /* Keep clist frozen to cause modifications to the clist (inserts, appends, others that are extremely slow
	   in GTK2) to not be drawn, allow refreshes to occur at strategic points for performance */
  	gtk_clist_freeze(conversations->table);

    /* after retapping, redraw table */
    draw_ct_table_data(conversations);
}



static void
ct_nb_switch_page_cb(GtkNotebook *nb, GtkNotebookPage *pg _U_, guint page, gpointer data)
{
    GtkWidget *copy_bt = (GtkWidget *) data;
    void ** pages = g_object_get_data(G_OBJECT(nb), NB_PAGES_KEY);

    page++;

    if (pages && page > 0 && (int) page <= GPOINTER_TO_INT(pages[0]) && copy_bt) {
        g_object_set_data(G_OBJECT(copy_bt), CONV_PTR_KEY, pages[page]);
    }
}

static void
ct_win_destroy_notebook_cb(GtkWindow *win _U_, gpointer data)
{
    void ** pages = data;
    int page;

    /* first "page" contains the number of pages */
    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        ct_win_destroy_cb(NULL, pages[page]);
    }
    g_free(pages);
}

static conversations_table *
init_ct_notebook_page_cb(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    gboolean ret;
    GtkWidget *page_vbox;
    conversations_table *conversations;

    conversations=g_malloc(sizeof(conversations_table));
    conversations->name=table_name;
    conversations->filter=filter;
    conversations->resolve_names=TRUE;
    conversations->use_dfilter=FALSE;

    page_vbox=gtk_vbox_new(FALSE, 6);
    conversations->win = page_vbox;
    gtk_container_set_border_width(GTK_CONTAINER(page_vbox), 6);

    ret = init_ct_table_page(conversations, page_vbox, hide_ports, table_name, tap_name, filter, packet_func);
    if(ret == FALSE) {
        g_free(conversations);
        return NULL;
    }

    return conversations;
}


typedef struct {
    gboolean hide_ports;       /* hide TCP / UDP port columns */
    const char *table_name;    /* GUI output name */
    const char *tap_name;      /* internal name */
    const char *filter;        /* display filter string (unused) */
    tap_packet_cb packet_func; /* function to be called for new incoming packets */
} register_ct_t;


static GSList *registered_ct_tables = NULL;

void
register_conversation_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    register_ct_t *table;

    table = g_malloc(sizeof(register_ct_t));

    table->hide_ports   = hide_ports;
    table->table_name   = table_name;
    table->tap_name     = tap_name;
    table->filter       = filter;
    table->packet_func  = packet_func;

    registered_ct_tables = g_slist_append(registered_ct_tables, table);
}


static void
ct_resolve_toggle_dest(GtkWidget *widget, gpointer data)
{
    int page;
    void ** pages = data;
    gboolean resolve_names;
    conversations_table *conversations;


    resolve_names = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        conversations = pages[page];
        conversations->resolve_names = resolve_names;

        draw_ct_table_addresses(conversations);

        /* Allow table to redraw */
        gtk_clist_thaw(conversations->table);
        gtk_clist_freeze(conversations->table);
    }
}


static void
ct_filter_toggle_dest(GtkWidget *widget, gpointer data)
{
    int page;
    void ** pages = data;
    gboolean use_filter;
    conversations_table *conversations;

    use_filter = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        conversations = pages[page];
        conversations->use_dfilter = use_filter;
        reset_ct_table_data(conversations);
    }

    cf_retap_packets(&cfile, FALSE);

    /* after retapping, redraw table */
    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        draw_ct_table_data(pages[page]);
    }
}


void
init_conversation_notebook_cb(GtkWidget *w _U_, gpointer d _U_)
{
    conversations_table *conversations;
    char title[256];
    GtkWidget *vbox;
    GtkWidget *hbox;
    GtkWidget *bbox;
    GtkWidget *close_bt, *help_bt;
    GtkWidget *win;
    GtkWidget *resolv_cb;
    GtkWidget *filter_cb;
    int page;
    void ** pages;
    GtkWidget *nb;
    GtkWidget *page_lb;
    GSList  *current_table;
    register_ct_t *registered;
    GtkTooltips *tooltips = gtk_tooltips_new();
    GtkWidget *copy_bt;

    pages = g_malloc(sizeof(void *) * (g_slist_length(registered_ct_tables) + 1));

    g_snprintf(title, 255, "Conversations: %s", cf_get_display_name(&cfile));
    win=window_new(GTK_WINDOW_TOPLEVEL, title);
    gtk_window_set_default_size(GTK_WINDOW(win), 750, 400);

    vbox=gtk_vbox_new(FALSE, 6);
    gtk_container_add(GTK_CONTAINER(win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    nb = gtk_notebook_new();
    gtk_container_add(GTK_CONTAINER(vbox), nb);
    g_object_set_data(G_OBJECT(nb), NB_PAGES_KEY, pages);

    page = 0;

    current_table = registered_ct_tables;
    while(current_table) {
        registered = current_table->data;
        page_lb = gtk_label_new("");
        conversations = init_ct_notebook_page_cb(registered->hide_ports, registered->table_name, registered->tap_name,
            registered->filter, registered->packet_func);
        g_object_set_data(G_OBJECT(conversations->win), CONV_PTR_KEY, conversations);
        gtk_notebook_append_page(GTK_NOTEBOOK(nb), conversations->win, page_lb);
        conversations->win = win;
        conversations->page_lb = page_lb;
        pages[++page] = conversations;

        current_table = g_slist_next(current_table);
    }

    pages[0] = GINT_TO_POINTER(page);

    hbox = gtk_hbox_new(FALSE, 3);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    resolv_cb = gtk_check_button_new_with_mnemonic("Name resolution");
    gtk_container_add(GTK_CONTAINER(hbox), resolv_cb);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(resolv_cb), TRUE);
    gtk_tooltips_set_tip(tooltips, resolv_cb, "Show results of name resolutions rather than the \"raw\" values. "
        "Please note: The corresponding name resolution must be enabled.", NULL);

    g_signal_connect(resolv_cb, "toggled", G_CALLBACK(ct_resolve_toggle_dest), pages);

    filter_cb = gtk_check_button_new_with_mnemonic("Limit to display filter");
    gtk_container_add(GTK_CONTAINER(hbox), filter_cb);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(filter_cb), FALSE);
    gtk_tooltips_set_tip(tooltips, filter_cb, "Limit the list to conversations matching the current display filter.", NULL);

    g_signal_connect(filter_cb, "toggled", G_CALLBACK(ct_filter_toggle_dest), pages);

    /* Button row. */
    /* XXX - maybe we want to have a "Copy as CSV" stock button here? */
    /*copy_bt = gtk_button_new_with_label ("Copy content to clipboard as CSV");*/
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);

    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(win, close_bt, window_cancel_button_cb);

    copy_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
    gtk_tooltips_set_tip(tooltips, copy_bt,
        "Copy all statistical values of this page to the clipboard in CSV (Comma Separated Values) format.", NULL);
    g_signal_connect(copy_bt, "clicked", G_CALLBACK(copy_as_csv_cb), NULL);
    g_object_set_data(G_OBJECT(copy_bt), CONV_PTR_KEY, pages[page]);

    g_signal_connect(nb, "switch-page", G_CALLBACK(ct_nb_switch_page_cb), copy_bt);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_CONVERSATIONS_DIALOG);

    g_signal_connect(win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(win, "destroy", G_CALLBACK(ct_win_destroy_notebook_cb), pages);

    gtk_widget_show_all(win);
    window_present(win);

    cf_retap_packets(&cfile, FALSE);

    /* after retapping, redraw table */
    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        draw_ct_table_data(pages[page]);
    }
}


void
add_conversation_table_data(conversations_table *ct, const address *src, const address *dst, guint32 src_port, guint32 dst_port, int num_frames, int num_bytes, nstime_t *ts, SAT_E sat, int port_type)
{
    const address *addr1, *addr2;
    guint32 port1, port2;
    conv_t *conversation=NULL;
    int conversation_idx=0;
    gboolean new_conversation;

    if(src_port>dst_port){
        addr1=src;
        addr2=dst;
        port1=src_port;
        port2=dst_port;
    } else if(src_port<dst_port){
        addr2=src;
        addr1=dst;
        port2=src_port;
        port1=dst_port;
    } else if(CMP_ADDRESS(src, dst)<0){
        addr1=src;
        addr2=dst;
        port1=src_port;
        port2=dst_port;
    } else {
        addr2=src;
        addr1=dst;
        port2=src_port;
        port1=dst_port;
    }


    new_conversation=FALSE;
    /* XXX should be optimized to allocate n extra entries at a time
       instead of just one */
    /* if we dont have any entries at all yet */
    if(ct->conversations==NULL){
        ct->conversations=g_malloc(sizeof(conv_t));
        ct->num_conversations=1;
        conversation=&ct->conversations[0];
        conversation_idx=0;
        new_conversation=TRUE;
    }

    /* try to find it among the existing known conversations */
    if(conversation==NULL){
        guint32 i;
        for(i=0;i<ct->num_conversations;i++){
            if(  (!CMP_ADDRESS(&ct->conversations[i].src_address, addr1))&&(!CMP_ADDRESS(&ct->conversations[i].dst_address, addr2))&&(ct->conversations[i].src_port==port1)&&(ct->conversations[i].dst_port==port2) ){
                conversation=&ct->conversations[i];
                conversation_idx=i;
                break;
            }
            if( (!CMP_ADDRESS(&ct->conversations[i].src_address, addr2))&&(!CMP_ADDRESS(&ct->conversations[i].dst_address, addr1))&&(ct->conversations[i].src_port==port2)&&(ct->conversations[i].dst_port==port1) ){
                conversation=&ct->conversations[i];
                conversation_idx=i;
                break;
            }
        }
    }

    /* if we still dont know what conversation this is it has to be a new one
       and we have to allocate it and append it to the end of the list */
    if(conversation==NULL){
        new_conversation=TRUE;
        ct->num_conversations++;
        ct->conversations=g_realloc(ct->conversations, ct->num_conversations*sizeof(conv_t));
        conversation=&ct->conversations[ct->num_conversations-1];
        conversation_idx=ct->num_conversations-1;
    }

    /* if this is a new conversation we need to initialize the struct */
    if(new_conversation){
        COPY_ADDRESS(&conversation->src_address, addr1);
        COPY_ADDRESS(&conversation->dst_address, addr2);
        conversation->sat=sat;
        conversation->port_type=port_type;
        conversation->src_port=port1;
        conversation->dst_port=port2;
        conversation->rx_frames=0;
        conversation->tx_frames=0;
        conversation->rx_bytes=0;
        conversation->tx_bytes=0;
        if (ts) {
            memcpy(&conversation->start_time, ts, sizeof(conversation->start_time));
            memcpy(&conversation->stop_time, ts, sizeof(conversation->stop_time));
        } else {
            nstime_set_unset(&conversation->start_time);
            nstime_set_unset(&conversation->stop_time);
        }
    }

    /* update the conversation struct */
    if( (!CMP_ADDRESS(src, addr1))&&(!CMP_ADDRESS(dst, addr2))&&(src_port==port1)&&(dst_port==port2) ){
        conversation->tx_frames+=num_frames;
        conversation->tx_bytes+=num_bytes;
    } else {
        conversation->rx_frames+=num_frames;
        conversation->rx_bytes+=num_bytes;
    }

    if (ts) {
        if (nstime_cmp(ts, &conversation->stop_time) > 0) {
            memcpy(&conversation->stop_time, ts, sizeof(conversation->stop_time));
        } else if (nstime_cmp(ts, &conversation->start_time) < 0) {
            memcpy(&conversation->start_time, ts, sizeof(conversation->start_time));
        }
    }

    /* if this was a new conversation we have to create a clist row for it */
    if(new_conversation){
        char *entries[NUM_COLS];
        char frames[COL_STR_LEN], bytes[COL_STR_LEN],
             txframes[COL_STR_LEN], txbytes[COL_STR_LEN],
             rxframes[COL_STR_LEN], rxbytes[COL_STR_LEN],
             start_time[COL_STR_LEN], duration[COL_STR_LEN],
             txbps[COL_STR_LEN], rxbps[COL_STR_LEN];
        double duration_s;

        /* these values will be filled by call to draw_ct_table_addresses() below */
        entries[0] = "";
        entries[1] = "";
        entries[2] = "";
        entries[3] = "";

        g_snprintf(frames, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", conversation->tx_frames+conversation->rx_frames);
        entries[4]=frames;
        g_snprintf(bytes, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", conversation->tx_bytes+conversation->rx_bytes);
        entries[5]=bytes;

        g_snprintf(txframes, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", conversation->tx_frames);
        entries[6]=txframes;
        g_snprintf(txbytes, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", conversation->tx_bytes);
        entries[7]=txbytes;

        g_snprintf(rxframes, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", conversation->rx_frames);
        entries[8]=rxframes;
        g_snprintf(rxbytes, COL_STR_LEN, "%" G_GINT64_MODIFIER "u", conversation->rx_bytes);
        entries[9]=rxbytes;

        duration_s = nstime_to_sec(&conversation->start_time) - nstime_to_sec(&conversation->stop_time);
        g_snprintf(start_time, COL_STR_LEN, "%s", rel_time_to_secs_str(&conversation->start_time));
        g_snprintf(duration, COL_STR_LEN, "%.4f", duration_s);
        entries[10]=start_time;
        entries[11]=duration;
        if (duration_s > 0 && conversation->tx_frames > 1) {
            g_snprintf(txbps, COL_STR_LEN, "%.2f", (gint64) conversation->tx_bytes * 8 / duration_s);
            entries[12]=txbps;
        } else {
            entries[12] = NO_BPS_STR;
        }
        if (duration_s > 0 && conversation->rx_frames > 1) {
            g_snprintf(rxbps, COL_STR_LEN, "%.2f", (gint64) conversation->rx_bytes * 8 / duration_s);
            entries[13]=rxbps;
        } else {
            entries[13] = NO_BPS_STR;
        }

        gtk_clist_insert(ct->table, conversation_idx, entries);
        gtk_clist_set_row_data(ct->table, conversation_idx, (gpointer)(long) conversation_idx);

        draw_ct_table_address(ct, conversation_idx);
    }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab
 * :indentSize=4:tabSize=8:noTabs=true:
 */

