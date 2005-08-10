/* mem leak   should free the column_arrows when the table is destroyed */

/* conversations_table.c
 * conversations_table   2003 Ronnie Sahlberg
 * Helper routines common to all endpoint conversations tap.
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/to_str.h>
#include <epan/addr_resolv.h>
#include <epan/tap.h>

#include "compat_macros.h"
#include "sat.h"
#include "conversations_table.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"
#include "globals.h"
#include "find_dlg.h"
#include "color.h"
#include "gtk/color_dlg.h"
#include "gtkglobals.h"
#include "main.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "help_dlg.h"


#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

#define NUM_COLS 10


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
   of protocols,   either ethernet, tokenring, fddi etc so we must be more
   specific there  thats why we need specific_addr_type
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
			case SAT_FDDI:
				return "fddi.src";
			case SAT_TOKENRING:
				return "tr.src";
                        default:
                            ;
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
                            ;
			}
                        break;
		default:
			;
		}
                break;
	case FN_DST_ADDRESS:
		switch(addr->type){
		case AT_ETHER:
			switch(specific_addr_type){
			case SAT_ETHER:
				return "eth.dst";
			case SAT_FDDI:
				return "fddi.dst";
			case SAT_TOKENRING:
				return "tr.dst";
                        default:
                            ;
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
                            ;
			}
                        break;
		default:
			;
		}
                break;
	case FN_ANY_ADDRESS:
		switch(addr->type){
		case AT_ETHER:
			switch(specific_addr_type){
			case SAT_ETHER:
				return "eth.addr";
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
                            ;
			}
                        break;
		default:
			;
		}
                break;
	case FN_SRC_PORT:
		switch(port_type){
		case PT_TCP:
			return "tcp.srcport";
		case PT_UDP:
			return "udp.srcport";
                default:
                        ;
		}
		break;
	case FN_DST_PORT:
		switch(port_type){
		case PT_TCP:
			return "tcp.dstport";
		case PT_UDP:
			return "udp.dstport";
                default:
                        ;
		}
		break;
	case FN_ANY_PORT:
		switch(port_type){
		case PT_TCP:
			return "tcp.port";
		case PT_UDP:
			return "udp.port";
                default:
                        ;
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
	
	/* Allow clist to update */
	gtk_clist_thaw(ct->table);

    if(ct->page_lb) {
        g_snprintf(title, 255, "Conversations: %s", cf_get_display_name(&cfile));
        gtk_window_set_title(GTK_WINDOW(ct->win), title);
        g_snprintf(title, 255, "%s", ct->name);
        gtk_label_set_text(GTK_LABEL(ct->page_lb), title);
        gtk_widget_set_sensitive(ct->page_lb, FALSE);
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

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
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
	char *text1 = NULL;
	char *text2 = NULL;
	guint64 i1, i2;

	const GtkCListRow *row1 = ptr1;
	const GtkCListRow *row2 = ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	case 0:
	case 2:
		return strcmp (text1, text2);
	case 1:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
		sscanf(text1, "%" PRIu64, &i1);
		sscanf(text2, "%" PRIu64, &i2);
        /* XXX - this might cause trouble because of overflow problems */
        /* XXX - is this correct anyway? Subtracting two unsigned values will still be an unsigned value, which will never become negative */
		return (gint) (i1-i2);
	}
	g_assert_not_reached();
	
	/* Allow clist to redraw */
	
	gtk_clist_thaw(clist);
	gtk_clist_freeze(clist);
	
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
		clist->sort_type = GTK_SORT_DESCENDING;
		gtk_widget_show(col_arrows[column].descend_pm);
		gtk_clist_set_sort_column(clist, column);
	}

	gtk_clist_sort(clist);

	/* Allow update of clist */
	gtk_clist_thaw(clist);
	gtk_clist_freeze(clist);

}


/* action is encoded as
   filter_action*65536+filter_type*256+filter_direction

   filter_action:
	0: Match
	1: Prepare
	2: Find Frame
	3:   Find Next
	4:   Find Previous
	5: Colorize Conversation
   filter_type:
	0: Selected
	1: Not Selected
	2: And Selected
	3: Or Selected
	4: And Not Selected
	5: Or Not Selected
   filter_direction:
	0: A To/From B
	1: A To B
	2: A From B
	3: A To/From ANY
	4: A To ANY
	5: A From ANY
	6: A To/From ANY
	7: B To ANY
	8: B From ANY
*/
static void
ct_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
	int action, type, direction;
	int selection;
	conversations_table *ct = (conversations_table *)callback_data;
	char dirstr[128];
	char str[256];
	const char *current_filter;
	char *sport, *dport;

	action=(callback_action>>16)&0xff;
	type=(callback_action>>8)&0xff;
	direction=callback_action&0xff;


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
	case 0:
		/* A <-> B */
		g_snprintf(dirstr, 127, "%s==%s %s%s%s%s && %s==%s %s%s%s%s",
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
	case 1:
		/* A --> B */
		g_snprintf(dirstr, 127, "%s==%s %s%s%s%s && %s==%s %s%s%s%s",
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
	case 2:
		/* A <-- B */
		g_snprintf(dirstr, 127, "%s==%s %s%s%s%s && %s==%s %s%s%s%s",
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
	case 3:
		/* A <-> ANY */
		g_snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_ADDRESS),
			address_to_str(&ct->conversations[selection].src_address),
			sport?" && ":"",
			sport?ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_PORT):"",
			sport?"==":"",
			sport?sport:""
		);
		break;
	case 4:
		/* A --> ANY */
		g_snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_ADDRESS),
			address_to_str(&ct->conversations[selection].src_address),
			sport?" && ":"",
			sport?ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_PORT):"",
			sport?"==":"",
			sport?sport:""
		);
		break;
	case 5:
		/* A <-- ANY */
		g_snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_ADDRESS),
			address_to_str(&ct->conversations[selection].src_address),
			sport?" && ":"",
			sport?ct_get_filter_name(&ct->conversations[selection].src_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_DST_PORT):"",
			sport?"==":"",
			sport?sport:""
		);
		break;
	case 6:
		/* B <-> ANY */
		g_snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_ADDRESS),
			address_to_str(&ct->conversations[selection].dst_address),
			dport?" && ":"",
			dport?ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_ANY_PORT):"",
			dport?"==":"",
			dport?dport:""
		);
		break;
	case 7:
		/* B --> ANY */
		g_snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_ADDRESS),
			address_to_str(&ct->conversations[selection].dst_address),
			dport?" && ":"",
			dport?ct_get_filter_name(&ct->conversations[selection].dst_address, ct->conversations[selection].sat, ct->conversations[selection].port_type,  FN_SRC_PORT):"",
			dport?"==":"",
			dport?dport:""
		);
		break;
	case 8:
		/* B <-- ANY */
		g_snprintf(dirstr, 127, "%s==%s %s%s%s%s",
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

	current_filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	switch(type){
	case 0:
		/* selected */
		g_snprintf(str, 255, "%s", dirstr);
		break;
	case 1:
		/* not selected */
		g_snprintf(str, 255, "!(%s)", dirstr);
		break;
	case 2:
		/* and selected */
		g_snprintf(str, 255, "(%s) && (%s)", current_filter, dirstr);
		break;
	case 3:
		/* or selected */
		g_snprintf(str, 255, "(%s) || (%s)", current_filter, dirstr);
		break;
	case 4:
		/* and not selected */
		g_snprintf(str, 255, "(%s) && !(%s)", current_filter, dirstr);
		break;
	case 5:
		/* or not selected */
		g_snprintf(str, 255, "(%s) || !(%s)", current_filter, dirstr);
		break;
	}

	switch(action){
	case 0:
		/* match */
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
		main_filter_packets(&cfile, str, FALSE);
		gdk_window_raise(top_level->window);
		break;
	case 1:
		/* prepare */
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
		break;
	case 2:
		/* find packet */
		find_frame_with_filter(str);
		break;
	case 3:
		/* find next */
		find_previous_next_frame_with_filter(str, FALSE);
		break;
	case 4:
		/* find previous */
		find_previous_next_frame_with_filter(str, TRUE);
		break;
	case 5:
		/* colorize conversation */
		color_display_with_filter(str);
		break;
	}

}

static gint
ct_show_popup_menu_cb(void *widg _U_, GdkEvent *event, conversations_table *ct)
{
	GdkEventButton *bevent = (GdkEventButton *)event;
    gint row;
    gint column;


    /* To qoute the "Gdk Event Structures" doc:
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
	ITEM_FACTORY_ENTRY("/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected/A <-> B", NULL,
		ct_select_filter_cb, 0*65536+0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected/A --> B", NULL,
		ct_select_filter_cb, 0*65536+0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected/A <-- B", NULL,
		ct_select_filter_cb, 0*65536+0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 0*65536+0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected/A --> ANY", NULL,
		ct_select_filter_cb, 0*65536+0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 0*65536+0*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 0*65536+0*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 0*65536+0*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected/ANY --> B", NULL,
		ct_select_filter_cb, 0*65536+0*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected/A <-> B", NULL,
		ct_select_filter_cb, 0*65536+1*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected/A --> B", NULL,
		ct_select_filter_cb, 0*65536+1*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected/A <-- B", NULL,
		ct_select_filter_cb, 0*65536+1*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected/A --> ANY", NULL,
		ct_select_filter_cb, 0*65536+1*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 0*65536+1*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 0*65536+1*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 0*65536+1*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 0*65536+1*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected/ANY --> B", NULL,
		ct_select_filter_cb, 0*65536+1*256+8, NULL, NULL),


	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected/A <-> B", NULL,
		ct_select_filter_cb, 0*65536+2*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected/A --> B", NULL,
		ct_select_filter_cb, 0*65536+2*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected/A <-- B", NULL,
		ct_select_filter_cb, 0*65536+2*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 0*65536+2*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected/A --> ANY", NULL,
		ct_select_filter_cb, 0*65536+2*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 0*65536+2*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 0*65536+2*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 0*65536+2*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected/ANY --> B", NULL,
		ct_select_filter_cb, 0*65536+2*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected/A <-> B", NULL,
		ct_select_filter_cb, 0*65536+3*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected/A --> B", NULL,
		ct_select_filter_cb, 0*65536+3*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected/A <-- B", NULL,
		ct_select_filter_cb, 0*65536+3*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 0*65536+3*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected/A --> ANY", NULL,
		ct_select_filter_cb, 0*65536+3*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 0*65536+3*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 0*65536+3*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 0*65536+3*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected/ANY --> B", NULL,
		ct_select_filter_cb, 0*65536+3*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected/A <-> B", NULL,
		ct_select_filter_cb, 0*65536+4*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected/A --> B", NULL,
		ct_select_filter_cb, 0*65536+4*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected/A <-- B", NULL,
		ct_select_filter_cb, 0*65536+4*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 0*65536+4*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected/A --> ANY", NULL,
		ct_select_filter_cb, 0*65536+4*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 0*65536+4*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 0*65536+4*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 0*65536+4*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected/ANY --> B", NULL,
		ct_select_filter_cb, 0*65536+4*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected/A <-> B", NULL,
		ct_select_filter_cb, 0*65536+5*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected/A --> B", NULL,
		ct_select_filter_cb, 0*65536+5*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected/A <-- B", NULL,
		ct_select_filter_cb, 0*65536+5*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 0*65536+5*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected/A --> ANY", NULL,
		ct_select_filter_cb, 0*65536+5*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 0*65536+5*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 0*65536+5*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 0*65536+5*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected/ANY --> B", NULL,
		ct_select_filter_cb, 0*65536+5*256+8, NULL, NULL),

	/* Prepare */
	ITEM_FACTORY_ENTRY("/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected/A <-> B", NULL,
		ct_select_filter_cb, 1*65536+0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected/A --> B", NULL,
		ct_select_filter_cb, 1*65536+0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected/A <-- B", NULL,
		ct_select_filter_cb, 1*65536+0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 1*65536+0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected/A --> ANY", NULL,
		ct_select_filter_cb, 1*65536+0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 1*65536+0*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 1*65536+0*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 1*65536+0*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected/ANY --> B", NULL,
		ct_select_filter_cb, 1*65536+0*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected/A <-> B", NULL,
		ct_select_filter_cb, 1*65536+1*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected/A --> B", NULL,
		ct_select_filter_cb, 1*65536+1*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected/A <-- B", NULL,
		ct_select_filter_cb, 1*65536+1*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 1*65536+1*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected/A --> ANY", NULL,
		ct_select_filter_cb, 1*65536+1*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 1*65536+1*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 1*65536+1*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 1*65536+1*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected/ANY --> B", NULL,
		ct_select_filter_cb, 1*65536+1*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected/A <-> B", NULL,
		ct_select_filter_cb, 1*65536+2*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected/A --> B", NULL,
		ct_select_filter_cb, 1*65536+2*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected/A <-- B", NULL,
		ct_select_filter_cb, 1*65536+2*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 1*65536+2*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected/A --> ANY", NULL,
		ct_select_filter_cb, 1*65536+2*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 1*65536+2*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 1*65536+2*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 1*65536+2*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected/ANY --> B", NULL,
		ct_select_filter_cb, 1*65536+2*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected/A <-> B", NULL,
		ct_select_filter_cb, 1*65536+3*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected/A --> B", NULL,
		ct_select_filter_cb, 1*65536+3*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected/A <-- B", NULL,
		ct_select_filter_cb, 1*65536+3*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 1*65536+3*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected/A --> ANY", NULL,
		ct_select_filter_cb, 1*65536+3*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 1*65536+3*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 1*65536+3*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 1*65536+3*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected/ANY --> B", NULL,
		ct_select_filter_cb, 1*65536+3*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected/A <-> B", NULL,
		ct_select_filter_cb, 1*65536+4*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected/A --> B", NULL,
		ct_select_filter_cb, 1*65536+4*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected/A <-- B", NULL,
		ct_select_filter_cb, 1*65536+4*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 1*65536+4*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected/A --> ANY", NULL,
		ct_select_filter_cb, 1*65536+4*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 1*65536+4*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 1*65536+4*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 1*65536+4*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected/ANY --> B", NULL,
		ct_select_filter_cb, 1*65536+4*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected/A <-> B", NULL,
		ct_select_filter_cb, 1*65536+5*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected/A --> B", NULL,
		ct_select_filter_cb, 1*65536+5*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected/A <-- B", NULL,
		ct_select_filter_cb, 1*65536+5*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected/A <-> ANY", NULL,
		ct_select_filter_cb, 1*65536+5*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected/A --> ANY", NULL,
		ct_select_filter_cb, 1*65536+5*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected/A <-- ANY", NULL,
		ct_select_filter_cb, 1*65536+5*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected/ANY <-> B", NULL,
		ct_select_filter_cb, 1*65536+5*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected/ANY <-- B", NULL,
		ct_select_filter_cb, 1*65536+5*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected/ANY --> B", NULL,
		ct_select_filter_cb, 1*65536+5*256+8, NULL, NULL),

	/* Find Packet */
	ITEM_FACTORY_ENTRY("/Find Packet", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet/A <-> B", NULL,
		ct_select_filter_cb, 2*65536+0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet/A --> B", NULL,
		ct_select_filter_cb, 2*65536+0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet/A <-- B", NULL,
		ct_select_filter_cb, 2*65536+0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet/A <-> ANY", NULL,
		ct_select_filter_cb, 2*65536+0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet/A --> ANY", NULL,
		ct_select_filter_cb, 2*65536+0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet/A <-- ANY", NULL,
		ct_select_filter_cb, 2*65536+0*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet/ANY <-> B", NULL,
		ct_select_filter_cb, 2*65536+0*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet/ANY <-- B", NULL,
		ct_select_filter_cb, 2*65536+0*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Packet/ANY --> B", NULL,
		ct_select_filter_cb, 2*65536+0*256+8, NULL, NULL),
	/* Find Next */
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next/A <-> B", NULL,
		ct_select_filter_cb, 3*65536+0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next/A --> B", NULL,
		ct_select_filter_cb, 3*65536+0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next/A <-- B", NULL,
		ct_select_filter_cb, 3*65536+0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next/A <-> ANY", NULL,
		ct_select_filter_cb, 3*65536+0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next/A --> ANY", NULL,
		ct_select_filter_cb, 3*65536+0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next/A <-- ANY", NULL,
		ct_select_filter_cb, 3*65536+0*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next/ANY <-> B", NULL,
		ct_select_filter_cb, 3*65536+0*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next/ANY <-- B", NULL,
		ct_select_filter_cb, 3*65536+0*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Next/ANY --> B", NULL,
		ct_select_filter_cb, 3*65536+0*256+8, NULL, NULL),
	/* Find Previous */
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous/A <-> B", NULL,
		ct_select_filter_cb, 4*65536+0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous/A --> B", NULL,
		ct_select_filter_cb, 4*65536+0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous/A <-- B", NULL,
		ct_select_filter_cb, 4*65536+0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous/A <-> ANY", NULL,
		ct_select_filter_cb, 4*65536+0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous/A --> ANY", NULL,
		ct_select_filter_cb, 4*65536+0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous/A <-- ANY", NULL,
		ct_select_filter_cb, 4*65536+0*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous/ANY <-> B", NULL,
		ct_select_filter_cb, 4*65536+0*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous/ANY <-- B", NULL,
		ct_select_filter_cb, 4*65536+0*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Packet/Find Previous/ANY --> B", NULL,
		ct_select_filter_cb, 4*65536+0*256+8, NULL, NULL),
	/* Colorize Conversation */
	ITEM_FACTORY_ENTRY("/Colorize Conversation", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Colorize Conversation/A <-> B", NULL,
		ct_select_filter_cb, 5*65536+0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Colorize Conversation/A --> B", NULL,
		ct_select_filter_cb, 5*65536+0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Colorize Conversation/A <-- B", NULL,
		ct_select_filter_cb, 5*65536+0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Colorize Conversation/A <-> ANY", NULL,
		ct_select_filter_cb, 5*65536+0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Colorize Conversation/A --> ANY", NULL,
		ct_select_filter_cb, 5*65536+0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Colorize Conversation/A <-- ANY", NULL,
		ct_select_filter_cb, 5*65536+0*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Colorize Conversation/ANY <-> B", NULL,
		ct_select_filter_cb, 5*65536+0*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Colorize Conversation/ANY <-- B", NULL,
		ct_select_filter_cb, 5*65536+0*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Colorize Conversation/ANY --> B", NULL,
		ct_select_filter_cb, 5*65536+0*256+8, NULL, NULL),


};

static void
ct_create_popup_menu(conversations_table *ct)
{
	GtkItemFactory *item_factory;

	item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

	gtk_item_factory_create_items_ac(item_factory, sizeof(ct_list_menu_items)/sizeof(ct_list_menu_items[0]), ct_list_menu_items, ct, 2);

	ct->menu = gtk_item_factory_get_widget(item_factory, "<main>");
	SIGNAL_CONNECT(ct->table, "button_press_event", ct_show_popup_menu_cb, ct);
}

/* Draw/refresh the address fields of a single entry at the specified index */
static void
draw_ct_table_address(conversations_table *ct, int conversation_idx)
{
    const char *entry;
    char *port;
    guint32 pt;
    int rownum;

    rownum=gtk_clist_find_row_from_data(ct->table, (gpointer)conversation_idx);

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

    if (ct->page_lb) {
        if(ct->num_conversations) {
            g_snprintf(title, 255, "%s: %u", ct->name, ct->num_conversations);
        } else {
            g_snprintf(title, 255, "%s", ct->name);
        }
        gtk_label_set_text(GTK_LABEL(ct->page_lb), title);
        gtk_widget_set_sensitive(ct->page_lb, ct->num_conversations);
    }

    for(i=0;i<ct->num_conversations;i++){
        char str[16];

        j=gtk_clist_find_row_from_data(ct->table, (gpointer)i);

        g_snprintf(str, 16, "%" PRIu64, ct->conversations[i].tx_frames+ct->conversations[i].rx_frames);
        gtk_clist_set_text(ct->table, j, 4, str);
        g_snprintf(str, 16, "%" PRIu64, ct->conversations[i].tx_bytes+ct->conversations[i].rx_bytes);
        gtk_clist_set_text(ct->table, j, 5, str);


        g_snprintf(str, 16, "%" PRIu64, ct->conversations[i].tx_frames);
        gtk_clist_set_text(ct->table, j, 6, str);
        g_snprintf(str, 16, "%" PRIu64, ct->conversations[i].tx_bytes);
        gtk_clist_set_text(ct->table, j, 7, str);


        g_snprintf(str, 16, "%" PRIu64, ct->conversations[i].rx_frames);
        gtk_clist_set_text(ct->table, j, 8, str);
        g_snprintf(str, 16, "%" PRIu64, ct->conversations[i].rx_bytes);
        gtk_clist_set_text(ct->table, j, 9, str);

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

#if (GTK_MAJOR_VERSION >= 2)
static void
copy_as_csv_cb(GtkWindow *win _U_, gpointer data)
{
   guint32         i,j;                 
   gchar           *table_entry;                      
   gchar           *CSV_str;         
   GtkClipboard    *cb;  
   
   conversations_table *talkers=(conversations_table *)data;
   
   CSV_str=g_new(gchar,(80*(talkers->num_conversations+1))); /* 80 chars * num rows */
   strcpy(CSV_str,"");                                   /* initialize string   */
   /* Add the column headers to the CSV data */
   for(i=0;i<talkers->num_columns;i++){                  /* all columns         */
    if((i==1 || i==3) && !talkers->has_ports) continue;  /* Don't add the port column if it's empty */
     strcat(CSV_str,talkers->default_titles[i]);         /* add the column heading to the CSV string */
     strcat(CSV_str,",");
   }
   strcat(CSV_str,"\n");                                 /* new row */
 
   /* Add the column values to the CSV data */
   for(i=0;i<talkers->num_conversations;i++){                /* all rows            */
    for(j=0;j<talkers->num_columns;j++){                 /* all columns         */
     if((j==1 || j==3) && !talkers->has_ports) continue; /* Don't add the port column if it's empty */
     gtk_clist_get_text(talkers->table,i,j,&table_entry);/* copy table item into string */
     strcat(CSV_str,table_entry);                        /* add the table entry to the CSV string */
     strcat(CSV_str,",");
    } 
    strcat(CSV_str,"\n");                                /* new row */  
   }

   /* Now that we have the CSV data, copy it into the default clipboard */
   cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);     /* Get the default clipboard */
   gtk_clipboard_set_text(cb, CSV_str, -1);             /* Copy the CSV data into the clipboard */
   g_free(CSV_str);                                     /* Free the memory */
} 
#endif


static gboolean
init_ct_table_page(conversations_table *conversations, GtkWidget *vbox, gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    int i;
    column_arrows *col_arrows;
    GtkStyle *win_style;
    GtkWidget *column_lb;
    GString *error_string;
    GtkWidget *label;
    char title[256];
#if (GTK_MAJOR_VERSION >= 2)
    GtkWidget *copy_bt;
    GtkTooltips *tooltips = gtk_tooltips_new();
#endif           


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

    g_snprintf(title, 255, "%s Conversations", table_name);
    label=gtk_label_new(title);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);


    conversations->scrolled_window=scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), conversations->scrolled_window, TRUE, TRUE, 0);

    conversations->table=(GtkCList *)gtk_clist_new(NUM_COLS);

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
            gtk_widget_show(col_arrows[i].descend_pm);
        }
        gtk_clist_set_column_widget(GTK_CLIST(conversations->table), i, col_arrows[i].table);
        gtk_widget_show(col_arrows[i].table);
    }
    gtk_clist_column_titles_show(GTK_CLIST(conversations->table));

    gtk_clist_set_compare_func(conversations->table, ct_sort_column);
    gtk_clist_set_sort_column(conversations->table, 4);
    gtk_clist_set_sort_type(conversations->table, GTK_SORT_DESCENDING);


    gtk_clist_set_column_auto_resize(conversations->table, 0, TRUE);
    gtk_clist_set_column_auto_resize(conversations->table, 1, TRUE);
    gtk_clist_set_column_auto_resize(conversations->table, 2, TRUE);
    gtk_clist_set_column_auto_resize(conversations->table, 3, TRUE);
    gtk_clist_set_column_auto_resize(conversations->table, 4, TRUE);
    gtk_clist_set_column_auto_resize(conversations->table, 5, TRUE);
    gtk_clist_set_column_auto_resize(conversations->table, 6, TRUE);
    gtk_clist_set_column_auto_resize(conversations->table, 7, TRUE);
    gtk_clist_set_column_auto_resize(conversations->table, 8, TRUE);
    gtk_clist_set_column_auto_resize(conversations->table, 9, TRUE);

    gtk_clist_set_shadow_type(conversations->table, GTK_SHADOW_IN);
    gtk_clist_column_titles_show(conversations->table);
    gtk_container_add(GTK_CONTAINER(conversations->scrolled_window), (GtkWidget *)conversations->table);

    SIGNAL_CONNECT(conversations->table, "click-column", ct_click_column_cb, col_arrows);

    conversations->num_conversations=0;
    conversations->conversations=NULL;

    /* hide srcport and dstport if we don't use ports */
    if(hide_ports){
        gtk_clist_set_column_visibility(conversations->table, 1, FALSE);
        gtk_clist_set_column_visibility(conversations->table, 3, FALSE);
    }

    /* create popup menu for this table */
    ct_create_popup_menu(conversations);

#if (GTK_MAJOR_VERSION >= 2)
    /* XXX - maybe we want to have a "Copy as CSV" stock button here? */
    /*copy_bt = gtk_button_new_with_label ("Copy content to clipboard as CSV");*/
    copy_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_COPY);
    gtk_tooltips_set_tip(tooltips, copy_bt, 
        "Copy all statistical values of this page to the clipboard in CSV (Comma Seperated Values) format.", NULL);
    SIGNAL_CONNECT(copy_bt, "clicked", copy_as_csv_cb,(gpointer *) conversations);    
    gtk_box_pack_start(GTK_BOX(vbox), copy_bt, FALSE, FALSE, 0); 
#endif                 

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


    conversations=g_malloc(sizeof(conversations_table));

    conversations->name=table_name;
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
    if(topic_available(HELP_STATS_CONVERSATIONS_DIALOG)) {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    } else {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    }
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(conversations->win, close_bt, window_cancel_button_cb);

    if(topic_available(HELP_STATS_CONVERSATIONS_DIALOG)) {
        help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
        SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_STATS_CONVERSATIONS_DIALOG);
    }

    SIGNAL_CONNECT(conversations->win, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(conversations->win, "destroy", ct_win_destroy_cb, conversations);

    gtk_widget_show_all(conversations->win);
    window_present(conversations->win);

    cf_retap_packets(&cfile);

	
    /* Keep clist frozen to cause modifications to the clist (inserts, appends, others that are extremely slow
	   in GTK2) to not be drawn, allow refreshes to occur at strategic points for performance */
  	gtk_clist_freeze(conversations->table);

    /* after retapping, redraw table */
    draw_ct_table_data(conversations);
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
}




static conversations_table *
init_ct_notebook_page_cb(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    gboolean ret;
    GtkWidget *page_vbox;
    conversations_table *conversations;

    conversations=g_malloc(sizeof(conversations_table));
    conversations->name=table_name;
    conversations->resolve_names=TRUE;

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
    int page;
    void ** pages;
    GtkWidget *nb;
    GtkWidget *page_lb;
    GSList  *current_table;
    register_ct_t *registered;
    GtkTooltips *tooltips = gtk_tooltips_new();


    pages = g_malloc(sizeof(void *) * (g_slist_length(registered_ct_tables) + 1));

    g_snprintf(title, 255, "Conversations: %s", cf_get_display_name(&cfile));
    win=window_new(GTK_WINDOW_TOPLEVEL, title);
    gtk_window_set_default_size(GTK_WINDOW(win), 750, 400);

    vbox=gtk_vbox_new(FALSE, 6);
    gtk_container_add(GTK_CONTAINER(win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    nb = gtk_notebook_new();
    gtk_container_add(GTK_CONTAINER(vbox), nb);

    page = 0;

    current_table = registered_ct_tables;
    while(current_table) {
        registered = current_table->data;
        page_lb = gtk_label_new("");
        conversations = init_ct_notebook_page_cb(registered->hide_ports, registered->table_name, registered->tap_name,
            registered->filter, registered->packet_func);
        gtk_notebook_append_page(GTK_NOTEBOOK(nb), conversations->win, page_lb);
        conversations->win = win;
        conversations->page_lb = page_lb;
        pages[++page] = conversations;

        current_table = g_slist_next(current_table);
    }

    pages[0] = GINT_TO_POINTER(page);

    hbox = gtk_hbox_new(FALSE, 3);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Name resolution", NULL);
    gtk_container_add(GTK_CONTAINER(hbox), resolv_cb);
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(resolv_cb), TRUE);
    gtk_tooltips_set_tip(tooltips, resolv_cb, "Show results of name resolutions rather than the \"raw\" values. "
        "Please note: The corresponding name resolution must be enabled.", NULL);

    SIGNAL_CONNECT(resolv_cb, "toggled", ct_resolve_toggle_dest, pages);

    /* Button row. */
    if(topic_available(HELP_STATS_CONVERSATIONS_DIALOG)) {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    } else {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    }
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(win, close_bt, window_cancel_button_cb);

    if(topic_available(HELP_STATS_CONVERSATIONS_DIALOG)) {
        help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
        SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_STATS_CONVERSATIONS_DIALOG);
    }

    SIGNAL_CONNECT(win, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(win, "destroy", ct_win_destroy_notebook_cb, pages);

    gtk_widget_show_all(win);
    window_present(win);

    cf_retap_packets(&cfile);

    /* after retapping, redraw table */
    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        draw_ct_table_data(pages[page]);
    }
}


void
add_conversation_table_data(conversations_table *ct, const address *src, const address *dst, guint32 src_port, guint32 dst_port, int num_frames, int num_bytes, SAT_E sat, int port_type)
{
    const address *addr1, *addr2;
    guint32 port1, port2;
    conversation_t *conversation=NULL;
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
        ct->conversations=g_malloc(sizeof(conversation_t));
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
        ct->conversations=g_realloc(ct->conversations, ct->num_conversations*sizeof(conversation_t));
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
    }

    /* update the conversation struct */
    if( (!CMP_ADDRESS(src, addr1))&&(!CMP_ADDRESS(dst, addr2))&&(src_port==port1)&&(dst_port==port2) ){
        conversation->tx_frames+=num_frames;
        conversation->tx_bytes+=num_bytes;
    } else {
        conversation->rx_frames+=num_frames;
        conversation->rx_bytes+=num_bytes;
    }

    /* if this was a new conversation we have to create a clist row for it */
    if(new_conversation){
        char *entries[NUM_COLS];
        char frames[16],bytes[16],txframes[16],txbytes[16],rxframes[16],rxbytes[16];

        /* these values will be filled by call to draw_ct_table_addresses() below */
        entries[0] = "";
        entries[1] = "";
        entries[2] = "";
        entries[3] = "";

        g_snprintf(frames, 16, "%" PRIu64, conversation->tx_frames+conversation->rx_frames);
        entries[4]=frames;
        g_snprintf(bytes, 16, "%" PRIu64, conversation->tx_bytes+conversation->rx_bytes);
        entries[5]=bytes;

        g_snprintf(txframes, 16, "%" PRIu64, conversation->tx_frames);
        entries[6]=txframes;
        g_snprintf(txbytes, 16, "%" PRIu64, conversation->tx_bytes);
        entries[7]=txbytes;

        g_snprintf(rxframes, 16, "%" PRIu64, conversation->rx_frames);
        entries[8]=rxframes;
        g_snprintf(rxbytes, 16, "%" PRIu64, conversation->rx_bytes);
        entries[9]=rxbytes;

        gtk_clist_insert(ct->table, conversation_idx, entries);
        gtk_clist_set_row_data(ct->table, conversation_idx, (gpointer) conversation_idx);

        draw_ct_table_address(ct, conversation_idx);
    }
}
