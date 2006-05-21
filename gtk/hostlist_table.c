/* hostlist_table.c   2004 Ian Schorr
 * modified from endpoint_talkers_table.c   2003 Ronnie Sahlberg
 * Helper routines common to all host list taps.
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
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/to_str.h>
#include <epan/addr_resolv.h>
#include <epan/tap.h>

#include "compat_macros.h"
#include "hostlist_table.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"
#include "globals.h"
#include "find_dlg.h"
#include "color.h"
#include "gtk/color_dlg.h"
#include "gtkglobals.h"
#include "main.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "help_dlg.h"


#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

#define NUM_COLS 8


/* convert a port number into a string */
static char *
hostlist_port_to_str(int port_type, guint32 port)
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


#define FN_ANY_ADDRESS		0
#define FN_ANY_PORT		1

/* given an address (to distinguish between ipv4 and ipv6 for tcp/udp
   a port_type and a name_type (FN_...)
   return a string for the filter name

   some addresses, like AT_ETHER may actually be any of multiple types
   of protocols,   either ethernet, tokenring, fddi etc so we must be more
   specific there  thats why we need specific_addr_type
*/
static const char *
hostlist_get_filter_name(address *addr, int specific_addr_type, int port_type, int name_type)
{
	switch(name_type){
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
                        default :
                                ;
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
	case FN_ANY_PORT:
		switch(port_type){
		case PT_TCP:
			return "tcp.port";
		case PT_UDP:
			return "udp.port";
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
reset_hostlist_table_data(hostlist_table *hosts)
{
    guint32 i;
    char title[256];
	
	/* Allow clist to update */
    gtk_clist_thaw(hosts->table);

    if(hosts->page_lb) {
        g_snprintf(title, 255, "Endpoints: %s", cf_get_display_name(&cfile));
        gtk_window_set_title(GTK_WINDOW(hosts->win), title);
        g_snprintf(title, 255, "%s", hosts->name);
        gtk_label_set_text(GTK_LABEL(hosts->page_lb), title);
        gtk_widget_set_sensitive(hosts->page_lb, FALSE);
    } else {
        g_snprintf(title, 255, "%s Endpoints: %s", hosts->name, cf_get_display_name(&cfile));
        gtk_window_set_title(GTK_WINDOW(hosts->win), title);
    }

    /* remove all entries from the clist */
    gtk_clist_clear(hosts->table);

    /* delete all hosts */
    for(i=0;i<hosts->num_hosts;i++){
        g_free((gpointer)hosts->hosts[i].address.data);
    }
    g_free(hosts->hosts);
    hosts->hosts=NULL;
    hosts->num_hosts=0;
}

static void
reset_hostlist_table_data_cb(void *arg)
{
    reset_hostlist_table_data(arg);
}

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
hostlist_win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	hostlist_table *hosts=(hostlist_table *)data;

	protect_thread_critical_region();
	remove_tap_listener(hosts);
	unprotect_thread_critical_region();

	reset_hostlist_table_data(hosts);
	g_free(hosts);
}

static gint
hostlist_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	char *text1 = NULL;
	char *text2 = NULL;
	guint64 i1, i2;

	const GtkCListRow *row1 = ptr1;
	const GtkCListRow *row2 = ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	case 0: /* Address */
	case 1: /* (Port) */
		return strcmp (text1, text2);
	case 2: /* Packets */
	case 3: /* Bytes */
	case 4: /* Tx Packets */
	case 5: /* Tx Bytes */
	case 6: /* Rx Packets */
	case 7: /* Rx Bytes */
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
hostlist_click_column_cb(GtkCList *clist, gint column, gpointer data)
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
   filter_action*256+filter_type

   filter_action:
	0: Match
	1: Prepare
	2: Find Frame
	3:   Find Next
	4:   Find Previous
	5: Colorize Host Traffic
   filter_type:
	0: Selected
	1: Not Selected
	2: And Selected
	3: Or Selected
	4: And Not Selected
	5: Or Not Selected
*/
static void
hostlist_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
 	int action, type;
	int selection;
	hostlist_table *hl=(hostlist_table *)callback_data;
	char dirstr[128];
	char str[256];
	const char *current_filter;
	char *sport;

	action = (callback_action>>8)&0xff;
	type = callback_action&0xff;

	selection=GPOINTER_TO_INT(g_list_nth_data(GTK_CLIST(hl->table)->selection, 0));
	if(selection>=(int)hl->num_hosts){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No hostlist selected");
		return;
	}
	/* translate it back from row index to index in hostlist array */
	selection=GPOINTER_TO_INT(gtk_clist_get_row_data(hl->table, selection));

	sport=hostlist_port_to_str(hl->hosts[selection].port_type, hl->hosts[selection].port);

	g_snprintf(dirstr, 127, "%s==%s %s%s%s%s",
		hostlist_get_filter_name(&hl->hosts[selection].address,
		hl->hosts[selection].sat, hl->hosts[selection].port_type,  FN_ANY_ADDRESS),
		address_to_str(&hl->hosts[selection].address),
		sport?" && ":"",
		sport?hostlist_get_filter_name(&hl->hosts[selection].address, hl->hosts[selection].sat, hl->hosts[selection].port_type,  FN_ANY_PORT):"",
		sport?"==":"",
		sport?sport:"");

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
		/* find frame */
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
		/* colorize host traffic */
		color_display_with_filter(str);
		break;
	}
}
static gint
hostlist_show_popup_menu_cb(void *widg _U_, GdkEvent *event, hostlist_table *et)
{
    GdkEventButton *bevent = (GdkEventButton *)event;
    gint row;
    gint column;

    /* To qoute the "Gdk Event Structures" doc:
     * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
    if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
        /* if this is a right click on one of our columns, select it and popup the context menu */
        if(gtk_clist_get_selection_info(et->table,
                                          (gint) (((GdkEventButton *)event)->x),
                                          (gint) (((GdkEventButton *)event)->y),
                                             &row, &column)) {
            gtk_clist_unselect_all(et->table);
            gtk_clist_select_row(et->table, row, -1);

            gtk_menu_popup(GTK_MENU(et->menu), NULL, NULL, NULL, NULL,
                bevent->button, bevent->time);
        }
    }

    return FALSE;
}

static GtkItemFactoryEntry hostlist_list_menu_items[] =
{
	/* Match */
	ITEM_FACTORY_ENTRY("/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected", NULL,
		hostlist_select_filter_cb, 0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Not Selected", NULL,
		hostlist_select_filter_cb, 0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and Selected", NULL,
		hostlist_select_filter_cb, 0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected", NULL,
		hostlist_select_filter_cb, 0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected", NULL,
		hostlist_select_filter_cb, 0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected", NULL,
		hostlist_select_filter_cb, 0*256+5, NULL, NULL),

	/* Prepare */
	ITEM_FACTORY_ENTRY("/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected", NULL,
		hostlist_select_filter_cb, 1*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected", NULL,
		hostlist_select_filter_cb, 1*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected", NULL,
		hostlist_select_filter_cb, 1*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected", NULL,
		hostlist_select_filter_cb, 1*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected", NULL,
		hostlist_select_filter_cb, 1*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected", NULL,
		hostlist_select_filter_cb, 1*256+5, NULL, NULL),

	/* Find Frame */
	ITEM_FACTORY_ENTRY("/Find Frame", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Find Frame/Find Frame", NULL,
		hostlist_select_filter_cb, 2*256+0, NULL, NULL),
	/* Find Next */
	ITEM_FACTORY_ENTRY("/Find Frame/Find Next", NULL,
		hostlist_select_filter_cb, 3*256+0, NULL, NULL),
	/* Find Previous */
	ITEM_FACTORY_ENTRY("/Find Frame/Find Previous", NULL,
		hostlist_select_filter_cb, 4*256+0, NULL, NULL),
	/* Colorize Host Traffic */
	ITEM_FACTORY_ENTRY("/Colorize Host Traffic", NULL,
		hostlist_select_filter_cb, 5*256+0, NULL, NULL),

};

static void
hostlist_create_popup_menu(hostlist_table *hl)
{
    GtkItemFactory *item_factory;

    item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

    gtk_item_factory_create_items_ac(item_factory, sizeof(hostlist_list_menu_items)/sizeof(hostlist_list_menu_items[0]), hostlist_list_menu_items, hl, 2);

    hl->menu = gtk_item_factory_get_widget(item_factory, "<main>");
    SIGNAL_CONNECT(hl->table, "button_press_event", hostlist_show_popup_menu_cb, hl);
}


/* Draw/refresh the address field of a single entry at the specified index */
static void
draw_hostlist_table_address(hostlist_table *hl, int hostlist_idx)
{
    const char *entry;
    char *port;
    guint32 pt;
    int rownum;

    rownum=gtk_clist_find_row_from_data(hl->table, (gpointer)hostlist_idx);

    if (!hl->resolve_names)
        entry=address_to_str(&hl->hosts[hostlist_idx].address);
    else
        entry=get_addr_name(&hl->hosts[hostlist_idx].address);

		gtk_clist_set_text(hl->table, rownum, 0, entry);

    pt = hl->hosts[hostlist_idx].port_type;
    if(!hl->resolve_names) pt = PT_NONE;
    switch(pt) {
    case(PT_TCP):
        entry=get_tcp_port(hl->hosts[hostlist_idx].port);
        break;
    case(PT_UDP):
        entry=get_udp_port(hl->hosts[hostlist_idx].port);
        break;
    default:
        port=hostlist_port_to_str(hl->hosts[hostlist_idx].port_type, hl->hosts[hostlist_idx].port);
        entry=port?port:"";
    }
    gtk_clist_set_text(hl->table, rownum, 1, entry);
}

/* Refresh the address fields of all entries in the list */
static void
draw_hostlist_table_addresses(hostlist_table *hl)
{
    guint32 i;

    for(i=0;i<hl->num_hosts;i++){
        draw_hostlist_table_address(hl, i);
    }
}


static void
draw_hostlist_table_data(hostlist_table *hl)
{
    guint32 i;
    int j;
    char title[256];

    if (hl->page_lb) {
        if(hl->num_hosts) {
            g_snprintf(title, 255, "%s: %u", hl->name, hl->num_hosts);
        } else {
            g_snprintf(title, 255, "%s", hl->name);
        }
        gtk_label_set_text(GTK_LABEL(hl->page_lb), title);
        gtk_widget_set_sensitive(hl->page_lb, hl->num_hosts);
    }

    for(i=0;i<hl->num_hosts;i++){
        char str[16];

        j=gtk_clist_find_row_from_data(hl->table, (gpointer)i);

        g_snprintf(str, 16, "%" PRIu64, hl->hosts[i].tx_frames+hl->hosts[i].rx_frames);
        gtk_clist_set_text(hl->table, j, 2, str);
        g_snprintf(str, 16, "%" PRIu64, hl->hosts[i].tx_bytes+hl->hosts[i].rx_bytes);
        gtk_clist_set_text(hl->table, j, 3, str);


        g_snprintf(str, 16, "%" PRIu64, hl->hosts[i].tx_frames);
        gtk_clist_set_text(hl->table, j, 4, str);
        g_snprintf(str, 16, "%" PRIu64, hl->hosts[i].tx_bytes);
        gtk_clist_set_text(hl->table, j, 5, str);


        g_snprintf(str, 16, "%" PRIu64, hl->hosts[i].rx_frames);
        gtk_clist_set_text(hl->table, j, 6, str);
        g_snprintf(str, 16, "%" PRIu64, hl->hosts[i].rx_bytes);
        gtk_clist_set_text(hl->table, j, 7, str);

    }
	
    draw_hostlist_table_addresses(hl);
	
    gtk_clist_sort(hl->table);

    /* Allow table to redraw. */
    gtk_clist_thaw(hl->table);
    gtk_clist_freeze(hl->table);
}

static void
draw_hostlist_table_data_cb(void *arg)
{
    draw_hostlist_table_data(arg);
}

#if (GTK_MAJOR_VERSION >= 2)
static void
copy_as_csv_cb(GtkWindow *win _U_, gpointer data)
{
   guint32         i,j;
   gchar           *table_entry;
   GtkClipboard    *cb;  
   GString         *CSV_str = g_string_new("");
   
   hostlist_table *hosts=(hostlist_table *)data;
   
   /* Add the column headers to the CSV data */
   for(i=0;i<hosts->num_columns;i++){                  /* all columns         */
    if(i==1 && !hosts->has_ports) continue;            /* Don't add the port column if it's empty */
     g_string_append(CSV_str,hosts->default_titles[i]);/* add the column heading to the CSV string */
    if(i!=hosts->num_columns-1)
     g_string_append(CSV_str,",");
   }
   g_string_append(CSV_str,"\n");                      /* new row */
 
   /* Add the column values to the CSV data */
   for(i=0;i<hosts->num_hosts;i++){                    /* all rows            */
    for(j=0;j<hosts->num_columns;j++){                 /* all columns         */
     if(j==1 && !hosts->has_ports) continue;           /* Don't add the port column if it's empty */
     gtk_clist_get_text(hosts->table,i,j,&table_entry);/* copy table item into string */
     g_string_append(CSV_str,table_entry);             /* add the table entry to the CSV string */
    if(j!=hosts->num_columns-1)
     g_string_append(CSV_str,",");
    } 
    g_string_append(CSV_str,"\n");                     /* new row */  
   }

   /* Now that we have the CSV data, copy it into the default clipboard */
   cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);    /* Get the default clipboard */
   gtk_clipboard_set_text(cb, CSV_str->str, -1);       /* Copy the CSV data into the clipboard */
   g_string_free(CSV_str, TRUE);                       /* Free the memory */
} 
#endif


static gboolean
init_hostlist_table_page(hostlist_table *hosttable, GtkWidget *vbox, gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    int i;
    column_arrows *col_arrows;
    GtkStyle *win_style;
    GtkWidget *column_lb;
    GString *error_string;
    char title[256];
#if (GTK_MAJOR_VERSION >= 2)
    GtkWidget *copy_bt;
    GtkTooltips *tooltips = gtk_tooltips_new();
#endif           


    hosttable->num_columns=NUM_COLS; 
    hosttable->default_titles[0] = "Address";
    hosttable->default_titles[1] = "Port";
    hosttable->default_titles[2] = "Packets";
    hosttable->default_titles[3] = "Bytes";
    hosttable->default_titles[4] = "Tx Packets";
    hosttable->default_titles[5] = "Tx Bytes";
    hosttable->default_titles[6] = "Rx Packets";
    hosttable->default_titles[7] = "Rx Bytes";
    hosttable->has_ports=!hide_ports;
    hosttable->num_hosts = 0;
    hosttable->resolve_names=TRUE;

    g_snprintf(title, 255, "%s Endpoints", table_name); 
    hosttable->page_lb = gtk_label_new(title);                                                 
    gtk_box_pack_start(GTK_BOX(vbox), hosttable->page_lb, FALSE, FALSE, 0);

    hosttable->scrolled_window=scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), hosttable->scrolled_window, TRUE, TRUE, 0);

    hosttable->table=(GtkCList *)gtk_clist_new(NUM_COLS);

    col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_COLS);
    win_style = gtk_widget_get_style(hosttable->scrolled_window);
    for (i = 0; i < NUM_COLS; i++) {
        col_arrows[i].table = gtk_table_new(2, 2, FALSE);
        gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
        column_lb = gtk_label_new(hosttable->default_titles[i]);
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
        gtk_clist_set_column_widget(GTK_CLIST(hosttable->table), i, col_arrows[i].table);
        gtk_widget_show(col_arrows[i].table);
    }
    gtk_clist_column_titles_show(GTK_CLIST(hosttable->table));

    gtk_clist_set_compare_func(hosttable->table, hostlist_sort_column);
    gtk_clist_set_sort_column(hosttable->table, 4);
    gtk_clist_set_sort_type(hosttable->table, GTK_SORT_DESCENDING);

    gtk_clist_set_column_auto_resize(hosttable->table, 0, TRUE);
    gtk_clist_set_column_auto_resize(hosttable->table, 1, TRUE);
    gtk_clist_set_column_auto_resize(hosttable->table, 2, TRUE);
    gtk_clist_set_column_auto_resize(hosttable->table, 3, TRUE);
    gtk_clist_set_column_auto_resize(hosttable->table, 4, TRUE);
    gtk_clist_set_column_auto_resize(hosttable->table, 5, TRUE);
    gtk_clist_set_column_auto_resize(hosttable->table, 6, TRUE);
    gtk_clist_set_column_auto_resize(hosttable->table, 7, TRUE);

    gtk_clist_set_shadow_type(hosttable->table, GTK_SHADOW_IN);
    gtk_clist_column_titles_show(hosttable->table);
    gtk_container_add(GTK_CONTAINER(hosttable->scrolled_window), (GtkWidget *)hosttable->table);

    SIGNAL_CONNECT(hosttable->table, "click-column", hostlist_click_column_cb, col_arrows);

    hosttable->num_hosts=0;
    hosttable->hosts=NULL;

    /* hide srcport and dstport if we don't use ports */
    if(hide_ports){
        gtk_clist_set_column_visibility(hosttable->table, 1, FALSE);
    }

    /* create popup menu for this table */
    hostlist_create_popup_menu(hosttable);

#if (GTK_MAJOR_VERSION >= 2)
    /* XXX - maybe we want to have a "Copy as CSV" stock button here? */
    /*copy_bt = gtk_button_new_with_label ("Copy content to clipboard as CSV");*/
    copy_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_COPY);
    gtk_tooltips_set_tip(tooltips, copy_bt, 
        "Copy all statistical values of this page to the clipboard in CSV (Comma Seperated Values) format.", NULL);
    SIGNAL_CONNECT(copy_bt, "clicked", copy_as_csv_cb,(gpointer *) hosttable);
    gtk_box_pack_start(GTK_BOX(vbox), copy_bt, FALSE, FALSE, 0);
#endif

    /* register the tap and rerun the taps on the packet list */
    error_string=register_tap_listener(tap_name, hosttable, filter, reset_hostlist_table_data_cb, packet_func, draw_hostlist_table_data_cb);
    if(error_string){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
        g_string_free(error_string, TRUE);
        g_free(hosttable);
        return FALSE;
    }

    return TRUE;
}


void
init_hostlist_table(gboolean hide_ports, const char *table_name, const char *tap_name, const char *filter, tap_packet_cb packet_func)
{
    hostlist_table *hosttable;
    char title[256];
    GtkWidget *vbox;
    GtkWidget *bbox;
    GtkWidget *close_bt, *help_bt;
    gboolean ret;


    hosttable=g_malloc(sizeof(hostlist_table));

    hosttable->name=table_name;
    g_snprintf(title, 255, "%s Endpoints: %s", table_name, cf_get_display_name(&cfile));
    hosttable->win=window_new(GTK_WINDOW_TOPLEVEL, title);
    
    gtk_window_set_default_size(GTK_WINDOW(hosttable->win), 750, 400);

    vbox=gtk_vbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(hosttable->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    ret = init_hostlist_table_page(hosttable, vbox, hide_ports, table_name, tap_name, filter, packet_func);
    if(ret == FALSE) {
        g_free(hosttable);
        return;
    }

    /* Button row. */
    if(topic_available(HELP_STATS_ENDPOINTS_DIALOG)) {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    } else {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    }
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(hosttable->win, close_bt, window_cancel_button_cb);

    if(topic_available(HELP_STATS_ENDPOINTS_DIALOG)) {
        help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
        SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_STATS_ENDPOINTS_DIALOG);
    }

    SIGNAL_CONNECT(hosttable->win, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(hosttable->win, "destroy", hostlist_win_destroy_cb, hosttable);

    gtk_widget_show_all(hosttable->win);
    window_present(hosttable->win);

    cf_retap_packets(&cfile, FALSE);
	
    /* Keep clist frozen to cause modifications to the clist (inserts, appends, others that are extremely slow
	   in GTK2) to not be drawn, allow refreshes to occur at strategic points for performance */
  	gtk_clist_freeze(hosttable->table);


    /* after retapping, redraw table */
    draw_hostlist_table_data(hosttable);
}


static void
hostlist_win_destroy_notebook_cb(GtkWindow *win _U_, gpointer data)
{
    void ** pages = data;
    int page;

    /* first "page" contains the number of pages */
    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        hostlist_win_destroy_cb(NULL, pages[page]);
    }
}




static hostlist_table *
init_hostlist_notebook_page_cb(gboolean hide_ports, char *table_name, char *tap_name, char *filter, tap_packet_cb packet_func)
{
    gboolean ret;
    GtkWidget *page_vbox;
    hostlist_table *hosttable;

    hosttable=g_malloc(sizeof(hostlist_table));
    hosttable->name=table_name;
    hosttable->resolve_names=TRUE;

    page_vbox=gtk_vbox_new(FALSE, 6);
    hosttable->win = page_vbox;
    gtk_container_set_border_width(GTK_CONTAINER(page_vbox), 6);

    ret = init_hostlist_table_page(hosttable, page_vbox, hide_ports, table_name, tap_name, filter, packet_func);
    if(ret == FALSE) {
        g_free(hosttable);
        return NULL;
    }

    return hosttable;
}


typedef struct {
    gboolean hide_ports;       /* hide TCP / UDP port columns */
    char *table_name;          /* GUI output name */
    char *tap_name;            /* internal name */
    char *filter;              /* display filter string (unused) */
    tap_packet_cb packet_func; /* function to be called for new incoming packets */
} register_hostlist_t;


static GSList *registered_hostlist_tables = NULL;

void
register_hostlist_table(gboolean hide_ports, char *table_name, char *tap_name, char *filter, tap_packet_cb packet_func)
{
    register_hostlist_t *table;

    table = g_malloc(sizeof(register_hostlist_t));

    table->hide_ports   = hide_ports;
    table->table_name   = table_name;
    table->tap_name     = tap_name;
    table->filter       = filter;
    table->packet_func  = packet_func;

    registered_hostlist_tables = g_slist_append(registered_hostlist_tables, table);
}


static void
hostlist_resolve_toggle_dest(GtkWidget *widget, gpointer data)
{
    int page;
    void ** pages = data;
    gboolean resolve_names;
    hostlist_table *hosttable;


    resolve_names = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));

    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        hosttable = pages[page];
        hosttable->resolve_names = resolve_names;

        draw_hostlist_table_addresses(hosttable);

        gtk_clist_thaw(hosttable->table);
        gtk_clist_freeze(hosttable->table);
    }
}


void
init_hostlist_notebook_cb(GtkWidget *w _U_, gpointer d _U_)
{
    hostlist_table *hosttable;
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
    register_hostlist_t *registered;
    GtkTooltips *tooltips = gtk_tooltips_new();


    pages = g_malloc(sizeof(void *) * (g_slist_length(registered_hostlist_tables) + 1));

    win=window_new(GTK_WINDOW_TOPLEVEL, "hostlist");
    g_snprintf(title, 255, "Endpoints: %s", cf_get_display_name(&cfile));
    gtk_window_set_title(GTK_WINDOW(win), title);
    gtk_window_set_default_size(GTK_WINDOW(win), 750, 400);

    vbox=gtk_vbox_new(FALSE, 6);
    gtk_container_add(GTK_CONTAINER(win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    nb = gtk_notebook_new();
    gtk_container_add(GTK_CONTAINER(vbox), nb);

    page = 0;

    current_table = registered_hostlist_tables;
    while(current_table) {
        registered = current_table->data;
        page_lb = gtk_label_new("");
        hosttable = init_hostlist_notebook_page_cb(registered->hide_ports, registered->table_name, registered->tap_name,
            registered->filter, registered->packet_func);
        gtk_notebook_append_page(GTK_NOTEBOOK(nb), hosttable->win, page_lb);
        hosttable->win = win;
        hosttable->page_lb = page_lb;
        pages[++page] = hosttable;

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

    SIGNAL_CONNECT(resolv_cb, "toggled", hostlist_resolve_toggle_dest, pages);

    /* Button row. */
    if(topic_available(HELP_STATS_ENDPOINTS_DIALOG)) {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    } else {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    }
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(win, close_bt, window_cancel_button_cb);

    if(topic_available(HELP_STATS_ENDPOINTS_DIALOG)) {
        help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
        SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_STATS_ENDPOINTS_DIALOG);
    }

    SIGNAL_CONNECT(win, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(win, "destroy", hostlist_win_destroy_notebook_cb, pages);

    gtk_widget_show_all(win);
    window_present(win);

    cf_retap_packets(&cfile, FALSE);

    /* after retapping, redraw table */
    for (page=1; page<=GPOINTER_TO_INT(pages[0]); page++) {
        draw_hostlist_table_data(pages[page]);
    }
}



void
add_hostlist_table_data(hostlist_table *hl, const address *addr, guint32 port, gboolean sender, int num_frames, int num_bytes, SAT_E sat, int port_type)
{
    hostlist_talker_t *talker=NULL;
    int talker_idx=0;
    gboolean new_talker;

    new_talker=FALSE;
    /* XXX should be optimized to allocate n extra entries at a time
       instead of just one */
    /* if we dont have any entries at all yet */
    if(hl->hosts==NULL){
        hl->hosts=g_malloc(sizeof(hostlist_talker_t));
        hl->num_hosts=1;
        talker=&hl->hosts[0];
        talker_idx=0;
        new_talker=TRUE;
    }

    /* try to find it among the existing known hosts */
    if(talker==NULL){
        guint32 i;
        for(i=0;i<hl->num_hosts;i++){
            if(  (!CMP_ADDRESS(&hl->hosts[i].address, addr))&&(hl->hosts[i].port==port) ){
                talker=&hl->hosts[i];
                talker_idx=i;
                break;
            }
        }
    }

    /* if we still dont know what talker this is it has to be a new one
       and we have to allocate it and append it to the end of the list */
    if(talker==NULL){
        new_talker=TRUE;
        hl->num_hosts++;
        hl->hosts=g_realloc(hl->hosts, hl->num_hosts*sizeof(hostlist_talker_t));
        talker=&hl->hosts[hl->num_hosts-1];
        talker_idx=hl->num_hosts-1;
    }

    /* if this is a new talker we need to initialize the struct */
    if(new_talker){
        COPY_ADDRESS(&talker->address, addr);
        talker->sat=sat;
        talker->port_type=port_type;
        talker->port=port;
        talker->rx_frames=0;
        talker->tx_frames=0;
        talker->rx_bytes=0;
        talker->tx_bytes=0;
    }

    /* update the talker struct */
    if( sender ){
        talker->tx_frames+=num_frames;
        talker->tx_bytes+=num_bytes;
    } else {
        talker->rx_frames+=num_frames;
        talker->rx_bytes+=num_bytes;
    }

    /* if this was a new talker we have to create a clist row for it */
    if(new_talker){
        char *entries[NUM_COLS];
        char frames[16],bytes[16],txframes[16],txbytes[16],rxframes[16],rxbytes[16];

        /* these values will be filled by call to draw_hostlist_table_addresses() below */
        entries[0]="";
        entries[1]="";

        g_snprintf(frames, 16, "%" PRIu64, talker->tx_frames+talker->rx_frames);
        entries[2]=frames;
        g_snprintf(bytes, 16, "%" PRIu64, talker->tx_bytes+talker->rx_bytes);
        entries[3]=bytes;

        g_snprintf(txframes, 16, "%" PRIu64, talker->tx_frames);
        entries[4]=txframes;
        g_snprintf(txbytes, 16, "%" PRIu64, talker->tx_bytes);
        entries[5]=txbytes;

        g_snprintf(rxframes, 16, "%" PRIu64, talker->rx_frames);
        entries[6]=rxframes;
        g_snprintf(rxbytes, 16, "%" PRIu64, talker->rx_bytes);
        entries[7]=rxbytes;

        gtk_clist_insert(hl->table, talker_idx, entries);
        gtk_clist_set_row_data(hl->table, talker_idx, (gpointer) talker_idx);

		draw_hostlist_table_address(hl, talker_idx);
    }
}
