/* hostlist_table.c   2004 Ian Schorr
 * modified from endpoint_talkers_table.c   2003 Ronnie Sahlberg
 * Helper routines common to all host list taps.
 *
 * $Id: hostlist_table.c,v 1.4 2004/02/23 22:48:51 guy Exp $
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
#include "compat_macros.h"
#include "epan/packet_info.h"
#include "epan/to_str.h"
#include "hostlist_table.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"
#include "globals.h"
#include "tap.h"
#include "gtk/find_dlg.h"
#include "color.h"
#include "gtk/color_dlg.h"
#include "gtkglobals.h"
#include "main.h"
#include "ui_util.h"

extern GtkWidget   *main_display_filter_widget;


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
		snprintf(strp, 11, "%d", port);
		return strp;
	}
	return NULL;
}


#define FN_ANY_ADDRESS		0
#define FN_ANY_PORT		1

/* given an address (to distinguis between ipv4 and ipv6 for tcp/udp
   a port_type and a name_type (FN_...)
   return a string for the filter name

   some addresses, like AT_ETHER may actually be any of multiple types
   of protocols,   either ethernet, tokenring, fddi etc so we must be more 
   specific there  thats why we need specific_addr_type
*/
static char *
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
			}
		case AT_IPv4:
			return "ip.addr";
		case AT_IPv6:
			return "ipv6.addr";
		case AT_IPX:
			return "ipx.addr";
		case AT_FC:
			return "fc.id";
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

	snprintf(title, 255, "%s: %s", hosts->name, cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(hosts->win), title);

	/* remove all entries from the clist */
	for(i=0;i<hosts->num_hosts;i++){
		gtk_clist_remove(hosts->table, hosts->num_hosts-i);
	}

	/* delete all hosts */
	for(i=0;i<hosts->num_hosts;i++){
		g_free((gpointer)hosts->hosts[i].src_address.data);
	}
	g_free(hosts->hosts);
	hosts->hosts=NULL;
	hosts->num_hosts=0;
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
	int i1, i2;

	GtkCListRow *row1 = (GtkCListRow *) ptr1;
	GtkCListRow *row2 = (GtkCListRow *) ptr2;

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
		i1=atoi(text1);
		i2=atoi(text2);
		return i1-i2;
	}
	g_assert_not_reached();
	return 0;
}

static void
hostlist_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
	column_arrows *col_arrows = (column_arrows *) data;
	int i;

	gtk_clist_freeze(clist);

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
	gtk_clist_thaw(clist);

	gtk_clist_sort(clist);
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
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No conversation selected");
		return;
	}
	/* translate it back from row index to index in hostlist array */
	selection=GPOINTER_TO_INT(gtk_clist_get_row_data(hl->table, selection));

	sport=hostlist_port_to_str(hl->hosts[selection].port_type, hl->hosts[selection].src_port);

	snprintf(dirstr, 127, "%s==%s %s%s%s%s",
		hostlist_get_filter_name(&hl->hosts[selection].src_address, 
		hl->hosts[selection].sat, hl->hosts[selection].port_type,  FN_ANY_ADDRESS),
		address_to_str(&hl->hosts[selection].src_address),
		sport?" && ":"",
		sport?hostlist_get_filter_name(&hl->hosts[selection].src_address, hl->hosts[selection].sat, hl->hosts[selection].port_type,  FN_ANY_PORT):"",
		sport?"==":"",
		sport?sport:"");

	current_filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	switch(type){
	case 0:
		/* selected */
		snprintf(str, 255, "%s", dirstr);
		break;
	case 1:
		/* not selected */
		snprintf(str, 255, "!(%s)", dirstr);
		break;
	case 2:
		/* and selected */
		snprintf(str, 255, "(%s) && (%s)", current_filter, dirstr);
		break;
	case 3:
		/* or selected */
		snprintf(str, 255, "(%s) || (%s)", current_filter, dirstr);
		break;
	case 4:
		/* and not selected */
		snprintf(str, 255, "(%s) && !(%s)", current_filter, dirstr);
		break;
	case 5:
		/* or not selected */
		snprintf(str, 255, "(%s) || !(%s)", current_filter, dirstr);
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

	if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
		gtk_menu_popup(GTK_MENU(et->menu), NULL, NULL, NULL, NULL, 
			bevent->button, bevent->time);
	}

	return FALSE;
}

static GtkItemFactoryEntry hostlist_list_menu_items[] =
{
	/* Match */
	ITEM_FACTORY_ENTRY("/Match Display Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected", NULL, 
		hostlist_select_filter_cb, 0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected", NULL, 
		hostlist_select_filter_cb, 0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected", NULL, 
		hostlist_select_filter_cb, 0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected", NULL, 
		hostlist_select_filter_cb, 0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected", NULL, 
		hostlist_select_filter_cb, 0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected", NULL, 
		hostlist_select_filter_cb, 0*256+5, NULL, NULL),

	/* Prepare */
	ITEM_FACTORY_ENTRY("/Prepare Display Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected", NULL, 
		hostlist_select_filter_cb, 1*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected", NULL, 
		hostlist_select_filter_cb, 1*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected", NULL, 
		hostlist_select_filter_cb, 1*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected", NULL, 
		hostlist_select_filter_cb, 1*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected", NULL, 
		hostlist_select_filter_cb, 1*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected", NULL, 
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
	hl->item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

	gtk_item_factory_create_items_ac(hl->item_factory, sizeof(hostlist_list_menu_items)/sizeof(hostlist_list_menu_items[0]), hostlist_list_menu_items, hl, 2);

	hl->menu = gtk_item_factory_get_widget(hl->item_factory, "<main>");
	SIGNAL_CONNECT(hl->table, "button_press_event", hostlist_show_popup_menu_cb, hl);
}



/* XXX should freeze/thaw table here and in the srt thingy? */
static void 
draw_hostlist_table_data(hostlist_table *hl)
{
	guint32 i;
	int j;

	for(i=0;i<hl->num_hosts;i++){
		char str[16];

		j=gtk_clist_find_row_from_data(hl->table, (gpointer)i);

		sprintf(str, "%u", hl->hosts[i].tx_frames+hl->hosts[i].rx_frames);
		gtk_clist_set_text(hl->table, j, 2, str);		
		sprintf(str, "%u", hl->hosts[i].tx_bytes+hl->hosts[i].rx_bytes);
		gtk_clist_set_text(hl->table, j, 3, str);		


		sprintf(str, "%u", hl->hosts[i].tx_frames);
		gtk_clist_set_text(hl->table, j, 4, str);	
		sprintf(str, "%u", hl->hosts[i].tx_bytes);
		gtk_clist_set_text(hl->table, j, 5, str);		


		sprintf(str, "%u", hl->hosts[i].rx_frames);
		gtk_clist_set_text(hl->table, j, 6, str);		
		sprintf(str, "%u", hl->hosts[i].rx_bytes);
		gtk_clist_set_text(hl->table, j, 7, str);		

	}
	gtk_clist_sort(hl->table);
}

void
init_hostlist_table(gboolean hide_ports, char *table_name, char *tap_name, char *filter, void *packet_func)
{
	int i;
	column_arrows *col_arrows;
	GdkBitmap *ascend_bm, *descend_bm;
	GdkPixmap *ascend_pm, *descend_pm;
	GtkStyle *win_style;
	GtkWidget *column_lb;
	GString *error_string;
	hostlist_table *hosttable;
	GtkWidget *vbox;
	GtkWidget *label;
	char title[256];
	char *default_titles[] = { "Address", "Port", "Frames", "Bytes", "Tx Frames", "Tx Bytes", "Rx Frames", "Rx Bytes" };


	hosttable=g_malloc(sizeof(hostlist_table));

	hosttable->name=table_name;
	hosttable->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(hosttable->win), 750, 400);
	snprintf(title, 255, "%s: %s", table_name, cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(hosttable->win), title);

	SIGNAL_CONNECT(hosttable->win, "destroy", hostlist_win_destroy_cb, hosttable);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(hosttable->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new(table_name);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_hostlist_table() */
	gtk_widget_show(hosttable->win);


	hosttable->scrolled_window=scrolled_window_new(NULL, NULL);
	gtk_box_pack_start(GTK_BOX(vbox), hosttable->scrolled_window, TRUE, TRUE, 0);

	hosttable->table=(GtkCList *)gtk_clist_new(NUM_COLS);

	gtk_widget_show(GTK_WIDGET(hosttable->table));
	gtk_widget_show(hosttable->scrolled_window);

	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_COLS);
	win_style = gtk_widget_get_style(hosttable->scrolled_window);
	ascend_pm = gdk_pixmap_create_from_xpm_d(hosttable->scrolled_window->window,
			&ascend_bm,
			&win_style->bg[GTK_STATE_NORMAL],
			(gchar **)clist_ascend_xpm);
	descend_pm = gdk_pixmap_create_from_xpm_d(hosttable->scrolled_window->window,
			&descend_bm,
			&win_style->bg[GTK_STATE_NORMAL],
			(gchar **)clist_descend_xpm);
	for (i = 0; i < NUM_COLS; i++) {
		col_arrows[i].table = gtk_table_new(2, 2, FALSE);
		gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
		column_lb = gtk_label_new(default_titles[i]);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		gtk_widget_show(column_lb);

		col_arrows[i].ascend_pm = gtk_pixmap_new(ascend_pm, ascend_bm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		col_arrows[i].descend_pm = gtk_pixmap_new(descend_pm, descend_bm);
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


	/*XXX instead of this we should probably have some code to
		dynamically adjust the width of the columns */
	gtk_clist_set_column_width(hosttable->table, 0, 100);
	gtk_clist_set_column_width(hosttable->table, 1, 40);
	gtk_clist_set_column_width(hosttable->table, 2, 70);
	gtk_clist_set_column_width(hosttable->table, 3, 60);
	gtk_clist_set_column_width(hosttable->table, 4, 70);
	gtk_clist_set_column_width(hosttable->table, 5, 60);
	gtk_clist_set_column_width(hosttable->table, 6, 70);
	gtk_clist_set_column_width(hosttable->table, 7, 60);


	gtk_clist_set_shadow_type(hosttable->table, GTK_SHADOW_IN);
	gtk_clist_column_titles_show(hosttable->table);
	gtk_container_add(GTK_CONTAINER(hosttable->scrolled_window), (GtkWidget *)hosttable->table);

	SIGNAL_CONNECT(hosttable->table, "click-column", hostlist_click_column_cb, col_arrows);

	gtk_widget_show(GTK_WIDGET(hosttable->table));
	gtk_widget_show(hosttable->scrolled_window);

	hosttable->num_hosts=0;
	hosttable->hosts=NULL;

	/* hide srcport and dstport if we don't use ports */
	if(hide_ports){
		gtk_clist_set_column_visibility(hosttable->table, 1, FALSE);
	}

	/* create popup menu for this table */
	hostlist_create_popup_menu(hosttable);


	/* register the tap and rerun the taps on the packet list */
	error_string=register_tap_listener(tap_name, hosttable, filter, (void *)reset_hostlist_table_data, packet_func, (void *)draw_hostlist_table_data);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(hosttable);
		return;
	}

	gtk_widget_show_all(hosttable->win);
	retap_packets(&cfile);

}

void 
add_hostlist_table_data(hostlist_table *hl, address *addr, guint32 src_port, gboolean sender, int num_frames, int num_bytes, int sat, int port_type)
{
	address *addr1;
	guint32 port1;
	hostlist_talker_t *talker=NULL;
	int talker_idx=0;
	gboolean new_talker;
	
	addr1=addr;
	port1=src_port;

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
			if(  (!CMP_ADDRESS(&hl->hosts[i].src_address, addr1))&&(hl->hosts[i].src_port==port1) ){
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
		COPY_ADDRESS(&talker->src_address, addr1);
		talker->sat=sat;
		talker->port_type=port_type;
		talker->src_port=port1;
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
		char *sport;
		char frames[16],bytes[16],txframes[16],txbytes[16],rxframes[16],rxbytes[16];

		sport=hostlist_port_to_str(talker->port_type, talker->src_port);

		entries[0]=address_to_str(&talker->src_address);
		entries[1]=sport?sport:"";

		sprintf(frames,"%u", talker->tx_frames+talker->rx_frames);
		entries[2]=frames;
		sprintf(bytes,"%u", talker->tx_bytes+talker->rx_bytes);
		entries[3]=bytes;

		sprintf(txframes,"%u", talker->tx_frames);
		entries[4]=txframes;
		sprintf(txbytes,"%u", talker->tx_bytes);
		entries[5]=txbytes;

		sprintf(rxframes,"%u", talker->rx_frames);
		entries[6]=rxframes;
		sprintf(rxbytes,"%u", talker->rx_bytes);
		entries[7]=rxbytes;

		gtk_clist_insert(hl->table, talker_idx, entries);
		gtk_clist_set_row_data(hl->table, talker_idx, (gpointer) talker_idx);
	}

}

