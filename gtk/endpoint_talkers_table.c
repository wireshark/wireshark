/* mem leak   should free the column_arrows when the table is destroyed */

/* endpoint_talkers_table.c
 * endpoint_talkers_table   2003 Ronnie Sahlberg
 * Helper routines common to all endpoint talkers tap.
 *
 * $Id: endpoint_talkers_table.c,v 1.10 2003/09/02 08:27:26 sahlberg Exp $
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
#include "epan/filesystem.h"
#include "epan/to_str.h"
#include "endpoint_talkers_table.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"
#include "globals.h"
#include "tap.h"

extern GtkWidget   *main_display_filter_widget;

#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

#define NUM_COLS 10

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
void
ett_win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	endpoints_table *talkers=(endpoints_table *)data;

	protect_thread_critical_region();
	remove_tap_listener(talkers);
	unprotect_thread_critical_region();

	reset_ett_table_data(talkers);
	g_free(talkers);
}



void
reset_ett_table_data(endpoints_table *et)
{
	guint32 i;
	char title[256];

	snprintf(title, 255, "%s Conversations: %s", et->name, get_basename(cfile.filename));
	gtk_window_set_title(GTK_WINDOW(et->win), title);

	/* remove all entries from the clist */
	for(i=0;i<et->num_endpoints;i++){
		gtk_clist_remove(et->table, et->num_endpoints-1-i);
	}

	/* delete all endpoints */
	for(i=0;i<et->num_endpoints;i++){
		g_free((gpointer)et->endpoints[i].src_address.data);
		g_free((gpointer)et->endpoints[i].dst_address.data);
	}
	g_free(et->endpoints);
	et->endpoints=NULL;
	et->num_endpoints=0;
}


static gint
ett_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
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
	case 8:
	case 9:
		i1=atoi(text1);
		i2=atoi(text2);
		return i1-i2;
	}
	g_assert_not_reached();
	return 0;
}


static void
ett_click_column_cb(GtkCList *clist, gint column, gpointer data)
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
   filter_action*65536+filter_type*256+filter_direction

   filter_action:
	0: Match
	1: Prepare
   filter_type:
	0: Selected
	1: Not Selected
	2: And Selected
	3: Or Selected
	4: And Not Selected
	5: Or Not Selected
   filter_direction:
	0: EP1 To/From EP2
	1: EP1 To EP2
	2: EP1 From EP2
	3: EP1 To/From ANY
	4: EP1 To ANY
	5: EP1 From ANY
6: EP1 To/From ANY
	7: EP2 To ANY
	8: EP2 From ANY
*/
static void
ett_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
	int action, type, direction;
	int selection;
	endpoints_table *et = (endpoints_table *)callback_data;
	char dirstr[128];
	char str[256];
	char *current_filter;

	action=(callback_action>>16)&0xff;
	type=(callback_action>>8)&0xff;
	direction=callback_action&0xff;


	selection=GPOINTER_TO_INT(g_list_nth_data(GTK_CLIST(et->table)->selection, 0));
	if(selection>=(int)et->num_endpoints){
		simple_dialog(ESD_TYPE_WARN, NULL, "No conversation selected");
		return;
	}
	/* translate it back from row index to index in enndpoint array */
	selection=GPOINTER_TO_INT(gtk_clist_get_row_data(et->table, selection));

	switch(direction){
	case 0:
		/* EP1 <-> EP2 */
		snprintf(dirstr, 127, "%s==%s %s%s%s%s && %s==%s %s%s%s%s",
			et->filter_names[0], 
			address_to_str(&et->endpoints[selection].src_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[3]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].src_port):"",
			et->filter_names[0], 
			address_to_str(&et->endpoints[selection].dst_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[3]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].dst_port):""
		);
		break;
	case 1:
		/* EP1 --> EP2 */
		snprintf(dirstr, 127, "%s==%s %s%s%s%s && %s==%s %s%s%s%s",
			et->filter_names[1], 
			address_to_str(&et->endpoints[selection].src_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[4]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].src_port):"",
			et->filter_names[2], 
			address_to_str(&et->endpoints[selection].dst_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[5]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].dst_port):""
		);
		break;
	case 2:
		/* EP1 <-- EP2 */
		snprintf(dirstr, 127, "%s==%s %s%s%s%s && %s==%s %s%s%s%s",
			et->filter_names[2], 
			address_to_str(&et->endpoints[selection].src_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[5]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].src_port):"",
			et->filter_names[1], 
			address_to_str(&et->endpoints[selection].dst_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[4]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].dst_port):""
		);
		break;
	case 3:
		/* EP1 <-> ANY */
		snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			et->filter_names[0], 
			address_to_str(&et->endpoints[selection].src_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[3]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].src_port):""
		);
		break;
	case 4:
		/* EP1 --> ANY */
		snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			et->filter_names[1], 
			address_to_str(&et->endpoints[selection].src_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[4]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].src_port):""
		);
		break;
	case 5:
		/* EP1 <-- ANY */
		snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			et->filter_names[2], 
			address_to_str(&et->endpoints[selection].src_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[5]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].src_port):""
		);
		break;
	case 6:
		/* EP2 <-> ANY */
		snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			et->filter_names[0], 
			address_to_str(&et->endpoints[selection].dst_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[3]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].dst_port):""
		);
		break;
	case 7:
		/* EP2 --> ANY */
		snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			et->filter_names[1], 
			address_to_str(&et->endpoints[selection].dst_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[4]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].dst_port):""
		);
		break;
	case 8:
		/* EP2 <-- ANY */
		snprintf(dirstr, 127, "%s==%s %s%s%s%s",
			et->filter_names[2], 
			address_to_str(&et->endpoints[selection].dst_address),
			(et->port_to_str)?" && ":"",
			(et->port_to_str)?et->filter_names[5]:"",
			(et->port_to_str)?"==":"",
			(et->port_to_str)?et->port_to_str(et->endpoints[selection].dst_port):""
		);
		break;
	}

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

	gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);

	switch(action){
	case 0:
		/* match */
		/* XXX FIXME, this is not enough to make the dispplay filters
		reapply to the main window */
		filter_packets(&cfile, str);
	case 1:
		/* prepare */
		/* do nothing */
		break;
	}

}

static gint
ett_show_popup_menu_cb(endpoints_table *et, GdkEvent *event, gpointer vet)
{
	GdkEventButton *bevent = (GdkEventButton *)event;

	if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
		gtk_menu_popup(GTK_MENU(et->menu), NULL, NULL, NULL, NULL, 
			bevent->button, bevent->time);
	}

	return FALSE;
}

static GtkItemFactoryEntry ett_list_menu_items[] =
{
	/* Match */
	ITEM_FACTORY_ENTRY("/Match Display Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 0*65536+0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 0*65536+0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 0*65536+0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 0*65536+0*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+0*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+0*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 0*65536+0*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+1*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 0*65536+1*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+1*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 0*65536+1*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 0*65536+1*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 0*65536+1*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+1*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+1*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Not Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 0*65536+1*256+8, NULL, NULL),


	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+2*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 0*65536+2*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+2*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 0*65536+2*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 0*65536+2*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 0*65536+2*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+2*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+2*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 0*65536+2*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+3*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 0*65536+3*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+3*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 0*65536+3*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 0*65536+3*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 0*65536+3*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+3*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+3*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 0*65536+3*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+4*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 0*65536+4*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+4*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 0*65536+4*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 0*65536+4*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 0*65536+4*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+4*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+4*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/And Not Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 0*65536+4*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+5*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 0*65536+5*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+5*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 0*65536+5*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 0*65536+5*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 0*65536+5*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 0*65536+5*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 0*65536+5*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Match Display Filter/Or Not Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 0*65536+5*256+8, NULL, NULL),

	/* Prepare */
	ITEM_FACTORY_ENTRY("/Prepare Display Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 1*65536+0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 1*65536+0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 1*65536+0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 1*65536+0*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+0*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+0*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 1*65536+0*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+1*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 1*65536+1*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+1*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 1*65536+1*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 1*65536+1*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 1*65536+1*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+1*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+1*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Not Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 1*65536+1*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+2*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 1*65536+2*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+2*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 1*65536+2*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 1*65536+2*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 1*65536+2*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+2*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+2*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 1*65536+2*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+3*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 1*65536+3*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+3*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 1*65536+3*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 1*65536+3*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 1*65536+3*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+3*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+3*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 1*65536+3*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+4*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 1*65536+4*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+4*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 1*65536+4*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 1*65536+4*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 1*65536+4*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+4*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+4*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/And Not Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 1*65536+4*256+8, NULL, NULL),

	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected/EP1 <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+5*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected/EP1 --> EP2", NULL,
		ett_select_filter_cb, 1*65536+5*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected/EP1 <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+5*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected/EP1 <-> ANY", NULL,
		ett_select_filter_cb, 1*65536+5*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected/EP1 --> ANY", NULL,
		ett_select_filter_cb, 1*65536+5*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected/EP1 <-- ANY", NULL,
		ett_select_filter_cb, 1*65536+5*256+5, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected/ANY <-> EP2", NULL,
		ett_select_filter_cb, 1*65536+5*256+6, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected/ANY <-- EP2", NULL,
		ett_select_filter_cb, 1*65536+5*256+7, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare Display Filter/Or Not Selected/ANY --> EP2", NULL,
		ett_select_filter_cb, 1*65536+5*256+8, NULL, NULL),


};

static void
ett_create_popup_menu(endpoints_table *et)
{
	et->item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

	gtk_item_factory_create_items_ac(et->item_factory, sizeof(ett_list_menu_items)/sizeof(ett_list_menu_items[0]), ett_list_menu_items, et, 2);

	et->menu = gtk_item_factory_get_widget(et->item_factory, "<main>");
	gtk_signal_connect_object(GTK_OBJECT(et->table), "button_press_event", GTK_SIGNAL_FUNC(ett_show_popup_menu_cb), GTK_OBJECT(et));
}





void
init_ett_table(endpoints_table *et, GtkWidget *vbox, char *(*port_to_str)(guint32), char **filter_names)
{
	int i;
	column_arrows *col_arrows;
	GdkBitmap *ascend_bm, *descend_bm;
	GdkPixmap *ascend_pm, *descend_pm;
	GtkStyle *win_style;
	GtkWidget *column_lb;
	char *default_titles[] = { "EP1 Address", "Port", "EP2 Address", "Port", "Frames", "Bytes", "-> Frames", "-> Bytes", "<- Frames", "<- Bytes" };


	et->scrolled_window=gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(et->scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	gtk_box_pack_start(GTK_BOX(vbox), et->scrolled_window, TRUE, TRUE, 0);

	et->table=(GtkCList *)gtk_clist_new(NUM_COLS);

	gtk_widget_show(GTK_WIDGET(et->table));
	gtk_widget_show(et->scrolled_window);

	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_COLS);
	win_style = gtk_widget_get_style(et->scrolled_window);
	ascend_pm = gdk_pixmap_create_from_xpm_d(et->scrolled_window->window,
			&ascend_bm,
			&win_style->bg[GTK_STATE_NORMAL],
			(gchar **)clist_ascend_xpm);
	descend_pm = gdk_pixmap_create_from_xpm_d(et->scrolled_window->window,
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
		gtk_clist_set_column_widget(GTK_CLIST(et->table), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}
	gtk_clist_column_titles_show(GTK_CLIST(et->table));

	gtk_clist_set_compare_func(et->table, ett_sort_column);
	gtk_clist_set_sort_column(et->table, 4);
	gtk_clist_set_sort_type(et->table, GTK_SORT_DESCENDING);


	/*XXX instead of this we should probably have some code to
		dynamically adjust the width of the columns */
	gtk_clist_set_column_width(et->table, 0, 100);
	gtk_clist_set_column_width(et->table, 1, 40);
	gtk_clist_set_column_width(et->table, 2, 100);
	gtk_clist_set_column_width(et->table, 3, 40);
	gtk_clist_set_column_width(et->table, 4, 70);
	gtk_clist_set_column_width(et->table, 5, 60);
	gtk_clist_set_column_width(et->table, 6, 70);
	gtk_clist_set_column_width(et->table, 7, 60);
	gtk_clist_set_column_width(et->table, 8, 70);
	gtk_clist_set_column_width(et->table, 9, 60);


	gtk_clist_set_shadow_type(et->table, GTK_SHADOW_IN);
	gtk_clist_column_titles_show(et->table);
	gtk_container_add(GTK_CONTAINER(et->scrolled_window), (GtkWidget *)et->table);

	SIGNAL_CONNECT(et->table, "click-column", ett_click_column_cb, col_arrows);

	gtk_widget_show(GTK_WIDGET(et->table));
	gtk_widget_show(et->scrolled_window);

	et->num_endpoints=0;
	et->endpoints=NULL;
	et->port_to_str=port_to_str;
	et->filter_names=filter_names;

	/* hide srcport and dstport if we dont use ports */
	if(!port_to_str){
		gtk_clist_set_column_visibility(et->table, 1, FALSE);
		gtk_clist_set_column_visibility(et->table, 3, FALSE);
	}

	/* create popup menu for this table */
	ett_create_popup_menu(et);
}


void 
add_ett_table_data(endpoints_table *et, address *src, address *dst, guint32 src_port, guint32 dst_port, int num_frames, int num_bytes)
{
	address *addr1, *addr2;
	guint32 port1, port2;
	endpoint_talker_t *talker=NULL;
	int talker_idx=0;
	gboolean new_talker;
	int res;

	res=CMP_ADDRESS(src, dst);

	if(res<0){
		addr1=src;
		addr2=dst;
		port1=src_port;
		port2=dst_port;
	} else if(res>0) {
		addr2=src;
		addr1=dst;
		port2=src_port;
		port1=dst_port;
	} else {
		if(src_port>dst_port){
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
	}


	new_talker=FALSE;
	/* XXX should be optimized to allocate n extra entries at a time
	   instead of just one */
	/* if we dont have any entries at all yet */
	if(et->endpoints==NULL){
		et->endpoints=g_malloc(sizeof(endpoint_talker_t));
		et->num_endpoints=1;
		talker=&et->endpoints[0];
		talker_idx=0;
		new_talker=TRUE;
	}

	/* try to find it among the existing known talkers */
	if(talker==NULL){
		guint32 i;
		for(i=0;i<et->num_endpoints;i++){
			if(  (!CMP_ADDRESS(&et->endpoints[i].src_address, addr1))&&(!CMP_ADDRESS(&et->endpoints[i].dst_address, addr2))&&(et->endpoints[i].src_port==port1)&&(et->endpoints[i].dst_port==port2) ){
				talker=&et->endpoints[i];
				talker_idx=i;
				break;
			}
			if( (!CMP_ADDRESS(&et->endpoints[i].src_address, addr2))&&(!CMP_ADDRESS(&et->endpoints[i].dst_address, addr1))&&(et->endpoints[i].src_port==port2)&&(et->endpoints[i].dst_port==port1) ){
				talker=&et->endpoints[i];
				talker_idx=i;
				break;
			}
		}
	}

	/* if we still dont know what talker this is it has to be a new one
	   and we have to allocate it and append it to the end of the list */
	if(talker==NULL){
		new_talker=TRUE;
		et->num_endpoints++;
		et->endpoints=g_realloc(et->endpoints, et->num_endpoints*sizeof(endpoint_talker_t));
		talker=&et->endpoints[et->num_endpoints-1];
		talker_idx=et->num_endpoints-1;
	}

	/* if this is a new talker we need to initialize the struct */
	if(new_talker){
		COPY_ADDRESS(&talker->src_address, addr1);
		COPY_ADDRESS(&talker->dst_address, addr2);
		talker->src_port=port1;
		talker->dst_port=port2;
		talker->rx_frames=0;
		talker->tx_frames=0;
		talker->rx_bytes=0;
		talker->tx_bytes=0;
	}

	/* update the talker struct */
	if( (!CMP_ADDRESS(src, addr1))&&(!CMP_ADDRESS(dst, addr2))&&(src_port==port1)&&(dst_port==port2) ){
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

		entries[0]=address_to_str(&talker->src_address);
		entries[1]=(et->port_to_str)?et->port_to_str(talker->src_port):"";
		entries[2]=address_to_str(&talker->dst_address);
		entries[3]=(et->port_to_str)?et->port_to_str(talker->dst_port):"";

		sprintf(frames,"%u", talker->tx_frames+talker->rx_frames);
		entries[4]=frames;
		sprintf(bytes,"%u", talker->tx_bytes+talker->rx_bytes);
		entries[5]=bytes;

		sprintf(txframes,"%u", talker->tx_frames);
		entries[6]=txframes;
		sprintf(txbytes,"%u", talker->tx_bytes);
		entries[7]=txbytes;

		sprintf(rxframes,"%u", talker->rx_frames);
		entries[8]=rxframes;
		sprintf(rxbytes,"%u", talker->rx_bytes);
		entries[9]=rxbytes;

		gtk_clist_insert(et->table, talker_idx, entries);
		gtk_clist_set_row_data(et->table, talker_idx, (gpointer) talker_idx);
	}

}


/* XXX should freeze/thaw table here and in the srt thingy? */
void 
draw_ett_table_data(endpoints_table *et)
{
	guint32 i;
	int j;

	for(i=0;i<et->num_endpoints;i++){
		char str[16];

		j=gtk_clist_find_row_from_data(et->table, (gpointer)i);

		sprintf(str, "%u", et->endpoints[i].tx_frames+et->endpoints[i].rx_frames);
		gtk_clist_set_text(et->table, j, 4, str);		
		sprintf(str, "%u", et->endpoints[i].tx_bytes+et->endpoints[i].rx_bytes);
		gtk_clist_set_text(et->table, j, 5, str);		


		sprintf(str, "%u", et->endpoints[i].tx_frames);
		gtk_clist_set_text(et->table, j, 6, str);	
		sprintf(str, "%u", et->endpoints[i].tx_bytes);
		gtk_clist_set_text(et->table, j, 7, str);		


		sprintf(str, "%u", et->endpoints[i].rx_frames);
		gtk_clist_set_text(et->table, j, 8, str);		
		sprintf(str, "%u", et->endpoints[i].rx_bytes);
		gtk_clist_set_text(et->table, j, 9, str);		

	}
	gtk_clist_sort(et->table);
}
