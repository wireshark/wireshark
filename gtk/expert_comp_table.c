/* expert_comp_table.c
 * expert_comp_table   2005 Greg Morris
 * Portions copied from service_response_time_table.c by Ronnie Sahlberg
 * Helper routines common to all composite expert statistics
 * tap.
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
#include "compat_macros.h"
#include "epan/packet_info.h"
#include "expert_comp_table.h"

#if (GTK_MAJOR_VERSION < 2)
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#endif

#include "simple_dialog.h"
#include "globals.h"
#include "gtk/find_dlg.h"
#include "color.h"
#include "gtk/color_dlg.h"
#include "main.h"
#include "gui_utils.h"
#include "gtkglobals.h"
#include "webbrowser.h"
#include <epan/expert.h>
#include <epan/emem.h>

#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

#define SORT_ALPHABETICAL 0

#if (GTK_MAJOR_VERSION >= 2)
static gint
sort_iter_compare_func (GtkTreeModel *model,
GtkTreeIter *a,
GtkTreeIter *b,
gpointer userdata)
{
    gint sortcol = GPOINTER_TO_INT(userdata);
    gint ret = 0;
    switch (sortcol)
    {
        case SORT_ALPHABETICAL:
        {
        gchar *name1, *name2;
        gtk_tree_model_get(model, a, 0, &name1, -1);
        gtk_tree_model_get(model, b, 0, &name2, -1);
        if (name1 == NULL || name2 == NULL)
        {
            if (name1 == NULL && name2 == NULL)
                break; /* both equal => ret = 0 */
            ret = (name1 == NULL) ? -1 : 1;
        }
        else
        {
            ret = g_ascii_strcasecmp(name1,name2);
        }
        g_free(name1);
        g_free(name2);
        }
        break;
        default:
        g_return_val_if_reached(0);
    }
    return ret;
}
#endif

#if (GTK_MAJOR_VERSION < 2)

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;

static void
error_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
	column_arrows *col_arrows = (column_arrows *) data;
	int i;

	gtk_clist_freeze(clist);

	for (i = 0; i < 4; i++) {
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
		if(column>=2){
			clist->sort_type = GTK_SORT_DESCENDING;
			gtk_widget_show(col_arrows[column].descend_pm);
		} else {
			clist->sort_type = GTK_SORT_ASCENDING;
			gtk_widget_show(col_arrows[column].ascend_pm);
		}
		gtk_clist_set_sort_column(clist, column);
	}
	gtk_clist_thaw(clist);

	gtk_clist_sort(clist);
}

static gint
error_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	char *text1 = NULL;
	char *text2 = NULL;
	float f1,f2;

	const GtkCListRow *row1 = ptr1;
	const GtkCListRow *row2 = ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	case 0:
	case 2:
	case 1:
		return strcmp (text1, text2);
	case 3:
	case 4:
	case 5:
		sscanf(text1,"%f",&f1);
		sscanf(text2,"%f",&f2);
		if(fabs(f1-f2)<0.000005)
			return 0;
		if(f1>f2)
			return 1;
		return -1;
	}
	g_assert_not_reached();
	return 0;
}

#else
enum
{
   GROUP_COLUMN,
   PROTOCOL_COLUMN,
   SUMMARY_COLUMN,
   COUNT_COLUMN,
   N_COLUMNS
};
#endif

static gint find_summary_data(error_equiv_table *err, const expert_info_t *expert_data)
{
    gint i;
    
    /* First time thru values will be 0 */
    if (err->num_procs==0) {
        return -1;
    }
    for (i=0;i<err->num_procs;i++) {
        if (strcmp(err->procedures[i].entries[2], expert_data->summary) == 0) {
            return i;
        }
    }
    return -1;
}

/* action is encoded as 
   filter_action*256+filter_type

   filter_action:
	0: Match
	1: Prepare
	2: Find Frame
	3:   Find Next
	4:   Find Previous
	5: Colorize Procedure
    6: Lookup on Internet
   filter_type:
	0: Selected
	1: Not Selected
	2: And Selected
	3: Or Selected
	4: And Not Selected
	5: Or Not Selected
*/
static void
error_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
	int action, type, selection;
	error_equiv_table *err = (error_equiv_table *)callback_data;
	char str[256];
	const char *current_filter;

#if (GTK_MAJOR_VERSION >= 2)
    GtkTreeIter iter;
    GtkTreeModel *model;
    const expert_info_t expert_data;
#endif

    action=(callback_action>>8)&0xff;
	type=callback_action&0xff;


#if (GTK_MAJOR_VERSION < 2)
   	selection=GPOINTER_TO_INT(g_list_nth_data(GTK_CLIST(err->table)->selection, 0));
#else
    gtk_tree_selection_get_selected(err->select, &model, &iter);

    gtk_tree_model_get (model, &iter, GROUP_COLUMN, &expert_data.group, -1);
    gtk_tree_model_get (model, &iter, PROTOCOL_COLUMN, &expert_data.protocol, -1);
    gtk_tree_model_get (model, &iter, SUMMARY_COLUMN, &expert_data.summary, -1);
    
    if (strcmp((char *)expert_data.group, "Packet:")==0) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "You cannot filter or search for packet number. Click on a valid item header.");
        return;
    }

    selection = find_summary_data(err, &expert_data);
#endif

	if(selection>=(int)err->num_procs){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No items are selected");
		return;
	}
#if (GTK_MAJOR_VERSION < 2)
	/* translate it back from row index to index in procedures array */
    selection=GPOINTER_TO_INT(gtk_clist_get_row_data(err->table, selection));
#endif

	current_filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));

    /* Some expert data doesn't pass an expert item. Without this we cannot create a filter */
    /* But allow for searching of internet for error string */
    if (action != 6 && action != 7) {
        if (err->procedures[selection].fvalue_value==NULL) {
            if (action != 2 && action != 3 && action != 4) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Wireshark cannot create a filter on this item - %s, try using find instead.", err->procedures[selection].entries[2]);
                return;
            }
        }
    	switch(type){
    	case 0:
    		/* selected */
            /* if no expert item was passed */
            if (err->procedures[selection].fvalue_value==NULL) {
                g_snprintf(str, 255, "%s", err->procedures[selection].entries[2]);
            }
            else
            {
                /* expert item exists. Use it. */
                g_snprintf(str, 255, "%s", err->procedures[selection].fvalue_value);
            }
    		break;
    	case 1:
    		/* not selected */
            /* if no expert item was passed */
            if (err->procedures[selection].fvalue_value==NULL) {
                g_snprintf(str, 255, "!%s", err->procedures[selection].entries[2]);
            }
            else
            {
                /* expert item exists. Use it. */
                g_snprintf(str, 255, "!(%s)", err->procedures[selection].fvalue_value);
            }
    		break;
            /* the remaining cases will only exist if the expert item exists so no need to check */
    	case 2:
    		/* and selected */
    		g_snprintf(str, 255, "(%s) && (%s)", current_filter, err->procedures[selection].fvalue_value);
    		break;
    	case 3:
    		/* or selected */
    		g_snprintf(str, 255, "(%s) || (%s)", current_filter, err->procedures[selection].fvalue_value);
    		break;
    	case 4:
    		/* and not selected */
    		g_snprintf(str, 255, "(%s) && !(%s)", current_filter, err->procedures[selection].fvalue_value);
    		break;
    	case 5:
    		/* or not selected */
    		g_snprintf(str, 255, "(%s) || !(%s)", current_filter, err->procedures[selection].fvalue_value);
    		break;
        default:
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't find menu type - %u", type);
    	}
    }

	switch(action){
	case 0:
		/* match */
		main_filter_packets(&cfile, str, FALSE);
        break;
	case 1:
		/* prepare */
        gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
		break;
	case 2:
		/* find frame */
        /* When trying to perform a find without expert item, we must pass
         * the expert string to the find window. The user might need to modify
         * the string and click on the text search to locate the packet in question.
         * So regardless of the type we will just bring up the find window and allow
         * the user to modify the search criteria and options.
         */
            find_frame_with_filter(str);
		break;
	case 3:
		/* find next */
        /* In the case of find next, if there was no expert item, then most likely the expert
         * string was modified to locate the text inside the message. So we can't just perform
         * a find with the expert string or we will not really be performing a find next.
         * In an effort to allow the user to modify the string and/or continue searching, we
         * will just present the user with the find window again with the default expert string.
         * A better aproach would be to attempt in capturing the last find string and utilize this 
         * with a find next/previous. Also a better approach might be to just send a <Ctl-N> keystroke.
         */
        if (err->procedures[selection].fvalue_value==NULL) {
            find_frame_with_filter(str);
        }
        else
        { 
            /* We have an expert item so just continue search without find dialog. */
		    find_previous_next_frame_with_filter(str, FALSE);
        }
		break;
	case 4:
		/* find previous */
        /* In the case of find previous, if there was no expert item, then most likely the expert
         * string was modified to locate the text inside the message. So we can't just perform
         * a find with the expert string or we will not really be performing a find previous.
         * In an effort to allow the user to modify the string and/or continue searching, we
         * will just present the user with the find window again with the default expert string.
         * A better aproach would be to attempt in capturing the last find string and utilize this 
         * with a find next/previous. Also a better approach might be to just send a <Ctl-B> keystroke.
         */
        if (err->procedures[selection].fvalue_value==NULL) {
            find_frame_with_filter(str);
        }
        else
        { 
            /* We have an expert item so just continue search without find dialog. */
		    find_previous_next_frame_with_filter(str, TRUE);
        }
		break;
	case 5:
		/* colorize procedure */
		color_display_with_filter(str);
		break;
	case 6:
		/* Lookup expert string on internet. Default search via www.google.com */
		g_snprintf(str, 255, "http://www.google.com/search?hl=en&q=%s+'%s'", err->procedures[selection].entries[1], err->procedures[selection].entries[2]);
        browser_open_url(str);
		break;
#if (GTK_MAJOR_VERSION < 2)
    case 7:
        /* Goto the first occurance (packet) in the trace */
        cf_goto_frame(&cfile, err->procedures[selection].packet_num);
        break;
#endif
    default:
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't find menu action - %u", action);
	}

}

static gint
error_show_popup_menu_cb(void *widg _U_, GdkEvent *event, error_equiv_table *err)
{
	GdkEventButton *bevent = (GdkEventButton *)event;

	if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
		gtk_menu_popup(GTK_MENU(err->menu), NULL, NULL, NULL, NULL, 
			bevent->button, bevent->time);
	}

	return FALSE;
}

static GtkItemFactoryEntry error_list_menu_items[] =
{
	/* Match */
	ITEM_FACTORY_ENTRY("/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/Selected", NULL,
		error_select_filter_cb, 0*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... not Selected", NULL,
		error_select_filter_cb, 0*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/.. and Selected", NULL,
		error_select_filter_cb, 0*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or Selected", NULL,
		error_select_filter_cb, 0*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... and not Selected", NULL,
		error_select_filter_cb, 0*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Apply as Filter/... or not Selected", NULL,
		error_select_filter_cb, 0*256+5, NULL, NULL),

	/* Prepare */
	ITEM_FACTORY_ENTRY("/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Selected", NULL,
		error_select_filter_cb, 1*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/Not Selected", NULL,
		error_select_filter_cb, 1*256+1, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and Selected", NULL,
		error_select_filter_cb, 1*256+2, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or Selected", NULL,
		error_select_filter_cb, 1*256+3, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... and not Selected", NULL,
		error_select_filter_cb, 1*256+4, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Prepare a Filter/... or not Selected", NULL,
		error_select_filter_cb, 1*256+5, NULL, NULL),

	/* Find Frame */
	ITEM_FACTORY_ENTRY("/Find Frame", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Find Frame/Find Frame", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Find Frame/Find Frame/Selected", NULL,
		error_select_filter_cb, 2*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Frame/Find Frame/Not Selected", NULL,
		error_select_filter_cb, 2*256+1, NULL, NULL),
	/* Find Next */
	ITEM_FACTORY_ENTRY("/Find Frame/Find Next", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Find Frame/Find Next/Selected", NULL,
		error_select_filter_cb, 3*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Frame/Find Next/Not Selected", NULL,
		error_select_filter_cb, 3*256+1, NULL, NULL),

	/* Find Previous */
	ITEM_FACTORY_ENTRY("/Find Frame/Find Previous", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Find Frame/Find Previous/Selected", NULL,
		error_select_filter_cb, 4*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Find Frame/Find Previous/Not Selected", NULL,
		error_select_filter_cb, 4*256+1, NULL, NULL),

	/* Colorize Procedure */
	ITEM_FACTORY_ENTRY("/Colorize Procedure", NULL, NULL, 0, "<Branch>", NULL),
	ITEM_FACTORY_ENTRY("/Colorize Procedure/Selected", NULL,
		error_select_filter_cb, 5*256+0, NULL, NULL),
	ITEM_FACTORY_ENTRY("/Colorize Procedure/Not Selected", NULL,
		error_select_filter_cb, 5*256+1, NULL, NULL),

	/* Search Internet */
	ITEM_FACTORY_ENTRY("/Internet Search for Info Text", NULL,
		error_select_filter_cb, 6*256+0, NULL, NULL),
#if (GTK_MAJOR_VERSION < 2)
   	/* Go to first packet matching this entry */
	ITEM_FACTORY_ENTRY("/Goto First Occurrence", NULL,
		error_select_filter_cb, 7*256+0, NULL, NULL),
#endif
};

#if (GTK_MAJOR_VERSION >= 2)
static void
expert_goto_pkt_cb (GtkTreeSelection *selection, gpointer data)
{
        GtkTreeIter iter;
        GtkTreeModel *model;
        gchar *pkt;
        gchar *grp;
        error_equiv_table *err=data;

        if (gtk_tree_selection_get_selected (selection, &model, &iter))
        {
                gtk_tree_model_get (model, &iter, PROTOCOL_COLUMN, &pkt, -1);
                gtk_tree_model_get (model, &iter, GROUP_COLUMN, &grp, -1);

                if (strcmp(grp, "Packet:")==0) {
                    cf_goto_frame(&cfile, atoi(pkt));
                }
                g_free (pkt);
                g_free (grp);
        }
}
#endif

static void
error_create_popup_menu(error_equiv_table *err)
{
	GtkItemFactory *item_factory;


#if (GTK_MAJOR_VERSION >= 2)
    err->select = gtk_tree_view_get_selection (GTK_TREE_VIEW (err->tree_view));
    gtk_tree_selection_set_mode (err->select, GTK_SELECTION_SINGLE);
    g_signal_connect (G_OBJECT (err->select), "changed",
                  G_CALLBACK (expert_goto_pkt_cb),
                  err);
#endif
	item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

	gtk_item_factory_create_items_ac(item_factory, sizeof(error_list_menu_items)/sizeof(error_list_menu_items[0]), error_list_menu_items, err, 2);

	err->menu = gtk_item_factory_get_widget(item_factory, "<main>");
#if (GTK_MAJOR_VERSION >= 2)
	SIGNAL_CONNECT(err->tree_view, "button_press_event", error_show_popup_menu_cb, err);
#else
	SIGNAL_CONNECT(err->table, "button_press_event", error_show_popup_menu_cb, err);
#endif
}

void
init_error_table(error_equiv_table *err, guint16 num_procs, GtkWidget *vbox)
{
	guint16 i, j;
#if (GTK_MAJOR_VERSION < 2)
	column_arrows *col_arrows;
	GdkBitmap *ascend_bm, *descend_bm;
	GdkPixmap *ascend_pm, *descend_pm;
	GtkStyle *win_style;
	GtkWidget *column_lb;

    GtkTooltips *tooltips = gtk_tooltips_new();
	const char *default_titles[] = { "Group", "Protocol", "Summary", "Count"};

	err->scrolled_window=scrolled_window_new(NULL, NULL);
	gtk_box_pack_start(GTK_BOX(vbox), err->scrolled_window, TRUE, TRUE, 0);

	err->table=(GtkCList *)gtk_clist_new(4);

	gtk_widget_show(GTK_WIDGET(err->table));
	gtk_widget_show(err->scrolled_window);

	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * 4);
	win_style = gtk_widget_get_style(err->scrolled_window);
	ascend_pm = gdk_pixmap_create_from_xpm_d(err->scrolled_window->window,
			&ascend_bm,
			&win_style->bg[GTK_STATE_NORMAL],
			(gchar **)clist_ascend_xpm);
	descend_pm = gdk_pixmap_create_from_xpm_d(err->scrolled_window->window,
			&descend_bm,
			&win_style->bg[GTK_STATE_NORMAL],
			(gchar **)clist_descend_xpm);
	for (i = 0; i < 4; i++) {
		col_arrows[i].table = gtk_table_new(2, 2, FALSE);
		gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
		column_lb = gtk_label_new(default_titles[i]);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		gtk_widget_show(column_lb);

		col_arrows[i].ascend_pm = gtk_pixmap_new(ascend_pm, ascend_bm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		col_arrows[i].descend_pm = gtk_pixmap_new(descend_pm, descend_bm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm, 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
		if (i == 3) {
			gtk_widget_show(col_arrows[i].descend_pm);
		}
		gtk_clist_set_column_widget(GTK_CLIST(err->table), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}
	gtk_clist_column_titles_show(GTK_CLIST(err->table));

	gtk_clist_set_compare_func(err->table, error_sort_column);
	gtk_clist_set_sort_column(err->table, 3);
	gtk_clist_set_sort_type(err->table, GTK_SORT_DESCENDING);


	/*XXX instead of this we should probably have some code to
		dynamically adjust the width of the columns */
	gtk_clist_set_column_width(err->table, 0, 75);
	gtk_clist_set_column_width(err->table, 1, 75);
	gtk_clist_set_column_width(err->table, 2, 400);
	gtk_clist_set_column_width(err->table, 3, 50);


	gtk_clist_set_shadow_type(err->table, GTK_SHADOW_IN);
	gtk_clist_column_titles_show(err->table);
	gtk_container_add(GTK_CONTAINER(err->scrolled_window), (GtkWidget *)err->table);

	SIGNAL_CONNECT(err->table, "click-column", error_click_column_cb, col_arrows);

	gtk_widget_show(GTK_WIDGET(err->table));
#else
    GtkTreeStore *store;
    GtkWidget *tree;
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;
    GtkTreeSortable *sortable;

    /* Create the store */
    store = gtk_tree_store_new (4,       /* Total number of columns */
                               G_TYPE_STRING,   /* Group              */
                               G_TYPE_STRING,   /* Protocol           */
                               G_TYPE_STRING,   /* Summary            */
                               G_TYPE_STRING);  /* Count              */

    /* Create a view */
    tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
    err->tree_view = GTK_TREE_VIEW(tree);
    sortable = GTK_TREE_SORTABLE(store);

    /* Setup the sortable columns */
    gtk_tree_sortable_set_sort_func(sortable, SORT_ALPHABETICAL, sort_iter_compare_func, GINT_TO_POINTER(SORT_ALPHABETICAL), NULL);
    gtk_tree_sortable_set_sort_column_id(sortable, SORT_ALPHABETICAL, GTK_SORT_ASCENDING);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW (tree), FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (store));

    /* Create a cell render */
    renderer = gtk_cell_renderer_text_new ();

    /* Create the first column, associating the "text" attribute of the
     * cell_renderer to the first column of the model */
    column = gtk_tree_view_column_new_with_attributes ("Group", renderer, "text", GROUP_COLUMN, NULL);
    gtk_tree_view_column_set_sort_column_id(column, 0);
    gtk_tree_view_column_set_resizable(column, TRUE);
    /* Add the column to the view. */
    gtk_tree_view_append_column (GTK_TREE_VIEW (err->tree_view), column);
 
    /* Second column.. Protocol. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Protocol", renderer, "text", PROTOCOL_COLUMN, NULL);
    gtk_tree_view_column_set_sort_column_id(column, 1);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column (GTK_TREE_VIEW (err->tree_view), column);
 
    /* Third column.. Summary. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Summary", renderer, "text", SUMMARY_COLUMN, NULL);
    gtk_tree_view_column_set_sort_column_id(column, 2);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column (GTK_TREE_VIEW (err->tree_view), column);
 
    /* Last column.. Count. */
    column = gtk_tree_view_column_new_with_attributes ("Count", renderer, "text", COUNT_COLUMN, NULL);
    gtk_tree_view_column_set_sort_column_id(column, 3);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column (GTK_TREE_VIEW (err->tree_view), column);
 
 	err->scrolled_window=scrolled_window_new(NULL, NULL);

    gtk_container_add(GTK_CONTAINER(err->scrolled_window), GTK_WIDGET (err->tree_view));

	gtk_box_pack_start(GTK_BOX(vbox), err->scrolled_window, TRUE, TRUE, 0);

    gtk_tree_view_set_search_column (err->tree_view, SUMMARY_COLUMN); /* Allow searching the summary */
    gtk_tree_view_set_reorderable (err->tree_view, TRUE);   /* Allow user to reorder data with drag n drop */
    
    /* Now enable the sorting of each column */
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(err->tree_view), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(err->tree_view), TRUE);

	gtk_container_add(GTK_CONTAINER(err->scrolled_window), GTK_WIDGET (err->tree_view));
#endif

	gtk_widget_show(err->scrolled_window);

    err->num_procs=num_procs;
	err->procedures=g_malloc(sizeof(error_procedure_t)*(num_procs+1));
	for(i=0;i<num_procs;i++){
		for(j=0;j<3;j++){
			err->procedures[i].entries[j]=NULL; /* reset all values */
		}
	}

	/* create popup menu for this table */
  	error_create_popup_menu(err);
}

void
init_error_table_row(error_equiv_table *err, const expert_info_t *expert_data)
{
    guint16 old_num_procs=err->num_procs;
    guint16 j;
    gint row=0;

#if (GTK_MAJOR_VERSION >= 2)
    GtkTreeStore *store;
#endif

    /* we have discovered a new procedure. Extend the table accordingly */
    row = find_summary_data(err, expert_data);
    if(row==-1){
        /* First time we have seen this event so initialize memory table */
#if (GTK_MAJOR_VERSION < 2)
        row = 0;
        old_num_procs++;

	err->procedures=g_realloc(err->procedures, (sizeof(error_procedure_t)*(old_num_procs+1)));
        err->procedures[err->num_procs].count=0;
	for(j=0;j<4;j++)
        {
            err->procedures[err->num_procs].entries[j]=NULL;
	}
        err->procedures[err->num_procs].packet_num = (guint32)expert_data->packet_num;                        /* First packet num */
	err->procedures[err->num_procs].entries[0]=(char *)g_strdup(val_to_str(expert_data->group, expert_group_vals,"Unknown group (%u)"), NULL);   /* Group */
        err->procedures[err->num_procs].entries[1]=(char *)g_strdup(expert_data->protocol, NULL);    /* Protocol */
        err->procedures[err->num_procs].entries[2]=(char *)g_strdup(expert_data->summary, NULL);     /* Summary */
    	err->procedures[err->num_procs].entries[3]=(char *)g_strdup_printf("%d", err->procedures[row].count);     /* Count */
        err->procedures[err->num_procs].fvalue_value = NULL;
    }
    /* Store the updated count of events */
    err->num_procs = old_num_procs;
#else
        row = old_num_procs; /* Number of expert events since this is a new event */
        err->procedures=g_realloc(err->procedures, (sizeof(error_procedure_t)*(old_num_procs+1)));
        err->procedures[row].count=0; /* count of events for this item */
        err->procedures[row].fvalue_value = NULL; /* Filter string value */
        for(j=0;j<4;j++){
            err->procedures[row].entries[j]=NULL;
        }
        
        /* Create the item in our memory table */
        err->procedures[row].entries[0]=(char *)g_strdup(val_to_str(expert_data->group, expert_group_vals,"Unknown group (%u)"));  /* Group */
        err->procedures[row].entries[1]=(char *)g_strdup(expert_data->protocol);    /* Protocol */
        err->procedures[row].entries[2]=(char *)g_strdup(expert_data->summary);     /* Summary */

        /* Create a new item in our tree view */
        store = GTK_TREE_STORE(gtk_tree_view_get_model(err->tree_view)); /* Get store */
        gtk_tree_store_append (store, &err->procedures[row].iter, NULL);  /* Acquire an iterator */
        
        gtk_tree_store_set (store, &err->procedures[row].iter,
                    GROUP_COLUMN, (char *)g_strdup(val_to_str(expert_data->group, expert_group_vals,"Unknown group (%u)")),
                    PROTOCOL_COLUMN, (char *)g_strdup(expert_data->protocol),
                    SUMMARY_COLUMN, (char *)g_strdup(expert_data->summary), -1);

        /* If an expert item was passed then build the filter string */
        if (expert_data->pitem) {
            char *filter;

            filter = proto_construct_match_selected_string(expert_data->pitem->finfo, NULL);
            if (filter != NULL)
                err->procedures[row].fvalue_value = g_strdup(filter);
        }
        /* Store the updated count of events */
        err->num_procs = ++old_num_procs;
    }

    /* Update our memory table with event data */
    err->procedures[row].count++; /* increment the count of events for this item */

    /* Store the updated count for this event item */
    err->procedures[row].entries[3]=(char *)g_strdup_printf("%d", err->procedures[row].count);     /* Count */

    /* Update the tree with new count for this event */
    store = GTK_TREE_STORE(gtk_tree_view_get_model(err->tree_view));
    gtk_tree_store_set(store, &err->procedures[row].iter, COUNT_COLUMN, (char *)g_strdup_printf("%d", err->procedures[row].count), -1);
#endif
}

void
add_error_table_data(error_equiv_table *err, const expert_info_t *expert_data)
{
	error_procedure_t *errp;
    gint index;
#if (GTK_MAJOR_VERSION < 2)
    gint row;
#else
    GtkTreeStore    *store;
    GtkTreeIter      new_iter;
#endif

    index = find_summary_data(err,expert_data);

    /* We should never encounter a condition where we cannot find the expert data. If
     * we do then we will just abort.
     */
    if (index == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find expert data. Aborting");
        return;
    }
	errp=&err->procedures[index];

#if (GTK_MAJOR_VERSION < 2)
   	if (errp->count==0){
		row=gtk_clist_append(err->table, err->procedures[index].entries);
		gtk_clist_set_row_data(err->table, row, (gpointer) index);
	}
    errp->count++;
    err->procedures[index].entries[3] = (char *)g_strdup_printf("%d", errp->count);
#else

    store = GTK_TREE_STORE(gtk_tree_view_get_model(err->tree_view));

    gtk_tree_store_append(store, &new_iter, &errp->iter);

    gtk_tree_store_set(store, &new_iter,
                           GROUP_COLUMN, "Packet:",
                           PROTOCOL_COLUMN, (char *)g_strdup_printf("%d", expert_data->packet_num),
                           -1);
#endif
}


#if (GTK_MAJOR_VERSION < 2)
void
draw_error_table_data(error_equiv_table *err)
{
	int i,j;
	char *strp;

	for(i=0;i<err->num_procs;i++){
		/* ignore procedures with no calls (they don't have CList rows) */
		if(err->procedures[i].count==0){
			continue;
		}

		j=gtk_clist_find_row_from_data(err->table, (gpointer)i);
		strp=g_strdup_printf("%d", err->procedures[i].count);
		gtk_clist_set_text(err->table, j, 3, strp);
		err->procedures[i].entries[3]=(char *)strp;


	}
	gtk_clist_sort(err->table);
}
#endif

void
reset_error_table_data(error_equiv_table *err)
{
	guint16 i;
#if (GTK_MAJOR_VERSION >= 2)
    GtkTreeStore    *store;
#endif

	for(i=0;i<err->num_procs;i++){
		err->procedures[i].entries[0] = NULL;
		err->procedures[i].entries[1] = NULL;
		err->procedures[i].entries[2] = NULL;
		err->procedures[i].entries[3] = NULL;
#if (GTK_MAJOR_VERSION < 2)
        err->procedures[i].packet_num=0;
#else
        err->procedures[i].count=0;
#endif

	}

#if (GTK_MAJOR_VERSION < 2)
	gtk_clist_clear(err->table);
#else
    store = GTK_TREE_STORE(gtk_tree_view_get_model(err->tree_view));
    gtk_tree_store_clear(store);
#endif
    err->num_procs = 0;
}

void
free_error_table_data(error_equiv_table *err)
{
	guint16 i,j;

	for(i=0;i<err->num_procs;i++){
		for(j=0;j<4;j++){
			if(err->procedures[i].entries[j]){
				err->procedures[i].entries[j]=NULL;
			}
            err->procedures[i].fvalue_value=NULL;

#if (GTK_MAJOR_VERSION < 2)
            err->procedures[i].packet_num=0;
#else
            err->procedures[i].count=0;
#endif
		}
	}
	err->procedures=NULL;
	err->num_procs=0;
}
