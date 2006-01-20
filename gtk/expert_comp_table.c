/* expert_comp_table.c
 * expert_comp_table   2005 Greg Morris
 * Portions copied from service_response_time_table.c by Ronnie Sahlberg
 * Helper routines common to all composite expert statistics
 * tap.
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
#include "compat_macros.h"
#include "epan/packet_info.h"
#include "expert_comp_table.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
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

/* XXX - move this to a common header file */
static const value_string expert_group_vals[] = {
	{ PI_CHECKSUM,		"Checksum" },
	{ PI_SEQUENCE,		"Sequence" },
	{ PI_RESPONSE_CODE, "Response" },
	{ PI_UNDECODED,		"Undecoded" },
	{ PI_MALFORMED,		"Malformed" },
	{ PI_REASSEMBLE,	"Reassemble" },
/*	{ PI_SECURITY,		"Security" },*/
	{ 0, NULL }
};

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


#if (GTK_MAJOR_VERSION >= 2)
static void
copy_as_csv_cb(GtkWindow *win _U_, gpointer data)
{
   guint32         i,j;
   gchar           *table_entry;
   GtkClipboard    *cb;
   GString         *CSV_str = g_string_new("");

   error_equiv_table *expert=(error_equiv_table *)data;

   /* Add the column headers to the CSV data */
   g_string_append(CSV_str,"Summary,Group,Protocol,Count"); /* add the column headings to the CSV string */
   g_string_append(CSV_str,"\n");                        /* new row */

   /* Add the column values to the CSV data */
   for(i=0;i<expert->num_procs;i++){                     /* all rows            */
    for(j=0;j<4;j++){                                    /* all columns         */
     gtk_clist_get_text(expert->table,i,j,&table_entry); /* copy table item into string */
     g_string_append(CSV_str,table_entry);               /* add the table entry to the CSV string */
    if(j!=(4-1))
     g_string_append(CSV_str,",");
    }
    g_string_append(CSV_str,"\n");                       /* new row */
   }

   /* Now that we have the CSV data, copy it into the default clipboard */
   cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);      /* Get the default clipboard */
   gtk_clipboard_set_text(cb, CSV_str->str, -1);         /* Copy the CSV data into the clipboard */
   g_string_free(CSV_str, TRUE);                         /* Free the memory */
}
#endif

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

    action=(callback_action>>8)&0xff;
	type=callback_action&0xff;

	selection=GPOINTER_TO_INT(g_list_nth_data(GTK_CLIST(err->table)->selection, 0));
	if(selection>=(int)err->num_procs){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No items are selected");
		return;
	}
	/* translate it back from row index to index in procedures array */
	selection=GPOINTER_TO_INT(gtk_clist_get_row_data(err->table, selection));

	current_filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));

    /* Some expert data doesn't pass an expert item. Without this we cannot create a filter */
    /* But allow for searching of internet for error string */
    if (action != 6 && action != 7) {
        if (err->procedures[selection].fvalue_value==NULL) {
            if (action != 2 && action != 3 && action != 4) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Ethereal cannot create a filter on this item - %s, try using find instead.", err->procedures[selection].entries[2]);
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
    case 7:
        /* Goto the first occurance (packet) in the trace */
        cf_goto_frame(&cfile, err->procedures[selection].packet_num);
        break;
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

	/* Go to first packet matching this entry */
	ITEM_FACTORY_ENTRY("/Goto First Occurance", NULL,
		error_select_filter_cb, 7*256+0, NULL, NULL),
};

static void
error_create_popup_menu(error_equiv_table *err)
{
	GtkItemFactory *item_factory;

	item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

	gtk_item_factory_create_items_ac(item_factory, sizeof(error_list_menu_items)/sizeof(error_list_menu_items[0]), error_list_menu_items, err, 2);

	err->menu = gtk_item_factory_get_widget(item_factory, "<main>");
	SIGNAL_CONNECT(err->table, "button_press_event", error_show_popup_menu_cb, err);
}

void
init_error_table(error_equiv_table *err, guint16 num_procs, GtkWidget *vbox)
{
	guint16 i, j;
	column_arrows *col_arrows;
	GdkBitmap *ascend_bm, *descend_bm;
	GdkPixmap *ascend_pm, *descend_pm;
	GtkStyle *win_style;
	GtkWidget *column_lb;
#if (GTK_MAJOR_VERSION >= 2)
    GtkWidget *copy_bt;
#endif
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
	gtk_widget_show(err->scrolled_window);


	err->num_procs=num_procs;
	err->procedures=g_malloc(sizeof(error_procedure_t)*(num_procs+1));
	for(i=0;i<num_procs;i++){
		for(j=0;j<3;j++){
			err->procedures[i].entries[j]=NULL; /* reset all values */
		}
	}

#if (GTK_MAJOR_VERSION >= 2)
    /* XXX - maybe we want to have a "Copy as CSV" stock button here? */
    /*copy_bt = gtk_button_new_with_label ("Copy content to clipboard as CSV");*/
    copy_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_COPY);
    gtk_tooltips_set_tip(tooltips, copy_bt,
        "Copy all expert information to the clipboard in CSV (Comma Seperated Values) format.", NULL);
    SIGNAL_CONNECT(copy_bt, "clicked", copy_as_csv_cb,(gpointer *) err);
    gtk_box_pack_start(GTK_BOX(vbox), copy_bt, FALSE, FALSE, 0);
#endif

	/* create popup menu for this table */
  	error_create_popup_menu(err);
}

static gint find_summary_data(error_equiv_table *err, const expert_info_t *expert_data)
{
    gint i;
    
    /* First time thru values will be 0 */
    if (err->num_procs==0 || err->procedures[0].entries[2]==0) {
        return -1;
    }
    for (i=0;i<err->num_procs;i++) {
        if (strcmp(err->procedures[i].entries[2], expert_data->summary) == 0) {
            return i;
        }
    }
    return -1;
}

void
init_error_table_row(error_equiv_table *err, const expert_info_t *expert_data)
{
    guint16 old_num_procs=err->num_procs;
    guint16 j;
    gint row=0;

	/* we have discovered a new procedure. Extend the table accordingly */
    row = find_summary_data(err, expert_data);
	if(row==-1){
        row = 0;
        old_num_procs++;
		err->procedures=g_realloc(err->procedures, (sizeof(error_procedure_t)*(old_num_procs+1)));
        err->procedures[err->num_procs].count=0;
		for(j=0;j<4;j++){
			err->procedures[err->num_procs].entries[j]=NULL;
		}
        err->procedures[err->num_procs].packet_num = (guint32)expert_data->packet_num;                        /* First packet num */
	}
	err->procedures[err->num_procs].entries[0]=(char *)val_to_str(expert_data->group, expert_group_vals,"Unknown group (%u)");   /* Group */
    err->procedures[err->num_procs].entries[1]=(char *)expert_data->protocol;                                 /* Protocol */
    err->procedures[err->num_procs].entries[2]=(char *)expert_data->summary;                                  /* Summary */
	err->procedures[err->num_procs].entries[3]=(char *)g_strdup_printf("%d", err->procedures[row].count);     /* Count */
    err->procedures[err->num_procs].fvalue_value = NULL;
    if (expert_data->pitem && strcmp(expert_data->pitem->finfo->value.ftype->name,"FT_NONE")!=0) {
        err->procedures[err->num_procs].fvalue_value = g_strdup_printf("%s", proto_construct_dfilter_string(expert_data->pitem->finfo, NULL));
    }
    err->num_procs = old_num_procs;                                                           
}

void
add_error_table_data(error_equiv_table *err, const expert_info_t *expert_data)
{
	error_procedure_t *errp;
	gint row;
    gint index;

    index = find_summary_data(err,expert_data);

    /* We should never encounter a condition where we cannot find the expert data. If
     * we do then we will just abort.
     */
    if (index == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find expert data. Aborting");
        return;
    }
	errp=&err->procedures[index];

	/*
	 * If the count of calls for this procedure is currently zero, it's
	 * going to become non-zero, so add a row for it (we don't want
	 * rows for procedures that have no calls - especially if the
	 * procedure has no calls because the index doesn't correspond
	 * to a procedure, but is an unused/reserved value).
	 *
	 * (Yes, this means that the rows aren't in order by anything
	 * interesting.  That's why we have the table sorted by a column.)
	 */
	if (errp->count==0){
		row=gtk_clist_append(err->table, err->procedures[index].entries);
		gtk_clist_set_row_data(err->table, row, (gpointer) index);
	}
    errp->count++;
    err->procedures[index].entries[3] = (char *)g_strdup_printf("%d", errp->count);
}

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


void
reset_error_table_data(error_equiv_table *err)
{
	guint16 i;

	for(i=0;i<err->num_procs;i++){
		err->procedures[i].entries[0] = NULL;
		err->procedures[i].entries[1] = NULL;
		err->procedures[i].entries[2] = NULL;
		err->procedures[i].entries[3] = NULL;
        err->procedures[i].packet_num=0;
	}
	gtk_clist_clear(err->table);
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
            err->procedures[i].packet_num=0;
		}
	}
	err->procedures=NULL;
	err->num_procs=0;
}
