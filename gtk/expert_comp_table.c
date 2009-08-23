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

#include "epan/packet_info.h"
#include "epan/strutil.h"

#include <epan/expert.h>

#include "../simple_dialog.h"
#include "../globals.h"
#include "../color.h"

#include "gtk/expert_comp_table.h"
#include "gtk/filter_utils.h"
#include "gtk/find_dlg.h"
#include "gtk/color_dlg.h"
#include "gtk/main.h"
#include "gtk/gui_utils.h"
#include "gtk/gtkglobals.h"
#include "gtk/webbrowser.h"

#if 0
#define SORT_ALPHABETICAL 0

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
enum
{
   GROUP_COLUMN,
   PROTOCOL_COLUMN,
   SUMMARY_COLUMN,
   COUNT_COLUMN,
   N_COLUMNS
};

static gint find_summary_data(error_equiv_table *err, const expert_info_t *expert_data)
{
    guint i;
    error_procedure_t *procedure;
    
    /* First time thru values will be 0 */
    if (err->num_procs==0) {
        return -1;
    }
    for (i=0;i<err->num_procs;i++) {
        procedure = &g_array_index(err->procs_array, error_procedure_t, i);
        if (strcmp(procedure->entries[1], expert_data->protocol) == 0 &&
            strcmp(procedure->entries[2], expert_data->summary) == 0) {
            return i;
        }
    }
    return -1;
}

static void
error_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
    int action, type, selection;
    error_equiv_table *err = (error_equiv_table *)callback_data;
    char str[512];
    const char *current_filter;
    error_procedure_t *procedure;

    GtkTreeIter iter;
    GtkTreeModel *model;
    expert_info_t expert_data;
    gchar *grp;

    action=FILTER_ACTION(callback_action);
    type=FILTER_ACTYPE(callback_action);


    gtk_tree_selection_get_selected(err->select, &model, &iter);

    gtk_tree_model_get (model, &iter, 
                        GROUP_COLUMN,    &grp,
                        PROTOCOL_COLUMN, &expert_data.protocol,
                        SUMMARY_COLUMN,  &expert_data.summary,
                        -1);
    
    if (strcmp(grp, "Packet:")==0) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "You cannot filter or search for packet number. Click on a valid item header.");
        g_free(grp);
        g_free(expert_data.summary);
        return;
    }

    g_free(grp);

    /* XXX: find_summary_data doesn't (currently) reference expert_data.group.   */
    /*      If "group" is required, then the message from GROUP_COLUMN will need */
    /*       to be translated to the group number (or the actual group number    */
    /*       will also need to be stored in the TreeModel).                      */
    selection = find_summary_data(err, &expert_data);

    g_free(expert_data.summary);

    if(selection>=(int)err->num_procs){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No items are selected");
        return;
    }
    current_filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));

    /* Some expert data doesn't pass an expert item. Without this we cannot create a filter */
    /* But allow for searching of internet for error string */
    procedure = &g_array_index(err->procs_array, error_procedure_t, selection);

    /* FIXME what is 7 ?*/
    if (action != ACTION_WEB_LOOKUP && action != 7) {
        char *msg;
        if (0 /*procedure->fvalue_value==NULL*/) {
            if (action != ACTION_FIND_FRAME && action != ACTION_FIND_NEXT && action != ACTION_FIND_PREVIOUS) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Wireshark cannot create a filter on this item - %s, try using find instead.", 
                              procedure->entries[2]);
                return;
            }
        }
        msg = g_malloc(escape_string_len(procedure->entries[2]));
        escape_string(msg, procedure->entries[2]);
        switch(type){
        case ACTYPE_SELECTED:
            /* if no expert item was passed */
            if (procedure->fvalue_value==NULL) {
                g_snprintf(str, sizeof(str), "expert.message==%s", msg);
            }
            else
            {
                /* expert item exists. Use it. */
                g_strlcpy(str, procedure->fvalue_value, sizeof(str));
            }
            break;
        case ACTYPE_NOT_SELECTED:
            /* if no expert item was passed */
            if (procedure->fvalue_value==NULL) {
                g_snprintf(str, sizeof(str), "!(expert.message==%s)", msg);
            }
            else
            {
                /* expert item exists. Use it. */
                g_snprintf(str, sizeof(str), "!(%s)", procedure->fvalue_value);
            }
            break;
            /* the remaining cases will only exist if the expert item exists so no need to check */
        case ACTYPE_AND_SELECTED:
            if ((!current_filter) || (0 == strlen(current_filter)))
                g_snprintf(str, sizeof(str), "expert.message==%s", msg);
            else
                g_snprintf(str, sizeof(str), "(%s) && (expert.message==%s)", current_filter, msg);
            break;
        case ACTYPE_OR_SELECTED:
            if ((!current_filter) || (0 == strlen(current_filter)))
                g_snprintf(str, sizeof(str), "expert.message==%s", msg);
            else
                g_snprintf(str, sizeof(str), "(%s) || (expert.message==%s)", current_filter, msg);
            break;
        case ACTYPE_AND_NOT_SELECTED:
            if ((!current_filter) || (0 == strlen(current_filter)))
                g_snprintf(str, sizeof(str), "!(expert.message==%s)", msg);
            else
                g_snprintf(str, sizeof(str), "(%s) && !(expert.message==%s)", current_filter, msg);
            break;
        case ACTYPE_OR_NOT_SELECTED:
            if ((!current_filter) || (0 == strlen(current_filter)))
                g_snprintf(str, sizeof(str), "!(expert.message==%s)", msg);
            else
                g_snprintf(str, sizeof(str), "(%s) || !(expert.message==%s)", current_filter, msg);
            break;
        default:
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Can't find menu type - %u", type);
        }
        g_free(msg);
    }

    switch(action){
    case ACTION_MATCH:
        main_filter_packets(&cfile, str, FALSE);
        break;
    case ACTION_PREPARE:
        gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
        break;
    case ACTION_FIND_FRAME:
        /* When trying to perform a find without expert item, we must pass
         * the expert string to the find window. The user might need to modify
         * the string and click on the text search to locate the packet in question.
         * So regardless of the type we will just bring up the find window and allow
         * the user to modify the search criteria and options.
         */
        find_frame_with_filter(str);
        break;
    case ACTION_FIND_NEXT:
        /* In the case of find next, if there was no expert item, then most likely the expert
         * string was modified to locate the text inside the message. So we can't just perform
         * a find with the expert string or we will not really be performing a find next.
         * In an effort to allow the user to modify the string and/or continue searching, we
         * will just present the user with the find window again with the default expert string.
         * A better aproach would be to attempt in capturing the last find string and utilize this 
         * with a find next/previous. Also a better approach might be to just send a <Ctl-N> keystroke.
         */
        if (procedure->fvalue_value==NULL) {
            find_frame_with_filter(str);
        }
        else
        { 
            /* We have an expert item so just continue search without find dialog. */
            find_previous_next_frame_with_filter(str, FALSE);
        }
        break;
    case ACTION_FIND_PREVIOUS:
        /* In the case of find previous, if there was no expert item, then most likely the expert
         * string was modified to locate the text inside the message. So we can't just perform
         * a find with the expert string or we will not really be performing a find previous.
         * In an effort to allow the user to modify the string and/or continue searching, we
         * will just present the user with the find window again with the default expert string.
         * A better aproach would be to attempt in capturing the last find string and utilize this 
         * with a find next/previous. Also a better approach might be to just send a <Ctl-B> keystroke.
         */
        if (procedure->fvalue_value==NULL) {
            find_frame_with_filter(str);
        }
        else
        { 
            /* We have an expert item so just continue search without find dialog. */
            find_previous_next_frame_with_filter(str, TRUE);
        }
        break;
    case ACTION_COLORIZE:
        color_display_with_filter(str);
        break;
    case ACTION_WEB_LOOKUP:
        /* Lookup expert string on internet. Default search via www.google.com */
        g_snprintf(str, sizeof(str), "http://www.google.com/search?hl=en&q=%s+'%s'", procedure->entries[1], procedure->entries[2]);
        browser_open_url(str);
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
	{"/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, 0),
		NULL, NULL,},
	{"/Apply as Filter/... not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, 0),
		NULL, NULL,},
	{"/Apply as Filter/.. and Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, 0),
		NULL, NULL,},
	{"/Apply as Filter/... or Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, 0),
		NULL, NULL,},
	{"/Apply as Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, 0),
		NULL, NULL,},
	{"/Apply as Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, 0),
		NULL, NULL,},

	/* Prepare */
	{"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, 0),
		NULL, NULL,},
	{"/Prepare a Filter/Not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, 0),
		NULL, NULL,},
	{"/Prepare a Filter/... and Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, 0),
		NULL, NULL,},
	{"/Prepare a Filter/... or Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, 0),
		NULL, NULL,},
	{"/Prepare a Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, 0),
		NULL, NULL,},
	{"/Prepare a Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, 0),
		NULL, NULL,},

	/* Find Frame */
	{"/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame/Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, 0),
		NULL, NULL,},
	{"/Find Frame/Find Frame/Not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_NOT_SELECTED, 0),
		NULL, NULL,},
	/* Find Next */
	{"/Find Frame/Find Next", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Next/Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, 0),
		NULL, NULL,},
	{"/Find Frame/Find Next/Not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_NOT_SELECTED, 0),
		NULL, NULL,},

	/* Find Previous */
	{"/Find Frame/Find Previous", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Previous/Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, 0),
		NULL, NULL,},
	{"/Find Frame/Find Previous/Not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_NOT_SELECTED, 0),
		NULL, NULL,},

	/* Colorize Procedure */
	{"/Colorize Procedure", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Colorize Procedure/Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, 0),
		NULL, NULL,},
	{"/Colorize Procedure/Not Selected", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_NOT_SELECTED, 0),
		NULL, NULL,},

	/* Search Internet */
	{"/Internet Search for Info Text", NULL,
		GTK_MENU_FUNC(error_select_filter_cb), CALLBACK_WEB_LOOKUP, NULL, NULL,}
};

static void
expert_goto_pkt_cb (GtkTreeSelection *selection, gpointer data _U_)
{
        GtkTreeIter iter;
        GtkTreeModel *model;
        gchar *pkt;
        gchar *grp;

        if (gtk_tree_selection_get_selected (selection, &model, &iter))
        {
                gtk_tree_model_get (model, &iter, 
                                    PROTOCOL_COLUMN, &pkt,
                                    GROUP_COLUMN,    &grp,
                                    -1);

                if (strcmp(grp, "Packet:")==0) {
                    cf_goto_frame(&cfile, atoi(pkt));
                }
                g_free (pkt);
                g_free (grp);
        }
}

static void
error_create_popup_menu(error_equiv_table *err)
{
    GtkItemFactory *item_factory;


    err->select = gtk_tree_view_get_selection (GTK_TREE_VIEW (err->tree_view));
    gtk_tree_selection_set_mode (err->select, GTK_SELECTION_SINGLE);
    g_signal_connect (G_OBJECT (err->select), "changed",
                  G_CALLBACK (expert_goto_pkt_cb),
                  err);
    item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

    gtk_item_factory_create_items_ac(item_factory, sizeof(error_list_menu_items)/sizeof(error_list_menu_items[0]), error_list_menu_items, err, 2);

    err->menu = gtk_item_factory_get_widget(item_factory, "<main>");
    g_signal_connect(err->tree_view, "button_press_event", G_CALLBACK(error_show_popup_menu_cb), err);
}

void
init_error_table(error_equiv_table *err, guint num_procs, GtkWidget *vbox)
{
    GtkTreeStore *store;
    GtkWidget *tree;
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;
    GtkTreeSortable *sortable;

    /* Create the store */
    store = gtk_tree_store_new (4,       /* Total number of columns */
#if 0
                               G_TYPE_POINTER,   /* Group              */
                               G_TYPE_POINTER,   /* Protocol           */
                               G_TYPE_POINTER,   /* Summary            */
#else
                               G_TYPE_STRING,   /* Group              */
                               G_TYPE_STRING,   /* Protocol           */
                               G_TYPE_STRING,   /* Summary            */
#endif
                               G_TYPE_INT);     /* Count              */

    /* Create a view */
    tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
    err->tree_view = GTK_TREE_VIEW(tree);
    sortable = GTK_TREE_SORTABLE(store);

    /* Setup the sortable columns */
#if 0
    gtk_tree_sortable_set_sort_func(sortable, SORT_ALPHABETICAL, sort_iter_compare_func, GINT_TO_POINTER(SORT_ALPHABETICAL), NULL);
    gtk_tree_sortable_set_sort_column_id(sortable, SORT_ALPHABETICAL, GTK_SORT_ASCENDING);
#endif
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW (tree), FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (store));

    /* Create a cell renderer */
    renderer = gtk_cell_renderer_text_new ();

    /* Create the first column, associating the "text" attribute of the
     * cell_renderer to the first column of the model */
    column = gtk_tree_view_column_new_with_attributes ("Group", renderer, "text", GROUP_COLUMN, NULL);
    gtk_tree_view_column_set_sort_column_id(column, GROUP_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    /* Add the column to the view. */
    gtk_tree_view_append_column (GTK_TREE_VIEW (err->tree_view), column);
 
    /* Second column.. Protocol. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Protocol", renderer, "text", PROTOCOL_COLUMN, NULL);
    gtk_tree_view_column_set_sort_column_id(column, PROTOCOL_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column (GTK_TREE_VIEW (err->tree_view), column);
 
    /* Third column.. Summary. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Summary", renderer, "text", SUMMARY_COLUMN, NULL);
    gtk_tree_view_column_set_sort_column_id(column, SUMMARY_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column (GTK_TREE_VIEW (err->tree_view), column);
 
    /* Last column.. Count. */
    column = gtk_tree_view_column_new_with_attributes ("Count", renderer, "text", COUNT_COLUMN, NULL);
    gtk_tree_view_column_set_sort_column_id(column, COUNT_COLUMN);
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

    gtk_widget_show(err->scrolled_window);

    err->num_procs=num_procs;

    err->text = g_string_chunk_new(100);
    err->procs_array = g_array_sized_new(FALSE, FALSE, sizeof(error_procedure_t), num_procs);

    /* create popup menu for this table */
    error_create_popup_menu(err);
}

void
init_error_table_row(error_equiv_table *err, const expert_info_t *expert_data)
{
    guint old_num_procs=err->num_procs;
    guint j;
    gint row=0;
    error_procedure_t *procedure;
    GtkTreeStore *store;
    GtkTreeIter   new_iter;

    /* we have discovered a new procedure. Extend the table accordingly */
    row = find_summary_data(err, expert_data);
    if(row==-1){
        error_procedure_t new_procedure;
        /* First time we have seen this event so initialize memory table */
        row = old_num_procs; /* Number of expert events since this is a new event */

        new_procedure.count=0; /* count of events for this item */
        new_procedure.fvalue_value = NULL; /* Filter string value */
        for(j=0;j<4;j++){
            new_procedure.entries[j]=NULL;
        }
        g_array_append_val(err->procs_array, new_procedure);
        procedure = &g_array_index(err->procs_array, error_procedure_t, row);
        
        /* Create the item in our memory table */
        procedure->entries[0]=(char *)g_string_chunk_insert(err->text, 
                val_to_str(expert_data->group, expert_group_vals,"Unknown group (%u)"));  /* Group */
        procedure->entries[1]=(char *)g_string_chunk_insert(err->text, expert_data->protocol);    /* Protocol */
        procedure->entries[2]=(char *)g_string_chunk_insert(err->text, expert_data->summary);     /* Summary */

        /* Create a new item in our tree view */
        store = GTK_TREE_STORE(gtk_tree_view_get_model(err->tree_view)); /* Get store */
        gtk_tree_store_append (store, &procedure->iter, NULL);  /* Acquire an iterator */
        
        gtk_tree_store_set (store, &procedure->iter,
                    GROUP_COLUMN, procedure->entries[0],
                    PROTOCOL_COLUMN, procedure->entries[1],
                    SUMMARY_COLUMN,  procedure->entries[2], -1);
        
        /* If an expert item was passed then build the filter string */
        if (expert_data->pitem) {
            char *filter;
            
            g_assert(PITEM_FINFO(expert_data->pitem));
            filter = proto_construct_match_selected_string(PITEM_FINFO(expert_data->pitem), NULL);
            if (filter != NULL)
                procedure->fvalue_value = g_string_chunk_insert(err->text, filter);
        }
        /* Store the updated count of events */
        err->num_procs = ++old_num_procs;
    }

    /* Update our memory table with event data */
    procedure = &g_array_index(err->procs_array, error_procedure_t, row);
    procedure->count++; /* increment the count of events for this item */

#if 0
    /* Store the updated count for this event item */
    err->procedures[row].entries[3]=(char *)g_strdup_printf("%d", err->procedures[row].count);     /* Count */
#endif

    /* Update the tree with new count for this event */
    store = GTK_TREE_STORE(gtk_tree_view_get_model(err->tree_view));
    gtk_tree_store_set(store, &procedure->iter, COUNT_COLUMN, procedure->count, -1);
    gtk_tree_store_append(store, &new_iter, &procedure->iter);
    gtk_tree_store_set(store, &new_iter,
                       GROUP_COLUMN,    "Packet:",
                       PROTOCOL_COLUMN, (char *)g_strdup_printf("%d", expert_data->packet_num),
                       COUNT_COLUMN,    1,
                       -1);
}

void
reset_error_table_data(error_equiv_table *err)
{
    GtkTreeStore    *store;

    store = GTK_TREE_STORE(gtk_tree_view_get_model(err->tree_view));
    gtk_tree_store_clear(store);
    err->num_procs = 0;
    /* g_string_chunk_clear() is introduced in glib 2.14 */
    g_string_chunk_free(err->text);
    err->text = g_string_chunk_new(100);

    g_array_set_size(err->procs_array, 0);
}

void
free_error_table_data(error_equiv_table *err)
{
    err->num_procs=0;
    g_string_chunk_free(err->text);
    g_array_free(err->procs_array, TRUE);
}
