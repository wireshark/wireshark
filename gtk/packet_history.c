/* packet_history.c
 * packet history related functions   2004 Ulf Lamping
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

#include <gtk/gtk.h>

#include <stdio.h>

#include "file.h"
#include "globals.h"

#include "menu.h"
#include "packet_history.h"


GList *history_current = NULL;
GList *history_list = NULL;
gboolean ignore_jump = FALSE;


#if 0
/* print the complete packet history to console */
static void history_print(void) {
    GList *current = g_list_first(history_list);

    printf(" List:\n");

    while(current) {
        if(current == history_current) {
            printf(" Row: %u *\n", GPOINTER_TO_INT(current->data));
        } else {
            printf(" Row: %u\n", GPOINTER_TO_INT(current->data));
        }
        current = g_list_next(current);
    }
}
#endif


/* adjust menu and toolbar sensitivity depending on the history entries */
static void adjust_menus(void) {

    if(history_current) {
        set_menus_for_packet_history(
            (g_list_previous(history_current) != NULL),
            (g_list_next(history_current) != NULL));
    } else {
        /* we don't have any history */
        set_menus_for_packet_history(FALSE, FALSE);
    }

    /* history_print(); */
}


/* clear the history list from the given entry to the end of the list */
static void clear_list(GList *current) {
    GList *next_packet;


    while(current) {
        next_packet = g_list_next(current);
        history_list = g_list_remove(history_list, current->data);
        current = next_packet;
    }
}


/* add an entry to the history list */
void packet_history_add(gint row) {

    if(ignore_jump) {
        /* we jumping back and forward in history, so don't change list */
        return;
    }

    if (history_current) {
        /* clear list behind current position */
        clear_list(g_list_next(history_current));

        /* ignore duplicates */
        if(GPOINTER_TO_INT(history_current->data) == row) {
            adjust_menus();
            return;
        }
    }

    /* add row */
    history_list = g_list_append(history_list, GINT_TO_POINTER(row));
    history_current = g_list_last(history_list);

    adjust_menus();
}


void packet_history_clear(void) {
    
    /* clear "old" list */
    clear_list(history_list);
    history_current = NULL;

    /* add the currently selected first row */
    packet_history_add(0);

    adjust_menus();
}


static void packet_history_back(void) {
    GList *previous;

    if(history_current) {
        previous = g_list_previous(history_current);

        /* do we have a previous entry */
        if(previous) {
            history_current = previous;

            /* goto that packet but don't change history */
            ignore_jump = TRUE;
            cf_goto_frame(&cfile, GPOINTER_TO_INT(previous->data) +1);
            ignore_jump = FALSE;
        }
    }

    adjust_menus();
}


static void packet_history_forward(void) {
    GList *next;

    if(history_current) {
        next = g_list_next(history_current);

        /* do we have a forward entry? */
        if(next) {
            history_current = next;

            /* goto that packet but don't change history */
            ignore_jump = TRUE;
            cf_goto_frame(&cfile, GPOINTER_TO_INT(next->data) +1);
            ignore_jump = FALSE;
        }
    }

    adjust_menus();
}


void history_forward_cb(GtkWidget *widget _U_, gpointer data _U_) {
    packet_history_forward();
}


void history_back_cb(GtkWidget *widget _U_, gpointer data _U_) {
    packet_history_back();
}

