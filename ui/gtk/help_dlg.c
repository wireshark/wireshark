/* help_dlg.c
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <stdio.h>
#include <errno.h>

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "ui/gtk/help_dlg.h"
#include "ui/gtk/text_page_utils.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/webbrowser.h"


#define HELP_DIR        "help"
#define NOTEBOOK_KEY    "notebook_key"

/*
 * Keep a static pointer to the current "Help" window, if any, so that
 * if somebody tries to do "Help->Help" while there's already a
 * "Help" window up, we just pop up the existing one, rather than
 * creating a new one.
*/
static GtkWidget *help_w = NULL;

/*
 * Keep a list of text widgets and corresponding file names as well
 * (for text format changes).
 */
typedef struct {
    char *topic;
    char *pathname;
    GtkWidget *page;
} help_page_t;

static GSList *help_text_pages = NULL;


/**
 * Redraw all help pages, to use a new font.
 */
void help_redraw(void)
{
    GSList *help_page_ent;
    help_page_t *help_page;

    if (help_w != NULL) {
        for (help_page_ent = help_text_pages; help_page_ent != NULL;
             help_page_ent = g_slist_next(help_page_ent))
        {
            help_page = (help_page_t *)help_page_ent->data;
            text_page_redraw(help_page->page, help_page->pathname);
        }
    }
}

void
topic_action(topic_action_e action)
{
    char *url;

    url = topic_action_url(action);

    if(url != NULL) {
        browser_open_url(url);
        g_free(url);
    }
}

void
topic_cb(GtkWidget *w _U_, topic_action_e action)
{
    topic_action(action);
}

gboolean
topic_menu_cb(GtkWidget *w _U_, GdkEventButton *event _U_, gpointer user_data)
{
    topic_action((topic_action_e)GPOINTER_TO_INT(user_data));
    return TRUE;
}
