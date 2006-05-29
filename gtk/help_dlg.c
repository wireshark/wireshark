/* help_dlg.c
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "epan/filesystem.h"
#include "help_dlg.h"
#include "text_page.h"
#include <epan/prefs.h>
#include "gtkglobals.h"
#include "gui_utils.h"
#include "compat_macros.h"
#include "dlg_utils.h"
#include "simple_dialog.h"
#include "webbrowser.h"
#include "file_util.h"

#ifdef HHC_DIR
#include <windows.h>
#include <htmlhelp.h>
#include "epan/strutil.h"
#endif


#define HELP_DIR	"help"


#define NOTEBOOK_KEY    "notebook_key"

static void help_destroy_cb(GtkWidget *w, gpointer data);

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


/*
 * Helper function to show a simple help text page.
 */
static GtkWidget * help_page(const char *topic, const char *filename)
{
  GtkWidget *text_page;
  char *relative_path, *absolute_path;
  help_page_t *page;

  relative_path = g_strconcat(HELP_DIR, G_DIR_SEPARATOR_S, filename, NULL);
  absolute_path = get_datafile_path(relative_path);
  text_page = text_page_new(absolute_path);
  g_free(relative_path);
  gtk_widget_show(text_page);

  page = g_malloc(sizeof (help_page_t));
  page->topic = g_strdup(topic);
  page->pathname = absolute_path;
  page->page = text_page;
  help_text_pages = g_slist_append(help_text_pages, page);

  return text_page;
}


/*
 * Create and show help dialog.
 */
static
void help_dialog(void)
{
  GtkWidget *main_vb, *bbox, *help_nb, *close_bt, *label, *topic_vb;
  char line[4096+1];	/* XXX - size? */
  char *p;
  char *filename;
  char *help_toc_file_path;
  FILE *help_toc_file;

  if (help_w != NULL) {
    /* There's already a "Help" dialog box; reactivate it. */
    reactivate_window(help_w);
    return;
  }

  help_toc_file_path = get_datafile_path(HELP_DIR G_DIR_SEPARATOR_S "toc");
  help_toc_file = eth_fopen(help_toc_file_path, "r");
  if (help_toc_file == NULL) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not open file \"%s\": %s",
                  help_toc_file_path, strerror(errno));
    g_free(help_toc_file_path);
    return;
  }

  help_w = window_new_with_geom(GTK_WINDOW_TOPLEVEL, "Wireshark: Help", "help");
  gtk_window_set_default_size(GTK_WINDOW(help_w), DEF_WIDTH, DEF_HEIGHT);
  gtk_container_border_width(GTK_CONTAINER(help_w), 2);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 1);
  gtk_container_add(GTK_CONTAINER(help_w), main_vb);

  /* help topics container */
  help_nb = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), help_nb);
  OBJECT_SET_DATA(help_w, NOTEBOOK_KEY, help_nb);

  /* help topics */
  while (fgets(line, sizeof line, help_toc_file) != NULL) {
    /* Strip off line ending. */
    p = strpbrk(line, "\r\n");
    if (p == NULL)
      break;		/* last line has no line ending */
    *p = '\0';
    /* {Topic title}:{filename of help file} */
    p = strchr(line, ':');
    if (p != NULL) {
      *p++ = '\0';
      filename = p;

      /*
       * "line" refers to the topic now, and "filename" refers to the
       * file name.
       */
      topic_vb = help_page(line, filename);
      label = gtk_label_new(line);
      gtk_notebook_append_page(GTK_NOTEBOOK(help_nb), topic_vb, label);
    }
  }
  if(ferror(help_toc_file)) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Error reading file \"%s\": %s",
                  help_toc_file_path, strerror(errno));
  }
  fclose(help_toc_file);


  /* Button row */
  bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
  gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);

  close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
  window_set_cancel_button(help_w, close_bt, window_cancel_button_cb);

  SIGNAL_CONNECT(help_w, "delete_event", window_delete_event_cb, NULL);
  SIGNAL_CONNECT(help_w, "destroy", help_destroy_cb, NULL);

  gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(help_w));

  gtk_widget_show_all(help_w);
  window_present(help_w);
} /* help_dialog */


gboolean topic_available(topic_action_e action) {

#ifdef WIRESHARK_EUG_DIR
    if(action == HELP_CAPTURE_INTERFACES_DETAILS_DIALOG) {
        /* page currently not existing in user's guide */
        return FALSE;
    }
    /* online: we have almost all possible pages available */
    return TRUE;
#else
    /* offline: we have only some pages available */
    switch(action) {
    case(HELP_CONTENT):
        return TRUE;
        break;
    case(HELP_GETTING_STARTED):
        return TRUE;
        break;
    case(HELP_CAPTURE_OPTIONS_DIALOG):
        return TRUE;
        break;
    case(HELP_CAPTURE_FILTERS_DIALOG):
        return TRUE;
        break;
    case(HELP_DISPLAY_FILTERS_DIALOG):
        return TRUE;
        break;
    default:
        return FALSE;
    }
#endif
}

/*
 * Open the help dialog and show a specific help page.
 */
static void help_topic(const gchar *topic) {

#ifdef HHC_DIR
    HWND hw;
    GString *url = g_string_new("");

    g_string_append_printf(url, "%s\\user-guide.chm::/%s>Wireshark Help", 
        get_datafile_dir(), topic);

    hw = HtmlHelpW(NULL, 
        utf_8to16(url->str), 
        HH_DISPLAY_TOPIC, 0); 

    if(hw == NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not open help file: %s\\user-guide.chm",
            get_datafile_dir());
    }

    g_string_free(url, TRUE /* free_segment */);

    return;
#else
    gchar       *page_topic;
    GtkWidget   *help_nb;
    GSList      *help_page_ent;
    gint        page_num = 0;
    help_page_t *page;


    /* show help dialog, if not already opened */
    help_dialog();

    help_nb = OBJECT_GET_DATA(help_w, NOTEBOOK_KEY);

    /* find page to display */
    for (help_page_ent = help_text_pages; help_page_ent != NULL;
         help_page_ent = g_slist_next(help_page_ent))
    {
        page = (help_page_t *)help_page_ent->data;
        page_topic = page->topic;
        if (strcmp (page_topic, topic) == 0) {
            /* topic page found, switch to notebook page */
            gtk_notebook_set_page(GTK_NOTEBOOK(help_nb), page_num);
            return;
        }
        page_num++;
    }
#endif

    /* topic page not found, default (first page) will be shown */
}


/*
 * Help dialog is closed now.
 */
static void help_destroy_cb(GtkWidget *w _U_, gpointer data _U_)
{
  GSList *help_page_ent;
  help_page_t *page;

  /* Free up the list of help pages. */
  for (help_page_ent = help_text_pages; help_page_ent != NULL;
       help_page_ent = g_slist_next(help_page_ent)) {
    page = (help_page_t *)help_page_ent->data;
    g_free(page->topic);
    g_free(page->pathname);
    g_free(page);
  }
  g_slist_free(help_text_pages);
  help_text_pages = NULL;

  /* Note that we no longer have a Help window. */
  help_w = NULL;
}


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


#ifdef HHC_DIR
#define ONLINE_HELP_CALL help_topic
#define ONLINE_HELP_PREFIX "eug_chm/"
#else
#define ONLINE_HELP_CALL browser_open_data_file
#define ONLINE_HELP_PREFIX "eug_html_chunked/"
#endif

static void
topic_action(topic_action_e action)
{
    /* pages online at www.wireshark.org */
    switch(action) {
    case(ONLINEPAGE_HOME):
        browser_open_url ("http://www.wireshark.org");
        break;
    case(ONLINEPAGE_WIKI):
        browser_open_url ("http://wiki.wireshark.org");
        break;
    case(ONLINEPAGE_DOWNLOAD):
        browser_open_url ("http://www.wireshark.org/download.html");
        break;
    case(ONLINEPAGE_USERGUIDE):
        browser_open_url ("http://www.wireshark.org/docs/eug_html_chunked");
        break;
    case(ONLINEPAGE_FAQ):
        browser_open_url ("http://www.wireshark.org/faq.html");
        break;
    case(ONLINEPAGE_SAMPLE_FILES):
        browser_open_url ("http://wiki.wireshark.org/SampleCaptures");
        break;

    /* local manual pages */
    case(LOCALPAGE_MAN_WIRESHARK):
        browser_open_data_file("wireshark.html");
        break;
    case(LOCALPAGE_MAN_WIRESHARK_FILTER):
        browser_open_data_file("wireshark-filter.html");
        break;
    case(LOCALPAGE_MAN_TWIRESHARK):
        browser_open_data_file("twireshark.html");
        break;
    case(LOCALPAGE_MAN_DUMPCAP):
        browser_open_data_file("dumpcap.html");
        break;
    case(LOCALPAGE_MAN_MERGECAP):
        browser_open_data_file("mergecap.html");
        break;
    case(LOCALPAGE_MAN_EDITCAP):
        browser_open_data_file("editcap.html");
        break;
    case(LOCALPAGE_MAN_TEXT2PCAP):
        browser_open_data_file("text2pcap.html");
        break;

#ifdef WIRESHARK_EUG_DIR
    /* local help pages (User's Guide) */
    case(HELP_CONTENT):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX "index.html");
        break;
    case(HELP_CAPTURE_OPTIONS_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX "ChCapCaptureOptions.html");
        break;
    case(HELP_CAPTURE_FILTERS_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX "ChWorkDefineFilterSection.html");
        break;
    case(HELP_DISPLAY_FILTERS_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX "ChWorkDefineFilterSection.html");
        break;
    case(HELP_COLORING_RULES_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChCustColorizationSection.html");
        break;
    case(HELP_PRINT_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChIOPrintSection.html");
        break;
    case(HELP_FIND_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChWorkFindPacketSection.html");
        break;
    case(HELP_GOTO_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChWorkGoToPacketSection.html");
        break;
    case(HELP_CAPTURE_INTERFACES_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChCapInterfaceSection.html");
        break;
    case(HELP_ENABLED_PROTOCOLS_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChCustProtocolDissectionSection.html");
        break;
    case(HELP_DECODE_AS_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChCustProtocolDissectionSection.html");
        break;
    case(HELP_DECODE_AS_SHOW_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChCustProtocolDissectionSection.html");
        break;
    case(HELP_FOLLOW_TCP_STREAM_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChAdvFollowTCPSection.html");
        break;
    case(HELP_STATS_SUMMARY_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChStatSummary.html");
        break;
    case(HELP_STATS_PROTO_HIERARCHY_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChStatHierarchy.html");
        break;
    case(HELP_STATS_ENDPOINTS_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChStatEndpoints.html");
        break;
    case(HELP_STATS_CONVERSATIONS_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChStatConversations.html");
        break;
    case(HELP_STATS_IO_GRAPH_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChStatIOGraphs.html");
        break;
    case(HELP_FILESET_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChIOFileSetSection.html");
        break;
    case(HELP_CAPTURE_INTERFACES_DETAILS_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChCapInterfaceDetailsSection.html");
        break;
    case(HELP_PREFERENCES_DIALOG):
        ONLINE_HELP_CALL(ONLINE_HELP_PREFIX  "ChCustPreferencesSection.html");
        break;
#else
    /* only some help pages are available for offline reading */
    case(HELP_CONTENT):
        help_topic("Overview");
        break;
    case(HELP_GETTING_STARTED):
        help_topic("Getting Started");
        break;
    case(HELP_CAPTURE_OPTIONS_DIALOG):
        help_topic("Capturing");
        break;
    case(HELP_CAPTURE_FILTERS_DIALOG):
        help_topic("Capture Filters");
        break;
    case(HELP_DISPLAY_FILTERS_DIALOG):
        help_topic("Display Filters");
        break;
#endif

    default:
        g_assert_not_reached();
    }
}


void 
topic_cb(GtkWidget *w _U_, topic_action_e action)
{
    topic_action(action);
}

void 
topic_menu_cb(GtkWidget *w _U_, gpointer data _U_, topic_action_e action) {
    topic_action(action);
}

