/* packet_list.c
 * packet list related functions   2002 Olivier Abad
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

#include <gtk/gtk.h>
#include <string.h>

#include "globals.h"
#include "gtkglobals.h"
#include "epan/epan.h"
#include "color.h"
#include "color_filters.h"
#include "../ui_util.h"
#include "gui_utils.h"
#include "main.h"
#include "menu.h"
#include "colors.h"
#include <epan/column.h>
#include "epan/column_info.h"
#include "compat_macros.h"
#include <epan/prefs.h>
#include "file_dlg.h"
#include "packet_list.h"
#include "keys.h"
#include "font_utils.h"
#include "packet_history.h"

#include <epan/timestamp.h>

#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"

#include "progress_dlg.h"

#define N_PROGBAR_UPDATES 100


/*
 * XXX - gross hack.
 * This lets us use GtkCList in GTK+ 1.3[.x] and later, and EthCList on
 * GTK+ 1.2[.x], at least until we either use GTK+ 2.x's native widgets
 * or make EthCList work on 1.3[.x] and 2.x.
 */
#if GTK_MAJOR_VERSION >= 2 || GTK_MINOR_VERSION >= 3
#define EthCList				GtkCList
#define EthCListRow				GtkCListRow
#define eth_clist_append			gtk_clist_append
#define eth_clist_clear				gtk_clist_clear
#define eth_clist_column_titles_show		gtk_clist_column_titles_show
#define eth_clist_find_row_from_data		gtk_clist_find_row_from_data
#define eth_clist_freeze			gtk_clist_freeze
#define eth_clist_get_row_data			gtk_clist_get_row_data
#define eth_clist_get_selection_info		gtk_clist_get_selection_info
#define eth_clist_moveto			gtk_clist_moveto
#define eth_clist_new				gtk_clist_new
#define eth_clist_row_is_visible		gtk_clist_row_is_visible
#define eth_clist_select_row			gtk_clist_select_row
#define eth_clist_set_background		gtk_clist_set_background
#define eth_clist_set_column_auto_resize	gtk_clist_set_column_auto_resize
#define eth_clist_set_column_justification	gtk_clist_set_column_justification
#define eth_clist_set_column_resizeable		gtk_clist_set_column_resizeable
#define eth_clist_set_column_width		gtk_clist_set_column_width
#define eth_clist_set_column_widget		gtk_clist_set_column_widget
#define eth_clist_set_compare_func		gtk_clist_set_compare_func
#define eth_clist_set_foreground		gtk_clist_set_foreground
#define eth_clist_set_row_data			gtk_clist_set_row_data
#define eth_clist_set_selection_mode		gtk_clist_set_selection_mode
#define eth_clist_set_sort_column		gtk_clist_set_sort_column
#define eth_clist_set_text			gtk_clist_set_text
#define eth_clist_sort				gtk_clist_sort
#define eth_clist_thaw				gtk_clist_thaw
#define ETH_CLIST				GTK_CLIST
#else
#include "ethclist.h"
#endif

typedef struct column_arrows {
  GtkWidget *table;
  GtkWidget *ascend_pm;
  GtkWidget *descend_pm;
} column_arrows;

GtkWidget *packet_list;

/* EthClist compare routine, overrides default to allow numeric comparison */

#define COMPARE_FRAME_NUM()	((fdata1->num < fdata2->num) ? -1 : \
				 (fdata1->num > fdata2->num) ? 1 : \
				 0)

#define COMPARE_NUM(f)	((fdata1->f < fdata2->f) ? -1 : \
			 (fdata1->f > fdata2->f) ? 1 : \
			 COMPARE_FRAME_NUM())

/* Compare time stamps.
   A packet whose time is a reference time is considered to have
   a lower time stamp than any frame with a non-reference time;
   if both packets' times are reference times, we compare the
   times of the packets. */
#define COMPARE_TS(ts) \
		((fdata1->flags.ref_time && !fdata2->flags.ref_time) ? -1 : \
		 (!fdata1->flags.ref_time && fdata2->flags.ref_time) ? 1 : \
		 (fdata1->ts.secs < fdata2->ts.secs) ? -1 : \
		 (fdata1->ts.secs > fdata2->ts.secs) ? 1 : \
		 (fdata1->ts.nsecs < fdata2->ts.nsecs) ? -1 :\
		 (fdata1->ts.nsecs > fdata2->ts.nsecs) ? 1 : \
		 COMPARE_FRAME_NUM())
static gint
packet_list_compare(EthCList *clist, gconstpointer  ptr1, gconstpointer  ptr2)
{
  /* Get row data structures */
  const EthCListRow *row1 = (const EthCListRow *)ptr1;
  const EthCListRow *row2 = (const EthCListRow *)ptr2;

  /* Get the frame data structures for the rows */
  const frame_data *fdata1 = row1->data;
  const frame_data *fdata2 = row2->data;

  /* Get row text strings */
  const char *text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
  const char *text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

  /* Attempt to convert to numbers */
  double  num1;
  double  num2;

  int ret;

  gint  col_fmt = cfile.cinfo.col_fmt[clist->sort_column];

  switch (col_fmt) {

  case COL_NUMBER:
    return COMPARE_FRAME_NUM();

  case COL_CLS_TIME:
    switch (timestamp_get_type()) {

    case TS_ABSOLUTE:
    case TS_ABSOLUTE_WITH_DATE:
      return COMPARE_TS(abs_ts);

    case TS_RELATIVE:
      return COMPARE_TS(rel_ts);

    case TS_DELTA:
      return COMPARE_TS(del_ts);

    case TS_NOT_SET:
      return 0;
    }
    return 0;

  case COL_ABS_TIME:
  case COL_ABS_DATE_TIME:
    return COMPARE_TS(abs_ts);

  case COL_REL_TIME:
    return COMPARE_TS(rel_ts);

  case COL_DELTA_TIME:
    return COMPARE_TS(del_ts);

  case COL_PACKET_LENGTH:
    return COMPARE_NUM(pkt_len);

  case COL_CUMULATIVE_BYTES:
    return COMPARE_NUM(cum_bytes);

  default:
    num1 = atof(text1);
    num2 = atof(text2);
    if ((col_fmt == COL_UNRES_SRC_PORT) || (col_fmt == COL_UNRES_DST_PORT) ||
        ((num1 != 0) && (num2 != 0) && ((col_fmt == COL_DEF_SRC_PORT) || (col_fmt == COL_RES_SRC_PORT) ||
                                      (col_fmt == COL_DEF_DST_PORT) || (col_fmt == COL_RES_DST_PORT)))) {

      /* Compare numeric column */

      if (num1 < num2)
        return -1;
      else if (num1 > num2)
        return 1;
      else
        return COMPARE_FRAME_NUM();
    }

    else {

      /* Compare text column */
      if (!text2) {
      	if (text1)
      	  return 1;
      	else
      	  return COMPARE_FRAME_NUM();
      }

      if (!text1)
        return -1;

      ret = strcmp(text1, text2);
      if (ret == 0)
        return COMPARE_FRAME_NUM();
      else
        return ret;
    }
  }
}

/* What to do when a column is clicked */
static void
packet_list_click_column_cb(EthCList *clist, gint column, gpointer data)
{
  column_arrows *col_arrows = (column_arrows *) data;
  int i;

  eth_clist_freeze(clist);

  for (i = 0; i < cfile.cinfo.num_cols; i++) {
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
  }
  else {
    clist->sort_type = GTK_SORT_ASCENDING;
    gtk_widget_show(col_arrows[column].ascend_pm);
    eth_clist_set_sort_column(clist, column);
  }
  eth_clist_thaw(clist);

  eth_clist_sort(clist);
}

/* What to do when a list item is selected/unselected */
static void
packet_list_select_cb(GtkWidget *w _U_, gint row, gint col _U_, gpointer evt _U_) {

/* Remove the hex display tabbed pages */
  while( (gtk_notebook_get_nth_page( GTK_NOTEBOOK(byte_nb_ptr), 0)))
    gtk_notebook_remove_page( GTK_NOTEBOOK(byte_nb_ptr), 0);

  cf_select_packet(&cfile, row);
  gtk_widget_grab_focus(packet_list);
  packet_history_add(row);
}

static void
packet_list_unselect_cb(GtkWidget *w _U_, gint row _U_, gint col _U_, gpointer evt _U_) {

  cf_unselect_packet(&cfile);
}

/* mark packets */
static void
set_frame_mark(gboolean set, frame_data *frame, gint row) {
  GdkColor fg, bg;

  if (row == -1)
    return;
  if (set) {
    cf_mark_frame(&cfile, frame);
    color_t_to_gdkcolor(&fg, &prefs.gui_marked_fg);
    color_t_to_gdkcolor(&bg, &prefs.gui_marked_bg);
    eth_clist_set_foreground(ETH_CLIST(packet_list), row, &fg);
    eth_clist_set_background(ETH_CLIST(packet_list), row, &bg);
  } else {
    color_filter_t *cfilter = frame->color_filter;

    cf_unmark_frame(&cfile, frame);
    /* Restore the color from the matching color filter if any */
    if (cfilter) { /* The packet matches a color filter */
      color_t_to_gdkcolor(&fg, &cfilter->fg_color);
      color_t_to_gdkcolor(&bg, &cfilter->bg_color);
      eth_clist_set_foreground(ETH_CLIST(packet_list), row, &fg);
      eth_clist_set_background(ETH_CLIST(packet_list), row, &bg);
    } else { /* No color filter match */
      eth_clist_set_foreground(ETH_CLIST(packet_list), row, NULL);
      eth_clist_set_background(ETH_CLIST(packet_list), row, NULL);
    }
  }
}

/* call this after last set_frame_mark is done */
static void mark_frames_ready(void) {
  file_set_save_marked_sensitive();
  packets_bar_update();
}

void packet_list_mark_frame_cb(GtkWidget *w _U_, gpointer data _U_) {
  if (cfile.current_frame) {
    /* XXX hum, should better have a "cfile->current_row" here ... */
    set_frame_mark(!cfile.current_frame->flags.marked,
		   cfile.current_frame,
		   eth_clist_find_row_from_data(ETH_CLIST(packet_list),
						cfile.current_frame));
    mark_frames_ready();
  }
}

static void mark_all_frames(gboolean set) {
  frame_data *fdata;
  
  /* XXX: we might need a progressbar here */
  for (fdata = cfile.plist; fdata != NULL; fdata = fdata->next) {
    set_frame_mark(set,
		   fdata,
		   eth_clist_find_row_from_data(ETH_CLIST(packet_list), fdata));
  }
  mark_frames_ready();
}

void packet_list_update_marked_frames(void) {
  frame_data *fdata;

  if (cfile.plist == NULL) return;

  /* XXX: we might need a progressbar here */
  for (fdata = cfile.plist; fdata != NULL; fdata = fdata->next) {
    if (fdata->flags.marked)
      set_frame_mark(TRUE,
		     fdata,
		     eth_clist_find_row_from_data(ETH_CLIST(packet_list),
						  fdata));
  }
  mark_frames_ready();
}

void packet_list_mark_all_frames_cb(GtkWidget *w _U_, gpointer data _U_) {
  mark_all_frames(TRUE);
}

void packet_list_unmark_all_frames_cb(GtkWidget *w _U_, gpointer data _U_) {
  mark_all_frames(FALSE);
}

gboolean
packet_list_get_event_row_column(GtkWidget *w, GdkEventButton *event_button,
				 gint *row, gint *column)
{
    return eth_clist_get_selection_info(ETH_CLIST(w), 
                                 (gint) event_button->x, (gint) event_button->y, 
                                  row, column);
}

#if GTK_MAJOR_VERSION < 2
static void
packet_list_button_pressed_cb(GtkWidget *w, GdkEvent *event, gpointer data _U_)
{
    GdkEventButton *event_button = (GdkEventButton *)event;
    gint row, column;

    if (w == NULL || event == NULL)
        return;

    if (event->type == GDK_BUTTON_PRESS && event_button->button == 2 &&
        event_button->window == ETH_CLIST(w)->clist_window &&
        packet_list_get_event_row_column(w, event_button, &row, &column)) {
        frame_data *fdata = (frame_data *) eth_clist_get_row_data(ETH_CLIST(w),
                                                                  row);
        set_frame_mark(!fdata->flags.marked, fdata, row);
        mark_frames_ready();
    }
}
#else
static gint
packet_list_button_pressed_cb(GtkWidget *w, GdkEvent *event, gpointer data _U_)
{
    GdkEventButton *event_button = (GdkEventButton *)event;
    gint row, column;

    if (w == NULL || event == NULL)
        return FALSE;

    if (event->type == GDK_BUTTON_PRESS && event_button->button == 2 &&
        event_button->window == ETH_CLIST(w)->clist_window &&
        eth_clist_get_selection_info(ETH_CLIST(w), (gint) event_button->x,
                                     (gint) event_button->y, &row, &column)) {
        frame_data *fdata = (frame_data *)eth_clist_get_row_data(ETH_CLIST(w),
                                                                 row);
        set_frame_mark(!fdata->flags.marked, fdata, row);
        mark_frames_ready();
        return TRUE;
    }
    return FALSE;
}
#endif

/* Set the selection mode of the packet list window. */
void
packet_list_set_sel_browse(gboolean val)
{
        GtkSelectionMode new_mode;
        /* initialize with a mode we don't use, so that the mode == new_mode
         * test will fail the first time */
        static GtkSelectionMode mode = GTK_SELECTION_MULTIPLE;

        /* Yeah, GTK uses "browse" in the case where we do not, but oh well. I
         * think "browse" in Ethereal makes more sense than "SINGLE" in GTK+ */
        new_mode = val ? GTK_SELECTION_SINGLE : GTK_SELECTION_BROWSE;

	if (mode == new_mode) {
		/*
		 * The mode isn't changing, so don't do anything.
		 * In particular, don't gratuitiously unselect the
		 * current packet.
		 *
		 * XXX - why do we have to unselect the current packet
		 * ourselves?  The documentation for the GtkCList at
		 *
		 *	http://developer.gnome.org/doc/API/gtk/gtkclist.html
		 *
		 * says "Note that setting the widget's selection mode to
		 * one of GTK_SELECTION_BROWSE or GTK_SELECTION_SINGLE will
		 * cause all the items in the GtkCList to become deselected."
		 */
		return;
	}

	if (cfile.finfo_selected)
		cf_unselect_packet(&cfile);

        mode = new_mode;
        eth_clist_set_selection_mode(ETH_CLIST(packet_list), mode);
}

/* Set the font of the packet list window. */
void
packet_list_set_font(FONT_TYPE *font)
{
	int i;
	gint col_width;
#if GTK_MAJOR_VERSION < 2
	GtkStyle *style;

	style = gtk_style_new();
	gdk_font_unref(style->font);
	style->font = font;
	gdk_font_ref(font);

	gtk_widget_set_style(packet_list, style);
#else
        PangoLayout *layout;

        gtk_widget_modify_font(packet_list, font);
#endif

	/* Compute default column sizes. */
	for (i = 0; i < cfile.cinfo.num_cols; i++) {
#if GTK_MAJOR_VERSION < 2
		col_width = gdk_string_width(font,
			get_column_longest_string(get_column_format(i)));
#else
                layout = gtk_widget_create_pango_layout(packet_list,
		    get_column_longest_string(get_column_format(i)));
                pango_layout_get_pixel_size(layout, &col_width, NULL);
                g_object_unref(G_OBJECT(layout));
#endif
		eth_clist_set_column_width(ETH_CLIST(packet_list), i,
			col_width);
	}
}

GtkWidget *
packet_list_new(e_prefs *prefs)
{
    GtkWidget *pkt_scrollw;
    int            i;

    /* Packet list */
    pkt_scrollw = scrolled_window_new(NULL, NULL);
    /* The usual policy for scrolled windows is to set both scrollbars to automatic,
     * meaning they'll only appear if the content doesn't fit into the window.
     *
     * As this doesn't seem to work in some cases for the vertical scrollbar
     * (see http://bugs.ethereal.com/bugzilla/show_bug.cgi?id=220),
     * we show that scrollbar always. */
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(pkt_scrollw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
#if GTK_MAJOR_VERSION >= 2
    /* the eth_clist will have it's own GTK_SHADOW_IN, so don't use a shadow 
     * for both widgets */
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(pkt_scrollw), 
                                    GTK_SHADOW_NONE);
#endif

    packet_list = eth_clist_new(cfile.cinfo.num_cols);
    /* Column titles are filled in below */
    gtk_container_add(GTK_CONTAINER(pkt_scrollw), packet_list);

    packet_list_set_sel_browse(prefs->gui_plist_sel_browse);
    packet_list_set_font(user_font_get_regular());
    gtk_widget_set_name(packet_list, "packet list");
    SIGNAL_CONNECT(packet_list, "select-row", packet_list_select_cb, NULL);
    SIGNAL_CONNECT(packet_list, "unselect-row", packet_list_unselect_cb, NULL);
    for (i = 0; i < cfile.cinfo.num_cols; i++) {
        /* For performance reasons, columns do not automatically resize, 
           but are resizeable by the user. */
        eth_clist_set_column_auto_resize(ETH_CLIST(packet_list), i, FALSE);
        eth_clist_set_column_resizeable(ETH_CLIST(packet_list), i, TRUE);

        /* Right-justify some special columns. */
        if (cfile.cinfo.col_fmt[i] == COL_NUMBER ||
            cfile.cinfo.col_fmt[i] == COL_PACKET_LENGTH ||
            cfile.cinfo.col_fmt[i] == COL_CUMULATIVE_BYTES ||
            cfile.cinfo.col_fmt[i] == COL_DCE_CALL)
            eth_clist_set_column_justification(ETH_CLIST(packet_list), i,
                                               GTK_JUSTIFY_RIGHT);
    }
    SIGNAL_CONNECT(packet_list, "button_press_event", popup_menu_handler,
                   OBJECT_GET_DATA(popup_menu_object, PM_PACKET_LIST_KEY));
    SIGNAL_CONNECT(packet_list, "button_press_event",
                   packet_list_button_pressed_cb, NULL);
    eth_clist_set_compare_func(ETH_CLIST(packet_list), packet_list_compare);
    gtk_widget_show(packet_list);

    return pkt_scrollw;
}

void
packet_list_set_column_titles(void)
{
    GtkStyle      *win_style;
    GdkPixmap     *ascend_pm, *descend_pm;
    GdkBitmap     *ascend_bm, *descend_bm;
    column_arrows *col_arrows;
    int            i;
    GtkWidget     *column_lb;

    win_style = gtk_widget_get_style(top_level);
    ascend_pm = gdk_pixmap_create_from_xpm_d(top_level->window, &ascend_bm,
                                             &win_style->bg[GTK_STATE_NORMAL],
                                             (gchar **) clist_ascend_xpm);
    descend_pm = gdk_pixmap_create_from_xpm_d(top_level->window, &descend_bm,
                                              &win_style->bg[GTK_STATE_NORMAL],
                                              (gchar **) clist_descend_xpm);

    col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) *
                                            cfile.cinfo.num_cols);
    for (i = 0; i < cfile.cinfo.num_cols; i++) {
        col_arrows[i].table = gtk_table_new(2, 2, FALSE);
        gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
        column_lb = gtk_label_new(cfile.cinfo.col_title[i]);
        gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2,
                         GTK_SHRINK, GTK_SHRINK, 0, 0);
        gtk_widget_show(column_lb);
        col_arrows[i].ascend_pm = gtk_pixmap_new(ascend_pm, ascend_bm);
        gtk_table_attach(GTK_TABLE(col_arrows[i].table),
                         col_arrows[i].ascend_pm,
                         1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
        if (i == 0) {
            gtk_widget_show(col_arrows[i].ascend_pm);
        }
        col_arrows[i].descend_pm = gtk_pixmap_new(descend_pm, descend_bm);
        gtk_table_attach(GTK_TABLE(col_arrows[i].table),
                         col_arrows[i].descend_pm,
                         1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
        eth_clist_set_column_widget(ETH_CLIST(packet_list), i,
                                    col_arrows[i].table);
        gtk_widget_show(col_arrows[i].table);
    }
    eth_clist_column_titles_show(ETH_CLIST(packet_list));
    SIGNAL_CONNECT(packet_list, "click-column", packet_list_click_column_cb,
                   col_arrows);
}

void
packet_list_clear(void)
{
    packet_history_clear();

    eth_clist_clear(ETH_CLIST(packet_list));
}

void
packet_list_freeze(void)
{
    eth_clist_freeze(ETH_CLIST(packet_list));
}

static void
packet_list_resize_columns(void) {
    int         i;
    int         progbar_nextstep;
    int         progbar_quantum;
    gboolean    progbar_stop_flag;
    GTimeVal    progbar_start_time;
    float       progbar_val;
    progdlg_t  *progbar = NULL;
    gchar       status_str[100];

    /* Update the progress bar when it gets to this value. */
    progbar_nextstep = 0;
    /* When we reach the value that triggers a progress bar update,
       bump that value by this amount. */
    progbar_quantum = cfile.cinfo.num_cols/N_PROGBAR_UPDATES;
    /* Progress so far. */
    progbar_val = 0.0;

    progbar_stop_flag = FALSE;
    g_get_current_time(&progbar_start_time);


    main_window_update();

    for (i = 0; i < cfile.cinfo.num_cols; i++) {
      /* Create the progress bar if necessary.
         We check on every iteration of the loop, so that it takes no
         longer than the standard time to create it (otherwise, for a
         large file, we might take considerably longer than that standard
         time in order to get to the next progress bar step). */
      if (progbar == NULL)
         progbar = delayed_create_progress_dlg("Resizing", "Resize Columns", 
           &progbar_stop_flag, &progbar_start_time, progbar_val);

      if (i >= progbar_nextstep) {
        /* let's not divide by zero. I should never be started
         * with count == 0, so let's assert that
         */
        g_assert(cfile.cinfo.num_cols > 0);

        progbar_val = (gfloat) i / cfile.cinfo.num_cols;

        if (progbar != NULL) {
          g_snprintf(status_str, sizeof(status_str),
                     "%u of %u columns (%s)", i+1, cfile.cinfo.num_cols, cfile.cinfo.col_title[i]);
          update_progress_dlg(progbar, progbar_val, status_str);
        }

        progbar_nextstep += progbar_quantum;
      }

      if (progbar_stop_flag) {
        /* Well, the user decided to abort the resizing... */
        break;
      }

      /* auto resize the current column */
      eth_clist_set_column_auto_resize(ETH_CLIST(packet_list), i, TRUE);

      /* the current column should be resizeable by the user again */
      /* (will turn off auto resize again) */
      eth_clist_set_column_resizeable(ETH_CLIST(packet_list), i, TRUE);
    }

    /* We're done resizing the columns; destroy the progress bar if it
       was created. */
    if (progbar != NULL)
      destroy_progress_dlg(progbar);
}

void packet_list_resize_columns_cb(GtkWidget *widget _U_, gpointer data _U_)
{
    packet_list_resize_columns();
}

void
packet_list_thaw(void)
{
    eth_clist_thaw(ETH_CLIST(packet_list));
    packets_bar_update();
    /*packet_list_resize_columns();*/
}

void
packet_list_select_row(gint row)
{
    SIGNAL_EMIT_BY_NAME(packet_list, "select_row", row);
}

void
packet_list_moveto_end(void)
{
    eth_clist_moveto(ETH_CLIST(packet_list),
                     ETH_CLIST(packet_list)->rows - 1, -1, 1.0, 1.0);
}

gint
packet_list_append(const gchar *text[], gpointer data)
{
    gint row;

    row = eth_clist_append(ETH_CLIST(packet_list), (gchar **) text);
    eth_clist_set_row_data(ETH_CLIST(packet_list), row, data);
    return row;
}

void
packet_list_set_colors(gint row, color_t *fg, color_t *bg)
{
    GdkColor gdkfg, gdkbg;

    if (fg)
    {
        color_t_to_gdkcolor(&gdkfg, fg);
        eth_clist_set_foreground(ETH_CLIST(packet_list), row, &gdkfg);
    }
    if (bg)
    {
        color_t_to_gdkcolor(&gdkbg, bg);
        eth_clist_set_background(ETH_CLIST(packet_list), row, &gdkbg);
    }
}

gint
packet_list_find_row_from_data(gpointer data)
{
    return eth_clist_find_row_from_data(ETH_CLIST(packet_list), data);
}

void
packet_list_set_text(gint row, gint column, const gchar *text)
{
    eth_clist_set_text(ETH_CLIST(packet_list), row, column, text);
}

/* Set the column widths of those columns that show the time in
 * "command-line-specified" format. */
void
packet_list_set_cls_time_width(gint column)
{
    gint      width;
#if GTK_MAJOR_VERSION < 2
    GtkStyle *pl_style;

    pl_style = gtk_widget_get_style(packet_list);
    width = gdk_string_width(pl_style->font,
                             get_column_longest_string(COL_CLS_TIME));
#else
    PangoLayout  *layout;

    layout = gtk_widget_create_pango_layout(packet_list,
                 get_column_longest_string(COL_CLS_TIME));
    pango_layout_get_pixel_size(layout, &width, NULL);
    g_object_unref(G_OBJECT(layout));
#endif
    eth_clist_set_column_width(ETH_CLIST(packet_list), column, width);
}

gpointer
packet_list_get_row_data(gint row)
{
    return eth_clist_get_row_data(ETH_CLIST(packet_list), row);
}


/* get the first fully visible row number, given row MUST be visible */
static gint
packet_list_first_full_visible_row(gint row) {

	g_assert(eth_clist_row_is_visible(ETH_CLIST(packet_list), row) ==
        GTK_VISIBILITY_FULL);

	while(eth_clist_row_is_visible(ETH_CLIST(packet_list), row) ==
        GTK_VISIBILITY_FULL) {
		row--;
	}

	return ++row;
}

/* get the last fully visible row number, given row MUST be visible */
static gint
packet_list_last_full_visible_row(gint row) {

	g_assert(eth_clist_row_is_visible(ETH_CLIST(packet_list), row) ==
        GTK_VISIBILITY_FULL);

	while(eth_clist_row_is_visible(ETH_CLIST(packet_list), row) ==
        GTK_VISIBILITY_FULL) {
		row++;
	}

	return --row;
}

/* Set the selected row and the focus row of the packet list to the specified
 * row, and make it visible if it's not currently visible. */
void
packet_list_set_selected_row(gint row)
{
	gint visible_rows;
	gint first_row;
	gboolean full_visible;


	full_visible = eth_clist_row_is_visible(ETH_CLIST(packet_list), row) ==
        GTK_VISIBILITY_FULL;

    /* XXX - why is there no "eth_clist_set_focus_row()", so that we
     * can make the row for the frame we found the focus row?
     *
     * See http://www.gnome.org/mailing-lists/archives/gtk-list/2000-January/0038.shtml
     */
    ETH_CLIST(packet_list)->focus_row = row;

    eth_clist_select_row(ETH_CLIST(packet_list), row, -1);

    if (!full_visible) {

        eth_clist_freeze(ETH_CLIST(packet_list));

        eth_clist_moveto(ETH_CLIST(packet_list), row, -1, 0.0, 0.0);

		/* even after move still invisible (happens with empty list) -> give up */
		if(eth_clist_row_is_visible(ETH_CLIST(packet_list), row) !=
			GTK_VISIBILITY_FULL) {
			return;
		}

		/* The now selected row will be the first visible row in the list.
		 * This is inconvenient, as the user is usually interested in some 
		 * packets *before* the currently selected one too.
		 *
		 * Try to adjust the visible rows, so the currently selected row will 
		 * be shown around the first third of the list screen.
		 * 
		 * (This won't even do any harm if the current row is the first or the 
		 * last in the list) */
		visible_rows = packet_list_last_full_visible_row(row) - packet_list_first_full_visible_row(row);
		first_row = row - visible_rows / 3;

		eth_clist_moveto(ETH_CLIST(packet_list), first_row >= 0 ? first_row : 0, -1, 0.0, 0.0);

		eth_clist_thaw(ETH_CLIST(packet_list));
	}
}

/* Return the column number that the clist is currently sorted by */
gint
packet_list_get_sort_column(void)
{
    return ETH_CLIST(packet_list)->sort_column;
}
