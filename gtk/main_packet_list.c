/* main_packet_list.c
 * packet list related functions   2002 Olivier Abad
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
#include <string.h>

#include <epan/epan.h>
#include <epan/column.h>
#include <epan/column_info.h>
#include <epan/prefs.h>
#include <epan/timestamp.h>

#include "../globals.h"
#include "../color.h"
#include "../color_filters.h"
#include "../ui_util.h"
#include "../progress_dlg.h"

#include "gtk/gtkglobals.h"
#include "gtk/gui_utils.h"
#include "gtk/color_utils.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/keys.h"
#include "gtk/font_utils.h"
#include "gtk/packet_history.h"
#include "gtk/recent.h"
#include "gtk/main.h"
#include "gtk/main_menu.h"
#include "gtk/main_packet_list.h"
#include "gtk/main_statusbar.h"

#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"

#define N_PROGBAR_UPDATES 100

typedef struct column_arrows {
  GtkWidget *table;
  GtkWidget *ascend_pm;
  GtkWidget *descend_pm;
} column_arrows;

GtkWidget *packet_list;
static gboolean last_at_end = FALSE;

/* GtkClist compare routine, overrides default to allow numeric comparison */

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
packet_list_compare(GtkCList *clist, gconstpointer  ptr1, gconstpointer  ptr2)
{
  /* Get row data structures */
  const GtkCListRow *row1 = (const GtkCListRow *)ptr1;
  const GtkCListRow *row2 = (const GtkCListRow *)ptr2;

  /* Get the frame data structures for the rows */
  const frame_data *fdata1 = row1->data;
  const frame_data *fdata2 = row2->data;

  /* Get row text strings */
  const char *text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
  const char *text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

  /* Attempt to convert to numbers */
  double  num1;
  double  num2;

  /* For checking custom column type */
  header_field_info *hfi;
  gboolean custom_numeric = FALSE;

  int ret;

  gint  col_fmt = cfile.cinfo.col_fmt[clist->sort_column];

  switch (col_fmt) {

  case COL_NUMBER:
    return COMPARE_FRAME_NUM();

  case COL_CLS_TIME:
    switch (timestamp_get_type()) {

    case TS_ABSOLUTE:
    case TS_ABSOLUTE_WITH_DATE:
    case TS_EPOCH:
      return COMPARE_TS(abs_ts);

    case TS_RELATIVE:
      return COMPARE_TS(rel_ts);

    case TS_DELTA:
      return COMPARE_TS(del_cap_ts);

    case TS_DELTA_DIS:
      return COMPARE_TS(del_dis_ts);

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
    return COMPARE_TS(del_cap_ts);

  case COL_DELTA_TIME_DIS:
    return COMPARE_TS(del_dis_ts);

  case COL_PACKET_LENGTH:
    return COMPARE_NUM(pkt_len);

  case COL_CUMULATIVE_BYTES:
    return COMPARE_NUM(cum_bytes);

  case COL_CUSTOM:
    hfi = proto_registrar_get_byname(cfile.cinfo.col_custom_field[clist->sort_column]);
    if (hfi == NULL) {
        return COMPARE_FRAME_NUM();
    } else if ((hfi->strings == NULL) &&
               (((IS_FT_INT(hfi->type) || IS_FT_UINT(hfi->type)) &&
                 ((hfi->display == BASE_DEC) || (hfi->display == BASE_DEC_HEX) ||
                  (hfi->display == BASE_OCT))) ||
                (hfi->type == FT_DOUBLE) || (hfi->type == FT_FLOAT) ||
                (hfi->type == FT_BOOLEAN) || (hfi->type == FT_FRAMENUM) ||
                (hfi->type == FT_RELATIVE_TIME))) {
      
      /* Compare numeric column */
      custom_numeric = TRUE;
    }
    /* FALLTHRU */
  default:
    num1 = atof(text1);
    num2 = atof(text2);
    if ((col_fmt == COL_UNRES_SRC_PORT) || (col_fmt == COL_UNRES_DST_PORT) ||
	(custom_numeric) || 
        ((num1 != 0) && (num2 != 0) && ((col_fmt == COL_DEF_SRC_PORT) ||
                                        (col_fmt == COL_RES_SRC_PORT) || 
                                        (col_fmt == COL_DEF_DST_PORT) ||
                                        (col_fmt == COL_RES_DST_PORT)))) {

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
packet_list_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
  column_arrows *col_arrows = (column_arrows *) data;
  int i;

  gtk_clist_freeze(clist);

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
    gtk_clist_set_sort_column(clist, column);
  }
  gtk_clist_thaw(clist);

  gtk_clist_sort(clist);
}

static void
packet_list_resize_column_cb(GtkCList *clist _U_, gint column, gint width, gpointer data _U_)
{
  recent_set_column_width (column, width);
}

/* What to do when a list item is selected/unselected */
static void
packet_list_select_cb(GtkWidget *w _U_, gint row, gint col _U_, GdkEventButton *event _U_, gpointer evt _U_) {
  frame_data *fdata;

  /* Remove the hex display tabbed pages */
  while( (gtk_notebook_get_nth_page( GTK_NOTEBOOK(byte_nb_ptr), 0)))
    gtk_notebook_remove_page( GTK_NOTEBOOK(byte_nb_ptr), 0);

  cf_select_packet(&cfile, row);
  gtk_widget_grab_focus(packet_list);

  /* Lookup the frame number that corresponds to the list row number */
  fdata = (frame_data *)packet_list_get_row_data(row);
  if (fdata != NULL) {
    packet_history_add(fdata->num);
  }
}

static void
packet_list_unselect_cb(GtkWidget *w _U_, gint row _U_, gint col _U_, GdkEventButton *event _U_, gpointer evt _U_) {

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
    gtk_clist_set_foreground(GTK_CLIST(packet_list), row, &fg);
    gtk_clist_set_background(GTK_CLIST(packet_list), row, &bg);
  } else {
    color_filter_t *cfilter = frame->color_filter;

    cf_unmark_frame(&cfile, frame);
    /* Restore the color from the matching color filter if any */
    if (cfilter) { /* The packet matches a color filter */
      color_t_to_gdkcolor(&fg, &cfilter->fg_color);
      color_t_to_gdkcolor(&bg, &cfilter->bg_color);
      gtk_clist_set_foreground(GTK_CLIST(packet_list), row, &fg);
      gtk_clist_set_background(GTK_CLIST(packet_list), row, &bg);
    } else { /* No color filter match */
      gtk_clist_set_foreground(GTK_CLIST(packet_list), row, NULL);
      gtk_clist_set_background(GTK_CLIST(packet_list), row, NULL);
    }
  }
}

/* call this after last set_frame_mark is done */
static void mark_frames_ready(void) {
  file_save_update_dynamics();
  packets_bar_update();
}

void packet_list_mark_frame_cb(GtkWidget *w _U_, gpointer data _U_) {
  if (cfile.current_frame) {
    /* XXX hum, should better have a "cfile->current_row" here ... */
    set_frame_mark(!cfile.current_frame->flags.marked,
		   cfile.current_frame,
		   gtk_clist_find_row_from_data(GTK_CLIST(packet_list),
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
		   gtk_clist_find_row_from_data(GTK_CLIST(packet_list), fdata));
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
		     gtk_clist_find_row_from_data(GTK_CLIST(packet_list),
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
    return gtk_clist_get_selection_info(GTK_CLIST(w),
                                 (gint) event_button->x, (gint) event_button->y,
                                  row, column);
}

static gint
packet_list_button_pressed_cb(GtkWidget *w, GdkEvent *event, gpointer data _U_)
{
    GdkEventButton *event_button = (GdkEventButton *)event;
    gint row, column;

    if (w == NULL || event == NULL)
        return FALSE;

    if (event->type == GDK_BUTTON_PRESS && event_button->button == 2 &&
        event_button->window == GTK_CLIST(w)->clist_window &&
        gtk_clist_get_selection_info(GTK_CLIST(w), (gint) event_button->x,
                                     (gint) event_button->y, &row, &column)) {
        frame_data *fdata = (frame_data *)gtk_clist_get_row_data(GTK_CLIST(w),
                                                                 row);
        set_frame_mark(!fdata->flags.marked, fdata, row);
        mark_frames_ready();
        return TRUE;
    }
    return FALSE;
}

/* Set the selection mode of the packet list window. */
void
packet_list_set_sel_browse(gboolean val, gboolean force_set)
{
        GtkSelectionMode new_mode;
        /* initialize with a mode we don't use, so that the mode == new_mode
         * test will fail the first time */
        static GtkSelectionMode mode = GTK_SELECTION_MULTIPLE;

        /* Yeah, GTK uses "browse" in the case where we do not, but oh well. I
         * think "browse" in Wireshark makes more sense than "SINGLE" in GTK+ */
        new_mode = val ? GTK_SELECTION_SINGLE : GTK_SELECTION_BROWSE;

	if ((mode == new_mode) && !force_set) {
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
		cf_unselect_field(&cfile);

        mode = new_mode;
        gtk_clist_set_selection_mode(GTK_CLIST(packet_list), mode);
}

/* Set the font of the packet list window. */
void
packet_list_set_font(PangoFontDescription *font)
{
	int i;
	gint col_width;
        PangoLayout *layout;

	/* Manually set the font so it can be used right away in the
	 * pango_layout_get_pixel_size call below.  The gtk_widget_modify_font
	 * function only takes effect after the widget is displayed. */
	packet_list->style->font_desc = pango_font_description_copy(font);

        gtk_widget_modify_font(packet_list, font);

	/* Compute default column sizes. */
	for (i = 0; i < cfile.cinfo.num_cols; i++) {
		col_width = recent_get_column_width(i);
		if (col_width == -1) {
			layout = gtk_widget_create_pango_layout(packet_list,
			   get_column_width_string(get_column_format(i), i));
			pango_layout_get_pixel_size(layout, &col_width, NULL);
			g_object_unref(G_OBJECT(layout));
		}
		gtk_clist_set_column_width(GTK_CLIST(packet_list), i,
					   col_width);
	}
}

GtkWidget *
packet_list_new(e_prefs *prefs)
{
    GtkWidget *pkt_scrollw;
    header_field_info *hfi;
    gboolean custom_right_justify;
    int            i;

    /* Packet list */
    pkt_scrollw = scrolled_window_new(NULL, NULL);
    /* The usual policy for scrolled windows is to set both scrollbars to automatic,
     * meaning they'll only appear if the content doesn't fit into the window.
     *
     * As this doesn't seem to work in some cases for the vertical scrollbar
     * (see http://bugs.wireshark.org/bugzilla/show_bug.cgi?id=220),
     * we show that scrollbar always. */
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(pkt_scrollw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
    /* the gtk_clist will have it's own GTK_SHADOW_IN, so don't use a shadow
     * for both widgets */
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(pkt_scrollw),
                                    GTK_SHADOW_NONE);

    packet_list = gtk_clist_new(cfile.cinfo.num_cols);
    /* Column titles are filled in below */
    gtk_container_add(GTK_CONTAINER(pkt_scrollw), packet_list);

    packet_list_set_sel_browse(prefs->gui_plist_sel_browse, FALSE);
    packet_list_set_font(user_font_get_regular());
    gtk_widget_set_name(packet_list, "packet list");
    g_signal_connect(packet_list, "select-row", G_CALLBACK(packet_list_select_cb), NULL);
    g_signal_connect(packet_list, "unselect-row", G_CALLBACK(packet_list_unselect_cb), NULL);
    for (i = 0; i < cfile.cinfo.num_cols; i++) {
        /* For performance reasons, columns do not automatically resize,
           but are resizeable by the user. */
        gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), i, FALSE);
        gtk_clist_set_column_resizeable(GTK_CLIST(packet_list), i, TRUE);

        custom_right_justify = FALSE;
        if (cfile.cinfo.col_fmt[i] == COL_CUSTOM) {
          hfi = proto_registrar_get_byname(cfile.cinfo.col_custom_field[i]);
          if ((hfi != NULL) && (hfi->strings == NULL) && 
	      ((hfi->type == FT_BOOLEAN) || (hfi->type == FT_FRAMENUM) ||
	       (((hfi->display == BASE_DEC) || (hfi->display == BASE_OCT)) &&
		(IS_FT_INT(hfi->type) || IS_FT_UINT(hfi->type)  || 
		 (hfi->type == FT_INT64) || (hfi->type == FT_UINT64))))) {
            custom_right_justify = TRUE;
          }
        }

        /* Right-justify some special columns. */
        if (cfile.cinfo.col_fmt[i] == COL_NUMBER ||
            cfile.cinfo.col_fmt[i] == COL_PACKET_LENGTH ||
            cfile.cinfo.col_fmt[i] == COL_CUMULATIVE_BYTES ||
            cfile.cinfo.col_fmt[i] == COL_DCE_CALL ||
            cfile.cinfo.col_fmt[i] == COL_DCE_CTX ||
            custom_right_justify)
            gtk_clist_set_column_justification(GTK_CLIST(packet_list), i,
                                               GTK_JUSTIFY_RIGHT);
    }
    g_signal_connect(packet_list, "button_press_event", G_CALLBACK(popup_menu_handler),
                   g_object_get_data(G_OBJECT(popup_menu_object), PM_PACKET_LIST_KEY));
    g_signal_connect(packet_list, "button_press_event",
                   G_CALLBACK(packet_list_button_pressed_cb), NULL);
    g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_KEY, packet_list);
    gtk_clist_set_compare_func(GTK_CLIST(packet_list), packet_list_compare);
    gtk_widget_show(packet_list);

    return pkt_scrollw;
}

void
packet_list_recreate(void)
{
    gtk_widget_destroy(pkt_scrollw);

    prefs.num_cols = g_list_length(prefs.col_list);

    build_column_format_array(&cfile.cinfo, FALSE);

    pkt_scrollw = packet_list_new(&prefs);
    gtk_widget_show(pkt_scrollw);
    packet_list_set_column_titles();
    packet_list_set_sel_browse(prefs.gui_plist_sel_browse, TRUE);

    main_widgets_rearrange();

    if(cfile.state != FILE_CLOSED)
        cf_redissect_packets(&cfile);
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
        gtk_clist_set_column_widget(GTK_CLIST(packet_list), i,
                                    col_arrows[i].table);
        gtk_widget_show(col_arrows[i].table);
    }
    gtk_clist_column_titles_show(GTK_CLIST(packet_list));
    g_signal_connect(packet_list, "click-column", G_CALLBACK(packet_list_click_column_cb),
		     col_arrows);
    g_signal_connect(packet_list, "resize-column", G_CALLBACK(packet_list_resize_column_cb),
		     NULL);
}

void
packet_list_clear(void)
{
    packet_history_clear();

    gtk_clist_clear(GTK_CLIST(packet_list));
    gtk_widget_queue_draw(packet_list);
}

void
packet_list_freeze(void)
{
    gtk_clist_freeze(GTK_CLIST(packet_list));
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
           TRUE, &progbar_stop_flag, &progbar_start_time, progbar_val);

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
      gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), i, TRUE);

      /* the current column should be resizeable by the user again */
      /* (will turn off auto resize again) */
      gtk_clist_set_column_resizeable(GTK_CLIST(packet_list), i, TRUE);
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
    gtk_clist_thaw(GTK_CLIST(packet_list));
    packets_bar_update();
    /*packet_list_resize_columns();*/
}

void
packet_list_select_row(gint row)
{
    g_signal_emit_by_name(G_OBJECT(packet_list), "select_row", row);
}

static void
packet_list_next_prev(gboolean next)
{
    GtkWidget *focus = gtk_window_get_focus(GTK_WINDOW(top_level));
    g_signal_emit_by_name(G_OBJECT(packet_list), "scroll_vertical",
        next ? GTK_SCROLL_STEP_FORWARD : GTK_SCROLL_STEP_BACKWARD, 0.0);
    /* Set the focus back where it was */
    if (focus)
        gtk_window_set_focus(GTK_WINDOW(top_level), focus);
}

void
packet_list_next(void)
{
    packet_list_next_prev(TRUE);
}

void
packet_list_prev(void)
{
    packet_list_next_prev(FALSE);
}

void
packet_list_moveto_end(void)
{
    gtk_clist_moveto(GTK_CLIST(packet_list),
                     GTK_CLIST(packet_list)->rows - 1, -1, 1.0, 1.0);
}

gboolean
packet_list_check_end(void)
{
    gboolean at_end = FALSE;
    GtkAdjustment *adj;

    g_return_val_if_fail (packet_list != NULL, FALSE);
    adj = gtk_clist_get_vadjustment(GTK_CLIST(packet_list));
    g_return_val_if_fail (adj != NULL, FALSE);

    if (adj->value >= adj->upper - adj->page_size) {
        at_end = TRUE;
    }
#ifdef HAVE_LIBPCAP
    if (adj->value > 0 && at_end != last_at_end && at_end != auto_scroll_live) {
        menu_auto_scroll_live_changed(at_end);
    }
#endif
    last_at_end = at_end;
    return at_end;
}

gint
packet_list_append(const gchar *text[], gpointer data)
{
    gint row;

    row = gtk_clist_append(GTK_CLIST(packet_list), (gchar **) text);
    gtk_clist_set_row_data(GTK_CLIST(packet_list), row, data);
    return row;
}

void
packet_list_set_colors(gint row, color_t *fg, color_t *bg)
{
    GdkColor gdkfg, gdkbg;

    if (fg)
    {
        color_t_to_gdkcolor(&gdkfg, fg);
        gtk_clist_set_foreground(GTK_CLIST(packet_list), row, &gdkfg);
    }
    if (bg)
    {
        color_t_to_gdkcolor(&gdkbg, bg);
        gtk_clist_set_background(GTK_CLIST(packet_list), row, &gdkbg);
    }
}

gint
packet_list_find_row_from_data(gpointer data)
{
    return gtk_clist_find_row_from_data(GTK_CLIST(packet_list), data);
}

void
packet_list_set_text(gint row, gint column, const gchar *text)
{
    gtk_clist_set_text(GTK_CLIST(packet_list), row, column, text);
}

/* Set the column widths of those columns that show the time in
 * "command-line-specified" format. */
void
packet_list_set_time_width(gint col_fmt, gint column)
{
    gint      width = -1;
    PangoLayout  *layout;

    width = recent_get_column_width(column);
    if (width == -1) {
        layout = gtk_widget_create_pango_layout(packet_list,
                     get_column_longest_string(col_fmt));
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
    }
    gtk_clist_set_column_width(GTK_CLIST(packet_list), column, width);
}

gpointer
packet_list_get_row_data(gint row)
{
    return gtk_clist_get_row_data(GTK_CLIST(packet_list), row);
}


/* get the first fully visible row number, given row MUST be visible */
static gint
packet_list_first_full_visible_row(gint row) {

	g_assert(gtk_clist_row_is_visible(GTK_CLIST(packet_list), row) ==
        GTK_VISIBILITY_FULL);

	while(gtk_clist_row_is_visible(GTK_CLIST(packet_list), row) ==
        GTK_VISIBILITY_FULL) {
		row--;
	}

	return ++row;
}

/* get the last fully visible row number, given row MUST be visible */
static gint
packet_list_last_full_visible_row(gint row) {

	g_assert(gtk_clist_row_is_visible(GTK_CLIST(packet_list), row) ==
        GTK_VISIBILITY_FULL);

	while(gtk_clist_row_is_visible(GTK_CLIST(packet_list), row) ==
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


	full_visible = gtk_clist_row_is_visible(GTK_CLIST(packet_list), row) ==
        GTK_VISIBILITY_FULL;

    /* XXX - why is there no "gtk_clist_set_focus_row()", so that we
     * can make the row for the frame we found the focus row?
     *
     * See http://www.gnome.org/mailing-lists/archives/gtk-list/2000-January/0038.shtml
     */
    GTK_CLIST(packet_list)->focus_row = row;

    gtk_clist_select_row(GTK_CLIST(packet_list), row, -1);

    if (!full_visible) {

        gtk_clist_freeze(GTK_CLIST(packet_list));

        gtk_clist_moveto(GTK_CLIST(packet_list), row, -1, 0.0, 0.0);

		/* even after move still invisible (happens with empty list) -> give up */
		if(gtk_clist_row_is_visible(GTK_CLIST(packet_list), row) !=
			GTK_VISIBILITY_FULL) {
			gtk_clist_thaw(GTK_CLIST(packet_list));
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

		gtk_clist_moveto(GTK_CLIST(packet_list), first_row >= 0 ? first_row : 0, -1, 0.0, 0.0);

		gtk_clist_thaw(GTK_CLIST(packet_list));
	}
}

/* Return the column number that the clist is currently sorted by */
gint
packet_list_get_sort_column(void)
{
    return GTK_CLIST(packet_list)->sort_column;
}

void packet_list_copy_summary_cb(GtkWidget * w _U_, gpointer data _U_, copy_summary_type copy_type)
{
    gint row;
    gint col;
    gchar* celltext = NULL;
    GString* text;

	if(CS_CSV == copy_type) {
		text = g_string_new("\"");
	} else {
		text = g_string_new("");
	}

    if (cfile.current_frame) {
        /* XXX hum, should better have a "cfile->current_row" here ... */
        row = gtk_clist_find_row_from_data(GTK_CLIST(packet_list),
			        cfile.current_frame);
        for(col = 0; col < cfile.cinfo.num_cols; ++col) {
            if(col != 0) {
				if(CS_CSV == copy_type) {
					g_string_append(text,"\",\"");
				} else {
					g_string_append_c(text, '\t');
				}
            }
            if(0 != gtk_clist_get_text(GTK_CLIST(packet_list),row,col,&celltext)) {
                g_string_append(text,celltext);
            }
        }
		if(CS_CSV == copy_type) {
			g_string_append_c(text,'"');
		}
        copy_to_clipboard(text);
    }
    g_string_free(text,TRUE);
}

/* Re-sort the clist by the previously selected sort */
void
packet_list_set_sort_column(void)
{
    packet_list_freeze();

    gtk_clist_set_sort_column(GTK_CLIST(packet_list), packet_list_get_sort_column());

    gtk_clist_sort(GTK_CLIST(packet_list));

    packet_list_thaw();
}

void
packet_list_recent_write_all(FILE *rf)
{
  gint col;

  fprintf (rf, "%s:", RECENT_KEY_COL_WIDTH);
  for (col = 0; col < cfile.cinfo.num_cols; col++) {
     if (cfile.cinfo.col_fmt[col] == COL_CUSTOM) {
       fprintf (rf, " %%Cus:%s,", get_column_custom_field(col));
     } else {
       fprintf (rf, " %s,", col_format_to_string(cfile.cinfo.col_fmt[col]));
     }
     fprintf (rf, " %d", GTK_CLIST(packet_list)->column[col].width);
     if (col != cfile.cinfo.num_cols-1) {
       fprintf (rf, ",");
     }
   }
   fprintf (rf, "\n");
}
