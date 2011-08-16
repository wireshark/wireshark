/* time_shift_dlg.c
 * Routines for "Time Shift" window
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
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
#include <ctype.h>
#include <math.h>

#include <gtk/gtk.h>

#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>
#include <epan/nstime.h>
#include <epan/strutil.h>
#include <epan/prefs.h>

#include "../globals.h"
#include "../alert_box.h"
#include "../simple_dialog.h"
#include "../main_statusbar.h"

#include "gtk/gui_utils.h"
#include "gtk/time_shift_dlg.h"
#include "gtk/dlg_utils.h"
#include "gtk/stock_icons.h"
#include "gtk/prefs_dlg.h"
#include "gtk/keys.h"
#include "gtk/help_dlg.h"
#include "ui_util.h"

/* Capture callback data keys */
#define E_TIMESHIFT_SELECT          "timeshift_select"
#define E_TIMESHIFT_OFFSET_KEY      "timeshift_offset_te"
#define E_SETTIME_SELECT            "settime_select"
#define E_SETTIME_TIME_KEY          "settime_time_te"
#define E_SETTIME_PACKETNUMBER_KEY  "settime_packetnumber_te"
#define E_ADJTIME_SELECT            "adjtime_select"
#define E_ADJTIME_TIME1_KEY         "adjtime_time1_te"
#define E_ADJTIME_PACKETNUMBER1_KEY "adjtime_packetnumber1_te"
#define E_ADJTIME_TIME2_KEY         "adjtime_time2_te"
#define E_ADJTIME_PACKETNUMBER2_KEY "adjtime_packetnumber2_te"
#define E_UNDO_SELECT               "undo_select"
#define E_UNDO_SHIFT_KEY            "undo_shift_cb"

static void time_shift_apply_cb(GtkWidget *ok_bt, GtkWindow *parent_w);
static void time_shift_close_cb(GtkWidget *close_bt, gpointer parent_w);
static void time_shift_frame_destroy_cb(GtkWidget *win, gpointer user_data);

static void error_message(const gchar *msg);

#define	SHIFT_POS		0
#define	SHIFT_NEG		1
#define	SHIFT_SETTOZERO		1
#define	SHIFT_KEEPOFFSET	0
static void modify_time_init(frame_data *fd);
static void modify_time_perform(frame_data *fd, int neg, nstime_t *offset,
    int settozero);

/*
 * Keep a static pointer to the current "Time Shift" window, if any, so
 * that if somebody tries to do "Time Shift" while there's already a
 * "Time Shift" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *time_shift_frame_w;

void
time_shift_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget	*main_vb, *main_hb, *label,
		*types_frame, *types_vb,

		*timeshift_offset_hb,
		*timeshift_offset_text_box,

		*settime_time_hb,
		*settime_packetnumber_text_box,
		*settime_time_text_box,

		*adjtime_offset_hb,
		*adjtime_packetnumber1_text_box,
		*adjtime_packetnumber2_text_box,
		*adjtime_time1_text_box,
		*adjtime_time2_text_box,

		*undo_offset_hb,
		*undo_type_hb,

		*timeshift_rb, *settime_rb,
		*adjtime_rb, *undo_rb,

		*bbox, *apply_bt, *close_bt, *help_bt;
 
  if (time_shift_frame_w != NULL) {
    /* There's already a "Time Shift" dialog box; reactivate it. */
    reactivate_window(time_shift_frame_w);
    return;
  }
 
  time_shift_frame_w = dlg_window_new("Wireshark: Time Shift");
 
  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(time_shift_frame_w), main_vb);
  gtk_widget_show(main_vb);


  /*
   * Shift All Packets frame
   */
  main_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), main_hb);
  gtk_widget_show(main_hb);

  types_frame = gtk_frame_new(NULL);
  gtk_box_pack_start(GTK_BOX(main_hb), types_frame, TRUE, TRUE, 0);
  gtk_widget_show(types_frame);

  types_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(types_vb), 3);
  gtk_container_add(GTK_CONTAINER(types_frame), types_vb);
  gtk_widget_show(types_vb);

  /* Radio button row */
  timeshift_offset_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), timeshift_offset_hb, FALSE, FALSE, 0);
  gtk_widget_show(timeshift_offset_hb);

  timeshift_rb = gtk_radio_button_new_with_label (NULL, "Shift all packets");
  gtk_box_pack_start(GTK_BOX(timeshift_offset_hb), timeshift_rb, TRUE, TRUE, 0);
  gtk_widget_show(timeshift_rb);
  gtk_widget_set_tooltip_text(timeshift_rb, "Shift the time on the frames.");

  /* Time Shift entry row */
  timeshift_offset_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), timeshift_offset_hb, FALSE, FALSE, 0);
  gtk_widget_show(timeshift_offset_hb);

  label = gtk_label_new("Time offset in the format [+-][[hh:]mm:]ss[.ddd]");
  gtk_box_pack_start(GTK_BOX(timeshift_offset_hb), label, FALSE, FALSE, 0);
  gtk_widget_show(label);

  timeshift_offset_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(timeshift_offset_hb), timeshift_offset_text_box,
    TRUE, TRUE, 0);
  gtk_widget_show(timeshift_offset_text_box);
  gtk_widget_set_tooltip_text(timeshift_offset_text_box,
    "Enter the time to shift here. The format is "
    "[+-][[hh:]mm:]ss.[.ddddddddd].");

  /*
   * Set Packet Number to Time frame
   */
  main_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), main_hb);
  gtk_widget_show(main_hb);

  types_frame = gtk_frame_new(NULL);
  gtk_box_pack_start(GTK_BOX(main_hb), types_frame, TRUE, TRUE, 0);
  gtk_widget_show(types_frame);

  types_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(types_vb), 3);
  gtk_container_add(GTK_CONTAINER(types_frame), types_vb);
  gtk_widget_show(types_vb);

  /* time shift type row */
  settime_time_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), settime_time_hb, FALSE,
    FALSE, 0);
  gtk_widget_show(settime_time_hb);

  settime_rb = gtk_radio_button_new_with_label(gtk_radio_button_get_group(
    GTK_RADIO_BUTTON(timeshift_rb)), "Set packet to time");
  gtk_box_pack_start(GTK_BOX(settime_time_hb), settime_rb, TRUE, TRUE, 0);
  gtk_widget_show(settime_rb);
  gtk_widget_set_tooltip_text(settime_rb,
    "Set the time of a certain frame and adjust the rest of the frames "
    "automatically.");

  settime_time_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), settime_time_hb, FALSE,
    FALSE, 0);
  gtk_widget_show(settime_time_hb);

  label = gtk_label_new("Packet number");
  gtk_box_pack_start(GTK_BOX(settime_time_hb), label, FALSE, FALSE, 0);
  gtk_widget_show(label);

  settime_packetnumber_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(settime_time_hb), settime_packetnumber_text_box,
    TRUE, TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(settime_packetnumber_text_box), "");
  gtk_widget_show(settime_packetnumber_text_box);
  gtk_widget_set_tooltip_text(settime_packetnumber_text_box,
    "The frame which will be set to the time.");

  /* time shift row */
  settime_time_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), settime_time_hb, FALSE, FALSE,
    0);
  gtk_widget_show(settime_time_hb);

  label = gtk_label_new("Set packet to time [YYYY-MM-DD] hh:mm:ss[.ddd]");
  gtk_box_pack_start(GTK_BOX(settime_time_hb), label, FALSE, FALSE, 0);
  gtk_widget_show(label);

  settime_time_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(settime_time_hb), settime_time_text_box, TRUE,
    TRUE, 0);
  gtk_widget_show(settime_time_text_box);
  gtk_widget_set_tooltip_text(settime_time_text_box,
    "The time for the frame in the format of [YYYY-MM-DD] "
    "hh:mm:ss[.ddddddddd]");
 
  /*
   * Set two Packet Numbers to Time frame and extrapolate
   */
  main_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), main_hb);
  gtk_widget_show(main_hb);

  types_frame = gtk_frame_new(NULL);
  gtk_box_pack_start(GTK_BOX(main_hb), types_frame, TRUE, TRUE, 0);
  gtk_widget_show(types_frame);

  types_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(types_vb), 3);
  gtk_container_add(GTK_CONTAINER(types_frame), types_vb);
  gtk_widget_show(types_vb);

  /* packet number row 1 */
  adjtime_offset_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE, FALSE, 0);
  gtk_widget_show(adjtime_offset_hb);

  adjtime_rb = gtk_radio_button_new_with_label(gtk_radio_button_get_group(
    GTK_RADIO_BUTTON(timeshift_rb)), "Set packets to time and extrapolate");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_rb, TRUE, TRUE, 0);
  gtk_widget_show(adjtime_rb);
  gtk_widget_set_tooltip_text(adjtime_rb,
    "Set the time of two frames and adjust the rest of the frames "
    "automatically.");

  adjtime_offset_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE, FALSE, 0);
  gtk_widget_show(adjtime_offset_hb);

  label = gtk_label_new("Packet number");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), label, FALSE, FALSE, 0);
  gtk_widget_show(label);

  adjtime_packetnumber1_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_packetnumber1_text_box,
    TRUE, TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(adjtime_packetnumber1_text_box), "");
  gtk_widget_show(adjtime_packetnumber1_text_box);
  gtk_widget_set_tooltip_text(adjtime_packetnumber1_text_box,
    "The frame which will be set to the time.");

  /* time shift row */
  adjtime_offset_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE, FALSE,
    0);
  gtk_widget_show(adjtime_offset_hb);

  label = gtk_label_new("Set packet to time [YYYY-MM-DD] hh:mm:ss[.ddd]");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), label, FALSE, FALSE, 0);
  gtk_widget_show(label);

  adjtime_time1_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_time1_text_box, TRUE,
    TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(adjtime_time1_text_box), "");
  gtk_widget_show(adjtime_time1_text_box);
  gtk_widget_set_tooltip_text(adjtime_time1_text_box,
    "The time for the frame in the format of [YYYY-MM-DD] "
    "hh:mm:ss[.ddddddddd]");

  /* packet number row 2 */
  adjtime_offset_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE,
    FALSE, 0);
  gtk_widget_show(adjtime_offset_hb);

  label = gtk_label_new("Packet number");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), label, FALSE, FALSE, 0);
  gtk_widget_show(label);

  adjtime_packetnumber2_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_packetnumber2_text_box,
    TRUE, TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(adjtime_packetnumber2_text_box), "");
  gtk_widget_show(adjtime_packetnumber2_text_box);
  gtk_widget_set_tooltip_text(adjtime_packetnumber2_text_box,
    "The frame which will be set to the time.");

  /* time shift row */
  adjtime_offset_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE, FALSE,
    0);
  gtk_widget_show(adjtime_offset_hb);

  label = gtk_label_new("Set packet to time [YYYY-MM-DD] hh:mm:ss[.ddd]");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), label, FALSE, FALSE, 0);
  gtk_widget_show(label);

  adjtime_time2_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_time2_text_box, TRUE,
    TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(adjtime_time2_text_box), "");
  gtk_widget_show(adjtime_time2_text_box);
  gtk_widget_set_tooltip_text(adjtime_time2_text_box,
    "The time for the frame in the format of [YYYY-MM-DD] "
    "hh:mm:ss[.ddddddddd]");

  /*
   * Undo all shifts
   */
  main_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), main_hb);
  gtk_widget_show(main_hb);

  types_frame = gtk_frame_new(NULL);
  gtk_box_pack_start(GTK_BOX(main_hb), types_frame, TRUE, TRUE, 0);
  gtk_widget_show(types_frame);

  types_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(types_vb), 3);
  gtk_container_add(GTK_CONTAINER(types_frame), types_vb);
  gtk_widget_show(types_vb);

  /* time shift type row */
  undo_type_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(types_vb), undo_type_hb);
  gtk_widget_show(undo_type_hb);

  /* time shift row */
  undo_offset_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(types_vb), undo_offset_hb, FALSE,
    FALSE, 0);
  gtk_widget_show(undo_offset_hb);

  undo_rb = gtk_radio_button_new_with_label(gtk_radio_button_get_group(
    GTK_RADIO_BUTTON(timeshift_rb)), "Undo all shifts");
  gtk_box_pack_start(GTK_BOX(undo_offset_hb), undo_rb, TRUE, TRUE, 0);
  gtk_widget_show(undo_rb);
  gtk_widget_set_tooltip_text(undo_rb,
    "Undo all the Time Shift offsets on the frames.");
 
  /*
   * Button row
   */
  bbox = dlg_button_row_new(GTK_STOCK_APPLY, GTK_STOCK_CLOSE, GTK_STOCK_HELP,
    NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
  gtk_widget_show(bbox);

  apply_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_APPLY);
  g_signal_connect(apply_bt, "clicked", G_CALLBACK(time_shift_apply_cb),
    time_shift_frame_w);
  gtk_widget_set_tooltip_text(apply_bt,
    "Apply the Time Shift options to the frame data.");

  close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
  g_signal_connect(close_bt, "clicked", G_CALLBACK(time_shift_close_cb),
    time_shift_frame_w);
  gtk_widget_set_tooltip_text(close_bt, "Close this dialogbox.");

  help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb),
    (gpointer)HELP_TIME_SHIFT_DIALOG);
  gtk_widget_set_tooltip_text(help_bt,
    "Help on how the Time Shift feature works.");

  /* Link everything together */

  g_object_set_data(G_OBJECT(time_shift_frame_w), E_TIMESHIFT_SELECT,
    timeshift_rb);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_TIMESHIFT_OFFSET_KEY,
    timeshift_offset_text_box);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_SETTIME_SELECT, settime_rb);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_SETTIME_TIME_KEY,
    settime_time_text_box);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_SETTIME_PACKETNUMBER_KEY,
    settime_packetnumber_text_box);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_ADJTIME_SELECT, adjtime_rb);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_ADJTIME_TIME1_KEY,
    adjtime_time1_text_box);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_ADJTIME_PACKETNUMBER1_KEY,
    adjtime_packetnumber1_text_box);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_ADJTIME_TIME2_KEY,
    adjtime_time2_text_box);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_ADJTIME_PACKETNUMBER2_KEY,
    adjtime_packetnumber2_text_box);
  g_object_set_data(G_OBJECT(time_shift_frame_w), E_UNDO_SELECT, undo_rb);

  dlg_set_activate(timeshift_offset_text_box, apply_bt);

  /* Give the initial focus to the "offset" entry box. */
  gtk_widget_grab_focus(timeshift_offset_text_box);

  g_signal_connect(time_shift_frame_w, "delete_event",
    G_CALLBACK(window_delete_event_cb), NULL);
  g_signal_connect(time_shift_frame_w, "destroy",
    G_CALLBACK(time_shift_frame_destroy_cb), NULL);

  gtk_widget_show(time_shift_frame_w);
  window_present(time_shift_frame_w);
}

#ifdef _MSC_VER
#define localtime_r(a, b) memcpy((b), localtime((a)), sizeof(struct tm));
#endif

static void
error_message(const gchar *msg)
{
  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", msg);
}

static int  action_timeshift(GtkWindow *parent_w);
static void action_settime(GtkWindow *parent_w);
static void action_adjtime(GtkWindow *parent_w);
static void action_undo(GtkWindow *parent_w);

static void
time_shift_apply_cb(GtkWidget *ok_bt _U_, GtkWindow *parent_w)
{
  GtkWidget *flag_rb;

  if (cfile.state == FILE_CLOSED) {
    /* Nothing to do here */
    return;
  }
  if (cfile.state == FILE_READ_IN_PROGRESS) {
    error_message("The Time Shift functions are not available on live captures.");
    return;
  }


  flag_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_TIMESHIFT_SELECT);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_rb)) == TRUE) {
    action_timeshift(parent_w);
    return;
  }

  flag_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_SETTIME_SELECT);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_rb)) == TRUE) {
    action_settime(parent_w);
    return;
  }

  flag_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_ADJTIME_SELECT);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_rb)) == TRUE) {
    action_adjtime(parent_w);
    return;
  }

  flag_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_UNDO_SELECT);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_rb)) == TRUE) {
    action_undo(parent_w);
    return;
  }
}

#define CHECK_YEARS(Y)							\
  if (Y < 1970) {							\
    error_message("years must be larger than 1970");			\
    return(1);								\
  }
#define CHECK_MONTHS(M)							\
  if (M < 1 || M > 12) {						\
    error_message("months must be between [1..12]");			\
    return(1);								\
  }
#define CHECK_DAYS(D)							\
  if (D < 1 || D > 31) {						\
    error_message("days must be between [1..31]");			\
    return(1);								\
  }
#define CHECK_HOURS(h)							\
  if (h < 0 || h > 23) {						\
    error_message("hours must be between [0..23]");			\
    return(1);								\
  }
#define CHECK_HOUR(h)							\
  if (h < 0) {								\
    error_message("negative hours, you have have specified more than "  \
      "one minus character?");						\
    return(1);								\
  }									\
  offset_float += h * 3600
#define CHECK_MINUTE(m)					    \
  if (m < 0 || m > 59) {				    \
    error_message("minutes must be between [0..59]");	    \
    return(1);						    \
  }							    \
  offset_float += m * 60
#define CHECK_SECOND(s)					    \
  if (s < 0 || s > 59) {				    \
    error_message("seconds must be between [0..59]");	    \
    return(1);						    \
  }							    \
  offset_float += s
#define CHECK_SEC_DEC(f)                                   \
  if (f < 0) {						   \
    error_message("fractional seconds must be > 0");	   \
    return(1);						   \
  }							   \
  offset_float += f

static int
action_timeshift(GtkWindow *parent_w)
{
  GtkWidget	*offset_te;
  const gchar	*offset_text;
  gchar		*poffset_text;
  nstime_t	offset;
  long double	offset_float = 0;
  guint32	i;
  frame_data	*fd;
  int		neg;
  int		h, m;
  long double	f;

  /*
   * The following offset types are allowed:
   * -?((hh:)mm:)ss(.decimals)?
   *
   * Since Wireshark doesn't support regular expressions (please prove me
   * wrong :-) we will have to figure it out ourselves in the
   * following order:
   *
   * 1. hh:mm:ss.decimals
   * 2.    mm:ss.decimals
   * 3.       ss.decimals
   *
   */

  offset_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_TIMESHIFT_OFFSET_KEY);
  offset_text = gtk_entry_get_text(GTK_ENTRY(offset_te));
  poffset_text = (gchar *)offset_text;

  /* strip whitespace */
  while (isspace(poffset_text[0]))
    ++poffset_text;

  /* check for minus sign */
  neg = FALSE;
  if (poffset_text[0] == '-') {
    neg = TRUE;
    poffset_text++;
  }

  /* check for empty string */
  if (poffset_text[0] == '\0')
    return(1);

  h = m = 0;
  f = 0.0;
  if (sscanf(poffset_text, "%d:%d:%Lf", &h, &m, &f) == 3) {
    /* printf("%%d:%%d:%%d.%%d\n"); */
    CHECK_HOUR(h);
    CHECK_MINUTE(m);
    CHECK_SEC_DEC(f);
  } else if (sscanf(poffset_text, "%d:%Lf", &m, &f) == 2) {
    /* printf("%%d:%%d.%%d\n"); */
    CHECK_MINUTE(m);
    CHECK_SEC_DEC(f);
  } else if (sscanf(poffset_text, "%Lf", &f) == 1) {
    /* printf("%%d.%%d\n"); */
    CHECK_SEC_DEC(f);
  } else {
    error_message("Could not parse the time: Expected ((hh:)mm:)ss.(dec).");
    return(1);
  }

  if (offset_float == 0)
    return(1);

  nstime_set_zero(&offset);
  offset.secs = (time_t)floorl(offset_float);
  offset_float -= offset.secs;
  offset.nsecs = (int)(offset_float * 1000000000);

  if ((fd = frame_data_sequence_find(cfile.frames, 1)) == NULL)
    return(1); /* Shouldn't happen */
  modify_time_init(fd);

  for (i = 1; i <= cfile.count; i++) {
    if ((fd = frame_data_sequence_find(cfile.frames, i)) == NULL)
      continue;	/* Shouldn't happen */
    modify_time_perform(fd, neg, &offset, SHIFT_KEEPOFFSET);
  }
  new_packet_list_queue_draw();
  
  return(0);
}

static int
timestring2nstime(const gchar *ts, nstime_t *packettime, nstime_t *nstime)
{
  gchar		*pts;
  int		h, m, Y, M, D;
  long double	f;
  struct tm	tm, packettm;
  time_t	tt;
  long double	offset_float = 0;

  /*
   * The following time format is allowed:
   * [YYYY-MM-DD] hh:mm:ss(.decimals)?
   *
   * Since Wireshark doesn't support regular expressions (please prove me
   * wrong :-) we will have to figure it out ourselves in the
   * following order:
   *
   * 1. YYYY-MM-DD hh:mm:ss.decimals
   * 2.            hh:mm:ss.decimals
   *
   */

  pts = (gchar *)ts;

  /* strip whitespace */
  while (isspace(pts[0]))
    ++pts;

  /* check for empty string */
  if (pts[0] == '\0')
    return(1);

  if (sscanf(pts, "%d-%d-%d %d:%d:%Lf", &Y, &M, &D, &h, &m, &f) == 6) {
    /* printf("%%d-%%d-%%d %%d:%%d:%%f\n"); */
    CHECK_YEARS(Y);
    CHECK_MONTHS(M);
    CHECK_DAYS(D);
    CHECK_HOURS(h);
    CHECK_MINUTE(m);
    CHECK_SEC_DEC(f);
  } else if (sscanf(pts, "%d:%d:%Lf", &h, &m, &f) == 3) {
    /* printf("%%d:%%d:%%f\n"); */
    Y = M = D = 0;
    CHECK_HOUR(h);
    CHECK_MINUTE(m);
    CHECK_SEC_DEC(f);
  } else {
    error_message("Could not parse the time: Expected (YY-MM-DD) "
      "hh:mm:ss(.dec)");
    return(1);
  }

  localtime_r(&(packettime->secs), &packettm);

  /* Convert the time entered in an epoch offset */
  localtime_r(&(packettime->secs), &tm);
  if (Y == 0) {
    tm.tm_year = packettm.tm_year;
    tm.tm_mon = packettm.tm_mon;
    tm.tm_mday = packettm.tm_mday;
  } else {
    tm.tm_year = Y - 1900;
    tm.tm_mon = M - 1;
    tm.tm_mday = D;
  }
  tm.tm_hour = h;
  tm.tm_min = m;
  tm.tm_sec = (int)floorl(f);
  tt = mktime(&tm);
  if (tt == -1) {
    error_message("mktime went wrong. Was the time invalid?");
    return(1);
  }

  nstime->secs = tt;
  f -= tm.tm_sec;
  nstime->nsecs = (int)(f * 1000000000);

  return(0);
}

static void
action_settime(GtkWindow *parent_w)
{
  GtkWidget	*packetnumber_te;
  const gchar	*packetnumber_text;
  long		packetnumber;
  GtkWidget	*time_te;
  const gchar	*time_text;
  gchar		*ptime_text;
  nstime_t	settime, difftime, packettime;
  frame_data	*fd, *packetfd;
  guint32	i;

  packetnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_SETTIME_PACKETNUMBER_KEY);
  packetnumber_text = gtk_entry_get_text(GTK_ENTRY(packetnumber_te));
  packetnumber = strtol((char *)packetnumber_text, NULL, 10);

  time_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_SETTIME_TIME_KEY);
  time_text = gtk_entry_get_text(GTK_ENTRY(time_te));
  ptime_text = (gchar *)time_text;

  /*
   * Get a copy of the real time (abs_ts - shift_offset) do we can find out the
   * difference between the specified time and the original packet
   */
  if ((packetfd = frame_data_sequence_find(cfile.frames, packetnumber)) == NULL)
    return;
  nstime_delta(&packettime, &(packetfd->abs_ts), &(packetfd->shift_offset)); 

  if (timestring2nstime(time_text, &packettime, &settime) != 0)
    return;

  /* Calculate difference between packet time and requested time */
  nstime_delta(&difftime, &settime, &packettime); 

  /* Up to here nothing is changed */

  if ((fd = frame_data_sequence_find(cfile.frames, 1)) == NULL)
    return; /* Shouldn't happen */
  modify_time_init(fd);

  /* Set everything back to the original time */
  for (i = 1; i <= cfile.count; i++) {
    if ((fd = frame_data_sequence_find(cfile.frames, i)) == NULL)
      continue;	/* Shouldn't happen */
    modify_time_perform(fd, SHIFT_POS, &difftime, SHIFT_SETTOZERO);
  }

  new_packet_list_queue_draw();
}

#ifdef NOTDEF
static char *
nstime_string(const nstime_t *t)
{
  static char s[100];
  char ts[100];
  struct tm tm;

  localtime_r(&(t->secs), &tm);
  strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
  g_snprintf(s, 100, "%s.%d", ts, t->nsecs);
  return(s);
}
#endif

/*
 * If the line between (OT1, NT1) and (OT2, NT2) is a straight line
 * and (OT3, NT3) is on that line,
 * then (NT2 - NT1) / (OT2 - OT2) = (NT3 - NT1) / (OT3 - OT1) and 
 * then (OT3 - OT1) * (NT2 - NT1) / (OT2 - OT2) = (NT3 - NT1) and
 * then NT1 + (OT3 - OT1) * (NT2 - NT1) / (OT2 - OT2) = NT3 and
 * then NT3 = NT1 + (OT3 - OT1) * (NT2 - NT1) / (OT2 - OT2) and 
 * thus NT3 = NT1 + (OT3 - OT1) * (NT2 - NT1) / (OT2 - OT1)
 *   or NT3 = NT1 + (OT3 - OT1) * ( deltaNT12 / deltaOT12)
 *
 * All the things you come up when waiting for the train to come...
 */
static void
calcNT3(nstime_t *OT1, nstime_t *OT3, nstime_t *NT1, nstime_t *NT3,
  nstime_t *deltaOT, nstime_t *deltaNT)
{
  long double fnt, fot, f, secs, nsecs;

  fnt = (long double)deltaNT->secs + (deltaNT->nsecs / 1000000000.0L);
  fot = (long double)deltaOT->secs + (deltaOT->nsecs / 1000000000.0L);
  f = fnt / fot;

  nstime_copy(NT3, OT3);
  nstime_subtract(NT3, OT1);

  secs = f * (long double)NT3->secs;
  nsecs = f * (long double)NT3->nsecs;
  nsecs += (secs - floorl(secs)) * 1000000000.0L;
  while (nsecs > 1000000000L) {
    secs += 1;
    nsecs -= 1000000000L;
  }
  while (nsecs < 0) {
    secs -= 1;
    nsecs += 1000000000L;
  }
  NT3->secs = (time_t)secs;
  NT3->nsecs = (int)nsecs;
  nstime_add(NT3, NT1);
}

static void
action_adjtime(GtkWindow *parent_w _U_)
{
  GtkWidget	*packetnumber_te;
  const gchar	*packetnumber_text;
  long		packetnumber1, packetnumber2;
  GtkWidget	*time_te;
  const gchar	*time1_text, *time2_text;
  gchar		*ptime1_text, *ptime2_text;
  nstime_t	nt1, nt2, ot1, ot2, nt3;
  nstime_t	dnt, dot, d3t;
  frame_data	*fd, *packet1fd, *packet2fd;
  guint32	i;

  packetnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_ADJTIME_PACKETNUMBER1_KEY);
  packetnumber_text = gtk_entry_get_text(GTK_ENTRY(packetnumber_te));
  packetnumber1 = strtol((char *)packetnumber_text, NULL, 10);
  packetnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_ADJTIME_PACKETNUMBER2_KEY);
  packetnumber_text = gtk_entry_get_text(GTK_ENTRY(packetnumber_te));
  packetnumber2 = strtol((char *)packetnumber_text, NULL, 10);

  /*
   * The following time format is allowed:
   * [YYYY-MM-DD] hh:mm:ss(.decimals)?
   *
   * Since Wireshark doesn't support regular expressions (please prove me
   * wrong :-) we will have to figure it out ourselves in the
   * following order:
   *
   * 1. YYYY-MM-DD hh:mm:ss.decimals
   * 2.            hh:mm:ss.decimals
   *
   */

  time_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_ADJTIME_TIME1_KEY);
  time1_text = gtk_entry_get_text(GTK_ENTRY(time_te));
  ptime1_text = (gchar *)time1_text;
  time_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_ADJTIME_TIME2_KEY);
  time2_text = gtk_entry_get_text(GTK_ENTRY(time_te));
  ptime2_text = (gchar *)time2_text;

  /*
   * Get a copy of the real time (abs_ts - shift_offset) do we can find out the
   * difference between the specified time and the original packet
   */
  if ((packet1fd = frame_data_sequence_find(cfile.frames, packetnumber1)) == NULL)
    return;
  nstime_copy(&ot1, &(packet1fd->abs_ts));
  nstime_subtract(&ot1, &(packet1fd->shift_offset));

  if (timestring2nstime(time1_text, &ot1, &nt1) != 0)
    return;

  /*
   * Get a copy of the real time (abs_ts - shift_offset) do we can find out the
   * difference between the specified time and the original packet
   */
  if ((packet2fd = frame_data_sequence_find(cfile.frames, packetnumber2)) == NULL)
    return;
  nstime_copy(&ot2, &(packet2fd->abs_ts));
  nstime_subtract(&ot2, &(packet2fd->shift_offset));

  if (timestring2nstime(time2_text, &ot2, &nt2) != 0)
    return;
 
  nstime_copy(&dot, &ot2);
  nstime_subtract(&dot, &ot1);

  nstime_copy(&dnt, &nt2);
  nstime_subtract(&dnt, &nt1);

  /* Up to here nothing is changed */
  if ((fd = frame_data_sequence_find(cfile.frames, 1)) == NULL)
    return; /* Shouldn't happen */
  modify_time_init(fd);

  for (i = 1; i <= cfile.count; i++) {
    if ((fd = frame_data_sequence_find(cfile.frames, i)) == NULL)
      continue;	/* Shouldn't happen */

    /* Set everything back to the original time */
    nstime_subtract(&(fd->abs_ts), &(fd->shift_offset));
    nstime_set_zero(&(fd->shift_offset));

    /* Add the difference to each packet */
    calcNT3(&ot1, &(fd->abs_ts), &nt1, &nt3, &dot, &dnt);

    nstime_copy(&d3t, &nt3);
    nstime_subtract(&d3t, &(fd->abs_ts));

    modify_time_perform(fd, SHIFT_POS, &d3t, SHIFT_SETTOZERO);
  }

  new_packet_list_queue_draw();
}

static void
action_undo(GtkWindow *parent_w _U_)
{
  guint32	i;
  frame_data	*fd;
  nstime_t	nulltime;

  nulltime.secs = nulltime.nsecs = 0;

  if ((fd = frame_data_sequence_find(cfile.frames, 1)) == NULL)
    return; /* Shouldn't happen */
  modify_time_init(fd);

  for (i = 1; i <= cfile.count; i++) {
    if ((fd = frame_data_sequence_find(cfile.frames, i)) == NULL)
      continue;	/* Shouldn't happen */
    modify_time_perform(fd, SHIFT_NEG, &nulltime, SHIFT_SETTOZERO);
  }
  new_packet_list_queue_draw();
}

static void
time_shift_close_cb(GtkWidget *close_bt _U_, gpointer parent_w _U_)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  window_destroy(GTK_WIDGET(parent_w));
}

static void
time_shift_frame_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Time Shift" dialog box. */
  time_shift_frame_w = NULL;
}

static void
modify_time_init(frame_data *fd)
{
  modify_time_perform(fd, SHIFT_NEG, NULL, SHIFT_KEEPOFFSET);
}

static void
modify_time_perform(frame_data *fd, int neg, nstime_t *offset, int settozero)
{
  static frame_data *first_packet = NULL;
  static frame_data *lastdisplayed_packet = NULL;
  static frame_data *prevcaptured_packet = NULL;
  static nstime_t nulltime;

  /* Only for initializing */
  if (offset == NULL) {
    first_packet = fd;
    lastdisplayed_packet = NULL;
    prevcaptured_packet = NULL;
    nulltime.secs = nulltime.nsecs = 0;
    return;
  }
  if (first_packet == NULL) {
    fprintf(stderr, "modify_time_perform: not initialized?\n");
    return;
  }

  /* The actual shift */

  if (settozero == SHIFT_SETTOZERO) {
    nstime_subtract(&(fd->abs_ts), &(fd->shift_offset));
    nstime_copy(&(fd->shift_offset), &nulltime);
  }

  if (neg == SHIFT_POS) {
    nstime_add(&(fd->abs_ts), offset);
    nstime_add(&(fd->shift_offset), offset);
  } else if (neg == SHIFT_NEG) {
    nstime_subtract(&(fd->abs_ts), offset);
    nstime_subtract(&(fd->shift_offset), offset);
  } else {
    fprintf(stderr, "modify_time_perform: neg = %d?\n", neg);
  }

  /*
   * rel_ts     - Relative timestamp to first packet
   * del_dis_ts - Delta timestamp to previous displayed frame
   * del_cap_ts - Delta timestamp to previous captured frame
   */
  if (first_packet != NULL) {
    nstime_copy(&(fd->rel_ts), &(fd->abs_ts));
    nstime_subtract(&(fd->rel_ts), &(first_packet->abs_ts));
  } else
    nstime_copy(&(fd->rel_ts), &nulltime);

  if (prevcaptured_packet != NULL) {
    nstime_copy(&(fd->del_cap_ts), &(fd->abs_ts));
    nstime_subtract(&(fd->del_cap_ts), &(prevcaptured_packet->abs_ts));
  } else
    nstime_copy(&(fd->del_cap_ts), &nulltime);

  if (lastdisplayed_packet != NULL) {
    nstime_copy(&(fd->del_dis_ts), &(fd->abs_ts));
    nstime_subtract(&(fd->del_dis_ts), &(lastdisplayed_packet->abs_ts));
  } else
    nstime_copy(&(fd->del_dis_ts), &nulltime);

  prevcaptured_packet = fd;
  if (fd->flags.passed_dfilter)
    lastdisplayed_packet = fd;
}
