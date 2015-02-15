/* time_shift_dlg.c
 * Routines for "Time Shift" window
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>

#include "globals.h"

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "ui/time_shift.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/time_shift_dlg.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/help_dlg.h"

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
  GtkWidget     *main_vb, *label,
                *types_vb, *indent,

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
  GString * frame_str = g_string_new("");
  gint rb_size = 0, rb_spacing = 0, indent_width = 0;

  if (time_shift_frame_w != NULL) {
    /* There's already a "Time Shift" dialog box; reactivate it. */
    reactivate_window(time_shift_frame_w);
    return;
  }

  time_shift_frame_w = dlg_window_new("Wireshark: Time Shift");
  gtk_container_set_border_width (GTK_CONTAINER (time_shift_frame_w), DLG_OUTER_MARGIN);

  /* Container for each row of widgets */
  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_UNRELATED_SPACING, FALSE);
  gtk_container_add(GTK_CONTAINER(time_shift_frame_w), main_vb);


  /*
   * Shift All Packets frame
   */
  types_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_LABEL_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), types_vb, TRUE, TRUE, 0);

  /* Radio button row */
  timeshift_offset_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), timeshift_offset_hb, FALSE, FALSE, 0);

  timeshift_rb = gtk_radio_button_new_with_label (NULL, "Shift all packets");
  gtk_box_pack_start(GTK_BOX(timeshift_offset_hb), timeshift_rb, TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(timeshift_rb, "Shift the time on the frames.");

  gtk_widget_style_get(timeshift_rb, "indicator-size", &rb_size,
                       "indicator-spacing", &rb_spacing, NULL);
  indent_width += rb_size + rb_spacing;
  /* Time Shift entry row */
  timeshift_offset_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), timeshift_offset_hb, FALSE, FALSE, 0);

  indent = gtk_alignment_new(0,0,0,0);
  gtk_widget_set_size_request(indent, indent_width, -1);
  gtk_box_pack_start(GTK_BOX(timeshift_offset_hb), indent, FALSE, FALSE, 0);

  label = gtk_label_new("Time offset in the format [+-][[hh:]mm:]ss[.ddd]");
  gtk_box_pack_start(GTK_BOX(timeshift_offset_hb), label, FALSE, FALSE, 0);

  timeshift_offset_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(timeshift_offset_hb), timeshift_offset_text_box,
    TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(timeshift_offset_text_box,
    "Enter the time to shift here. The format is "
    "[+-][[hh:]mm:]ss.[.ddddddddd].");

  /*
   * Set Packet Number to Time frame
   */
  types_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_LABEL_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), types_vb, TRUE, TRUE, 0);
  /* time shift type row */
  settime_time_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), settime_time_hb, FALSE,
    FALSE, 0);

  settime_rb = gtk_radio_button_new_with_label(gtk_radio_button_get_group(
    GTK_RADIO_BUTTON(timeshift_rb)), "Set packet to time");
  gtk_box_pack_start(GTK_BOX(settime_time_hb), settime_rb, TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(settime_rb,
    "Set the time of a certain frame and adjust the rest of the frames "
    "automatically.");

  settime_time_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), settime_time_hb, FALSE,
    FALSE, 0);

  indent = gtk_alignment_new(0,0,0,0);
  gtk_widget_set_size_request(indent, indent_width, -1);
  gtk_box_pack_start(GTK_BOX(settime_time_hb), indent, FALSE, FALSE, 0);

  label = gtk_label_new("Packet number");
  gtk_box_pack_start(GTK_BOX(settime_time_hb), label, FALSE, FALSE, 0);

  if (cfile.current_frame) {
      g_string_printf(frame_str, "%u", cfile.current_frame->num);
  } else {
      g_string_printf(frame_str, "%u", cfile.first_displayed);
  }
  settime_packetnumber_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(settime_time_hb), settime_packetnumber_text_box,
    TRUE, TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(settime_packetnumber_text_box), frame_str->str);
  gtk_widget_set_tooltip_text(settime_packetnumber_text_box,
    "The frame which will be set to the time.");

  /* time shift row */
  settime_time_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), settime_time_hb, FALSE, FALSE,
    0);

  indent = gtk_alignment_new(0,0,0,0);
  gtk_widget_set_size_request(indent, indent_width, -1);
  gtk_box_pack_start(GTK_BOX(settime_time_hb), indent, FALSE, FALSE, 0);

  label = gtk_label_new("Set packet to time [YYYY-MM-DD] hh:mm:ss[.ddd]");
  gtk_box_pack_start(GTK_BOX(settime_time_hb), label, FALSE, FALSE, 0);

  settime_time_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(settime_time_hb), settime_time_text_box, TRUE,
    TRUE, 0);
  gtk_widget_set_tooltip_text(settime_time_text_box,
    "The time for the frame in the format of [YYYY-MM-DD] "
    "hh:mm:ss[.ddddddddd]");

  /*
   * Set two Packet Numbers to Time frame and extrapolate
   */
  types_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_LABEL_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), types_vb, TRUE, TRUE, 0);

  /* packet number row 1 */
  adjtime_offset_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE, FALSE, 0);

  adjtime_rb = gtk_radio_button_new_with_label(gtk_radio_button_get_group(
    GTK_RADIO_BUTTON(timeshift_rb)), "Set packets to time and extrapolate");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_rb, TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(adjtime_rb,
    "Set the time of two frames and adjust the rest of the frames "
    "automatically.");

  adjtime_offset_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE, FALSE, 0);

  indent = gtk_alignment_new(0,0,0,0);
  gtk_widget_set_size_request(indent, indent_width, -1);
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), indent, FALSE, FALSE, 0);

  label = gtk_label_new("Packet number");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), label, FALSE, FALSE, 0);

  adjtime_packetnumber1_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_packetnumber1_text_box,
    TRUE, TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(adjtime_packetnumber1_text_box), frame_str->str);
  gtk_widget_set_tooltip_text(adjtime_packetnumber1_text_box,
    "The frame which will be set to the time.");

  /* time shift row */
  adjtime_offset_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE, FALSE,
    0);

  indent = gtk_alignment_new(0,0,0,0);
  gtk_widget_set_size_request(indent, indent_width, -1);
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), indent, FALSE, FALSE, 0);

  label = gtk_label_new("Set packet to time [YYYY-MM-DD] hh:mm:ss[.ddd]");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), label, FALSE, FALSE, 0);

  adjtime_time1_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_time1_text_box, TRUE,
    TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(adjtime_time1_text_box), "");
  gtk_widget_set_tooltip_text(adjtime_time1_text_box,
    "The time for the frame in the format of [YYYY-MM-DD] "
    "hh:mm:ss[.ddddddddd]");

  /* packet number row 2 */
  adjtime_offset_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE,
    FALSE, 0);

  indent = gtk_alignment_new(0,0,0,0);
  gtk_widget_set_size_request(indent, indent_width, -1);
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), indent, FALSE, FALSE, 0);

  label = gtk_label_new("Packet number");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), label, FALSE, FALSE, 0);

  g_string_printf(frame_str, "%u", cfile.last_displayed);
  adjtime_packetnumber2_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_packetnumber2_text_box,
    TRUE, TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(adjtime_packetnumber2_text_box), frame_str->str);
  gtk_widget_set_tooltip_text(adjtime_packetnumber2_text_box,
    "The frame which will be set to the time.");

  /* time shift row */
  adjtime_offset_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), adjtime_offset_hb, FALSE, FALSE,
    0);

  indent = gtk_alignment_new(0,0,0,0);
  gtk_widget_set_size_request(indent, indent_width, -1);
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), indent, FALSE, FALSE, 0);

  label = gtk_label_new("Set packet to time [YYYY-MM-DD] hh:mm:ss[.ddd]");
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), label, FALSE, FALSE, 0);

  adjtime_time2_text_box = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(adjtime_offset_hb), adjtime_time2_text_box, TRUE,
    TRUE, 0);
  gtk_entry_set_text(GTK_ENTRY(adjtime_time2_text_box), "");
  gtk_widget_set_tooltip_text(adjtime_time2_text_box,
    "The time for the frame in the format of [YYYY-MM-DD] "
    "hh:mm:ss[.ddddddddd]");

  /*
   * Undo all shifts
   */
  types_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_LABEL_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), types_vb, TRUE, TRUE, 0);

  /* time shift type row */
  undo_type_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), undo_type_hb, TRUE, TRUE, 0);

  /* time shift row */
  undo_offset_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, DLG_BUTTON_SPACING, FALSE);
  gtk_box_pack_start(GTK_BOX(types_vb), undo_offset_hb, FALSE,
    FALSE, 0);

  undo_rb = gtk_radio_button_new_with_label(gtk_radio_button_get_group(
    GTK_RADIO_BUTTON(timeshift_rb)), "Undo all shifts");
  gtk_box_pack_start(GTK_BOX(undo_offset_hb), undo_rb, TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(undo_rb,
    "Undo all the Time Shift offsets on the frames.");

  /*
   * Button row
   */
  bbox = dlg_button_row_new(GTK_STOCK_APPLY, GTK_STOCK_CLOSE, GTK_STOCK_HELP,
    NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, TRUE, TRUE, 0);

  apply_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_APPLY);
  g_signal_connect(apply_bt, "clicked", G_CALLBACK(time_shift_apply_cb),
    time_shift_frame_w);
  gtk_widget_set_tooltip_text(apply_bt,
    "Apply the Time Shift options to the frame data.");

  close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
  window_set_cancel_button(time_shift_frame_w, close_bt, window_cancel_button_cb);
  g_signal_connect(close_bt, "clicked", G_CALLBACK(time_shift_close_cb),
    time_shift_frame_w);
  gtk_widget_set_tooltip_text(close_bt, "Close this dialog box.");

  help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
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

  g_string_free(frame_str, TRUE);
  gtk_widget_show_all(time_shift_frame_w);
  window_present(time_shift_frame_w);
}

static void
error_message(const gchar *msg)
{
  if (msg)
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", msg);
}

static void
time_shift_apply_cb(GtkWidget *ok_bt _U_, GtkWindow *parent_w)
{
  GtkWidget *flag_rb, *offset_te, *packetnumber_te, *time_te;
  const gchar *offset_text, *time_text, *time2_text;
  guint packet_num, packet2_num;

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
    offset_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
      E_TIMESHIFT_OFFSET_KEY);
    offset_text = gtk_entry_get_text(GTK_ENTRY(offset_te));
    error_message(time_shift_all(&cfile, offset_text));
    return;
  }

  flag_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_SETTIME_SELECT);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_rb)) == TRUE) {
    packetnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
            E_SETTIME_PACKETNUMBER_KEY);
    packet_num = (guint)strtol(gtk_entry_get_text(GTK_ENTRY(packetnumber_te)), NULL, 10);
    time_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
            E_SETTIME_TIME_KEY);
    time_text = gtk_entry_get_text(GTK_ENTRY(time_te));
    error_message(time_shift_settime(&cfile, packet_num, time_text));
    return;
  }

  flag_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
    E_ADJTIME_SELECT);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_rb)) == TRUE) {
    packetnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
            E_ADJTIME_PACKETNUMBER1_KEY);
    packet_num = (guint)strtol(gtk_entry_get_text(GTK_ENTRY(packetnumber_te)), NULL, 10);
    time_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
            E_ADJTIME_TIME1_KEY);
    time_text = gtk_entry_get_text(GTK_ENTRY(time_te));

    packetnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
            E_ADJTIME_PACKETNUMBER2_KEY);
    packet2_num = (guint)strtol(gtk_entry_get_text(GTK_ENTRY(packetnumber_te)), NULL, 10);
    time_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
            E_ADJTIME_TIME2_KEY);
    time2_text = gtk_entry_get_text(GTK_ENTRY(time_te));

    error_message(time_shift_adjtime(&cfile, packet_num, time_text, packet2_num, time2_text));
    return;
  }

  flag_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_UNDO_SELECT);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_rb)) == TRUE) {
    error_message(time_shift_undo(&cfile));
    return;
  }
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
