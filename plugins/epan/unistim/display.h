/*display.h
  * header field declarations, value_string def and true_false_string
  * definitions for display manager messages
  * Copyright 2007 Don Newton <dnewton@cypresscom.net>
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

#ifndef UNISTIM_DISPLAY_H
#define UNISTIM_DISPLAY_H

static int hf_display_write_cursor_move=-1;
static int hf_display_write_clear_left=-1;
static int hf_display_write_clear_right=-1;
static int hf_display_write_shift_left=-1;
static int hf_display_write_shift_right=-1;
static int hf_display_write_highlight=-1;
static int hf_display_write_tag=-1;
static int hf_display_write_address_numeric=-1;
static int hf_display_write_address_context=-1;
static int hf_display_write_address_line=-1;
static int hf_display_write_address_soft_key=-1;
static int hf_display_write_address_soft_label=-1;
static int hf_display_write_address_softkey_id=-1;
static int hf_display_write_address_char_pos=-1;
static int hf_display_write_address_line_number=-1;
static int hf_display_cursor_move_cmd=-1;
static int hf_display_cursor_blink=-1;
static int hf_icon_id=-1;
static int hf_display_arrow=-1;
static int hf_display_clear_numeric =-1;
static int hf_display_clear_context =-1;
static int hf_display_clear_date =-1;
static int hf_display_clear_time =-1;
static int hf_display_clear_line =-1;
static int hf_display_clear_status_bar_icon =-1;
static int hf_display_clear_softkey =-1;
static int hf_display_clear_softkey_label =-1;
static int hf_display_clear_line_1 =-1;
static int hf_display_clear_line_2 =-1;
static int hf_display_clear_line_3 =-1;
static int hf_display_clear_line_4 =-1;
static int hf_display_clear_line_5 =-1;
static int hf_display_clear_line_6 =-1;
static int hf_display_clear_line_7 =-1;
static int hf_display_clear_line_8 =-1;
static int hf_display_clear_status_bar_icon_1 =-1;
static int hf_display_clear_status_bar_icon_2 =-1;
static int hf_display_clear_status_bar_icon_3 =-1;
static int hf_display_clear_status_bar_icon_4 =-1;
static int hf_display_clear_status_bar_icon_5 =-1;
static int hf_display_clear_status_bar_icon_6 =-1;
static int hf_display_clear_status_bar_icon_7 =-1;
static int hf_display_clear_status_bar_icon_8 =-1;
static int hf_display_clear_soft_key_1 =-1;
static int hf_display_clear_soft_key_2 =-1;
static int hf_display_clear_soft_key_3 =-1;
static int hf_display_clear_soft_key_4 =-1;
static int hf_display_clear_soft_key_5 =-1;
static int hf_display_clear_soft_key_6 =-1;
static int hf_display_clear_soft_key_7 =-1;
static int hf_display_clear_soft_key_8 =-1;
static int hf_display_clear_sk_label_key_id=-1;
static int hf_display_clear_all_slks=-1;


static int hf_display_line_width=-1;
static int hf_display_lines=-1;
static int hf_display_softkey_width=-1;
static int hf_display_softkeys=-1;
static int hf_display_icon=-1;
static int hf_display_softlabel_key_width=-1;
static int hf_display_context_width=-1;
static int hf_display_numeric_width=-1;
static int hf_display_time_width=-1;
static int hf_display_date_width=-1;
static int hf_display_char_dload=-1;
static int hf_display_freeform_icon_dload=-1;
static int hf_display_icon_type=-1;
static int hf_display_charsets=-1;
static int hf_display_contrast=-1;
static int hf_display_cursor_numeric=-1;
static int hf_display_cursor_context =-1;
static int hf_display_cursor_line =-1;
static int hf_display_cursor_softkey =-1;
static int hf_display_cursor_softkey_id =-1;
static int hf_display_cursor_char_pos =-1;
static int hf_display_cursor_line_number =-1;
static int hf_display_hlight_start=-1;
static int hf_display_hlight_end=-1;
static int hf_display_date_format=-1;
static int hf_display_time_format=-1;
static int hf_display_use_time_format=-1;
static int hf_display_use_date_format=-1;
static int hf_display_context_format=-1;
static int hf_display_context_field=-1;
static int hf_display_char_address=-1;
static int hf_display_layer_number=-1;
static int hf_display_layer_skey_id=-1;
static int hf_display_layer_all_skeys=-1;
static int hf_display_once_or_cyclic=-1;
static int hf_display_layer_duration=-1;
static int hf_display_call_timer_mode=-1;
static int hf_display_call_timer_reset=-1;
static int hf_display_call_timer_display=-1;
static int hf_display_call_timer_delay=-1;
static int hf_display_call_timer_id=-1;


static const value_string arrow_dirs[]={
 {0x00,"Down"},
 {0x01,"Up"},
 {0x02,"Right"},
 {0x03,"Left"},
 {0,NULL}
};


static const value_string cursor_move_cmds[]={
 {0x00,"Set cursor at home (first character on the first text line)"},
 {0x01,"Set cursor at the address specified in the following byte"},
 {0x02,"Move the cursor by one to the left"},
 {0x03,"Move the cursor by one to the right"},
 {0x04,"Move the cursor to the left as specified by the Character Position field contained in the last byte"},
 {0x05,"Move the cursor to the right as specified by the Character Position field contained in the last byte"},
 {0x06,"Cursor ON"},
 {0x07,"Cursor OFF"},
 {0xff,"No Movement command"},
 {0,NULL}
};

static const value_string display_switch_msgs[]={
  {0x01,"Restore Default Character Table Configuration"},
  {0x04,"Arrow"},
  {0x05,"Query Status Bar Icon"},
  {0x06,"Highlight Off"},
  {0x07,"Highlight On"},
  {0x09,"Restore Time and Date"},
  {0x0a,"Clear Time and Date"},
  {0x0b,"Call Duration Timer"},
  {0x0c,"Query Display Manager"},
  {0x0d,"Download Call Duration Timer Delay"},
  {0x0e,"Disable Display Field"},
  {0x0f,"Clear Field"},
  {0x10,"Cursor Control"},
  {0x12,"Display Scroll with Data (before)"},
  {0x13,"Display Scroll with Data (after)"},
  {0x14,"Status Bar Icon Update"},
  {0x15,"Month Labels Download"},
  {0x16,"Call Duration Timer Label Download"},
  {0x17,"Time and Date Format"},
  {0x18,"Display Data Write address|no control|no tag|no"},
  {0x19,"Display Data Write address|yes control|no tag|no"},
  {0x1a,"Display Data Write address|no control|yes tag|no"},
  {0x1b,"Display Data Write address|yes control|yes tag|no"},
  {0x1c,"Display Data Write address|no control|no tag|yes"},
  {0x1d,"Display Data Write address|yes control|no tag|yes"},
  {0x1e,"Display Data Write address|no control|yes tag|yes"},
  {0x1f,"Display Data Write address|yes control|yes tag|yes"},
  {0x20,"Context Info Bar Format"},
  {0x21,"Set Default Character Table Configuration"},
  {0x22,"Special Character Download"},
  {0x23,"Highlighted Field Definition"},
  {0x24,"Contrast"},
  {0x25,"Caller Log Download"},
  {0x30,"Layered Softkey Text Download"},
  {0x31,"Layered Softkey Clear"},
  {0x32,"Set Visible Softkey Layer"},
  {0x33,"Layered Softkey Cadence Download"},
  {0x34,"Layered Softkey Cadencing On"},
  {0x35,"Layered Softkey Cadencing Off"},
  {0xff,"Reserved"},
  {0,NULL}
};
static const value_string display_phone_msgs[]={
 {0x00,"Display Manager Attributes Info"},
 {0x01,"Contrast Level Report"},
 {0x02,"Cursor Location Report"},
 {0x03,"Highlight Status On"},
 {0x04,"Current Character Table Configuration Status"},
 {0x05,"Default Character Table Configuration Status"},
 {0x06,"Timer And Date Format Report"},
 {0x07,"Status Bar Icon State Report"},
 {0x0a,"Highlight Status Off"},
 {0xff,"Reserved"},
 {0,NULL}
};

static const true_false_string once_or_cyclic={
 "After the full cadence sequence is executed, softkey field will be updated ",
 "After the full cadence sequence is executed, it is restarted from the top"
};


static const value_string display_formats[]={
 {0x00,"None"},
 {0x01,"Underline"},
 {0x02,"Overline"},
 {0x03,"Marquee (combination of an overline and an underline)"},
 {0x04,"Border"},
 {0x05,"Reverse-video"},
 {0x06,"Reverse-video with border"},
 {0,NULL}
};
static const value_string display_format_fields[]={
 {0x00,"Numeric Index field"},
 {0x01,"Context field"},
 {0x02,"Date field"},
 {0x03,"Time field"},
 {0,NULL}
};


static const value_string time_formats[]={
 {0x00,"12-hour clock, e.g. 10:34pm"},
 {0x01,"French clock, e.g. 22h34"},
 {0x02,"24-hour clock, e.g. 22:34"},
 {0x03,"Reserved"},
 {0,NULL}
};

static const value_string date_formats[]={
 {0x00,"Day first, e.g. 16Sep"},
 {0x01,"Month first, e.g. Sep16"},
 {0x02," Numeric standard, e.g. 09/16"},
 {0x03,"Numeric inverse, e.g. 16/09"},
 {0,NULL}
};

static const value_string icon_types[]={
 {0x00,"Fixed Form Icons"},
 {0x01,"Free Form Icons"},
 {0,NULL}
};

static const true_false_string call_duration_timer_mode={
  "Mode = start timer",
  "Mode = stop timer"
};

static const true_false_string call_duration_timer_reset={
  "Reset time to zero",
  "Do not reset timer"
};

static const true_false_string call_duration_display_timer={
  "Call Duration timer is shown on the display",
  "Call Duration timer is not shown on the display"
};

static const true_false_string call_duration_timer_delay={
  "Action occurs after Call Duration Timer Delay",
  "Action occurs immediately"
};

#endif

