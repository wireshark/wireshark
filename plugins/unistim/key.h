/* key.h
  * header field declarations, value_string def and true_false_string
  * definitions for key manager messages
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

#ifndef UNISTIM_KEY_H
#define UNISTIM_KEY_H


static int hf_key_icon_id=-1;
static int hf_key_led_cadence=-1;
static int hf_key_led_id=-1;
static int hf_key_programmable_keys=-1;
static int hf_keys_soft_keys=-1;
static int hf_keys_hd_key=-1;
static int hf_keys_mute_key=-1;
static int hf_keys_quit_key=-1;
static int hf_keys_copy_key=-1;
static int hf_keys_mwi_key=-1;
static int hf_keys_num_nav_keys=-1;
static int hf_keys_num_conspic_keys=-1;
static int hf_keys_send_key_rel=-1;
static int hf_keys_enable_vol=-1;
static int hf_keys_conspic_prog_key=-1;
static int hf_keys_acd_super_control=-1;
static int hf_keys_local_dial_feedback=-1;
static int hf_keys_admin_command=-1;
static int hf_keys_logical_icon_id=-1;
static int hf_keys_repeat_timer_one=-1;
static int hf_keys_repeat_timer_two=-1;
static int hf_keys_led_id=-1;
static int hf_keys_phone_icon_id=-1;
static int hf_keys_cadence_on_time=-1;
static int hf_keys_cadence_off_time=-1;
static int hf_keys_user_activity_timeout=-1;

static const value_string keys_led_ids[]={
 {0x00,"Message Waiting LED"},
 {0x01,"Handsfree or Supervisor Access* LED"},
 {0x02,"Headset LED"},
 {0x03,"Mute LED"},
 {0x07,"Query all LEDs"},
 {0,NULL}
};


static const value_string admin_commands[]={
 {0x00,"Global NIL mapping"},
 {0x01,"One-to-one mapping"},
 {0x02,"Single mapping"},
 {0x03,"RESERVED"},
 {0,NULL}
};

static const value_string key_switch_msgs[]={
 {0x00,"LED Update"},
 {0x01,"Query Hookswitch"},
 {0x02,"User Activity Timer Stop"},
 {0x03,"User Activity Timer Start"},
 {0x04,"Downloadable Free Form Icon Access (Hardcoded)"},
 {0x05,"Downloadable Free Form Icon Access (Downloadable)"},
 {0x06,"Query Key/Indicator Manager"},
 {0x07,"Key/Indicator Manager Options"},
 {0x08,"Logical Icon Mapping"},
 {0x09,"Key Repeat Timer Download"},
 {0x0a,"Query LED State"},
 {0x0b,"Query Phone Icon State"},
 {0x0c,"Indicator Cadence Download"},
 {0x0d,"User Activity Timer Download"},
 {0x0e,"Free Form Icon Download"},
 {0x0f,"Phone Icon Update"},
 {0xff,"Reserved"},
 {0,NULL}
};
static const value_string key_phone_msgs[]={
 {0x00,"Key Event"},
 {0x01,"LED Status Report"},
 {0x03,"On Hook"},
 {0x04,"Off Hook"},
 {0x05,"User Activity Timer Expired"},
 {0x06,"Hookswitch State (on hook)"},
 {0x07,"Hookswitch State (off hook)"},
 {0x08,"Key/Indicator Manager Attributes Info"},
 {0x09,"Key/Indicator Manager Options Report"},
 {0x0a,"Phone Icon Status Report"},
 {0xff,"Reserved"},
 {0,NULL}
};


static const true_false_string key_release={
 "The Key code will be sent when a valid key release occurs",
 "No command will be sent when a key is released"
};
static const true_false_string enable_vol={
 "Volume key depression will be sent",
 "Volume Key depression will not be sent"
};
static const true_false_string conspic_prog={
 "Forces the keycode associated with conspicuous key0 to be the same as progkey0",
 "Conspicuous value key 0 and programmable key 0 have different keycodes"
};
static const true_false_string acd_supervisor={
 "ACD supervisor path and indicator controlled by the Switch",
 "ACD supervisor path and indicator controlled by the Phone"
};

static const value_string local_dialpad_feedback[]={
 {0x00,"No tone feedback provided when a dial pad key is depressed"},
 {0x01,"Short 'click' provided when a dial pad key is depressed"},
 {0x02,"Corresponding DTMF tone provided when a dial pad key is depressed"},
 {0x03,"Reserved"},
 {0,NULL}
};

static const value_string number_nav_keys[]={
 {0x00,"no navigation keys"},
 {0x01,"two navigation keys"},
 {0x02,"four navigation keys"},
 {0x03,"not available"},
 {0,NULL}
};

static const value_string led_ids[]={
 {0x00,"Message Waiting LED"},
 {0x01,"Handsfree or Supervisor Access* LED"},
 {0x02,"Headset LED"},
 {0x03,"Mute LED"},
 {0,NULL}
};

static const value_string led_cadences[]={
 {0x00,"Off"},
 {0x01,"On"},
 {0x02,"Flash"},
 {0x03,"Flicker"},
 {0x04,""},
 {0x05,""},
 {0x06,"Blink"},
 {0x07,"Downloadable cadence"},
 {0,NULL}
};


#endif
