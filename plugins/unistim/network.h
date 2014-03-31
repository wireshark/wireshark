/* network.h
  * header field declarations, value_string def and true_false_string
  * definitions for network manager messages
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

#ifndef UNISTIM_NETWORK_H
#define UNISTIM_NETWORK_H


static int hf_net_diag_flag=-1;
static int hf_net_managers_flag=-1;
static int hf_net_attributes_flag=-1;
static int hf_net_serv_info_flag=-1;
static int hf_net_options_flag=-1;
static int hf_net_sanity_flag=-1;
static int hf_net_enable_diag=-1;
static int hf_net_enable_rudp=-1;
static int hf_net_server_id=-1;
static int hf_net_server_port=-1;
static int hf_net_server_action=-1;
static int hf_net_server_retry_count=-1;
static int hf_net_server_failover_id=-1;
static int hf_net_server_ip_address=-1;
static int hf_net_server_time_out=-1;
static int hf_net_server_config_element=-1;
static int hf_net_server_recovery_time_low=-1;
static int hf_net_server_recovery_time_high=-1;
static int hf_net_phone_rx_ovr_flag=-1;
static int hf_net_phone_tx_ovr_flag=-1;
static int hf_net_phone_rx_empty_flag=-1;
static int hf_net_phone_invalid_msg_flag=-1;
static int hf_net_phone_eeprom_insane_flag=-1;
static int hf_net_phone_eeprom_unsafe_flag=-1;
static int hf_net_phone_diag=-1;
static int hf_net_phone_rudp=-1;

static int hf_net_phone_primary_server_id=-1;
static int hf_net_phone_server_port=-1;
static int hf_net_phone_server_action=-1;
static int hf_net_phone_server_retry_count=-1;
static int hf_net_phone_server_failover_id=-1;
static int hf_net_phone_server_ip=-1;
static int hf_net_file_xfer_mode =-1;
static int hf_net_force_download =-1;
static int hf_net_use_file_server_port =-1;
static int hf_net_use_local_port=-1;
static int hf_net_file_server_port=-1;
static int hf_net_local_port=-1;
static int hf_net_file_server_address=-1;
static int hf_net_full_pathname=-1;
static int hf_net_file_identifier=-1;

static const value_string file_xfer_modes[]={
 {0x00,"TFTP"},
 {0x01,"TFTP with active UNIStim channel"},
 {0x02,"UFTP"},
 {0x03,"UFTP with active UNIStim channel"},
 {0x04,"Future Use"},
 {0,NULL}
};

static const value_string action_bytes[]={
 {0x00,"Reserved"},
 {0x01,"Establish Unistim connection with Server"},
 {0x02,"Not Assigned"},
 {0,NULL}
};

static int hf_key_code=-1;
static int hf_key_command=-1;

static const value_string key_cmds[]={
 {0x00,"Key Released"},
 {0x01,"Key Depressed"},
 {0x02,"Key Repeated"},
 {0,NULL}
};

static const value_string key_names[]={

 {0x00,"Dial Pad 0"},
 {0x01,"Dial Pad 1"},
 {0x02,"Dial Pad 2"},
 {0x03,"Dial Pad 3"},
 {0x04,"Dial Pad 4"},
 {0x05,"Dial Pad 5"},
 {0x06,"Dial Pad 6"},
 {0x07,"Dial Pad 7"},
 {0x08,"Dial Pad 8"},
 {0x09,"Dial Pad 9"},
 {0x0a,"Dial Pad *"},
 {0x0b,"Dial Pad #"},
 {0x0c,"Navigation Up"},
 {0x0d,"Navigation Down"},
 {0x0e,"Navigation Right"},
 {0x0f,"Navigation Left"},
 {0x10,"Quit"},
 {0x11,"Copy"},
 {0x12,"Volume Up"},
 {0x13,"Volume Down"},
 {0x14,"Soft Key 0"},
 {0x15,"Soft Key 1"},
 {0x16,"Soft Key 2"},
 {0x17,"Soft Key 3"},
 {0x1a,"Supervisor Access Key"},
 {0x1b,"Hold"},
 {0x1c,"Release"},
 {0x1d,"Mute"},
 {0x1e,"Headset"},
 {0x1f,"Handsfree"},
 {0x20,"Prog Key 0"},
 {0x21,"Prog Key 1"},
 {0x22,"Prog Key 2"},
 {0x23,"Prog Key 3"},
 {0x24,"Prog Key 4"},
 {0x25,"Prog Key 5"},
 {0x26,"Prog Key 6"},
 {0x27,"Prog Key 7"},
 {0x28,"Prog Key 8"},
 {0x29,"Prog Key 9"},
 {0x2a,"Prog Key 10"},
 {0x2b,"Prog Key 11"},
 {0x2c,"Prog Key 12"},
 {0x2d,"Prog Key 13"},
 {0x2e,"Prog Key 14"},
 {0x2f,"Prog Key 15"},
 {0x30,"Prog Key 16"},
 {0x31,"Prog Key 17"},
 {0x32,"Prog Key 18"},
 {0x33,"Prog Key 19"},
 {0x34,"Prog Key 20"},
 {0x35,"Prog Key 21"},
 {0x36,"Prog Key 22"},
 {0x37,"Prog Key 23"},
 {0x38,"Prog Key 24"},
 {0x3b,"Conspicuous Key 0"},
 {0x3c,"Conspicuous Key 1"},
 {0x3d,"Conspicuous Key 2"},
 {0x3e,"Conspicuous Key 3"},
 {0x3f,"Conspicuous Key 4"},
 {0,NULL}
};
static const value_string network_switch_msgs[]={
    {0x02,"Soft Reset"},
    {0x03,"Hard Reset"},
    {0x04,"Query Network Manager"},
    {0x05,"Network Manager Options"},
    {0x06,"QoS Configuration"},
    {0x09,"Set RTCP Source Description Item"},
    {0x0b,"Download Server Information"},
    {0x0c,"Server Switch"},
    {0x0d,"Query Network Configuration Element"},
    {0x0e,"Download Software Upgrade"},
    {0x0f,"Set RTCP Report Interval"},
    {0x10,"Set Primary Server"},
    {0x12,"Reset Watchdog"},
    {0x13,"Set Recovery Procedure Time Interval"},
    {0x14,"Transport Reliability Layer Parameters Download"},
    {0xff,"Reserved"},
    {0,NULL}
};
static const value_string network_phone_msgs[]={
 {0x00,"Soft Reset Ack"},
 {0x01,"Sanity OK"},
 {0x02,"Network Manager Attributes Info"},
 {0x03,"Network Manager Diagnostic Info"},
 {0x04,"Manager IDs"},
 {0x05,"Network Manager Options Report"},
 {0x08,"Resume Connection with Server"},
 {0x09,"Suspend Connection with Server"},
 {0x0b,"Network Configuration Element Report"},
 {0x0c,"Server Information Report"},
 {0xff,"Reserved"},
 {0,NULL}
};
static const value_string network_server_id[]={
 {0x00,"First Server"},
 {0x01,"Second Server"},
 {0x02,"Third Server"},
 {0x03,"Fourth Server"},
 {0x04,"Fifth Server"},
 {0x05,"Sixth Server"},
 {0x06,"Seventh Server"},
 {0x07,"Eighth Server"},
 {0x08,"Ninth Server"},
 {0x09,"Tenth Server"},
 {0,NULL}
};
static const value_string server_action[]={
 {0x00,"Reserved"},
 {0x01,"Establish UNISTIM Connection with Server"},
 {0,NULL}
};
static const value_string network_elements[]={
 {0x00,"IT IP Address"},
 {0x01,"IT Netmask"},
 {0x02,"Default Gateway IP Address"},
 {0x03,"First Server IP Address"},
 {0x04,"First Server Port Number"},
 {0x05,"Second Server IP Address"},
 {0x06,"Second Server Port Number"},
 {0x07,"First Server Action"},
 {0x08,"First Server Retry Count"},
 {0x09,"Boot Mode"},
 {0x0b,"Second Server Action"},
 {0x0c,"Second Server Retry Count"},
 {0x0e,"8-byte User PIN"},
 {0,NULL}
};



#endif

