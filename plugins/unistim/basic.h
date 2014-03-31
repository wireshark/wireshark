/* basic.h
  * header field declarations, value_string def and true_false_string
  * definitions for basic manager messages
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

#ifndef UNISTIM_BASIC_H
#define UNISTIM_BASIC_H

static int hf_basic_switch_query_flags=-1;
static int hf_basic_switch_query_attr=-1;
static int hf_basic_switch_query_opts=-1;
static int hf_basic_switch_query_fw=-1;
static int hf_basic_switch_query_hw_id=-1;
static int hf_basic_switch_query_it_type=-1;
static int hf_basic_switch_query_prod_eng_code=-1;
static int hf_basic_switch_query_gray_mkt_info=-1;
static int hf_basic_switch_options_secure=-1;
static int hf_basic_switch_element_id=-1;
static int hf_basic_switch_eeprom_data=-1;
static int hf_basic_switch_terminal_id=-1;

static int hf_basic_phone_eeprom_stat_cksum=-1;
static int hf_basic_phone_eeprom_dynam=-1;
static int hf_basic_phone_eeprom_net_config_cksum=-1;
static int hf_basic_phone_hw_id=-1;
static int hf_basic_phone_fw_ver=-1;
static int hf_basic_it_type=-1;
static int hf_basic_prod_eng_code=-1;
static int hf_basic_ether_address=-1;

static const value_string it_types[]={
 {0x02,"i2004"},
 {0x03,"i2002 Basic Etherset"},
 {0x04,"Nortel Conference phone 2033 (polycom)"},
 {0x10,"Juniper 7308"},
 {0x11,"i2050 Softphone"},
 {0x30,"Meridian M6350"},
 {0,NULL}
};
static const value_string basic_switch_msgs[]={
  {0x01,"Query Basic Manager"},
  {0x02,"Basic Manager Options"},
  {0x06,"EEprom Write"},
  {0x07,"Assign Terminal ID"},
  {0x08,"Encapsulate Command"},
  {0xff,"Reserved"},
  {0,NULL}
};
static const value_string basic_phone_msgs[]={
 {0x00,"Basic Manager Attributes Info"},
 {0x01,"Basic Manager Options Report"},
 {0x02,"Firmware Version"},
 {0x03,"IT Type"},
 {0x07,"Hardware ID"},
 {0x08,"Product Engineering Code"},
 {0x09,"Grey Market Info"},
 {0x0a,"Encapsulate Command"},
 {0x11,"Phone Ethernet Address"},
 {0x0b,"Startup reason"},
 {0xff,"Reserved"},
 {0,NULL}
};

#endif
