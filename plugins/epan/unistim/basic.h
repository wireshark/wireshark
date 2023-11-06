/* basic.h
 * header field declarations, value_string def and true_false_string
 * definitions for basic manager messages
 * Copyright 2007 Don Newton <dnewton@cypresscom.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UNISTIM_BASIC_H
#define UNISTIM_BASIC_H

static int hf_basic_switch_query_flags;
static int hf_basic_switch_query_attr;
static int hf_basic_switch_query_opts;
static int hf_basic_switch_query_fw;
static int hf_basic_switch_query_hw_id;
static int hf_basic_switch_query_it_type;
static int hf_basic_switch_query_prod_eng_code;
static int hf_basic_switch_query_gray_mkt_info;
static int hf_basic_switch_options_secure;
static int hf_basic_switch_element_id;
static int hf_basic_switch_eeprom_data;
static int hf_basic_switch_terminal_id;

static int hf_basic_phone_eeprom_stat_cksum;
static int hf_basic_phone_eeprom_dynam;
static int hf_basic_phone_eeprom_net_config_cksum;
static int hf_basic_phone_hw_id;
static int hf_basic_phone_fw_ver;
static int hf_basic_it_type;
static int hf_basic_prod_eng_code;
static int hf_basic_ether_address;

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
