/* packet-ipmi-transport.c
 * Sub-dissectors for IPMI messages (netFn=Transport)
 * Copyright 2007-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <epan/packet.h>

#include "packet-ipmi.h"

static gint ett_ipmi_trn_lan00_byte1 = -1;
static gint ett_ipmi_trn_lan01_byte1 = -1;
static gint ett_ipmi_trn_lan02_byte1 = -1;
static gint ett_ipmi_trn_lan02_byte2 = -1;
static gint ett_ipmi_trn_lan02_byte3 = -1;
static gint ett_ipmi_trn_lan02_byte4 = -1;
static gint ett_ipmi_trn_lan02_byte5 = -1;
static gint ett_ipmi_trn_lan04_byte1 = -1;
static gint ett_ipmi_trn_lan07_byte2 = -1;
static gint ett_ipmi_trn_lan07_byte3 = -1;
static gint ett_ipmi_trn_lan10_byte1 = -1;
static gint ett_ipmi_trn_lan17_byte1 = -1;
static gint ett_ipmi_trn_lan18_byte1 = -1;
static gint ett_ipmi_trn_lan18_byte2 = -1;
static gint ett_ipmi_trn_lan18_byte4 = -1;
static gint ett_ipmi_trn_lan19_byte1 = -1;
static gint ett_ipmi_trn_lan19_byte2 = -1;
static gint ett_ipmi_trn_lan19_byte3 = -1;
static gint ett_ipmi_trn_lan20_byte12 = -1;
static gint ett_ipmi_trn_lan21_byte1 = -1;
static gint ett_ipmi_trn_lan22_byte1 = -1;
static gint ett_ipmi_trn_lan24_byte1 = -1;
static gint ett_ipmi_trn_lan24_byte2 = -1;
static gint ett_ipmi_trn_lan24_byte3 = -1;
static gint ett_ipmi_trn_lan24_byte4 = -1;
static gint ett_ipmi_trn_lan24_byte5 = -1;
static gint ett_ipmi_trn_lan24_byte6 = -1;
static gint ett_ipmi_trn_lan24_byte7 = -1;
static gint ett_ipmi_trn_lan24_byte8 = -1;
static gint ett_ipmi_trn_lan25_byte1 = -1;
static gint ett_ipmi_trn_lan25_byte2 = -1;
static gint ett_ipmi_trn_lan25_byte34 = -1;
static gint ett_ipmi_trn_serial03_byte1 = -1;
static gint ett_ipmi_trn_serial04_byte1 = -1;
static gint ett_ipmi_trn_serial05_byte1 = -1;
static gint ett_ipmi_trn_serial05_byte2 = -1;
static gint ett_ipmi_trn_serial06_byte1 = -1;
static gint ett_ipmi_trn_serial07_byte1 = -1;
static gint ett_ipmi_trn_serial07_byte2 = -1;
static gint ett_ipmi_trn_serial08_byte1 = -1;
static gint ett_ipmi_trn_serial08_byte2 = -1;
static gint ett_ipmi_trn_serial09_byte1 = -1;
static gint ett_ipmi_trn_serial09_byte2 = -1;
static gint ett_ipmi_trn_serial16_byte1 = -1;
static gint ett_ipmi_trn_serial17_byte1 = -1;
static gint ett_ipmi_trn_serial17_byte2 = -1;
static gint ett_ipmi_trn_serial17_byte4 = -1;
static gint ett_ipmi_trn_serial17_byte5 = -1;
static gint ett_ipmi_trn_serial19_byte1 = -1;
static gint ett_ipmi_trn_serial19_byte2 = -1;
static gint ett_ipmi_trn_serial19_byte3 = -1;
static gint ett_ipmi_trn_serial20_byte1 = -1;
static gint ett_ipmi_trn_serial21_byte1 = -1;
static gint ett_ipmi_trn_serial22_byte1 = -1;
static gint ett_ipmi_trn_serial23_byte1 = -1;
static gint ett_ipmi_trn_serial24_byte1 = -1;
static gint ett_ipmi_trn_serial25_byte2 = -1;
static gint ett_ipmi_trn_serial28_byte1 = -1;
static gint ett_ipmi_trn_serial28_byte2 = -1;
static gint ett_ipmi_trn_serial28_byte10 = -1;
static gint ett_ipmi_trn_serial28_byte11 = -1;
static gint ett_ipmi_trn_serial28_byte12 = -1;
static gint ett_ipmi_trn_serial28_byte13 = -1;
static gint ett_ipmi_trn_serial28_byte14 = -1;
static gint ett_ipmi_trn_serial29_byte1 = -1;
static gint ett_ipmi_trn_serial29_byte2 = -1;
static gint ett_ipmi_trn_serial30_byte1 = -1;
static gint ett_ipmi_trn_serial30_byte2 = -1;
static gint ett_ipmi_trn_serial30_byte3 = -1;
static gint ett_ipmi_trn_serial33_byte1 = -1;
static gint ett_ipmi_trn_serial37_byte1 = -1;
static gint ett_ipmi_trn_serial43_byte1 = -1;
static gint ett_ipmi_trn_serial50_byte1 = -1;
static gint ett_ipmi_trn_serial51_byte2 = -1;
static gint ett_ipmi_trn_serial51_byte3 = -1;
static gint ett_ipmi_trn_01_byte1 = -1;
static gint ett_ipmi_trn_02_byte1 = -1;
static gint ett_ipmi_trn_02_rev = -1;
static gint ett_ipmi_trn_03_rq_byte1 = -1;
static gint ett_ipmi_trn_03_rq_byte2 = -1;
static gint ett_ipmi_trn_03_rs_byte1 = -1;
static gint ett_ipmi_trn_04_byte1 = -1;
static gint ett_ipmi_trn_04_byte2 = -1;
static gint ett_ipmi_trn_10_byte1 = -1;
static gint ett_ipmi_trn_11_byte1 = -1;
static gint ett_ipmi_trn_11_rev = -1;
static gint ett_ipmi_trn_12_rq_byte1 = -1;
static gint ett_ipmi_trn_12_rq_byte2 = -1;
static gint ett_ipmi_trn_12_rs_byte1 = -1;
static gint ett_ipmi_trn_13_byte1 = -1;
static gint ett_ipmi_trn_14_byte1 = -1;
static gint ett_ipmi_trn_15_byte1 = -1;
static gint ett_ipmi_trn_16_byte1 = -1;
static gint ett_ipmi_trn_17_byte1 = -1;
static gint ett_ipmi_trn_17_byte2 = -1;
static gint ett_ipmi_trn_18_byte1 = -1;
static gint ett_ipmi_trn_19_byte1 = -1;
static gint ett_ipmi_trn_19_byte2 = -1;
static gint ett_ipmi_trn_XX_usercap = -1;
static gint ett_ipmi_trn_XX_cbcp = -1;
static gint ett_ipmi_trn_1a_byte1 = -1;
static gint ett_ipmi_trn_1a_byte2 = -1;
static gint ett_ipmi_trn_1b_byte1 = -1;
static gint ett_ipmi_trn_1b_byte2 = -1;

static gint hf_ipmi_trn_lan00_sip = -1;

static gint hf_ipmi_trn_lanXX_oem = -1;
static gint hf_ipmi_trn_lanXX_passwd = -1;
static gint hf_ipmi_trn_lanXX_md5 = -1;
static gint hf_ipmi_trn_lanXX_md2 = -1;
static gint hf_ipmi_trn_lanXX_none = -1;

static gint hf_ipmi_trn_lan03_ip = -1;

static gint hf_ipmi_trn_lan04_ipsrc = -1;

static gint hf_ipmi_trn_lan05_ether = -1;

static gint hf_ipmi_trn_lan06_subnet = -1;

static gint hf_ipmi_trn_lan07_ttl = -1;
static gint hf_ipmi_trn_lan07_flags = -1;
static gint hf_ipmi_trn_lan07_precedence = -1;
static gint hf_ipmi_trn_lan07_tos = -1;

static gint hf_ipmi_trn_lan08_rmcp_port = -1;

static gint hf_ipmi_trn_lan09_rmcp_port = -1;

static gint hf_ipmi_trn_lan10_responses = -1;
static gint hf_ipmi_trn_lan10_gratuitous = -1;

static gint hf_ipmi_trn_lan11_arp_interval = -1;

static gint hf_ipmi_trn_lan12_def_gw_ip = -1;

static gint hf_ipmi_trn_lan13_def_gw_mac = -1;

static gint hf_ipmi_trn_lan14_bkp_gw_ip = -1;

static gint hf_ipmi_trn_lan15_bkp_gw_mac = -1;

static gint hf_ipmi_trn_lan16_comm_string = -1;

static gint hf_ipmi_trn_lan17_num_dst = -1;

static gint hf_ipmi_trn_lan18_dst_selector = -1;
static gint hf_ipmi_trn_lan18_ack = -1;
static gint hf_ipmi_trn_lan18_dst_type = -1;
static gint hf_ipmi_trn_lan18_tout = -1;
static gint hf_ipmi_trn_lan18_retries = -1;

static gint hf_ipmi_trn_lan19_dst_selector = -1;
static gint hf_ipmi_trn_lan19_addr_format = -1;
static gint hf_ipmi_trn_lan19_address = -1;
static gint hf_ipmi_trn_lan19_gw_sel = -1;
static gint hf_ipmi_trn_lan19_ip = -1;
static gint hf_ipmi_trn_lan19_mac = -1;

static gint hf_ipmi_trn_lan20_vlan_id_enable = -1;
static gint hf_ipmi_trn_lan20_vlan_id = -1;

static gint hf_ipmi_trn_lan21_vlan_prio = -1;

static gint hf_ipmi_trn_lan22_num_cs_entries = -1;

static gint hf_ipmi_trn_lan23_cs_entry = -1;

static gint hf_ipmi_trn_lan24_priv = -1;

static gint hf_ipmi_trn_lan25_dst_selector = -1;
static gint hf_ipmi_trn_lan25_addr_format = -1;
static gint hf_ipmi_trn_lan25_address = -1;
static gint hf_ipmi_trn_lan25_uprio = -1;
static gint hf_ipmi_trn_lan25_cfi = -1;
static gint hf_ipmi_trn_lan25_vlan_id = -1;

static gint hf_ipmi_trn_serial03_connmode = -1;
static gint hf_ipmi_trn_serial03_terminal = -1;
static gint hf_ipmi_trn_serial03_ppp = -1;
static gint hf_ipmi_trn_serial03_basic = -1;

static gint hf_ipmi_trn_serial04_timeout = -1;

static gint hf_ipmi_trn_serial05_cbcp_callback = -1;
static gint hf_ipmi_trn_serial05_ipmi_callback = -1;
static gint hf_ipmi_trn_serial05_cb_list = -1;
static gint hf_ipmi_trn_serial05_cb_user = -1;
static gint hf_ipmi_trn_serial05_cb_prespec = -1;
static gint hf_ipmi_trn_serial05_no_cb = -1;
static gint hf_ipmi_trn_serial05_cb_dest1 = -1;
static gint hf_ipmi_trn_serial05_cb_dest2 = -1;
static gint hf_ipmi_trn_serial05_cb_dest3 = -1;

static gint hf_ipmi_trn_serial06_inactivity = -1;
static gint hf_ipmi_trn_serial06_dcd = -1;

static gint hf_ipmi_trn_serial07_flowctl = -1;
static gint hf_ipmi_trn_serial07_dtrhangup = -1;
static gint hf_ipmi_trn_serial07_bitrate = -1;

static gint hf_ipmi_trn_serial08_esc_powerup = -1;
static gint hf_ipmi_trn_serial08_esc_reset = -1;
static gint hf_ipmi_trn_serial08_switch_authcap = -1;
static gint hf_ipmi_trn_serial08_switch_rmcp = -1;
static gint hf_ipmi_trn_serial08_esc_switch1 = -1;
static gint hf_ipmi_trn_serial08_esc_switch2 = -1;
static gint hf_ipmi_trn_serial08_switch_dcdloss = -1;
static gint hf_ipmi_trn_serial08_sharing = -1;
static gint hf_ipmi_trn_serial08_ping_callback = -1;
static gint hf_ipmi_trn_serial08_ping_direct = -1;
static gint hf_ipmi_trn_serial08_ping_retry = -1;

static gint hf_ipmi_trn_serial09_ring_duration = -1;
static gint hf_ipmi_trn_serial09_ring_dead = -1;

static gint hf_ipmi_trn_serial10_set_sel = -1;
static gint hf_ipmi_trn_serial10_init_str = -1;
static gint hf_ipmi_trn_serial11_esc_seq = -1;
static gint hf_ipmi_trn_serial12_hangup_seq = -1;
static gint hf_ipmi_trn_serial13_dial_cmd = -1;
static gint hf_ipmi_trn_serial14_page_blackout = -1;
static gint hf_ipmi_trn_serial15_comm_string = -1;

static gint hf_ipmi_trn_serial16_ndest = -1;

static gint hf_ipmi_trn_serial17_dest_sel = -1;
static gint hf_ipmi_trn_serial17_ack = -1;
static gint hf_ipmi_trn_serial17_dest_type = -1;
static gint hf_ipmi_trn_serial17_ack_timeout = -1;
static gint hf_ipmi_trn_serial17_alert_retries = -1;
static gint hf_ipmi_trn_serial17_call_retries = -1;
static gint hf_ipmi_trn_serial17_alert_ack_timeout = -1;
static gint hf_ipmi_trn_serial17_dialstr_sel = -1;
static gint hf_ipmi_trn_serial17_tap_sel = -1;
static gint hf_ipmi_trn_serial17_ipaddr_sel = -1;
static gint hf_ipmi_trn_serial17_ppp_sel = -1;
static gint hf_ipmi_trn_serial17_unknown = -1;

static gint hf_ipmi_trn_serial18_call_retry = -1;

static gint hf_ipmi_trn_serial19_destsel = -1;
static gint hf_ipmi_trn_serial19_flowctl = -1;
static gint hf_ipmi_trn_serial19_dtrhangup = -1;
static gint hf_ipmi_trn_serial19_stopbits = -1;
static gint hf_ipmi_trn_serial19_charsize = -1;
static gint hf_ipmi_trn_serial19_parity = -1;
static gint hf_ipmi_trn_serial19_bitrate = -1;

static gint hf_ipmi_trn_serial20_num_dial_strings = -1;
static gint hf_ipmi_trn_serial21_dialsel = -1;
static gint hf_ipmi_trn_serial21_blockno = -1;
static gint hf_ipmi_trn_serial21_dialstr = -1;
static gint hf_ipmi_trn_serial22_num_ipaddrs = -1;
static gint hf_ipmi_trn_serial23_destsel = -1;
static gint hf_ipmi_trn_serial23_ipaddr = -1;
static gint hf_ipmi_trn_serial24_num_tap_accounts = -1;
static gint hf_ipmi_trn_serial25_tap_acct = -1;
static gint hf_ipmi_trn_serial25_dialstr_sel = -1;
static gint hf_ipmi_trn_serial25_tapsrv_sel = -1;
static gint hf_ipmi_trn_serial26_tap_acct = -1;
static gint hf_ipmi_trn_serial26_tap_passwd = -1;
static gint hf_ipmi_trn_serial27_tap_acct = -1;
static gint hf_ipmi_trn_serial27_tap_pager_id = -1;

static gint hf_ipmi_trn_serial28_tapsrv_sel = -1;
static gint hf_ipmi_trn_serial28_confirm = -1;
static gint hf_ipmi_trn_serial28_srvtype = -1;
static gint hf_ipmi_trn_serial28_ctrl_esc = -1;
static gint hf_ipmi_trn_serial28_t2 = -1;
static gint hf_ipmi_trn_serial28_t1 = -1;
static gint hf_ipmi_trn_serial28_t4 = -1;
static gint hf_ipmi_trn_serial28_t3 = -1;
static gint hf_ipmi_trn_serial28_t6 = -1;
static gint hf_ipmi_trn_serial28_t5 = -1;
static gint hf_ipmi_trn_serial28_n2 = -1;
static gint hf_ipmi_trn_serial28_n1 = -1;
static gint hf_ipmi_trn_serial28_n4 = -1;
static gint hf_ipmi_trn_serial28_n3 = -1;

static gint hf_ipmi_trn_serial29_op = -1;
static gint hf_ipmi_trn_serial29_lineedit = -1;
static gint hf_ipmi_trn_serial29_deletectl = -1;
static gint hf_ipmi_trn_serial29_echo = -1;
static gint hf_ipmi_trn_serial29_handshake = -1;
static gint hf_ipmi_trn_serial29_o_newline = -1;
static gint hf_ipmi_trn_serial29_i_newline = -1;
static gint hf_ipmi_trn_serial30_snooping = -1;
static gint hf_ipmi_trn_serial30_snoopctl = -1;
static gint hf_ipmi_trn_serial30_negot_ctl = -1;
static gint hf_ipmi_trn_serial30_use_xmit_accm = -1;
static gint hf_ipmi_trn_serial30_xmit_addr_comp = -1;
static gint hf_ipmi_trn_serial30_xmit_proto_comp = -1;
static gint hf_ipmi_trn_serial30_ipaddr = -1;
static gint hf_ipmi_trn_serial30_accm = -1;
static gint hf_ipmi_trn_serial30_addr_comp = -1;
static gint hf_ipmi_trn_serial30_proto_comp = -1;
static gint hf_ipmi_trn_serial31_port = -1;
static gint hf_ipmi_trn_serial32_port = -1;
static gint hf_ipmi_trn_serial33_auth_proto = -1;
static gint hf_ipmi_trn_serial34_chap_name = -1;

static gint hf_ipmi_trn_serial35_recv_accm = -1;
static gint hf_ipmi_trn_serial35_xmit_accm = -1;
static gint hf_ipmi_trn_serial36_snoop_accm = -1;
static gint hf_ipmi_trn_serial37_num_ppp = -1;
static gint hf_ipmi_trn_serial38_acct_sel = -1;
static gint hf_ipmi_trn_serial38_dialstr_sel = -1;
static gint hf_ipmi_trn_serial39_acct_sel = -1;
static gint hf_ipmi_trn_serial39_ipaddr = -1;
static gint hf_ipmi_trn_serial40_acct_sel = -1;
static gint hf_ipmi_trn_serial40_username = -1;
static gint hf_ipmi_trn_serial41_acct_sel = -1;
static gint hf_ipmi_trn_serial41_userdomain = -1;
static gint hf_ipmi_trn_serial42_acct_sel = -1;
static gint hf_ipmi_trn_serial42_userpass = -1;
static gint hf_ipmi_trn_serial43_acct_sel = -1;
static gint hf_ipmi_trn_serial43_auth_proto = -1;
static gint hf_ipmi_trn_serial44_acct_sel = -1;
static gint hf_ipmi_trn_serial44_hold_time = -1;

static gint hf_ipmi_trn_serial45_src_ipaddr = -1;
static gint hf_ipmi_trn_serial45_dst_ipaddr = -1;
static gint hf_ipmi_trn_serial46_tx_bufsize = -1;
static gint hf_ipmi_trn_serial47_rx_bufsize = -1;
static gint hf_ipmi_trn_serial48_ipaddr = -1;
static gint hf_ipmi_trn_serial49_blockno = -1;
static gint hf_ipmi_trn_serial49_dialstr = -1;
static gint hf_ipmi_trn_serial50_115200 = -1;
static gint hf_ipmi_trn_serial50_57600 = -1;
static gint hf_ipmi_trn_serial50_38400 = -1;
static gint hf_ipmi_trn_serial50_19200 = -1;
static gint hf_ipmi_trn_serial50_9600 = -1;

static gint hf_ipmi_trn_serial51_port_assoc_sel = -1;
static gint hf_ipmi_trn_serial51_ipmi_channel = -1;
static gint hf_ipmi_trn_serial51_conn_num = -1;
static gint hf_ipmi_trn_serial51_ipmi_sharing = -1;
static gint hf_ipmi_trn_serial51_ipmi_sol = -1;
static gint hf_ipmi_trn_serial51_chan_num = -1;
static gint hf_ipmi_trn_serial52_port_assoc_sel = -1;
static gint hf_ipmi_trn_serial52_conn_name = -1;
static gint hf_ipmi_trn_serial53_port_assoc_sel = -1;
static gint hf_ipmi_trn_serial53_chan_name = -1;

static gint hf_ipmi_trn_01_chan = -1;
static gint hf_ipmi_trn_01_param = -1;
static gint hf_ipmi_trn_01_param_data = -1;

static gint hf_ipmi_trn_02_getrev = -1;
static gint hf_ipmi_trn_02_chan = -1;
static gint hf_ipmi_trn_02_param = -1;
static gint hf_ipmi_trn_02_set = -1;
static gint hf_ipmi_trn_02_block = -1;
static gint hf_ipmi_trn_02_rev_present = -1;
static gint hf_ipmi_trn_02_rev_compat = -1;
static gint hf_ipmi_trn_02_param_data = -1;

static gint hf_ipmi_trn_03_chan = -1;
static gint hf_ipmi_trn_03_arp_resp = -1;
static gint hf_ipmi_trn_03_gratuitous_arp = -1;
static gint hf_ipmi_trn_03_status_arp_resp = -1;
static gint hf_ipmi_trn_03_status_gratuitous_arp = -1;

static gint hf_ipmi_trn_04_chan = -1;
static gint hf_ipmi_trn_04_clear = -1;
static gint hf_ipmi_trn_04_rx_ippkts = -1;
static gint hf_ipmi_trn_04_rx_iphdr_err = -1;
static gint hf_ipmi_trn_04_rx_ipaddr_err = -1;
static gint hf_ipmi_trn_04_rx_ippkts_frag = -1;
static gint hf_ipmi_trn_04_tx_ippkts = -1;
static gint hf_ipmi_trn_04_rx_udppkts = -1;
static gint hf_ipmi_trn_04_rx_validrmcp = -1;
static gint hf_ipmi_trn_04_rx_udpproxy = -1;
static gint hf_ipmi_trn_04_dr_udpproxy = -1;

static gint hf_ipmi_trn_10_chan = -1;
static gint hf_ipmi_trn_10_param = -1;
static gint hf_ipmi_trn_10_param_data = -1;

static gint hf_ipmi_trn_11_getrev = -1;
static gint hf_ipmi_trn_11_chan = -1;
static gint hf_ipmi_trn_11_param = -1;
static gint hf_ipmi_trn_11_set = -1;
static gint hf_ipmi_trn_11_block = -1;
static gint hf_ipmi_trn_11_rev_present = -1;
static gint hf_ipmi_trn_11_rev_compat = -1;
static gint hf_ipmi_trn_11_param_data = -1;

static gint hf_ipmi_trn_12_chan = -1;
static gint hf_ipmi_trn_12_mux_setting = -1;
static gint hf_ipmi_trn_12_sw_to_sys = -1;
static gint hf_ipmi_trn_12_sw_to_bmc = -1;
static gint hf_ipmi_trn_12_alert = -1;
static gint hf_ipmi_trn_12_msg = -1;
static gint hf_ipmi_trn_12_req = -1;
static gint hf_ipmi_trn_12_mux_state = -1;

static gint hf_ipmi_trn_13_chan = -1;
static gint hf_ipmi_trn_13_code1 = -1;
static gint hf_ipmi_trn_13_code2 = -1;
static gint hf_ipmi_trn_13_code3 = -1;
static gint hf_ipmi_trn_13_code4 = -1;
static gint hf_ipmi_trn_13_code5 = -1;

static gint hf_ipmi_trn_14_chan = -1;
static gint hf_ipmi_trn_14_block = -1;
static gint hf_ipmi_trn_14_data = -1;

static gint hf_ipmi_trn_15_chan = -1;
static gint hf_ipmi_trn_15_block = -1;
static gint hf_ipmi_trn_15_data = -1;

static gint hf_ipmi_trn_16_chan = -1;
static gint hf_ipmi_trn_16_src_port = -1;
static gint hf_ipmi_trn_16_dst_port = -1;
static gint hf_ipmi_trn_16_src_addr = -1;
static gint hf_ipmi_trn_16_dst_addr = -1;
static gint hf_ipmi_trn_16_bytes = -1;

static gint hf_ipmi_trn_17_chan = -1;
static gint hf_ipmi_trn_17_clear = -1;
static gint hf_ipmi_trn_17_block_num = -1;
static gint hf_ipmi_trn_17_size = -1;
static gint hf_ipmi_trn_17_data = -1;

static gint hf_ipmi_trn_18_state = -1;
static gint hf_ipmi_trn_18_ipmi_ver = -1;

static gint hf_ipmi_trn_19_chan = -1;
static gint hf_ipmi_trn_19_dest_sel = -1;

static gint hf_ipmi_trn_XX_cap_cbcp = -1;
static gint hf_ipmi_trn_XX_cap_ipmi = -1;
static gint hf_ipmi_trn_XX_cbcp_from_list = -1;
static gint hf_ipmi_trn_XX_cbcp_user = -1;
static gint hf_ipmi_trn_XX_cbcp_prespec = -1;
static gint hf_ipmi_trn_XX_cbcp_nocb = -1;
static gint hf_ipmi_trn_XX_dst1 = -1;
static gint hf_ipmi_trn_XX_dst2 = -1;
static gint hf_ipmi_trn_XX_dst3 = -1;

static gint hf_ipmi_trn_1a_user = -1;
static gint hf_ipmi_trn_1a_chan = -1;

static gint hf_ipmi_trn_1b_user = -1;
static gint hf_ipmi_trn_1b_chan = -1;

static const value_string lan00_sip_vals[] = {
	{ 0x00, "Set complete" },
	{ 0x01, "Set in progress" },
	{ 0x02, "Commit write" },
	{ 0x03, "Reserved" },
	{ 0, NULL }
};

static const value_string lan04_ipsrc_vals[] = {
	{ 0x00, "Unspecified" },
	{ 0x01, "Static address (manually configured)" },
	{ 0x02, "Address obtained by BMC running DHCP" },
	{ 0x03, "Address loaded by BIOS or system software" },
	{ 0x04, "Address obtained by BMC running other address assignment protocol" },
	{ 0, NULL }
};

static const struct true_false_string lan18_ack_tfs = {
	"Acknowledged", "Unacknowledged"
};

static const value_string lan18_dst_type_vals[] = {
	{ 0x00, "PET Trap destination" },
	{ 0x06, "OEM 1" },
	{ 0x07, "OEM 2" },
	{ 0, NULL }
};

static const value_string lan19_af_vals[] = {
	{ 0x00, "IPv4 Address followed by Ethernet/802.3 MAC Address" },
	{ 0, NULL }
};

static const struct true_false_string lan19_gw_sel_tfs = {
	"Use backup gateway", "Use default gateway"
};

static const struct true_false_string lan20_enable_tfs = {
	"Enabled", "Disabled"
};

static const value_string lan24_priv_vals[] = {
	{ 0x00, "Unspecified" },
	{ 0x01, "Callback" },
	{ 0x02, "User" },
	{ 0x03, "Operator" },
	{ 0x04, "Administrator" },
	{ 0x05, "OEM" },
	{ 0, NULL }
};

static const value_string lan25_af_vals[] = {
	{ 0x00, "VLAN ID not used" },
	{ 0x01, "802.1q VLAN TAG" },
	{ 0, NULL }
};

static const value_string serialXX_flowctl_vals[] = {
	{ 0x00, "No flow control" },
	{ 0x01, "RTS/CTS flow control" },
	{ 0x02, "XON/XOFF flow control" },
	{ 0x03, "Reserved" },
	{ 0, NULL }
};

static const value_string serialXX_bitrate_vals[] = {
	{ 0x06, "9600 bps" },
	{ 0x07, "19.2 kbps" },
	{ 0x08, "38.4 kbps" },
	{ 0x09, "57.6 kbps" },
	{ 0x0A, "115.2 kbps" },
	{ 0, NULL }
};

static const struct true_false_string serial03_connmode_tfs = {
	"Direct Connect", "Modem Connect"
};

static const value_string serial17_dest_type_vals[] = {
	{ 0x00, "Dial Page" },
	{ 0x01, "TAP Page" },
	{ 0x02, "PPP Alert" },
	{ 0x03, "Basic Mode Callback" },
	{ 0x04, "PPP Mode Callback" },
	{ 0x0e, "OEM 1" },
	{ 0x0f, "OEM 2" },
	{ 0, NULL }
};

static const struct true_false_string serial19_stopbits_tfs = {
	"2 stop bits", "1 stop bit"
};

static const struct true_false_string serial19_charsize_tfs = {
	"7-bit", "8-bit"
};

static const value_string serial19_parity_vals[] = {
	{ 0x00, "No" },
	{ 0x01, "Odd" },
	{ 0x02, "Even" },
	{ 0, NULL }
};

static const value_string serial28_confirm_vals[] = {
	{ 0x00, "ACK received after end-of-transaction only" },
	{ 0x01, "Code 211 and ACK received after ETX" },
	{ 0x02, "Code 211 or 213, and ACK received after ETX" },
	{ 0, NULL }
};

static const value_string serial29_op_vals[] = {
	{ 0x00, "Set volatile settings" },
	{ 0x01, "Set non-volatile settings" },
	{ 0x02, "Restore default" },
	{ 0, NULL }
};

static const value_string serial29_delete_vals[] = {
	{ 0x00, "<del>" },
	{ 0x01, "<bksp><sp><bksp>" },
	{ 0, NULL }
};

static const value_string serial29_o_nl_vals[] = {
	{ 0x00, "None" },
	{ 0x01, "<CR><LF>" },
	{ 0x02, "<NUL>" },
	{ 0x03, "<CR>" },
	{ 0x04, "<LF><CR>" },
	{ 0x05, "<LF>" },
	{ 0, NULL }
};

static const value_string serial29_i_nl_vals[] = {
	{ 0x01, "<CR>" },
	{ 0x02, "<NUL>" },
	{ 0, NULL }
};

static const value_string serial30_snoopctl_vals[] = {
	{ 0x00, "BMC uses Transmit ACCM" },
	{ 0x01, "BMC uses Snoop ACCM" },
	{ 0, NULL }
};

static const value_string serial30_negoctl_vals[] = { 
	{ 0x00, "On initial connection and mux switch" },
	{ 0x01, "On initial connection" },
	{ 0x02, "Never" },
	{ 0, NULL }
};

static const struct true_false_string serial30_filter_tfs = {
	"Using Transmit ACCM", "Assuming all control chars escaped"
};

static const value_string serial30_ipaddr_val[] = {
	{ 0x00, "Request IP Address" },
	{ 0x01, "Request Fixed IP Address" },
	{ 0x02, "No Negotiation" },
	{ 0, NULL }
};

static const value_string serialXX_proto_vals[] = {
	{ 0x00, "None" },
	{ 0x01, "CHAP" },
	{ 0x02, "PAP" },
	{ 0x03, "MS-CHAP v1, Windows NT" },
	{ 0x04, "MS-CHAP v1, Lan Manager" },
	{ 0x05, "MS-CHAP v2" },
	{ 0, NULL }
};

static const struct true_false_string tfs_03_suspend = {
	"Suspend", "Do not suspend"
};

static const struct true_false_string tfs_03_arp_status = {
	"Occurring", "Suspended"
};

static const struct true_false_string tfs_04_clear = {
	"Clear", "Do not clear"
};

static const value_string vals_12_mux[] = {
	{ 0x00, "Get present status" },
	{ 0x01, "Request switch to system" },
	{ 0x02, "Request switch to BMC" },
	{ 0x03, "Force switch to system" },
	{ 0x04, "Force switch to BMC" },
	{ 0x05, "Block requests to switch to system" },
	{ 0x06, "Allow requests to switch to system" },
	{ 0x07, "Block requests to switch to BMC" },
	{ 0x08, "Allow requests to switch to BMC" },
	{ 0, NULL }
};

static const struct true_false_string tfs_12_blocked = {
	"blocked", "allowed"
};

static const struct true_false_string tfs_12_req = {
	"accepted/forced", "rejected"
};

static const struct true_false_string tfs_12_mux_state = {
	"BMC", "system"
};

static const value_string vals_18_state[] = {
	{ 0x00, "No session active" },
	{ 0x01, "Session active (mux switched to BMC)" },
	{ 0x02, "Switching mux to system" },
	{ 0, NULL }
};

static const int *lanXX_authtypes_byte[] = { &hf_ipmi_trn_lanXX_oem, &hf_ipmi_trn_lanXX_passwd, &hf_ipmi_trn_lanXX_md5,
		&hf_ipmi_trn_lanXX_md2, &hf_ipmi_trn_lanXX_none, NULL };

static void
lan_serial_00(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_lan00_sip, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_lan00_byte1,
			byte1, TRUE, 0);
}

static void
lan_serial_01(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Authentication types supported: ",
			"No authentication types supported for this channel", ett_ipmi_trn_lan01_byte1,
			lanXX_authtypes_byte, TRUE, 0);
}

static void
lan_serial_02(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Authentication types for Callback level: ",
			"No authentication types enabled", ett_ipmi_trn_lan02_byte1,
			lanXX_authtypes_byte, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, "Authentication types for User level: ",
			"No authentication types enabled", ett_ipmi_trn_lan02_byte2,
			lanXX_authtypes_byte, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, "Authentication types for Operator level: ",
			"No authentication types enabled", ett_ipmi_trn_lan02_byte3,
			lanXX_authtypes_byte, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 3, 1, "Authentication types for Administrator level: ",
			"No authentication types enabled", ett_ipmi_trn_lan02_byte4,
			lanXX_authtypes_byte, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 4, 1, "Authentication types for OEM level: ",
			"No authentication types enabled", ett_ipmi_trn_lan02_byte5,
			lanXX_authtypes_byte, TRUE, 0);
}

static void
lan_03(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan03_ip, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void
lan_04(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_lan04_ipsrc, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_lan04_byte1,
			byte1, TRUE, 0);
}

static void
lan_05(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan05_ether, tvb, 0, 6, FALSE);
}

static void
lan_06(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan06_subnet, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void
lan_07(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte2[] = { &hf_ipmi_trn_lan07_flags, NULL };
	static const int *byte3[] = { &hf_ipmi_trn_lan07_precedence, &hf_ipmi_trn_lan07_tos, NULL };

	proto_tree_add_item(tree, hf_ipmi_trn_lan07_ttl, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_trn_lan07_byte2, byte2, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL, ett_ipmi_trn_lan07_byte3, byte3, TRUE, 0);
}

static void
lan_08(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan08_rmcp_port, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static void
lan_09(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan09_rmcp_port, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static void
lan_10(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_lan10_responses, &hf_ipmi_trn_lan10_gratuitous, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_lan10_byte1, byte1, TRUE, 0);
}

static void
lan_11(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan11_arp_interval, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
lan_12(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan12_def_gw_ip, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void
lan_13(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan13_def_gw_mac, tvb, 0, 6, FALSE);
}

static void
lan_14(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan14_bkp_gw_ip, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void
lan_15(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan15_bkp_gw_mac, tvb, 0, 6, FALSE);
}

static void
lan_16(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_lan16_comm_string, tvb, 0, 18, ENC_ASCII|ENC_NA);
}

static void
lan_17(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_lan17_num_dst, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_lan17_byte1, byte1, TRUE, 0);
}

static void
lan_18(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_lan18_dst_selector, NULL };
	static const int *byte2[] = { &hf_ipmi_trn_lan18_ack, &hf_ipmi_trn_lan18_dst_type, NULL };
	static const int *byte4[] = { &hf_ipmi_trn_lan18_retries, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_lan18_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_trn_lan18_byte2, byte2, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_trn_lan18_tout, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_trn_lan18_byte4, byte4, TRUE, 0);
}

static void
lan_19(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_lan19_dst_selector, NULL };
	static const int *byte2[] = { &hf_ipmi_trn_lan19_addr_format, NULL };
	static const int *byte3[] = { &hf_ipmi_trn_lan19_gw_sel, NULL };
	guint8 v;

	v = tvb_get_guint8(tvb, 1) >> 4;
	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_lan19_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_trn_lan19_byte2, byte2, TRUE, 0);

	if (v == 0) {
		proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL, ett_ipmi_trn_lan19_byte3, byte3, TRUE, 0);
		proto_tree_add_item(tree, hf_ipmi_trn_lan19_ip, tvb, 3, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ipmi_trn_lan19_mac, tvb, 7, 6, FALSE);
		return;
	}

	proto_tree_add_item(tree, hf_ipmi_trn_lan19_address, tvb, 2, tvb_length(tvb) - 2, ENC_NA);
}

static void
lan_20(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte12[] = { &hf_ipmi_trn_lan20_vlan_id_enable, &hf_ipmi_trn_lan20_vlan_id, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 2, NULL, NULL, ett_ipmi_trn_lan20_byte12, byte12, TRUE, 0);
}

static void
lan_21(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_lan21_vlan_prio, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_lan21_byte1, byte1, TRUE, 0);
}

static void
lan_22(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_lan22_num_cs_entries, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_lan22_byte1, byte1, TRUE, 0);
}

static void
lan_23(tvbuff_t *tvb, proto_tree *tree)
{
	guint i;
	guint8 v;

	for (i = 0; i < 16; i++) {
		v = tvb_get_guint8(tvb, i + 1);
		proto_tree_add_uint_format(tree, hf_ipmi_trn_lan23_cs_entry, tvb, i + 1, 1,
				v, "Cipher Suite ID entry %c: %u", 'A' + i, v);
	}
}

static void
lan_24(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *ett[] = { &ett_ipmi_trn_lan24_byte1, &ett_ipmi_trn_lan24_byte2, &ett_ipmi_trn_lan24_byte3,
		&ett_ipmi_trn_lan24_byte4, &ett_ipmi_trn_lan24_byte5, &ett_ipmi_trn_lan24_byte6, &ett_ipmi_trn_lan24_byte7,
		&ett_ipmi_trn_lan24_byte8 };
	proto_tree *s_tree;
	proto_item *ti;
	guint i;
	guint8 v, v1, v2;

	for (i = 0; i < 8; i++) {
		v = tvb_get_guint8(tvb, i + 1);
		v1 = v & 0x0f;
		v2 = v >> 4;
		ti = proto_tree_add_text(tree, tvb, i + 1, 1,
				"Cipher Suite #%d: %s (0x%02x), Cipher Suite #%d: %s (0x%02x)",
				i * 2 + 1, val_to_str(v1, lan24_priv_vals, "Reserved"), v1,
				i * 2 + 2, val_to_str(v2, lan24_priv_vals, "Reserved"), v2);
		s_tree = proto_item_add_subtree(ti, *ett[i]);
		proto_tree_add_uint_format(s_tree, hf_ipmi_trn_lan24_priv, tvb, i + 1, 1,
				v2 << 4, "%sMaximum Privilege Level for Cipher Suite #%d: %s (0x%02x)",
				ipmi_dcd8(v, 0xf0), i * 2 + 2, val_to_str(v2, lan24_priv_vals, "Reserved"), v2);
		proto_tree_add_uint_format(s_tree, hf_ipmi_trn_lan24_priv, tvb, i + 1, 1,
				v1, "%sMaximum Privilege Level for Cipher Suite #%d: %s (0x%02x)",
				ipmi_dcd8(v, 0x0f), i * 2 + 1, val_to_str(v1, lan24_priv_vals, "Reserved"), v1);
	}
}

static void
lan_25(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_lan25_dst_selector, NULL };
	static const int *byte2[] = { &hf_ipmi_trn_lan25_addr_format, NULL };
	static const int *byte34[] = { &hf_ipmi_trn_lan25_uprio, &hf_ipmi_trn_lan25_cfi, &hf_ipmi_trn_lan25_vlan_id, NULL };
	guint8 v;

	v = tvb_get_guint8(tvb, 1) >> 4;
	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_lan25_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_trn_lan25_byte2, byte2, TRUE, 0);
	switch (v) {
		case 0:
			break;
		case 1:
			proto_tree_add_bitmask_text(tree, tvb, 2, 2, NULL, NULL, ett_ipmi_trn_lan25_byte34,
					byte34, TRUE, 0);
			break;
		default:
			proto_tree_add_item(tree, hf_ipmi_trn_lan25_address, tvb, 2, tvb_length(tvb) - 2, ENC_LITTLE_ENDIAN);
			break;
	}
}

static struct {
	void (*intrp)(tvbuff_t *tvb, proto_tree *tree);
	const char *name;
} lan_options[] = {
	{ lan_serial_00, "Set In Progress" },
	{ lan_serial_01, "Authentication Type Support" },
	{ lan_serial_02, "Authentication Type Enables" },
	{ lan_03, "IP Address" },
	{ lan_04, "IP Address Source" },
	{ lan_05, "MAC Address" },
	{ lan_06, "Subnet Mask" },
	{ lan_07, "IPv4 Header Parameters" },
	{ lan_08, "Primary RMCP Port Number" },
	{ lan_09, "Secondary RMCP Port Number" },
	{ lan_10, "BMC-generated ARP Control" },
	{ lan_11, "Gratuitous ARP Interval" },
	{ lan_12, "Default Gateway Address" },
	{ lan_13, "Default Gateway MAC Address" },
	{ lan_14, "Backup Gateway Address" },
	{ lan_15, "Backup Gateway MAC Address" },
	{ lan_16, "Community String" },
	{ lan_17, "Number of Destinations" },
	{ lan_18, "Destination Type" },
	{ lan_19, "Destination Addresses" },
	{ lan_20, "VLAN ID (802.1q)" },
	{ lan_21, "VLAN Priority (802.1q)" },
	{ lan_22, "Cipher Suite Entry Support (RMCP+)" },
	{ lan_23, "Cipher Suite Entries (RMCP+)" },
	{ lan_24, "Cipher Suite Privilege Levels (RMCP+)" },
	{ lan_25, "Destination Address VLAN TAGs" },
};

/* Set LAN Configuration Parameters
 */
static void
rq01(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_01_chan, NULL };
	tvbuff_t *next;
	const char *desc;
	guint8 pno;

	pno = tvb_get_guint8(tvb, 1);
	if (pno < array_length(lan_options)) {
		desc = lan_options[pno].name;
	} else if (pno >= 0xC0) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_01_byte1,
			byte1, TRUE, 0);
	proto_tree_add_uint_format_value(tree, hf_ipmi_trn_01_param, tvb, 1, 1,
			pno, "%s (0x%02x)", desc, pno);
	if (pno < array_length(lan_options)) {
		next = tvb_new_subset(tvb, 2, tvb_length(tvb) - 2, tvb_length(tvb) - 2);
		lan_options[pno].intrp(next, tree);
	} else {
		proto_tree_add_item(tree, hf_ipmi_trn_01_param_data, tvb, 2,
				tvb_length(tvb) - 2, ENC_NA);
	}
}

static const value_string cc01[] = {
	{ 0x80, "Parameter not supported" },
	{ 0x81, "Attempt to set the 'set in progress' value (in parameter #0) when not in the 'set complete' state" },
	{ 0x82, "Attempt to write read-only parameter" },
	{ 0x83, "Attempt to read write-only parameter" },
	{ 0, NULL }
};

/* Get LAN Configuration Parameters
 */
static void
rq02(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_02_getrev, &hf_ipmi_trn_02_chan, NULL };
	const char *desc;
	guint8 pno;

	pno = tvb_get_guint8(tvb, 1);

	if (!tree) {
		ipmi_setsaveddata(0, pno);
		ipmi_setsaveddata(1, tvb_get_guint8(tvb, 0) & 0x80);
		return;
	}

	if (pno < array_length(lan_options)) {
		desc = lan_options[pno].name;
	} else if (pno >= 0xC0) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_02_byte1, byte1, TRUE, 0);
	proto_tree_add_uint_format_value(tree, hf_ipmi_trn_02_param, tvb, 1, 1,
			pno, "%s (0x%02x)", desc, pno);
	proto_tree_add_item(tree, hf_ipmi_trn_02_set, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_02_block, tvb, 2, 1, ENC_LITTLE_ENDIAN);
}

static void
rs02(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_02_rev_present, &hf_ipmi_trn_02_rev_compat, NULL };
	proto_item *ti;
	tvbuff_t *next;
	const char *desc;
	guint32 pno, req;

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_02_rev, byte1, TRUE, 0);

	if (!ipmi_getsaveddata(0, &pno) || !ipmi_getsaveddata(1, &req)) {
		/* No request found - cannot parse further */
		if (tvb_length(tvb) > 1) {
			proto_tree_add_item(tree, hf_ipmi_trn_02_param_data, tvb, 1, tvb_length(tvb) - 1, ENC_NA);
		};
		return;
	}

	if ((req & 0x80) && tvb_length(tvb) > 1) {
		ti = proto_tree_add_text(tree, tvb, 0, 0, "Requested parameter revision; parameter data returned");
		PROTO_ITEM_SET_GENERATED(ti);
	} else if (!(req & 0x80) && tvb_length(tvb) == 1) {
		ti = proto_tree_add_text(tree, tvb, 0, 0, "Requested parameter data; only parameter version returned");
		PROTO_ITEM_SET_GENERATED(ti);
	}

	if (pno < array_length(lan_options)) {
		desc = lan_options[pno].name;
	} else if (pno >= 0xC0) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}

	ti = proto_tree_add_text(tree, tvb, 0, 0, "Parameter: %s", desc);
	PROTO_ITEM_SET_GENERATED(ti);

	if (tvb_length(tvb) > 1) {
		if (pno < array_length(lan_options)) {
			next = tvb_new_subset(tvb, 1, tvb_length(tvb) - 1, tvb_length(tvb) - 1);
			lan_options[pno].intrp(next, tree);
		} else {
			proto_tree_add_item(tree, hf_ipmi_trn_02_param_data, tvb, 1,
					tvb_length(tvb) - 1, ENC_NA);
		}
	}
}

static const value_string cc02[] = {
	{ 0x80, "Parameter not supported" },
	{ 0, NULL }
};

static void
rq03(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_03_chan, NULL };
	static const int *byte2[] = { &hf_ipmi_trn_03_arp_resp, &hf_ipmi_trn_03_gratuitous_arp, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_03_rq_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_03_rq_byte2, byte2, TRUE, 0);
}

static void
rs03(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_03_status_arp_resp,
		&hf_ipmi_trn_03_status_gratuitous_arp, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_03_rs_byte1, byte1, TRUE, 0);
}

static void
rq04(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_04_chan, NULL };
	static const int *byte2[] = { &hf_ipmi_trn_04_clear, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_04_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_04_byte2, byte2, TRUE, 0);
}

static void
rs04(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_04_rx_ippkts, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_04_rx_iphdr_err, tvb, 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_04_rx_ipaddr_err, tvb, 4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_04_rx_ippkts_frag, tvb, 6, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_04_tx_ippkts, tvb, 8, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_04_rx_udppkts, tvb, 10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_04_rx_validrmcp, tvb, 12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_04_rx_udpproxy, tvb, 14, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_04_dr_udpproxy, tvb, 16, 2, ENC_LITTLE_ENDIAN);
}

static void
serial_03(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_serial03_connmode, &hf_ipmi_trn_serial03_terminal,
		&hf_ipmi_trn_serial03_ppp, &hf_ipmi_trn_serial03_basic, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial03_byte1, byte1, TRUE, 0);
}

static void
serial04_timeout_fmt(gchar *s, guint32 v)
{
	if (v) {
		g_snprintf(s, ITEM_LABEL_LENGTH, "%d sec", 30 * v);
	}
	else {
		g_snprintf(s, ITEM_LABEL_LENGTH, "Does not timeout");
	}
}

static void
serial_04(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial04_timeout, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial04_byte1, byte1, TRUE, 0);
}

static void
serial_05(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_serial05_cbcp_callback,
		&hf_ipmi_trn_serial05_ipmi_callback, NULL };
	static const int *byte2[] = { &hf_ipmi_trn_serial05_cb_list, &hf_ipmi_trn_serial05_cb_user,
		&hf_ipmi_trn_serial05_cb_prespec, &hf_ipmi_trn_serial05_no_cb, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Callback capabilities: ", "None",
			ett_ipmi_trn_serial05_byte1, byte1, TRUE, BMT_NO_TFS);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, "CBCP negotiation options: ", "None",
			ett_ipmi_trn_serial05_byte2, byte2, TRUE, BMT_NO_TFS);
	proto_tree_add_item(tree, hf_ipmi_trn_serial05_cb_dest1, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial05_cb_dest2, tvb, 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial05_cb_dest3, tvb, 4, 1, ENC_LITTLE_ENDIAN);
}

static void
serial_06(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial06_inactivity,
		&hf_ipmi_trn_serial06_dcd, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial06_byte1, byte1, TRUE, 0);
}

static void
serial_07(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial07_flowctl, &hf_ipmi_trn_serial07_dtrhangup, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_serial07_bitrate, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial07_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial07_byte2, byte2, TRUE, 0);
}

static void
serial_08(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial08_esc_powerup,
		&hf_ipmi_trn_serial08_esc_reset, &hf_ipmi_trn_serial08_switch_authcap,
		&hf_ipmi_trn_serial08_switch_rmcp, &hf_ipmi_trn_serial08_esc_switch1,
		&hf_ipmi_trn_serial08_esc_switch2, &hf_ipmi_trn_serial08_switch_dcdloss, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_serial08_sharing,
		&hf_ipmi_trn_serial08_ping_callback, &hf_ipmi_trn_serial08_ping_direct,
		&hf_ipmi_trn_serial08_ping_retry, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Switch/escape settings", NULL,
			ett_ipmi_trn_serial08_byte1, byte1, TRUE, BMT_NO_APPEND);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, "Sharing/ping settings", NULL,
			ett_ipmi_trn_serial08_byte2, byte2, TRUE, BMT_NO_APPEND);
}

static void
serial_09(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial09_ring_duration, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_serial09_ring_dead, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial09_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial09_byte2, byte2, TRUE, 0);
}

static void
serial_10(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial10_set_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial10_init_str, tvb, 1, tvb_length(tvb) - 1, ENC_ASCII|ENC_NA);
}

static void
serial_11(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial11_esc_seq, tvb, 0, 5, ENC_ASCII|ENC_NA); 
}

static void
serial_12(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial12_hangup_seq, tvb, 0, 8, ENC_ASCII|ENC_NA);
}

static void
serial_13(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial13_dial_cmd, tvb, 0, 8, ENC_ASCII|ENC_NA);
}

static void
serial_14(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial14_page_blackout, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
serial_15(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial15_comm_string, tvb, 0, 18, ENC_ASCII|ENC_NA);
}

static void
serial_16(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial16_ndest, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial16_byte1, byte1, TRUE, 0);
}

static void
serial_17(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial17_dest_sel, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_serial17_ack, &hf_ipmi_trn_serial17_dest_type, NULL };
	static const gint *byte4[] = { &hf_ipmi_trn_serial17_alert_retries, &hf_ipmi_trn_serial17_call_retries, NULL };
	const gint *byte5[3] = { NULL, NULL, NULL };
	guint8 v;

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial17_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial17_byte2, byte2, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_trn_serial17_alert_ack_timeout, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 3, 1, NULL, NULL,
			ett_ipmi_trn_serial17_byte4, byte4, TRUE, 0);

	v = tvb_get_guint8(tvb, 1) & 0x0f;
	switch (v) {
		case 0: /* Dial Page */
		case 3: /* Basic Mode Callback */
			byte5[0] = &hf_ipmi_trn_serial17_dialstr_sel;
			break;
		case 1: /* TAP Page */
			byte5[0] = &hf_ipmi_trn_serial17_tap_sel;
			break;
		case 2: /* PPP Alert */
		case 4: /* PPP Callback */
			byte5[0] = &hf_ipmi_trn_serial17_ipaddr_sel;
			byte5[1] = &hf_ipmi_trn_serial17_ppp_sel;
			break;
		default:
			proto_tree_add_item(tree, hf_ipmi_trn_serial17_unknown, tvb, 4, 1, ENC_LITTLE_ENDIAN);
			return;
	}
	proto_tree_add_bitmask_text(tree, tvb, 4, 1, NULL, NULL,
			ett_ipmi_trn_serial17_byte5, byte5, TRUE, 0);
}

static void
serial_18(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial18_call_retry, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
serial_19(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial19_destsel, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_serial19_flowctl, &hf_ipmi_trn_serial19_dtrhangup,
		&hf_ipmi_trn_serial19_stopbits, &hf_ipmi_trn_serial19_charsize, &hf_ipmi_trn_serial19_parity, NULL };
	static const gint *byte3[] = { &hf_ipmi_trn_serial19_bitrate, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial19_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial19_byte2, byte2, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL,
			ett_ipmi_trn_serial19_byte3, byte3, TRUE, 0);
}

static void
serial_20(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial20_num_dial_strings, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial20_byte1, byte1, TRUE, 0);
}

static void
serial_21(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial21_dialsel, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial21_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_trn_serial21_blockno, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial21_dialstr, tvb, 2, 1, ENC_ASCII|ENC_NA);
}

static void
serial_22(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial22_num_ipaddrs, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial22_byte1, byte1, TRUE, 0);
}

static void
serial_23(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial23_destsel, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial23_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_trn_serial23_ipaddr, tvb, 1, 4, ENC_BIG_ENDIAN);
}

static void
serial_24(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial24_num_tap_accounts, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial24_byte1, byte1, TRUE, 0);
}

static void
serial_25(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte2[] = { &hf_ipmi_trn_serial25_dialstr_sel, &hf_ipmi_trn_serial25_tapsrv_sel, NULL };

	proto_tree_add_item(tree, hf_ipmi_trn_serial25_tap_acct, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial25_byte2, byte2, TRUE, 0);
}

static void
serial_26(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial26_tap_acct, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial26_tap_passwd, tvb, 1, 6, ENC_ASCII|ENC_NA);
}

static void
serial_27(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial27_tap_acct, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial27_tap_pager_id, tvb, 1, 16, ENC_ASCII|ENC_NA);
}

static void
serial_28(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial28_tapsrv_sel, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_serial28_confirm, NULL };
	static const gint *byte10[] = { &hf_ipmi_trn_serial28_t2, &hf_ipmi_trn_serial28_t1, NULL };
	static const gint *byte11[] = { &hf_ipmi_trn_serial28_t4, &hf_ipmi_trn_serial28_t3, NULL };
	static const gint *byte12[] = { &hf_ipmi_trn_serial28_t6, &hf_ipmi_trn_serial28_t5, NULL };
	static const gint *byte13[] = { &hf_ipmi_trn_serial28_n2, &hf_ipmi_trn_serial28_n1, NULL };
	static const gint *byte14[] = { &hf_ipmi_trn_serial28_n4, &hf_ipmi_trn_serial28_n3, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial28_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial28_byte2, byte2, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_trn_serial28_srvtype, tvb, 2, 3, ENC_ASCII|ENC_NA);
	proto_tree_add_item(tree, hf_ipmi_trn_serial28_ctrl_esc, tvb, 5, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 9, 1, NULL, NULL,
			ett_ipmi_trn_serial28_byte10, byte10, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 10, 1, NULL, NULL,
			ett_ipmi_trn_serial28_byte11, byte11, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 11, 1, NULL, NULL,
			ett_ipmi_trn_serial28_byte12, byte12, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 12, 1, NULL, NULL,
			ett_ipmi_trn_serial28_byte13, byte13, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 13, 1, NULL, NULL,
			ett_ipmi_trn_serial28_byte14, byte14, TRUE, 0);
}

static void
serial_29(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial29_op, &hf_ipmi_trn_serial29_lineedit,
		&hf_ipmi_trn_serial29_deletectl, &hf_ipmi_trn_serial29_echo, &hf_ipmi_trn_serial29_handshake, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_serial29_o_newline, &hf_ipmi_trn_serial29_i_newline, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial29_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial29_byte2, byte2, TRUE, 0);
}

static void
serial_30(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial30_snooping, &hf_ipmi_trn_serial30_snoopctl, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_serial30_negot_ctl, &hf_ipmi_trn_serial30_use_xmit_accm,
		&hf_ipmi_trn_serial30_xmit_addr_comp, &hf_ipmi_trn_serial30_xmit_proto_comp, NULL };
	static const gint *byte3[] = { &hf_ipmi_trn_serial30_ipaddr, &hf_ipmi_trn_serial30_accm,
		&hf_ipmi_trn_serial30_addr_comp, &hf_ipmi_trn_serial30_proto_comp, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial30_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial30_byte2, byte2, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL,
			ett_ipmi_trn_serial30_byte3, byte3, TRUE, 0);
}

static void
serial_31(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial31_port, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static void
serial_32(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial32_port, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static void
serial_33(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial33_auth_proto, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial33_byte1, byte1, TRUE, 0);
}

static void
serial_34(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial34_chap_name, tvb, 0, 16, ENC_ASCII|ENC_NA);
}

static void
serial_35(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial35_recv_accm, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial35_xmit_accm, tvb, 4, 4, ENC_BIG_ENDIAN);
}

static void
serial_36(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial36_snoop_accm, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void
serial_37(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial37_num_ppp, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_serial37_byte1, byte1, TRUE, 0);
}

static void
serial_38(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial38_acct_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial38_dialstr_sel, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

static void
serial_39(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial39_acct_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial39_ipaddr, tvb, 1, 4, ENC_BIG_ENDIAN);
}

static void
serial_40(tvbuff_t *tvb, proto_tree *tree)
{
	int slen;

	proto_tree_add_item(tree, hf_ipmi_trn_serial40_acct_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	slen = tvb_length(tvb) - 1;
	if (slen > 16) {
		slen = 16;
	}
	proto_tree_add_item(tree, hf_ipmi_trn_serial40_username, tvb, 1, slen, ENC_ASCII|ENC_NA);
}

static void
serial_41(tvbuff_t *tvb, proto_tree *tree)
{
	int slen;

	proto_tree_add_item(tree, hf_ipmi_trn_serial41_acct_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	slen = tvb_length(tvb) - 1;
	if (slen > 16) {
		slen = 16;
	}
	proto_tree_add_item(tree, hf_ipmi_trn_serial41_userdomain, tvb, 1, slen, ENC_ASCII|ENC_NA);
}

static void
serial_42(tvbuff_t *tvb, proto_tree *tree)
{
	int slen;

	proto_tree_add_item(tree, hf_ipmi_trn_serial42_acct_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	slen = tvb_length(tvb) - 1;
	if (slen > 16) {
		slen = 16;
	}
	proto_tree_add_item(tree, hf_ipmi_trn_serial42_userpass, tvb, 1, slen, ENC_ASCII|ENC_NA);
}

static void
serial_43(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial43_auth_proto, NULL };

	proto_tree_add_item(tree, hf_ipmi_trn_serial43_acct_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial43_byte1, byte1, TRUE, 0);
}

static void
serial_44(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial44_acct_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial44_hold_time, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

static void
serial_45(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial45_src_ipaddr, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial45_dst_ipaddr, tvb, 4, 4, ENC_BIG_ENDIAN);
}

static void
serial_46(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial46_tx_bufsize, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static void
serial_47(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial47_rx_bufsize, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static void
serial_48(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial48_ipaddr, tvb, 0, 4, ENC_BIG_ENDIAN);
}

static void
serial_49(tvbuff_t *tvb, proto_tree *tree)
{
	int slen;

	proto_tree_add_item(tree, hf_ipmi_trn_serial49_blockno, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	slen = tvb_length(tvb) - 1;
	if (slen > 16) {
		slen = 16;
	}
	proto_tree_add_item(tree, hf_ipmi_trn_serial49_dialstr, tvb, 1, slen, ENC_ASCII|ENC_NA);
}

static void
serial_50(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_serial50_115200, &hf_ipmi_trn_serial50_57600,
		&hf_ipmi_trn_serial50_38400, &hf_ipmi_trn_serial50_19200, &hf_ipmi_trn_serial50_9600, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Bit rate support: ", "None",
			ett_ipmi_trn_serial50_byte1, byte1, TRUE, 0);
}

static void
serial_51(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte2[] = { &hf_ipmi_trn_serial51_ipmi_channel, &hf_ipmi_trn_serial51_conn_num, NULL };
	static const gint *byte3[] = { &hf_ipmi_trn_serial51_ipmi_sharing,
		&hf_ipmi_trn_serial51_ipmi_sol, &hf_ipmi_trn_serial51_chan_num, NULL };

	proto_tree_add_item(tree, hf_ipmi_trn_serial51_port_assoc_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_serial51_byte2, byte2, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL,
			ett_ipmi_trn_serial51_byte3, byte3, TRUE, 0);
}

static void
serial_52(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial52_port_assoc_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial52_conn_name, tvb, 1, 16, ENC_NA);
}

static void
serial_53(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_serial53_port_assoc_sel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_serial53_chan_name, tvb, 1, 16, ENC_NA);
}

static struct {
	void (*intrp)(tvbuff_t *tvb, proto_tree *tree);
	const char *name;
} serial_options[] = {
	{ lan_serial_00, "Set In Progress" },
	{ lan_serial_01, "Authentication Type Support" },
	{ lan_serial_02, "Authentication Type Enables" },
	{ serial_03, "Connection Mode" },
	{ serial_04, "Session Inactivity Timeout" },
	{ serial_05, "Channel Callback Control" },
	{ serial_06, "Session Termination" },
	{ serial_07, "IPMI Messaging Comm Settings" },
	{ serial_08, "Mux Switch Control" },
	{ serial_09, "Modem Ring Time" },
	{ serial_10, "Modem Init String" },
	{ serial_11, "Modem Escape Sequence" },
	{ serial_12, "Modem Hang-up Sequence" },
	{ serial_13, "Modem Dial Command" },
	{ serial_14, "Page Blackout Interval" },
	{ serial_15, "Community String" },
	{ serial_16, "Number of Alert Destinations" },
	{ serial_17, "Destination Info" },
	{ serial_18, "Call Retry Interval" },
	{ serial_19, "Destination Comm Settings" },
	{ serial_20, "Number of Dial Strings" },
	{ serial_21, "Destination Dial Strings" },
	{ serial_22, "Number of Alert Destination IP Addresses" },
	{ serial_23, "Destination IP Addresses" },
	{ serial_24, "Number of TAP Accounts" },
	{ serial_25, "TAP Account" },
	{ serial_26, "TAP Passwords" },
	{ serial_27, "TAP Pager ID Strings" },
	{ serial_28, "TAP Service Settings" },
	{ serial_29, "Terminal Mode Configuration" },
	{ serial_30, "PPP Protocol Options" },
	{ serial_31, "PPP Primary RMCP Port" },
	{ serial_32, "PPP Secondary RMCP Port" },
	{ serial_33, "PPP Link Authentication" },
	{ serial_34, "CHAP Name" },
	{ serial_35, "PPP ACCM" },
	{ serial_36, "PPP Snoop ACCM" },
	{ serial_37, "Number of PPP Accounts" },
	{ serial_38, "PPP Account Dial String Selector" },
	{ serial_39, "PPP Account IP Addresses" },
	{ serial_40, "PPP Account User Names" },
	{ serial_41, "PPP Account User Domains" },
	{ serial_42, "PPP Account User Passwords" },
	{ serial_43, "PPP Account Authentication Settings" },
	{ serial_44, "PPP Account Connection Hold Times" },
	{ serial_45, "PPP UDP Proxy IP Header" },
	{ serial_46, "PPP UDP Proxy Transmit Buffer Size" },
	{ serial_47, "PPP UDP Proxy Receive Buffer Size" },
	{ serial_48, "PPP Remote Console IP Address" },
	{ serial_49, "System Phone Number" },
	{ serial_50, "Bitrate Support" },
	{ serial_51, "System Serial Port Association" },
	{ serial_52, "System Connector Names" },
	{ serial_53, "System Serial Channel Names" }
};

/* Set Serial/Modem Configuration Parameters
 */
static void
rq10(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_10_chan, NULL };
	tvbuff_t *next;
	const char *desc;
	guint8 pno;

	pno = tvb_get_guint8(tvb, 1);
	if (pno < array_length(serial_options)) {
		desc = serial_options[pno].name;
	} else if (pno >= 0xC0) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_trn_10_byte1,
			byte1, TRUE, 0);
	proto_tree_add_uint_format_value(tree, hf_ipmi_trn_10_param, tvb, 1, 1,
			pno, "%s (0x%02x)", desc, pno);
	if (pno < array_length(serial_options)) {
		next = tvb_new_subset(tvb, 2, tvb_length(tvb) - 2, tvb_length(tvb) - 2);
		serial_options[pno].intrp(next, tree);
	} else {
		proto_tree_add_item(tree, hf_ipmi_trn_10_param_data, tvb, 2,
				tvb_length(tvb) - 2, ENC_NA);
	}
}

static const value_string cc10[] = {
	{ 0x80, "Parameter not supported" },
	{ 0x81, "Attempt to set the 'set in progress' value (in parameter #0) when not in the 'set complete' state" },
	{ 0x82, "Attempt to write read-only parameter" },
	{ 0x83, "Attempt to read write-only parameter" },
	{ 0, NULL }
};

/* Get LAN Configuration Parameters
 */
static void
rq11(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_11_getrev, &hf_ipmi_trn_11_chan, NULL };
	const char *desc;
	guint8 pno;

	pno = tvb_get_guint8(tvb, 1);

	if (!tree) {
		ipmi_setsaveddata(0, pno);
		ipmi_setsaveddata(1, tvb_get_guint8(tvb, 0));
		return;
	}

	if (pno < array_length(serial_options)) {
		desc = serial_options[pno].name;
	} else if (pno >= 0xC0) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_11_byte1, byte1, TRUE, 0);
	proto_tree_add_uint_format_value(tree, hf_ipmi_trn_11_param, tvb, 1, 1,
			pno, "%s (0x%02x)", desc, pno);
	proto_tree_add_item(tree, hf_ipmi_trn_11_set, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_11_block, tvb, 2, 1, ENC_LITTLE_ENDIAN);
}

static void
rs11(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_trn_11_rev_present, &hf_ipmi_trn_11_rev_compat, NULL };
	proto_item *ti;
	tvbuff_t *next;
	const char *desc;
	guint32 pno, req;

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_11_rev, byte1, TRUE, 0);

	if (!ipmi_getsaveddata(0, &pno) || !ipmi_getsaveddata(1, &req)) {
		/* No request found - cannot parse further */
		if (tvb_length(tvb) > 1) {
			proto_tree_add_item(tree, hf_ipmi_trn_11_param_data, tvb, 1, tvb_length(tvb) - 1, ENC_NA);
		};
		return;
	}

	if (pno < array_length(serial_options)) {
		desc = serial_options[pno].name;
	} else if (pno >= 0xC0) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}

	if ((req & 0x80) && tvb_length(tvb) > 1) {
		ti = proto_tree_add_text(tree, tvb, 0, 0, "Requested parameter revision; parameter data returned");
		PROTO_ITEM_SET_GENERATED(ti);
	} else if (!(req & 0x80) && tvb_length(tvb) == 1) {
		ti = proto_tree_add_text(tree, tvb, 0, 0, "Requested parameter data; only parameter version returned");
		PROTO_ITEM_SET_GENERATED(ti);
	}

	ti = proto_tree_add_text(tree, tvb, 0, 0, "Parameter: %s", desc);
	PROTO_ITEM_SET_GENERATED(ti);

	if (tvb_length(tvb) > 1) {
		if (pno < array_length(serial_options)) {
			next = tvb_new_subset(tvb, 1, tvb_length(tvb) - 1, tvb_length(tvb) - 1);
			serial_options[pno].intrp(next, tree);
		} else {
			proto_tree_add_item(tree, hf_ipmi_trn_11_param_data, tvb, 1,
					tvb_length(tvb) - 1, ENC_NA);
		}
	}
}

static const value_string cc11[] = {
	{ 0x80, "Parameter not supported" },
	{ 0, NULL }
};

/* Set Serial/Modem Mux
 */
static void
rq12(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_12_chan, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_12_mux_setting, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_12_rq_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_12_rq_byte2, byte2, TRUE, 0);
}

static void
rs12(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_12_sw_to_sys, &hf_ipmi_trn_12_sw_to_bmc,
		&hf_ipmi_trn_12_alert, &hf_ipmi_trn_12_msg, &hf_ipmi_trn_12_req, &hf_ipmi_trn_12_mux_state, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_12_rs_byte1, byte1, TRUE, 0);
}

/* Get TAP Response Codes
 */
static void
rq13(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_13_chan, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_13_byte1, byte1, TRUE, 0);
}

static void
rs13(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_13_code1, tvb, 0, 3, ENC_ASCII|ENC_NA);
	proto_tree_add_item(tree, hf_ipmi_trn_13_code2, tvb, 3, 3, ENC_ASCII|ENC_NA);
	proto_tree_add_item(tree, hf_ipmi_trn_13_code3, tvb, 6, 3, ENC_ASCII|ENC_NA);
	proto_tree_add_item(tree, hf_ipmi_trn_13_code4, tvb, 9, 3, ENC_ASCII|ENC_NA);
	proto_tree_add_item(tree, hf_ipmi_trn_13_code5, tvb, 12, 3, ENC_ASCII|ENC_NA);
}

/* Set PPP UDP Proxy Transmit Data
 */
static void
rq14(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_14_chan, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_14_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_trn_14_block, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_14_data, tvb, 2, 16, ENC_NA);
}

/* Get PPP UDP Proxy Transmit Data
 */
static void
rq15(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_15_chan, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_15_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_trn_15_block, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

static void
rs15(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_trn_15_data, tvb, 0, 16, ENC_NA);
}

/* Send PPP UDP Proxy Packet
 */
static void
rq16(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_16_chan, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_16_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_trn_16_src_port, tvb, 1, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_16_dst_port, tvb, 3, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_16_src_addr, tvb, 5, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_16_dst_addr, tvb, 9, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_16_bytes, tvb, 13, 2, ENC_LITTLE_ENDIAN);
}

static const value_string cc16[] = {
	{ 0x80, "PPP link is not up" },
	{ 0x81, "IP protocol is not up" },
	{ 0, NULL }
};

/* Get PPP UDP Proxy Receive Data
 */
static void
tr17_fmt_blockno(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d%s",
			v, v ? "" : " (get received data length)");
}

static void
rq17(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_17_chan, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_17_clear, &hf_ipmi_trn_17_block_num, NULL };

	if (!tree) {
		/* Save block number */
		ipmi_setsaveddata(0, tvb_get_guint8(tvb, 1) & 0x7f);
		return;
	}

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_17_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_17_byte2, byte2, TRUE, 0);
}

static void
rs17(tvbuff_t *tvb, proto_tree *tree)
{
	guint32 bno;

	if (ipmi_getsaveddata(0, &bno) && bno == 0) {
		/* Request for length */
		proto_tree_add_item(tree, hf_ipmi_trn_17_size, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_ipmi_trn_17_data, tvb, 0,
				tvb_length(tvb) < 16 ? tvb_length(tvb) : 16, ENC_NA);
	}
}

static const value_string cc17[] = {
	{ 0x80, "No packet data available" },
	{ 0, NULL }
};

/* Serial/Modem Connection Active
 */
static void
rq18(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_18_state, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_18_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_trn_18_ipmi_ver, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

/* Callback
 */
static void
rq19(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_19_chan, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_19_dest_sel, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_19_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_19_byte2, byte2, TRUE, 0);
}

static const value_string cc19[] = {
	{ 0x81, "Callback rejected, alert in progress on this channel" },
	{ 0x82, "Callback rejected, IPMI messaging active on this channel" },
	{ 0, NULL }
};

/* Common for Set/Get User Callback Options
 */
static void
parse_callback_options(tvbuff_t *tvb, guint offs, proto_tree *tree)
{
	static const gint *usercap[] = { &hf_ipmi_trn_XX_cap_cbcp, &hf_ipmi_trn_XX_cap_ipmi, NULL };
	static const gint *cbcp[] = { &hf_ipmi_trn_XX_cbcp_from_list, &hf_ipmi_trn_XX_cbcp_user,
		&hf_ipmi_trn_XX_cbcp_prespec, &hf_ipmi_trn_XX_cbcp_nocb, NULL };

	proto_tree_add_bitmask_text(tree, tvb, offs, 1,
			"User callback capabilities: ", "None",
			ett_ipmi_trn_XX_usercap, usercap, TRUE, BMT_NO_TFS);
	proto_tree_add_bitmask_text(tree, tvb, offs + 1, 1,
			"CBCP negotiation options: ", "None",
			ett_ipmi_trn_XX_cbcp, cbcp, TRUE, BMT_NO_TFS);
	proto_tree_add_item(tree, hf_ipmi_trn_XX_dst1, tvb, offs + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_XX_dst2, tvb, offs + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_trn_XX_dst3, tvb, offs + 4, 1, ENC_LITTLE_ENDIAN);
}

/* Set User Callback Options
 */
static void
rq1a(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_1a_user, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_1a_chan, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_1a_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_1a_byte2, byte2, TRUE, 0);
	parse_callback_options(tvb, 2, tree);
}

/* Get User Callback Options
 */
static void
rq1b(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_trn_1b_user, NULL };
	static const gint *byte2[] = { &hf_ipmi_trn_1b_chan, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_trn_1b_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_trn_1b_byte2, byte2, TRUE, 0);
}

static void
rs1b(tvbuff_t *tvb, proto_tree *tree)
{
	parse_callback_options(tvb, 0, tree);
}

static const value_string cc21[] = {
	{ 0x80, "Parameter not supported" },
	{ 0x81, "Attempt to set the 'set in progress' value (in parameter #0) when not in the 'set complete' state" },
	{ 0x82, "Attempt to write read-only parameter" },
	{ 0x83, "Attempt to read write-only parameter" },
	{ 0, NULL }
};

static const value_string cc22[] = {
	{ 0x80, "Parameter not supported" },
	{ 0, NULL }
};

static const value_string cc33[] = {
	{ 0x80, "Target controller unavailable" },
	{ 0, NULL }
};

static ipmi_cmd_t cmd_transport[] = {
  /* LAN Device Commands */
  { 0x01, rq01, NULL, cc01, NULL, "Set LAN Configuration Parameters", 0 },
  { 0x02, rq02, rs02, cc02, NULL, "Get LAN Configuration Parameters", CMD_CALLRQ },
  { 0x03, rq03, rs03, NULL, NULL, "Suspend BMC ARPs", 0 },
  { 0x04, rq04, rs04, NULL, NULL, "Get IP/UDP/RMCP Statistics", 0 },

  /* Serial/Modem Device Commands */
  { 0x10, rq10, NULL, cc10, NULL, "Set Serial/Modem Configuration", 0 },
  { 0x11, rq11, rs11, cc11, NULL, "Get Serial/Modem Configuration", CMD_CALLRQ },
  { 0x12, rq12, rs12, NULL, NULL, "Set Serial/Modem Mux", 0 },
  { 0x13, rq13, rs13, NULL, NULL, "Get TAP Response Codes", 0 },
  { 0x14, rq14, NULL, NULL, NULL, "Set PPP UDP Proxy Transmit Data", 0 },
  { 0x15, rq15, rs15, NULL, NULL, "Get PPP UDP Proxy Transmit Data", 0 },
  { 0x16, rq16, NULL, cc16, NULL, "Send PPP UDP Proxy Packet", 0 },
  { 0x17, rq17, rs17, cc17, NULL, "Get PPP UDP Proxy Receive Data", CMD_CALLRQ },
  { 0x18, rq18, NULL, NULL, NULL, "Serial/Modem Connection Active", 0 },
  { 0x19, rq19, NULL, cc19, NULL, "Callback", 0 },
  { 0x1a, rq1a, NULL, NULL, NULL, "Set User Callback Options", 0 },
  { 0x1b, rq1b, rs1b, NULL, NULL, "Get User Callback Options", 0 },
  { 0x1c, IPMI_TBD,   NULL, NULL, "Set Serial Routing Mux", 0 },

  /* Serial-Over-LAN Commands */
  { 0x20, IPMI_TBD,   NULL, NULL, "SOL Activating", 0 },
  { 0x21, IPMI_TBD,   cc21, NULL, "Set SOL Configuration Parameters", 0 },
  { 0x22, IPMI_TBD,   cc22, NULL, "Get SOL Configuration Parameters", CMD_CALLRQ },

  /* Command Forwarding Commands */
  { 0x30, IPMI_TBD,   NULL, NULL, "Forwarded Command", 0 },
  { 0x31, IPMI_TBD,   NULL, NULL, "Set Forwarded Commands", 0 },
  { 0x32, IPMI_TBD,   NULL, NULL, "Get Forwarded Commands", 0 },
  { 0x33, IPMI_TBD,   cc33, NULL, "Enable Forwarded Commands", 0 },
};

void
ipmi_register_transport(gint proto_ipmi)
{
	static hf_register_info hf[] = {
		{ &hf_ipmi_trn_lan00_sip,
			{ "Set In Progress",
				"ipmi.lan00.sip", FT_UINT8, BASE_HEX, lan00_sip_vals, 0x03, NULL, HFILL }},

		{ &hf_ipmi_trn_lanXX_oem,
			{ "OEM Proprietary",
				"ipmi.lanXX.oem", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_trn_lanXX_passwd,
			{ "Straight password/key",
				"ipmi.lanXX.passwd", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_trn_lanXX_md5,
			{ "MD5",
				"ipmi.lanXX.md5", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_lanXX_md2,
			{ "MD2",
				"ipmi.lanXX.md2", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_lanXX_none,
			{ "None",
				"ipmi.lanXX.none", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

		{ &hf_ipmi_trn_lan03_ip,
			{ "IP Address",
				"ipmi.lan03.ip", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan04_ipsrc,
			{ "IP Address Source",
				"ipmi.lan04.ipsrc", FT_UINT8, BASE_HEX, lan04_ipsrc_vals, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_trn_lan05_ether,
			{ "MAC Address",
				"ipmi.lan05.mac", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan06_subnet,
			{ "Subnet Mask",
				"ipmi.lan06.subnet", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan07_ttl,
			{ "Time-to-live",
				"ipmi.lan07.ttl", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_lan07_flags,
			{ "Flags",
				"ipmi.lan07.flags", FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL }},
		{ &hf_ipmi_trn_lan07_precedence,
			{ "Precedence",
				"ipmi.lan07.precedence", FT_UINT8, BASE_DEC, NULL, 0xe0, NULL, HFILL }},
		{ &hf_ipmi_trn_lan07_tos,
			{ "Type of service",
				"ipmi.lan07.tos", FT_UINT8, BASE_HEX, NULL, 0x1e, NULL, HFILL }},

		{ &hf_ipmi_trn_lan08_rmcp_port,
			{ "Primary RMCP Port Number",
				"ipmi.lan08.rmcp_port", FT_UINT16, BASE_CUSTOM, ipmi_fmt_udpport, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan09_rmcp_port,
			{ "Secondary RMCP Port Number",
				"ipmi.lan09.rmcp_port", FT_UINT16, BASE_CUSTOM, ipmi_fmt_udpport, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan10_responses,
			{ "ARP responses",
				"ipmi.lan10.responses", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_lan10_gratuitous,
			{ "Gratuitous ARPs",
				"ipmi.lan10.gratuitous", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},

		{ &hf_ipmi_trn_lan11_arp_interval,
			{ "Gratuitous ARP interval",
				"ipmi.lan10.arp_interval", FT_UINT8, BASE_CUSTOM, ipmi_fmt_500ms_0based, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan12_def_gw_ip,
			{ "Default Gateway Address",
				"ipmi.lan12.def_gw_ip", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan13_def_gw_mac,
			{ "Default Gateway MAC Address",
				"ipmi.lan13.def_gw_mac", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan14_bkp_gw_ip,
			{ "Backup Gateway Address",
				"ipmi.lan14.bkp_gw_ip", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan15_bkp_gw_mac,
			{ "Backup Gateway MAC Address",
				"ipmi.lan15.bkp_gw_mac", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan16_comm_string,
			{ "Community String",
				"ipmi.lan16.comm_string", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan17_num_dst,
			{ "Number of Destinations",
				"ipmi.lan17.num_dst", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_trn_lan18_dst_selector,
			{ "Destination Selector",
				"ipmi.lan18.dst_selector", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_lan18_ack,
			{ "Alert Acknowledged",
				"ipmi.lan18.ack", FT_BOOLEAN, 8, TFS(&lan18_ack_tfs), 0x80, NULL, HFILL }},
		{ &hf_ipmi_trn_lan18_dst_type,
			{ "Destination Type",
				"ipmi.lan18.dst_type", FT_UINT8, BASE_HEX, lan18_dst_type_vals, 0x07, NULL, HFILL }},
		{ &hf_ipmi_trn_lan18_tout,
			{ "Timeout/Retry Interval",
				"ipmi.lan18.tout", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_0based, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_lan18_retries,
			{ "Retries",
				"ipmi.lan18.retries", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }},

		{ &hf_ipmi_trn_lan19_dst_selector,
			{ "Destination Selector",
				"ipmi.lan19.dst_selector", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_lan19_addr_format,
			{ "Address Format",
				"ipmi.lan19.addr_format", FT_UINT8, BASE_HEX, lan19_af_vals, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_lan19_address,
			{ "Address (format unknown)",
				"ipmi.lan19.address", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_lan19_gw_sel,
			{ "Gateway selector",
				"ipmi.lan19.gw_sel", FT_BOOLEAN, 8, TFS(&lan19_gw_sel_tfs), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_lan19_ip,
			{ "Alerting IP Address",
				"ipmi.lan19.ip", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_lan19_mac,
			{ "Alerting MAC Address",
				"ipmi.lan19.mac", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan20_vlan_id_enable,
			{ "VLAN ID Enable",
				"ipmi.lan20.vlan_id_enable", FT_BOOLEAN, 16, TFS(&lan20_enable_tfs), 0x8000, NULL, HFILL }},
		{ &hf_ipmi_trn_lan20_vlan_id,
			{ "VLAN ID",
				"ipmi.lan20.vlan_id", FT_UINT16, BASE_HEX, NULL, 0x0fff, NULL, HFILL }},

		{ &hf_ipmi_trn_lan21_vlan_prio,
			{ "VLAN Priority",
				"ipmi.lan21.vlan_prio", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }},

		{ &hf_ipmi_trn_lan22_num_cs_entries,
			{ "Number of Cipher Suite Entries",
				"ipmi.lan22.num_cs_entries", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},

		{ &hf_ipmi_trn_lan23_cs_entry,
			{ "Cipher Suite ID",
				"ipmi.lan23.cs_entry", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan24_priv,
			{ "Maximum Privilege Level",
				"ipmi.lan24.priv", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_lan25_dst_selector,
			{ "Destination Selector",
				"ipmi.lan25.dst_selector", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_lan25_addr_format,
			{ "Address Format",
				"ipmi.lan25.addr_format", FT_UINT8, BASE_HEX, lan25_af_vals, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_lan25_address,
			{ "Address (format unknown)",
				"ipmi.lan25.address", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_lan25_uprio,
			{ "User priority",
				"ipmi.lan25.uprio", FT_UINT16, BASE_DEC, NULL, 0xe000, NULL, HFILL }},
		{ &hf_ipmi_trn_lan25_cfi,
			{ "CFI",
				"ipmi.lan25.cfi", FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL }},
		{ &hf_ipmi_trn_lan25_vlan_id,
			{ "VLAN ID",
				"ipmi.lan25.vlan_id", FT_UINT16, BASE_HEX, NULL, 0x0fff, NULL, HFILL }},

		{ &hf_ipmi_trn_serial03_connmode,
			{ "Connection Mode",
				"ipmi.serial03.connmode", FT_BOOLEAN, 8, TFS(&serial03_connmode_tfs), 0x80, NULL, HFILL }},
		{ &hf_ipmi_trn_serial03_terminal,
			{ "Terminal Mode",
				"ipmi.serial03.terminal", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_serial03_ppp,
			{ "PPP Mode",
				"ipmi.serial03.ppp", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial03_basic,
			{ "Basic Mode",
				"ipmi.serial03.basic", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial04_timeout,
			{ "Session Inactivity Timeout",
				"ipmi.serial04.timeout", FT_UINT8, BASE_CUSTOM, serial04_timeout_fmt, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial05_cbcp_callback,
			{ "CBCP Callback",
				"ipmi.serial05.cbcp", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial05_ipmi_callback,
			{ "IPMI Callback",
				"ipmi.serial05.ipmi", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial05_cb_list,
			{ "Callback to list of possible numbers",
				"ipmi.serial05.cb_list", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08, NULL, HFILL }},
		{ &hf_ipmi_trn_serial05_cb_user,
			{ "Callback to user-specifiable number",
				"ipmi.serial05.cb_user", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_serial05_cb_prespec,
			{ "Callback to pre-specified number",
				"ipmi.serial05.cb_prespec", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial05_no_cb,
			{ "No callback",
				"ipmi.serial05.no_cb", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial05_cb_dest1,
			{ "Callback destination 1",
				"ipmi.serial05.cb_dest1", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial05_cb_dest2,
			{ "Callback destination 2",
				"ipmi.serial05.cb_dest2", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial05_cb_dest3,
			{ "Callback destination 3",
				"ipmi.serial05.cb_dest3", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial06_inactivity,
			{ "Session Inactivity Timeout",
				"ipmi.serial06.inactivity", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial06_dcd,
			{ "Close on DCD Loss",
				"ipmi.serial06.dcd", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial07_flowctl,
			{ "Flow Control",
				"ipmi.serial07.flowctl", FT_UINT8, BASE_HEX, serialXX_flowctl_vals, 0xc0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial07_dtrhangup,
			{ "DTR Hang-up",
				"ipmi.serial07.dtrhangup", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }},
		{ &hf_ipmi_trn_serial07_bitrate,
			{ "Bit rate",
				"ipmi.serial07.bitrate", FT_UINT8, BASE_HEX, serialXX_bitrate_vals, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_esc_powerup,
			{ "Power-up/wakeup via ESC-^",
				"ipmi.serial08.esc_powerup", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x40, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_esc_reset,
			{ "Hard reset via ESC-R-ESC-r-ESC-R",
				"ipmi.serial08.esc_reset", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_switch_authcap,
			{ "Baseboard-to-BMC switch on Get Channel Auth Capabilities",
				"ipmi.serial08.switch_authcap", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x10, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_switch_rmcp,
			{ "Switch to BMC on IPMI-RMCP pattern",
				"ipmi.serial08.switch_rmcp", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_esc_switch1,
			{ "BMC-to-Baseboard switch via ESC-Q",
				"ipmi.serial08.esc_switch1", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_esc_switch2,
			{ "Baseboard-to-BMC switch via ESC-(",
				"ipmi.serial08.esc_switch2", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_switch_dcdloss,
			{ "Switch to BMC on DCD loss",
				"ipmi.serial08.switch_dcdloss", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_sharing,
			{ "Serial Port Sharing",
				"ipmi.serial08.sharing", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_ping_callback,
			{ "Serial/Modem Connection Active during callback",
				"ipmi.serial08.ping_callback", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_ping_direct,
			{ "Serial/Modem Connection Active during direct call",
				"ipmi.serial08.ping_direct", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial08_ping_retry,
			{ "Retry Serial/Modem Connection Active",
				"ipmi.serial08.ping_retry", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial09_ring_duration,
			{ "Ring Duration",
				"ipmi.serial09.ring_duration", FT_UINT8, BASE_CUSTOM, ipmi_fmt_500ms_1based, 0x3f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial09_ring_dead,
			{ "Ring Dead Time",
				"ipmi.serial09.ring_dead", FT_UINT8, BASE_CUSTOM, ipmi_fmt_500ms_0based, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial10_set_sel,
			{ "Set selector (16-byte block #)",
				"ipmi.serial10.set_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial10_init_str,
			{ "Modem Init String",
				"ipmi.serial10.init_str", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial11_esc_seq,
			{ "Modem Escape Sequence",
				"ipmi.serial11.esc_seq", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial12_hangup_seq,
			{ "Modem Hang-up Sequence",
				"ipmi.serial12.hangup_seq", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial13_dial_cmd,
			{ "Modem Dial Command",
				"ipmi.serial13.dial_cmd", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial14_page_blackout,
			{ "Page Blackout Interval (minutes)",
				"ipmi.serial14.page_blackout", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial15_comm_string,
			{ "Community String",
				"ipmi.serial15.comm_string", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial16_ndest,
			{ "Number of non-volatile Alert Destinations",
				"ipmi.serial16.ndest", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_dest_sel,
			{ "Destination Selector",
				"ipmi.serial17.dest_sel", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_ack,
			{ "Alert Acknowledge",
				"ipmi.serial17.ack", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_dest_type,
			{ "Destination Type",
				"ipmi.serial17.dest_type", FT_UINT8, BASE_HEX, serial17_dest_type_vals, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_ack_timeout,
			{ "Alert Acknowledge Timeout",
				"ipmi.serial17.ack_timeout", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_alert_retries,
			{ "Alert retries",
				"ipmi.serial17.alert_retries", FT_UINT8, BASE_DEC, NULL, 0x70, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_call_retries,
			{ "Call retries",
				"ipmi.serial17.call_retries", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_alert_ack_timeout,
			{ "Alert Acknowledge Timeout",
				"ipmi.serial17.alert_ack_timeout", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_0based, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_dialstr_sel,
			{ "Dial String Selector",
				"ipmi.serial17.dialstr_sel", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_tap_sel,
			{ "TAP Account Selector",
				"ipmi.serial17.tap_sel", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_ipaddr_sel,
			{ "Destination IP Address Selector",
				"ipmi.serial17.ipaddr_sel", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_ppp_sel,
			{ "PPP Account Set Selector",
				"ipmi.serial17.ppp_sel", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial17_unknown,
			{ "Destination-specific (format unknown)",
				"ipmi.serial17.unknown", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial18_call_retry,
			{ "Call Retry Interval",
				"ipmi.serial18.call_retry", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial19_destsel,
			{ "Destination selector",
				"ipmi.serial19.destsel", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial19_flowctl,
			{ "Flow Control",
				"ipmi.serial19.flowctl", FT_UINT8, BASE_HEX, serialXX_flowctl_vals, 0xc0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial19_dtrhangup,
			{ "DTR Hang-up",
				"ipmi.serial19.dtrhangup", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }},
		{ &hf_ipmi_trn_serial19_stopbits,
			{ "Stop bits",
				"ipmi.serial19.stopbits", FT_BOOLEAN, 8, TFS(&serial19_stopbits_tfs), 0x10, NULL, HFILL }},
		{ &hf_ipmi_trn_serial19_charsize,
			{ "Character size",
				"ipmi.serial19.charsize", FT_BOOLEAN, 8, TFS(&serial19_charsize_tfs), 0x08, NULL, HFILL }},
		{ &hf_ipmi_trn_serial19_parity,
			{ "Parity",
				"ipmi.serial19.parity", FT_UINT8, BASE_HEX, serial19_parity_vals, 0x07, NULL, HFILL }},
		{ &hf_ipmi_trn_serial19_bitrate,
			{ "Bit rate",
				"ipmi.serial19.bitrate", FT_UINT8, BASE_HEX, serialXX_bitrate_vals, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial20_num_dial_strings,
			{ "Number of Dial Strings",
				"ipmi.serial20.num_dial_strings", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial21_dialsel,
			{ "Dial String Selector",
				"ipmi.serial21.dialsel", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial21_blockno,
			{ "Block number",
				"ipmi.serial21.blockno", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial21_dialstr,
			{ "Dial string",
				"ipmi.serial21.dialstr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial22_num_ipaddrs,
			{ "Number of Alert Destination IP Addresses",
				"ipmi.serial22.num_ipaddrs", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial23_destsel,
			{ "Destination IP Address selector",
				"ipmi.serial23.destsel", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial23_ipaddr,
			{ "Destination IP Address",
				"ipmi.serial23.ipaddr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial24_num_tap_accounts,
			{ "Number of TAP Accounts",
				"ipmi.serial24.num_tap_accounts", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial25_tap_acct,
			{ "TAP Account Selector",
				"ipmi.serial25.tap_acct", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial25_dialstr_sel,
			{ "Dial String Selector",
				"ipmi.serial25.dialstr_sel", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial25_tapsrv_sel,
			{ "TAP Service Settings Selector",
				"ipmi.serial25.tapsrv_sel", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial26_tap_acct,
			{ "TAP Account Selector",
				"ipmi.serial26.tap_acct", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial26_tap_passwd,
			{ "TAP Password",
				"ipmi.serial26.tap_passwd", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial27_tap_acct,
			{ "TAP Account Selector",
				"ipmi.serial27.tap_acct", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial27_tap_pager_id,
			{ "TAP Pager ID String",
				"ipmi.serial27.tap_pager_id", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_tapsrv_sel,
			{ "TAP Service Settings Selector",
				"ipmi.serial28.tapsrv_sel", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_confirm,
			{ "TAP Confirmation",
				"ipmi.serial28.confirm", FT_UINT8, BASE_HEX, serial28_confirm_vals, 0x03, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_srvtype,
			{ "TAP 'SST' Service Type",
				"ipmi.serial28.srvtype", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_ctrl_esc,
			{ "TAP Control-character escaping mask",
				"ipmi.serial28.ctrl_esc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_t2,
			{ "TAP T2",
				"ipmi.serial28.tap_t2", FT_UINT8, BASE_CUSTOM, ipmi_fmt_500ms_0based, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_t1,
			{ "TAP T1",
				"ipmi.serial28.tap_t1", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_0based, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_t4,
			{ "TAP T4",
				"ipmi.serial28.tap_t4", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_0based, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_t3,
			{ "TAP T3",
				"ipmi.serial28.tap_t3", FT_UINT8, BASE_CUSTOM, ipmi_fmt_2s_0based, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_t6,
			{ "IPMI T6",
				"ipmi.serial28.ipmi_t6", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_0based, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_t5,
			{ "TAP T5",
				"ipmi.serial28.tap_t5", FT_UINT8, BASE_CUSTOM, ipmi_fmt_2s_0based, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_n2,
			{ "TAP N2",
				"ipmi.serial28.tap_n2", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_n1,
			{ "TAP N1",
				"ipmi.serial28.tap_n1", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_n4,
			{ "IPMI N4",
				"ipmi.serial28.ipmi_n4", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial28_n3,
			{ "TAP N3",
				"ipmi.serial28.tap_n3", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial29_op,
			{ "Parameter Operation",
				"ipmi.serial29.op", FT_UINT8, BASE_HEX, serial29_op_vals, 0xc0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial29_lineedit,
			{ "Line Editing",
				"ipmi.serial29.lineedit", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }},
		{ &hf_ipmi_trn_serial29_deletectl,
			{ "Delete control",
				"ipmi.serial29.deletectl", FT_UINT8, BASE_HEX, serial29_delete_vals, 0x0c, NULL, HFILL }},
		{ &hf_ipmi_trn_serial29_echo,
			{ "Echo",
				"ipmi.serial29.echo", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial29_handshake,
			{ "Handshake",
				"ipmi.serial29.handshake", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial29_o_newline,
			{ "Output newline sequence",
				"ipmi.serial29.o_newline", FT_UINT8, BASE_HEX, serial29_o_nl_vals, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial29_i_newline,
			{ "Input newline sequence",
				"ipmi.serial29.i_newline", FT_UINT8, BASE_HEX, serial29_i_nl_vals, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_snooping,
			{ "System Negotiation Snooping",
				"ipmi.serial30.snooping", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_snoopctl,
			{ "Snoop ACCM Control",
				"ipmi.serial30.snoopctl", FT_UINT8, BASE_HEX, serial30_snoopctl_vals, 0x03, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_negot_ctl,
			{ "BMC negotiates link parameters",
				"ipmi.serial30.negot_ctl", FT_UINT8, BASE_HEX, serial30_negoctl_vals, 0x30, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_use_xmit_accm,
			{ "Filtering incoming chars",
				"ipmi.serial30.filter", FT_BOOLEAN, 8, TFS(&serial30_filter_tfs), 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_xmit_addr_comp,
			{ "Transmit with Address and Ctl Field Compression",
				"ipmi.serial30.xmit_addr_comp", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_xmit_proto_comp,
			{ "Transmit with Protocol Field Compression",
				"ipmi.serial30.xmit_proto_comp", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_ipaddr,
			{ "IP Address negotiation",
				"ipmi.serial30.ipaddr", FT_UINT8, BASE_HEX, serial30_ipaddr_val, 0x18, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_accm,
			{ "ACCM Negotiation",
				"ipmi.serial30.accm", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_addr_comp,
			{ "Address and Ctl Field Compression",
				"ipmi.serial30.addr_comp", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial30_proto_comp,
			{ "Protocol Field Compression",
				"ipmi.serial30.proto_comp", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial31_port,
			{ "Primary RMCP Port Number",
				"ipmi.serial31.port", FT_UINT16, BASE_CUSTOM, ipmi_fmt_udpport, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial32_port,
			{ "Secondary RMCP Port Number",
				"ipmi.serial32.port", FT_UINT16, BASE_CUSTOM, ipmi_fmt_udpport, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial33_auth_proto,
			{ "PPP Link Authentication Protocol",
				"ipmi.serial33.auth_proto", FT_UINT8, BASE_HEX, serialXX_proto_vals, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial34_chap_name,
			{ "CHAP Name",
				"ipmi.serial34.chap_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial35_recv_accm,
			{ "Receive ACCM",
				"ipmi.serial35.recv_accm", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial35_xmit_accm,
			{ "Transmit ACCM",
				"ipmi.serial35.xmit_accm", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial36_snoop_accm,
			{ "Snoop Receive ACCM",
				"ipmi.serial36.snoop_accm", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial37_num_ppp,
			{ "Number of PPP Accounts",
				"ipmi.serial37.num_ppp", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial38_acct_sel,
			{ "PPP Account Selector",
				"ipmi.serial38.acct_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial38_dialstr_sel,
			{ "Dial String Selector",
				"ipmi.serial38.dialstr_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial39_acct_sel,
			{ "PPP Account Selector",
				"ipmi.serial39.acct_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial39_ipaddr,
			{ "IP Address",
				"ipmi.serial39.ipaddr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial40_acct_sel,
			{ "PPP Account Selector",
				"ipmi.serial40.acct_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial40_username,
			{ "User Name",
				"ipmi.serial40.username", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial41_acct_sel,
			{ "PPP Account Selector",
				"ipmi.serial41.acct_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial41_userdomain,
			{ "User Domain",
				"ipmi.serial41.userdomain", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial42_acct_sel,
			{ "PPP Account Selector",
				"ipmi.serial42.acct_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial42_userpass,
			{ "User Password",
				"ipmi.serial42.userpass", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial43_acct_sel,
			{ "PPP Account Selector",
				"ipmi.serial43.acct_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial43_auth_proto,
			{ "Link Auth Type",
				"ipmi.serial43.auth_proto", FT_UINT8, BASE_HEX, serialXX_proto_vals, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial44_acct_sel,
			{ "PPP Account Selector",
				"ipmi.serial44.acct_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial44_hold_time,
			{ "Connection Hold Time",
				"ipmi.serial44.hold_time", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial45_src_ipaddr,
			{ "Source IP Address",
				"ipmi.serial45.src_ipaddr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial45_dst_ipaddr,
			{ "Destination IP Address",
				"ipmi.serial45.dst_ipaddr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial46_tx_bufsize,
			{ "Transmit Buffer Size",
				"ipmi.serial46.tx_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial47_rx_bufsize,
			{ "Receive Buffer Size",
				"ipmi.serial47.rx_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial48_ipaddr,
			{ "Remote Console IP Address",
				"ipmi.serial48.ipaddr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial49_blockno,
			{ "Block number",
				"ipmi.serial49.blockno", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial49_dialstr,
			{ "Dial string",
				"ipmi.serial49.dialstr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial50_115200,
			{ "115200",
				"ipmi.serial50.115200", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_trn_serial50_57600,
			{ "57600",
				"ipmi.serial50.57600", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_trn_serial50_38400,
			{ "38400",
				"ipmi.serial50.38400", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_serial50_19200,
			{ "19200",
				"ipmi.serial50.19200", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_serial50_9600,
			{ "9600",
				"ipmi.serial50.9600", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_serial51_port_assoc_sel,
			{ "Serial Port Association Entry",
				"ipmi.serial51.port_assoc_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial51_ipmi_channel,
			{ "IPMI Channel",
				"ipmi.serial51.ipmi_channel", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial51_conn_num,
			{ "Connector number",
				"ipmi.serial51.conn_num", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial51_ipmi_sharing,
			{ "Used with IPMI Serial Port Sharing",
				"ipmi.serial51.ipmi_sharing", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_trn_serial51_ipmi_sol,
			{ "Used with IPMI Serial-over-LAN",
				"ipmi.serial51.ipmi_sol", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_trn_serial51_chan_num,
			{ "Serial controller channel number",
				"ipmi.serial51.chan_num", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_serial52_port_assoc_sel,
			{ "Serial Port Association Entry",
				"ipmi.serial52.port_assoc_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial52_conn_name,
			{ "Connector Name",
				"ipmi.serial52_conn_name", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial53_port_assoc_sel,
			{ "Serial Port Association Entry",
				"ipmi.serial53.port_assoc_sel", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_serial53_chan_name,
			{ "Channel Name",
				"ipmi.serial52_chan_name", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_01_chan,
			{ "Channel",
				"ipmi.tr01.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_01_param,
			{ "Parameter Selector",
				"ipmi.tr01.param", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_01_param_data,
			{ "Parameter data",
				"ipmi.tr01.param_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_02_getrev,
			{ "Get parameter revision only",
				"ipmi.tr02.getrev", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_trn_02_chan,
			{ "Channel",
				"ipmi.tr02.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_02_param,
			{ "Parameter selector",
				"ipmi.tr02.param", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_02_set,
			{ "Set selector",
				"ipmi.tr02.set", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_02_block,
			{ "Block selector",
				"ipmi.tr02.block", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_02_rev_present,
			{ "Present parameter revision",
				"ipmi.tr02.rev.present", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_02_rev_compat,
			{ "Oldest forward-compatible",
				"ipmi.tr02.rev.compat", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_02_param_data,
			{ "Parameter data",
				"ipmi.tr02.param_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_03_chan,
			{ "Channel",
				"ipmi.tr03.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_03_arp_resp,
			{ "BMC-generated ARP responses",
				"ipmi.tr03.arp_resp", FT_BOOLEAN, 8, TFS(&tfs_03_suspend), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_03_gratuitous_arp,
			{ "Gratuitous ARPs",
				"ipmi.tr03.gratuitous_arp", FT_BOOLEAN, 8, TFS(&tfs_03_suspend), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_03_status_arp_resp,
			{ "ARP Response status",
				"ipmi.tr03.status_arp_resp", FT_BOOLEAN, 8, TFS(&tfs_03_arp_status), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_03_status_gratuitous_arp,
			{ "Gratuitous ARP status",
				"ipmi.tr03.status_gratuitous_arp", FT_BOOLEAN, 8, TFS(&tfs_03_arp_status), 0x01, NULL, HFILL }},

		{ &hf_ipmi_trn_04_chan,
			{ "Channel",
				"ipmi.tr04.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_04_clear,
			{ "Statistics",
				"ipmi.tr04.clear", FT_BOOLEAN, 8, TFS(&tfs_04_clear), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_04_rx_ippkts,
			{ "Received IP Packets",
				"ipmi.tr04.rx_ippkts", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_04_rx_iphdr_err,
			{ "Received IP Header Errors",
				"ipmi.tr04.rx_iphdr_err", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_04_rx_ipaddr_err,
			{ "Received IP Address Errors",
				"ipmi.tr04.rx_ipaddr_err", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_04_rx_ippkts_frag,
			{ "Received Fragmented IP Packets",
				"ipmi.tr04.rx_ippkts_frag", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_04_tx_ippkts,
			{ "Transmitted IP Packets",
				"ipmi.tr04.tx_ippkts", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_04_rx_udppkts,
			{ "Received UDP Packets",
				"ipmi.tr04.rx_udppkts", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_04_rx_validrmcp,
			{ "Received Valid RMCP Packets",
				"ipmi.tr04.rx_validrmcp", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_04_rx_udpproxy,
			{ "Received UDP Proxy Packets",
				"ipmi.tr04.rx_udpproxy", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_04_dr_udpproxy,
			{ "Dropped UDP Proxy Packets",
				"ipmi.tr04.dr_udpproxy", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_10_chan,
			{ "Channel",
				"ipmi.tr10.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_10_param,
			{ "Parameter Selector",
				"ipmi.tr10.param", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_10_param_data,
			{ "Parameter data",
				"ipmi.tr10.param_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_11_getrev,
			{ "Get parameter revision only",
				"ipmi.tr11.getrev", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_trn_11_chan,
			{ "Channel",
				"ipmi.tr11.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_11_param,
			{ "Parameter selector",
				"ipmi.tr11.param", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_11_set,
			{ "Set selector",
				"ipmi.tr11.set", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_11_block,
			{ "Block selector",
				"ipmi.tr11.block", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_11_rev_present,
			{ "Present parameter revision",
				"ipmi.tr11.rev.present", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_trn_11_rev_compat,
			{ "Oldest forward-compatible",
				"ipmi.tr11.rev.compat", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_11_param_data,
			{ "Parameter data",
				"ipmi.tr11.param_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_12_chan,
			{ "Channel",
				"ipmi.tr12.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_12_mux_setting,
			{ "Mux Setting",
				"ipmi.tr12.mux_setting", FT_UINT8, BASE_HEX, vals_12_mux, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_12_sw_to_sys,
			{ "Requests to switch to system",
				"ipmi.tr12.sw_to_sys", FT_BOOLEAN, 8, TFS(&tfs_12_blocked), 0x80, NULL, HFILL }},
		{ &hf_ipmi_trn_12_sw_to_bmc,
			{ "Requests to switch to BMC",
				"ipmi.tr12.sw_to_bmc", FT_BOOLEAN, 8, TFS(&tfs_12_blocked), 0x40, NULL, HFILL }},
		{ &hf_ipmi_trn_12_alert,
			{ "Alert in progress",
				"ipmi.tr12.alert", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_trn_12_msg,
			{ "IPMI/OEM messaging active",
				"ipmi.tr12.msg", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_12_req,
			{ "Request",
				"ipmi.tr12.req", FT_BOOLEAN, 8, TFS(&tfs_12_req), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_12_mux_state,
			{ "Mux set to",
				"ipmi.tr12.mux_state", FT_BOOLEAN, 8, TFS(&tfs_12_mux_state), 0x01, NULL, HFILL }},

		{ &hf_ipmi_trn_13_chan,
			{ "Channel",
				"ipmi.tr13.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_13_code1,
			{ "Last code",
				"ipmi.tr13.code1", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_13_code2,
			{ "2nd code",
				"ipmi.tr13.code2", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_13_code3,
			{ "3rd code",
				"ipmi.tr13.code3", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_13_code4,
			{ "4th code",
				"ipmi.tr13.code4", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_13_code5,
			{ "5th code",
				"ipmi.tr13.code5", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_14_chan,
			{ "Channel",
				"ipmi.tr14.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_14_block,
			{ "Block number",
				"ipmi.tr14.block", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_14_data,
			{ "Block data",
				"ipmi.tr14.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_15_chan,
			{ "Channel",
				"ipmi.tr15.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_15_block,
			{ "Block number",
				"ipmi.tr15.block", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_15_data,
			{ "Block data",
				"ipmi.tr15.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_16_chan,
			{ "Channel",
				"ipmi.tr16.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_16_src_port,
			{ "Source Port",
				"ipmi.tr16.src_port", FT_UINT16, BASE_CUSTOM, ipmi_fmt_udpport, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_16_dst_port,
			{ "Destination Port",
				"ipmi.tr16.dst_port", FT_UINT16, BASE_CUSTOM, ipmi_fmt_udpport, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_16_src_addr,
			{ "Source IP Address",
				"ipmi.tr16.src_addr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_16_dst_addr,
			{ "Destination IP Address",
				"ipmi.tr16.dst_addr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_16_bytes,
			{ "Bytes to send",
				"ipmi.tr16.bytes", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_17_chan,
			{ "Channel",
				"ipmi.tr17.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_17_clear,
			{ "Clear buffer",
				"ipmi.tr17.clear", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_trn_17_block_num,
			{ "Block number",
				"ipmi.tr17.block_num", FT_UINT8, BASE_CUSTOM, tr17_fmt_blockno, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_trn_17_size,
			{ "Number of received bytes",
				"ipmi.tr17.size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_17_data,
			{ "Block Data",
				"ipmi.tr17.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_18_state,
			{ "Session state",
				"ipmi.tr18.state", FT_UINT8, BASE_HEX, vals_18_state, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_18_ipmi_ver,
			{ "IPMI Version",
				"ipmi.tr18.ipmi_ver", FT_UINT8, BASE_CUSTOM, ipmi_fmt_version, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_19_chan,
			{ "Channel",
				"ipmi.tr19.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_trn_19_dest_sel,
			{ "Destination selector",
				"ipmi.tr19.dest_sel", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_trn_XX_cap_cbcp,
			{ "CBCP callback",
				"ipmi.trXX.cap_cbcp", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_XX_cap_ipmi,
			{ "IPMI callback",
				"ipmi.trXX.cap_ipmi", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_XX_cbcp_from_list,
			{ "Callback to one from list of numbers",
				"ipmi.trXX.cbcp_from_list", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x08, NULL, HFILL }},
		{ &hf_ipmi_trn_XX_cbcp_user,
			{ "Callback to user-specified number",
				"ipmi.trXX.cbcp_user", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }},
		{ &hf_ipmi_trn_XX_cbcp_prespec,
			{ "Callback to pre-specified number",
				"ipmi.trXX.cbcp_prespec", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_trn_XX_cbcp_nocb,
			{ "No callback",
				"ipmi.trXX.cbcp_nocb", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x01, NULL, HFILL }},
		{ &hf_ipmi_trn_XX_dst1,
			{ "Callback destination 1",
				"ipmi.trXX.dst1", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_XX_dst2,
			{ "Callback destination 2",
				"ipmi.trXX.dst2", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_trn_XX_dst3,
			{ "Callback destination 3",
				"ipmi.trXX.dst3", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_trn_1a_user,
			{ "User ID",
				"ipmi.tr1a.user", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
		{ &hf_ipmi_trn_1a_chan,
			{ "Channel",
				"ipmi.tr1a.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_trn_1b_user,
			{ "User ID",
				"ipmi.tr1b.user", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
		{ &hf_ipmi_trn_1b_chan,
			{ "Channel",
				"ipmi.tr1b.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},

	};
	static gint *ett[] = {
		&ett_ipmi_trn_lan00_byte1,
		&ett_ipmi_trn_lan01_byte1,
		&ett_ipmi_trn_lan02_byte1,
		&ett_ipmi_trn_lan02_byte2,
		&ett_ipmi_trn_lan02_byte3,
		&ett_ipmi_trn_lan02_byte4,
		&ett_ipmi_trn_lan02_byte5,
		&ett_ipmi_trn_lan04_byte1,
		&ett_ipmi_trn_lan07_byte2,
		&ett_ipmi_trn_lan07_byte3,
		&ett_ipmi_trn_lan10_byte1,
		&ett_ipmi_trn_lan17_byte1,
		&ett_ipmi_trn_lan18_byte1,
		&ett_ipmi_trn_lan18_byte2,
		&ett_ipmi_trn_lan18_byte4,
		&ett_ipmi_trn_lan19_byte1,
		&ett_ipmi_trn_lan19_byte2,
		&ett_ipmi_trn_lan19_byte3,
		&ett_ipmi_trn_lan20_byte12,
		&ett_ipmi_trn_lan21_byte1,
		&ett_ipmi_trn_lan22_byte1,
		&ett_ipmi_trn_lan24_byte1,
		&ett_ipmi_trn_lan24_byte2,
		&ett_ipmi_trn_lan24_byte3,
		&ett_ipmi_trn_lan24_byte4,
		&ett_ipmi_trn_lan24_byte5,
		&ett_ipmi_trn_lan24_byte6,
		&ett_ipmi_trn_lan24_byte7,
		&ett_ipmi_trn_lan24_byte8,
		&ett_ipmi_trn_lan25_byte1,
		&ett_ipmi_trn_lan25_byte2,
		&ett_ipmi_trn_lan25_byte34,
		&ett_ipmi_trn_serial03_byte1,
		&ett_ipmi_trn_serial04_byte1,
		&ett_ipmi_trn_serial05_byte1,
		&ett_ipmi_trn_serial05_byte2,
		&ett_ipmi_trn_serial06_byte1,
		&ett_ipmi_trn_serial07_byte1,
		&ett_ipmi_trn_serial07_byte2,
		&ett_ipmi_trn_serial08_byte1,
		&ett_ipmi_trn_serial08_byte2,
		&ett_ipmi_trn_serial09_byte1,
		&ett_ipmi_trn_serial09_byte2,
		&ett_ipmi_trn_serial16_byte1,
		&ett_ipmi_trn_serial17_byte1,
		&ett_ipmi_trn_serial17_byte2,
		&ett_ipmi_trn_serial17_byte4,
		&ett_ipmi_trn_serial17_byte5,
		&ett_ipmi_trn_serial19_byte1,
		&ett_ipmi_trn_serial19_byte2,
		&ett_ipmi_trn_serial19_byte3,
		&ett_ipmi_trn_serial20_byte1,
		&ett_ipmi_trn_serial21_byte1,
		&ett_ipmi_trn_serial22_byte1,
		&ett_ipmi_trn_serial23_byte1,
		&ett_ipmi_trn_serial24_byte1,
		&ett_ipmi_trn_serial25_byte2,
		&ett_ipmi_trn_serial28_byte1,
		&ett_ipmi_trn_serial28_byte2,
		&ett_ipmi_trn_serial28_byte10,
		&ett_ipmi_trn_serial28_byte11,
		&ett_ipmi_trn_serial28_byte12,
		&ett_ipmi_trn_serial28_byte13,
		&ett_ipmi_trn_serial28_byte14,
		&ett_ipmi_trn_serial29_byte1,
		&ett_ipmi_trn_serial29_byte2,
		&ett_ipmi_trn_serial30_byte1,
		&ett_ipmi_trn_serial30_byte2,
		&ett_ipmi_trn_serial30_byte3,
		&ett_ipmi_trn_serial33_byte1,
		&ett_ipmi_trn_serial37_byte1,
		&ett_ipmi_trn_serial43_byte1,
		&ett_ipmi_trn_serial50_byte1,
		&ett_ipmi_trn_serial51_byte2,
		&ett_ipmi_trn_serial51_byte3,
		&ett_ipmi_trn_01_byte1,
		&ett_ipmi_trn_02_byte1,
		&ett_ipmi_trn_02_rev,
		&ett_ipmi_trn_03_rq_byte1,
		&ett_ipmi_trn_03_rq_byte2,
		&ett_ipmi_trn_03_rs_byte1,
		&ett_ipmi_trn_04_byte1,
		&ett_ipmi_trn_04_byte2,
		&ett_ipmi_trn_10_byte1,
		&ett_ipmi_trn_11_byte1,
		&ett_ipmi_trn_11_rev,
		&ett_ipmi_trn_12_rq_byte1,
		&ett_ipmi_trn_12_rq_byte2,
		&ett_ipmi_trn_12_rs_byte1,
		&ett_ipmi_trn_13_byte1,
		&ett_ipmi_trn_14_byte1,
		&ett_ipmi_trn_15_byte1,
		&ett_ipmi_trn_16_byte1,
		&ett_ipmi_trn_17_byte1,
		&ett_ipmi_trn_17_byte2,
		&ett_ipmi_trn_18_byte1,
		&ett_ipmi_trn_19_byte1,
		&ett_ipmi_trn_19_byte2,
		&ett_ipmi_trn_XX_usercap,
		&ett_ipmi_trn_XX_cbcp,
		&ett_ipmi_trn_1a_byte1,
		&ett_ipmi_trn_1a_byte2,
		&ett_ipmi_trn_1b_byte1,
		&ett_ipmi_trn_1b_byte2,
	};

	proto_register_field_array(proto_ipmi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	ipmi_register_netfn_cmdtab(IPMI_TRANSPORT_REQ, IPMI_OEM_NONE, NULL, 0, NULL,
			cmd_transport, array_length(cmd_transport));
}
