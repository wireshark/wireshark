/* packet-ethercat-datagram.c
 * Routines for ethercat packet disassembly
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
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

/* Include files */

#include "config.h"

#include <epan/packet.h>

#include "packet-ethercat-datagram.h"
#include "packet-ecatmb.h"

void proto_register_ecat(void);
void proto_reg_handoff_ecat(void);

static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t ecat_mailbox_handle;

/* Define the EtherCAT proto */
static int proto_ecat_datagram = -1;

/* Define the tree for EtherCAT */
static int ett_ecat = -1;
static int ett_ecat_header = -1;
static int ett_ecat_dc = -1;
static int ett_ecat_length = -1;
static int ett_ecat_padding = -1;
static int ett_ecat_datagram_subtree = -1;
static int ett_ecat_reg_esc_features = -1;
static int ett_ecat_reg_dlctrl1 = -1;
static int ett_ecat_reg_dlctrl2 = -1;
static int ett_ecat_reg_dlctrl3 = -1;
static int ett_ecat_reg_dlctrl4 = -1;
static int ett_ecat_reg_dlstatus1 = -1;
static int ett_ecat_reg_dlstatus2 = -1;
static int ett_ecat_reg_alctrl = -1;
static int ett_ecat_reg_alstatus = -1;
static int ett_ecat_reg_pdictrl1 = -1;
static int ett_ecat_reg_pdictrl2 = -1;
static int ett_ecat_reg_ecat_mask = -1;
static int ett_ecat_reg_pdiL = -1;
static int ett_ecat_reg_ecat = -1;
static int ett_ecat_reg_pdi1 = -1;
static int ett_ecat_reg_crc0 = -1;
static int ett_ecat_reg_crc1 = -1;
static int ett_ecat_reg_crc2 = -1;
static int ett_ecat_reg_crc3 = -1;
static int ett_ecat_reg_wd_status = -1;
static int ett_ecat_reg_eeprom_assign = -1;
static int ett_ecat_reg_ctrlstat = -1;
static int ett_ecat_reg_mio_ctrlstat = -1;
static int ett_ecat_mio_addr = -1;
static int ett_ecat_mio_access = -1;
static int ett_ecat_mio_status0 = -1;
static int ett_ecat_mio_status1 = -1;
static int ett_ecat_mio_status2 = -1;
static int ett_ecat_mio_status3 = -1;
static int ett_ecat_reg_fmmu = -1;
static int ett_ecat_reg_syncman = -1;
static int ett_ecat_reg_syncman_ctrlstatus = -1;
static int ett_ecat_reg_syncman_sm_enable = -1;
static int ett_ecat_reg_dc_cycunitctrl = -1;
static int ett_ecat_dc_activation = -1;
static int ett_ecat_dc_activationstat = -1;
static int ett_ecat_dc_sync0_status = -1;
static int ett_ecat_dc_sync1_status = -1;
static int ett_ecat_dc_latch0_ctrl = -1;
static int ett_ecat_dc_latch1_ctrl = -1;
static int ett_ecat_dc_latch0_status = -1;
static int ett_ecat_dc_latch1_status = -1;

static int hf_ecat_sub;
static int hf_ecat_sub_data[10] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_cmd[10]  = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_idx[10]  = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_cnt[10]  = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_ado[10]  = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_adp[10]  = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_lad[10]  = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

/* static int hf_ecat_header = -1; */
static int hf_ecat_data = -1;
static int hf_ecat_cnt = -1;
static int hf_ecat_cmd = -1;
static int hf_ecat_idx = -1;
static int hf_ecat_adp = -1;
static int hf_ecat_ado = -1;
static int hf_ecat_lad = -1;
/* static int hf_ecat_len = -1; */
static int hf_ecat_int = -1;

static int hf_ecat_sub_dc_diff_da[10] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_dc_diff_bd[10] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_dc_diff_cb[10] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_dc_diff_cd[10] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_dc_diff_ba[10] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int hf_ecat_sub_dc_diff_ca[10] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

static int hf_ecat_dc_diff_da = -1;
static int hf_ecat_dc_diff_bd = -1;
static int hf_ecat_dc_diff_cb = -1;
static int hf_ecat_dc_diff_cd = -1;
static int hf_ecat_dc_diff_ba = -1;
static int hf_ecat_dc_diff_ca = -1;

static int hf_ecat_length_len = -1;
static int hf_ecat_length_r = -1;
static int hf_ecat_length_c = -1;
static int hf_ecat_length_m = -1;

static int hf_ecat_padding = -1;

static int hf_ecat_reg_revision = -1;
static int hf_ecat_reg_esc_type = -1;
static int hf_ecat_reg_esc_build = -1;
static int hf_ecat_reg_esc_fmmucnt = -1;
static int hf_ecat_reg_esc_smcnt = -1;
static int hf_ecat_reg_esc_ports = -1;
static int hf_ecat_reg_esc_dpram = -1;
static int hf_ecat_reg_esc_features = -1;
static int hf_ecat_reg_esc_features_fmmurestrict = -1;
static int hf_ecat_reg_esc_features_smaddrrestrict = -1;
static int hf_ecat_reg_esc_features_dcsupport = -1;
static int hf_ecat_reg_esc_features_dc64support = -1;
static int hf_ecat_reg_esc_features_ebuslowjitter = -1;
static int hf_ecat_reg_esc_features_ebusextlinkdetect = -1;
static int hf_ecat_reg_esc_features_miiextlinkdetect = -1;
static int hf_ecat_reg_esc_features_crcext = -1;
static int hf_ecat_reg_physaddr = -1;
static int hf_ecat_reg_physaddr2 = -1;
static int hf_ecat_reg_dlctrl1 = -1;
static int hf_ecat_reg_dlctrl1_killnonecat = -1;
static int hf_ecat_reg_dlctrl1_port0extlinkdetect = -1;
static int hf_ecat_reg_dlctrl1_port1extlinkdetect = -1;
static int hf_ecat_reg_dlctrl1_port2extlinkdetect = -1;
static int hf_ecat_reg_dlctrl1_port3extlinkdetect = -1;
static int hf_ecat_reg_dlctrl2 = -1;
static int hf_ecat_reg_dlctrl2_port0 = -1;
static int hf_ecat_reg_dlctrl2_port1 = -1;
static int hf_ecat_reg_dlctrl2_port2 = -1;
static int hf_ecat_reg_dlctrl2_port3 = -1;
static int hf_ecat_reg_dlctrl3 = -1;
static int hf_ecat_reg_dlctrl3_fifosize = -1;
static int hf_ecat_reg_dlctrl3_lowebusjit = -1;
static int hf_ecat_reg_dlctrl4 = -1;
static int hf_ecat_reg_dlctrl4_2ndaddress = -1;
static int hf_ecat_reg_dlstatus1 = -1;
static int hf_ecat_reg_dlstatus1_operation = -1;
static int hf_ecat_reg_dlstatus1_pdiwatchdog = -1;
static int hf_ecat_reg_dlstatus1_enhlinkdetect = -1;
static int hf_ecat_reg_dlstatus1_physlink_port0 = -1;
static int hf_ecat_reg_dlstatus1_physlink_port1 = -1;
static int hf_ecat_reg_dlstatus1_physlink_port2 = -1;
static int hf_ecat_reg_dlstatus1_physlink_port3 = -1;
static int hf_ecat_reg_dlstatus2 = -1;
static int hf_ecat_reg_dlstatus2_port0 = -1;
static int hf_ecat_reg_dlstatus2_port1 = -1;
static int hf_ecat_reg_dlstatus2_port2 = -1;
static int hf_ecat_reg_dlstatus2_port3 = -1;
static int hf_ecat_reg_regprotect = -1;
static int hf_ecat_reg_accessprotect = -1;
static int hf_ecat_reg_resetecat = -1;
static int hf_ecat_reg_resetpdi = -1;
static int hf_ecat_reg_regphysrwoffs = -1;
static int hf_ecat_reg_alctrl = -1;
static int hf_ecat_reg_alctrl_ctrl = -1;
static int hf_ecat_reg_alctrl_errack = -1;
static int hf_ecat_reg_alctrl_id = -1;
static int hf_ecat_reg_alstatus = -1;
static int hf_ecat_reg_alstatus_status = -1;
static int hf_ecat_reg_alstatus_err = -1;
static int hf_ecat_reg_alstatus_id = -1;
static int hf_ecat_reg_pdictrl1 = -1;
static int hf_ecat_reg_pdictrl1_pdi = -1;
static int hf_ecat_reg_pdictrl2 = -1;
static int hf_ecat_reg_pdictrl2_devemul = -1;
static int hf_ecat_reg_pdictrl2_enhlnkdetect = -1;
static int hf_ecat_reg_pdictrl2_dcsyncout = -1;
static int hf_ecat_reg_pdictrl2_dcsyncin = -1;
static int hf_ecat_reg_pdictrl2_enhlnkdetect0 = -1;
static int hf_ecat_reg_pdictrl2_enhlnkdetect1 = -1;
static int hf_ecat_reg_pdictrl2_enhlnkdetect2 = -1;
static int hf_ecat_reg_pdictrl2_enhlnkdetect3 = -1;
static int hf_ecat_reg_alstatuscode = -1;
static int hf_ecat_reg_ecat_mask = -1;
static int hf_ecat_reg_ecat_mask_latchevt = -1;
static int hf_ecat_reg_ecat_mask_escstatevt = -1;
static int hf_ecat_reg_ecat_mask_alstatevt = -1;
static int hf_ecat_reg_ecat_mask_sm0irq = -1;
static int hf_ecat_reg_ecat_mask_sm1irq = -1;
static int hf_ecat_reg_ecat_mask_sm2irq = -1;
static int hf_ecat_reg_ecat_mask_sm3irq = -1;
static int hf_ecat_reg_ecat_mask_sm4irq = -1;
static int hf_ecat_reg_ecat_mask_sm5irq = -1;
static int hf_ecat_reg_ecat_mask_sm6irq = -1;
static int hf_ecat_reg_ecat_mask_sm7irq = -1;
static int hf_ecat_reg_pdiL = -1;
static int hf_ecat_reg_pdiL_alctrl = -1;
static int hf_ecat_reg_pdiL_latchin = -1;
static int hf_ecat_reg_pdiL_sync0 = -1;
static int hf_ecat_reg_pdiL_sync1 = -1;
static int hf_ecat_reg_pdiL_smchg = -1;
static int hf_ecat_reg_pdiL_eepromcmdpen = -1;
static int hf_ecat_reg_pdiL_sm0 = -1;
static int hf_ecat_reg_pdiL_sm1 = -1;
static int hf_ecat_reg_pdiL_sm2 = -1;
static int hf_ecat_reg_pdiL_sm3 = -1;
static int hf_ecat_reg_pdiL_sm4 = -1;
static int hf_ecat_reg_pdiL_sm5 = -1;
static int hf_ecat_reg_pdiL_sm6 = -1;
static int hf_ecat_reg_pdiL_sm7 = -1;
static int hf_ecat_reg_pdiH = -1;
static int hf_ecat_reg_ecat = -1;
static int hf_ecat_reg_ecat_latchevt = -1;
static int hf_ecat_reg_ecat_escstatevt = -1;
static int hf_ecat_reg_ecat_alstatevt = -1;
static int hf_ecat_reg_ecat_sm0irq = -1;
static int hf_ecat_reg_ecat_sm1irq = -1;
static int hf_ecat_reg_ecat_sm2irq = -1;
static int hf_ecat_reg_ecat_sm3irq = -1;
static int hf_ecat_reg_ecat_sm4irq = -1;
static int hf_ecat_reg_ecat_sm5irq = -1;
static int hf_ecat_reg_ecat_sm6irq = -1;
static int hf_ecat_reg_ecat_sm7irq = -1;
static int hf_ecat_reg_pdi1 = -1;
static int hf_ecat_reg_pdi1_alctrl = -1;
static int hf_ecat_reg_pdi1_latchin = -1;
static int hf_ecat_reg_pdi1_sync0 = -1;
static int hf_ecat_reg_pdi1_sync1 = -1;
static int hf_ecat_reg_pdi1_smchg = -1;
static int hf_ecat_reg_pdi1_eepromcmdpen = -1;
static int hf_ecat_reg_pdi1_sm0 = -1;
static int hf_ecat_reg_pdi1_sm1 = -1;
static int hf_ecat_reg_pdi1_sm2 = -1;
static int hf_ecat_reg_pdi1_sm3 = -1;
static int hf_ecat_reg_pdi1_sm4 = -1;
static int hf_ecat_reg_pdi1_sm5 = -1;
static int hf_ecat_reg_pdi1_sm6 = -1;
static int hf_ecat_reg_pdi1_sm7 = -1;
static int hf_ecat_reg_pdi2 = -1;
static int hf_ecat_reg_crc0 = -1;
static int hf_ecat_reg_crc0_frame = -1;
static int hf_ecat_reg_crc0_rx = -1;
static int hf_ecat_reg_crc1 = -1;
static int hf_ecat_reg_crc1_frame = -1;
static int hf_ecat_reg_crc1_rx = -1;
static int hf_ecat_reg_crc2 = -1;
static int hf_ecat_reg_crc2_frame = -1;
static int hf_ecat_reg_crc2_rx = -1;
static int hf_ecat_reg_crc3 = -1;
static int hf_ecat_reg_crc3_frame = -1;
static int hf_ecat_reg_crc3_rx = -1;
static int hf_ecat_reg_crc_fwd0 = -1;
static int hf_ecat_reg_crc_fwd1 = -1;
static int hf_ecat_reg_crc_fwd2 = -1;
static int hf_ecat_reg_crc_fwd3 = -1;
static int hf_ecat_reg_processuniterr = -1;
static int hf_ecat_reg_pdierr = -1;
static int hf_ecat_reg_linklost0 = -1;
static int hf_ecat_reg_linklost1 = -1;
static int hf_ecat_reg_linklost2 = -1;
static int hf_ecat_reg_linklost3 = -1;
static int hf_ecat_reg_wd_divisor = -1;
static int hf_ecat_reg_wd_timepdi = -1;
static int hf_ecat_reg_wd_timesm = -1;
static int hf_ecat_reg_wd_status = -1;
static int hf_ecat_reg_wd_status_pdwatchdog = -1;
static int hf_ecat_reg_wd_cntsm = -1;
static int hf_ecat_reg_wd_cntpdi = -1;
static int hf_ecat_reg_eeprom_assign = -1;
static int hf_ecat_reg_eeprom_assign_ctrl = -1;
static int hf_ecat_reg_eeprom_assign_pdiaccess = -1;
static int hf_ecat_reg_eeprom_assign_status = -1;
static int hf_ecat_reg_ctrlstat = -1;
static int hf_ecat_reg_ctrlstat_wraccess = -1;
static int hf_ecat_reg_ctrlstat_eepromemul = -1;
static int hf_ecat_reg_ctrlstat_8bacc = -1;
static int hf_ecat_reg_ctrlstat_2bacc = -1;
static int hf_ecat_reg_ctrlstat_rdacc = -1;
static int hf_ecat_reg_ctrlstat_wracc = -1;
static int hf_ecat_reg_ctrlstat_reloadacc = -1;
static int hf_ecat_reg_ctrlstat_crcerr = -1;
static int hf_ecat_reg_ctrlstat_lderr = -1;
static int hf_ecat_reg_ctrlstat_cmderr = -1;
static int hf_ecat_reg_ctrlstat_wrerr = -1;
static int hf_ecat_reg_ctrlstat_busy = -1;
static int hf_ecat_reg_addrl = -1;
static int hf_ecat_reg_addrh = -1;
static int hf_ecat_reg_data0 = -1;
static int hf_ecat_reg_data1 = -1;
static int hf_ecat_reg_data2 = -1;
static int hf_ecat_reg_data3 = -1;
static int hf_ecat_reg_mio_ctrlstat = -1;
static int hf_ecat_reg_mio_ctrlstat_wracc1 = -1;
static int hf_ecat_reg_mio_ctrlstat_offsphy = -1;
static int hf_ecat_reg_mio_ctrlstat_rdacc = -1;
static int hf_ecat_reg_mio_ctrlstat_wracc2 = -1;
static int hf_ecat_reg_mio_ctrlstat_wrerr = -1;
static int hf_ecat_reg_mio_ctrlstat_busy = -1;
static int hf_ecat_reg_mio_addr = -1;
static int hf_ecat_reg_mio_addr_phyaddr = -1;
static int hf_ecat_reg_mio_addr_mioaddr = -1;
static int hf_ecat_reg_mio_data = -1;
static int hf_ecat_reg_mio_access = -1;
static int hf_ecat_reg_mio_access_ecatacc = -1;
static int hf_ecat_reg_mio_access_pdiacc = -1;
static int hf_ecat_reg_mio_access_forcereset = -1;
static int hf_ecat_reg_mio_status0 = -1;
static int hf_ecat_reg_mio_status0_physlink = -1;
static int hf_ecat_reg_mio_status0_link = -1;
static int hf_ecat_reg_mio_status0_linkstatuserr = -1;
static int hf_ecat_reg_mio_status0_readerr = -1;
static int hf_ecat_reg_mio_status0_linkpartnererr = -1;
static int hf_ecat_reg_mio_status0_phycfgupdated = -1;
static int hf_ecat_reg_mio_status1 = -1;
static int hf_ecat_reg_mio_status1_physlink = -1;
static int hf_ecat_reg_mio_status1_link = -1;
static int hf_ecat_reg_mio_status1_linkstatuserr = -1;
static int hf_ecat_reg_mio_status1_readerr = -1;
static int hf_ecat_reg_mio_status1_linkpartnererr = -1;
static int hf_ecat_reg_mio_status1_phycfgupdated = -1;
static int hf_ecat_reg_mio_status2 = -1;
static int hf_ecat_reg_mio_status2_physlink = -1;
static int hf_ecat_reg_mio_status2_link = -1;
static int hf_ecat_reg_mio_status2_linkstatuserr = -1;
static int hf_ecat_reg_mio_status2_readerr = -1;
static int hf_ecat_reg_mio_status2_linkpartnererr = -1;
static int hf_ecat_reg_mio_status2_phycfgupdated = -1;
static int hf_ecat_reg_mio_status3 = -1;
static int hf_ecat_reg_mio_status3_physlink = -1;
static int hf_ecat_reg_mio_status3_link = -1;
static int hf_ecat_reg_mio_status3_linkstatuserr = -1;
static int hf_ecat_reg_mio_status3_readerr = -1;
static int hf_ecat_reg_mio_status3_linkpartnererr = -1;
static int hf_ecat_reg_mio_status3_phycfgupdated = -1;
static int hf_ecat_reg_fmmu = -1;
static int hf_ecat_reg_fmmu_lstart = -1;
static int hf_ecat_reg_fmmu_llen = -1;
static int hf_ecat_reg_fmmu_lstartbit = -1;
static int hf_ecat_reg_fmmu_lendbit = -1;
static int hf_ecat_reg_fmmu_pstart = -1;
static int hf_ecat_reg_fmmu_pstartbit = -1;
static int hf_ecat_reg_fmmu_type = -1;
static int hf_ecat_reg_fmmu_typeread = -1;
static int hf_ecat_reg_fmmu_typewrite = -1;
static int hf_ecat_reg_fmmu_activate = -1;
static int hf_ecat_reg_fmmu_activate0 = -1;
static int hf_ecat_reg_syncman_ctrlstatus = -1;
static int hf_ecat_reg_syncman_pmode = -1;
static int hf_ecat_reg_syncman_access = -1;
static int hf_ecat_reg_syncman_irq_ecat = -1;
static int hf_ecat_reg_syncman_irq_pdi = -1;
static int hf_ecat_reg_syncman_wdt = -1;
static int hf_ecat_reg_syncman_irq_write = -1;
static int hf_ecat_reg_syncman_irq_read = -1;
static int hf_ecat_reg_syncman_1bufstate = -1;
static int hf_ecat_reg_syncman_3bufstate = -1;
static int hf_ecat_reg_syncman_sm_enable = -1;
static int hf_ecat_reg_syncman_enable = -1;
static int hf_ecat_reg_syncman_repeatreq = -1;
static int hf_ecat_reg_syncman_latchsmchg_ecat = -1;
static int hf_ecat_reg_syncman_latchsmchg_pdi = -1;
static int hf_ecat_reg_syncman_deactivate = -1;
static int hf_ecat_reg_syncman_repeatack = -1;
static int hf_ecat_reg_syncman = -1;
static int hf_ecat_reg_syncman_start = -1;
static int hf_ecat_reg_syncman_len = -1;
static int hf_ecat_reg_dc_recv0 = -1;
static int hf_ecat_reg_dc_recv1 = -1;
static int hf_ecat_reg_dc_recv2 = -1;
static int hf_ecat_reg_dc_recv3 = -1;
static int hf_ecat_reg_dc_systime = -1;
static int hf_ecat_reg_dc_systimeL = -1;
static int hf_ecat_reg_dc_systimeH = -1;
static int hf_ecat_reg_dc_recvtime64 = -1;
static int hf_ecat_reg_dc_systimeoffs = -1;
static int hf_ecat_reg_dc_systimeoffsl = -1;
static int hf_ecat_reg_dc_systimeoffsh = -1;
static int hf_ecat_reg_dc_systimedelay = -1;
static int hf_ecat_reg_dc_ctrlerr = -1;
static int hf_ecat_reg_dc_speedstart = -1;
static int hf_ecat_reg_dc_speeddiff = -1;
static int hf_ecat_reg_dc_fltdepth_systimediff = -1;
static int hf_ecat_reg_dc_fltdepth_speedcnt = -1;
static int hf_ecat_reg_dc_cycunitctrl = -1;
static int hf_ecat_reg_dc_cycunitctrl_access_cyclic = -1;
static int hf_ecat_reg_dc_cycunitctrl_access_latch0 = -1;
static int hf_ecat_reg_dc_cycunitctrl_access_latch1 = -1;
static int hf_ecat_reg_dc_activation = -1;
static int hf_ecat_reg_dc_activation_enablecyclic = -1;
static int hf_ecat_reg_dc_activation_gen_sync0 = -1;
static int hf_ecat_reg_dc_activation_gen_sync1 = -1;
static int hf_ecat_reg_dc_activation_autoactivation = -1;
static int hf_ecat_reg_dc_activation_stimeext = -1;
static int hf_ecat_reg_dc_activation_stimecheck = -1;
static int hf_ecat_reg_dc_activation_hlfrange = -1;
static int hf_ecat_reg_dc_activation_dblrange = -1;
static int hf_ecat_reg_dc_cycimpuls = -1;
static int hf_ecat_reg_dc_activationstat = -1;
static int hf_ecat_reg_dc_activationstat_sync0pend = -1;
static int hf_ecat_reg_dc_activationstat_sync1pend = -1;
static int hf_ecat_reg_dc_activationstat_stimeoutofrange = -1;
static int hf_ecat_reg_dc_sync0_status = -1;
static int hf_ecat_reg_dc_sync0_status_triggered = -1;
static int hf_ecat_reg_dc_sync1_status = -1;
static int hf_ecat_reg_dc_sync1_status_triggered = -1;
static int hf_ecat_reg_dc_starttime0 = -1;
static int hf_ecat_reg_dc_starttime1 = -1;
static int hf_ecat_reg_dc_cyctime0 = -1;
static int hf_ecat_reg_dc_cyctime1 = -1;
static int hf_ecat_reg_dc_latch0_ctrl_pos = -1;
static int hf_ecat_reg_dc_latch0_ctrl_neg = -1;
static int hf_ecat_reg_dc_latch1_ctrl_pos = -1;
static int hf_ecat_reg_dc_latch1_ctrl_neg = -1;
static int hf_ecat_reg_dc_latch0_status_eventpos = -1;
static int hf_ecat_reg_dc_latch0_status_eventneg = -1;
static int hf_ecat_reg_dc_latch0_status_pinstate = -1;
static int hf_ecat_reg_dc_latch1_status_eventpos = -1;
static int hf_ecat_reg_dc_latch1_status_eventneg = -1;
static int hf_ecat_reg_dc_latch1_status_pinstate = -1;
static int hf_ecat_reg_dc_latch0_ctrl = -1;
static int hf_ecat_reg_dc_latch1_ctrl = -1;
static int hf_ecat_reg_dc_latch0_status = -1;
static int hf_ecat_reg_dc_latch1_status = -1;
static int hf_ecat_reg_dc_latch0_pos = -1;
static int hf_ecat_reg_dc_latch0_neg = -1;
static int hf_ecat_reg_dc_latch1_pos = -1;
static int hf_ecat_reg_dc_latch1_neg = -1;
static int hf_ecat_reg_dc_rcvsyncmanchg = -1;
static int hf_ecat_reg_dc_pdismstart = -1;
static int hf_ecat_reg_dc_pdismchg = -1;


static const value_string EcCmdShort[] =
{
   {     0, "NOP" },
   {     1, "APRD" },
   {     2, "APWR" },
   {     3, "APRW" },
   {     4, "FPRD" },
   {     5, "FPWR" },
   {     6, "FPRW" },
   {     7, "BRD" },
   {     8, "BWR" },
   {     9, "BRW" },
   {    10, "LRD" },
   {    11, "LWR" },
   {    12, "LRW" },
   {    13, "ARMW" },
   {    14, "FRMW" },
   {   255, "EXT" },
   {   0, NULL }
};

static const value_string EcCmdLong[] =
{
   {     0, "No operation" },
   {     1, "Auto Increment Physical Read" },
   {     2, "Auto Increment Physical Write" },
   {     3, "Auto Increment Physical ReadWrite" },
   {     4, "Configured address Physical Read" },
   {     5, "Configured address Physical Write" },
   {     6, "Configured address Physical ReadWrite" },
   {     7, "Broadcast Read" },
   {     8, "Broadcast Write" },
   {     9, "Broadcast ReadWrite" },
   {    10, "Logical Read" },
   {    11, "Logical Write" },
   {    12, "Logical ReadWrite" },
   {    13, "Auto Increment Physical Read Multiple Write" },
   {    14, "Configured Address Physical Read Multiple Write" },
   {   255, "EXT" },
   {   0, NULL }
};

static const value_string ecat_subframe_reserved_vals[] =
{
   { 0, "Valid"},
   { 0, NULL}
};

static const true_false_string tfs_ecat_subframe_circulating_vals =
{
    "Frame has circulated once", "Frame is not circulating"
};

static const true_false_string tfs_ecat_subframe_more_vals =
{
    "More EtherCAT datagrams will follow", "Last EtherCAT datagram"
};

static const true_false_string tfs_ecat_fmmu_typeread =
{
   "Read in use", "Read ignore"
};

static const true_false_string tfs_ecat_fmmu_typewrite =
{
   "Write in use", "Write ignore"
};

static const true_false_string tfs_local_true_false =
{
   "True", "False",
};

static const true_false_string tfs_local_disabled_enabled =
{
   "Enabled", "Disabled",
};

static const true_false_string tfs_local_disable_enable =
{
   "Enable", "Disable",
};

static const true_false_string tfs_esc_reg_watchdog =
{
   "Okay", "Run out",
};


static const char* convertEcCmdToText(int cmd, const value_string ec_cmd[])
{
   return val_to_str(cmd, ec_cmd, "<UNKNOWN: %d>");
}

#define ENDOF(p) ((p)+1) /* pointer to end of *p*/

typedef enum
{
   EC_CMD_TYPE_NOP  =   0,
   EC_CMD_TYPE_APRD =   1,
   EC_CMD_TYPE_APWR =   2,
   EC_CMD_TYPE_APRW =   3,
   EC_CMD_TYPE_FPRD =   4,
   EC_CMD_TYPE_FPWR =   5,
   EC_CMD_TYPE_FPRW =   6,
   EC_CMD_TYPE_BRD  =   7,
   EC_CMD_TYPE_BWR  =   8,
   EC_CMD_TYPE_BRW  =   9,
   EC_CMD_TYPE_LRD  =  10,
   EC_CMD_TYPE_LWR  =  11,
   EC_CMD_TYPE_LRW  =  12,
   EC_CMD_TYPE_ARMW =  13,
   EC_CMD_TYPE_FRMW =  14,
   EC_CMD_TYPE_EXT  = 255
} EC_CMD_TYPE;

/* Esc Feature Reg 8  */
static const int * ecat_esc_reg_8[] = {
    &hf_ecat_reg_esc_features_fmmurestrict,
    &hf_ecat_reg_esc_features_smaddrrestrict,
    &hf_ecat_reg_esc_features_dcsupport,
    &hf_ecat_reg_esc_features_dc64support,
    &hf_ecat_reg_esc_features_ebuslowjitter,
    &hf_ecat_reg_esc_features_ebusextlinkdetect,
    &hf_ecat_reg_esc_features_miiextlinkdetect,
    &hf_ecat_reg_esc_features_crcext,
    NULL
};

/* Esc Status Reg 100 */
static const int * ecat_esc_reg_100[] =
{
    &hf_ecat_reg_dlctrl1_killnonecat,
    &hf_ecat_reg_dlctrl1_port0extlinkdetect,
    &hf_ecat_reg_dlctrl1_port1extlinkdetect,
    &hf_ecat_reg_dlctrl1_port2extlinkdetect,
    &hf_ecat_reg_dlctrl1_port3extlinkdetect,
    NULL
};

/* Esc Status Reg 101 */
static const value_string vals_esc_reg_101[] = {
   { 0, "Auto loop" },
   { 1, "Auto close only" },
   { 2, "Loop open" },
   { 3, "Loop closed" },
   { 0, NULL },
};

static const int *ecat_esc_reg_101[] =
{
    &hf_ecat_reg_dlctrl2_port0,
    &hf_ecat_reg_dlctrl2_port1,
    &hf_ecat_reg_dlctrl2_port2,
    &hf_ecat_reg_dlctrl2_port3,
    NULL
};

static const int *ecat_esc_reg_102[] = {
    &hf_ecat_reg_dlctrl3_fifosize,
    &hf_ecat_reg_dlctrl3_lowebusjit,
    NULL
};

static const int *ecat_esc_reg_103[] = {
    &hf_ecat_reg_dlctrl4_2ndaddress,
    NULL
};

/* Esc Status Reg 110 */
static const int *ecat_esc_reg_110[] =
{
    &hf_ecat_reg_dlstatus1_operation,
    &hf_ecat_reg_dlstatus1_pdiwatchdog,
    &hf_ecat_reg_dlstatus1_enhlinkdetect,
    &hf_ecat_reg_dlstatus1_physlink_port0,
    &hf_ecat_reg_dlstatus1_physlink_port1,
    &hf_ecat_reg_dlstatus1_physlink_port2,
    &hf_ecat_reg_dlstatus1_physlink_port3,
    NULL
};

/* Esc Status Reg 111 */
static const value_string vals_esc_reg_111[] = {
   { 0, "Loop open, no link" },
   { 1, "Loop closed, no link" },
   { 2, "Loop open, with link" },
   { 3, "Loop closed, with link" },
   { 0, NULL},
};

static const int *ecat_esc_reg_111[] =
{
    &hf_ecat_reg_dlstatus2_port0,
    &hf_ecat_reg_dlstatus2_port1,
    &hf_ecat_reg_dlstatus2_port2,
    &hf_ecat_reg_dlstatus2_port3,
    NULL
};

static const value_string vals_esc_reg_120[] = {
   { 1, "INIT" },
   { 2, "PREOP" },
   { 3, "BOOTSTRAP" },
   { 4, "SAFEOP" },
   { 8, "OP" },
   { 0, NULL},
};

static const int *ecat_esc_reg_120[] = {
    &hf_ecat_reg_alctrl_ctrl,
    &hf_ecat_reg_alctrl_errack,
    &hf_ecat_reg_alctrl_id,
    NULL
};

static const int *ecat_esc_reg_130[] = {
    &hf_ecat_reg_alstatus_status,
    &hf_ecat_reg_alstatus_err,
    &hf_ecat_reg_alstatus_id,
    NULL
};

static const value_string vals_esc_reg_140[] = {
   { 0, "None" },
   { 1, "4 bit dig. input" },
   { 2, "4 bit dig. output" },
   { 3, "2 bit dig. in/output" },
   { 4, "dig. in/output" },
   { 5, "SPI slave" },
   { 7, "EtherCAT bridge" },
   { 8, "16 bit uC (async)" },
   { 9, "8 bit uC (async)" },
   { 10, "16 bit uC (sync)" },
   { 11, "8 bit uC (sync)" },
   { 16, "32/0 bit dig. in/output" },
   { 17, "24/8 bit dig. in/output" },
   { 18, "16/16 bit dig. in/output" },
   { 19, "8/24 bit dig. in/output" },
   { 20, "0/32 bit dig. in/output" },
   { 128, "On chip bus" },
   { 0, NULL},
};

static const int *ecat_esc_reg_140[] = {
    &hf_ecat_reg_pdictrl1_pdi,
    NULL
};

static const int *ecat_esc_reg_141[] = {
    &hf_ecat_reg_pdictrl2_devemul,
    &hf_ecat_reg_pdictrl2_enhlnkdetect,
    &hf_ecat_reg_pdictrl2_dcsyncout,
    &hf_ecat_reg_pdictrl2_dcsyncin,
    &hf_ecat_reg_pdictrl2_enhlnkdetect0,
    &hf_ecat_reg_pdictrl2_enhlnkdetect1,
    &hf_ecat_reg_pdictrl2_enhlnkdetect2,
    &hf_ecat_reg_pdictrl2_enhlnkdetect3,
    NULL
};

static const int *ecat_esc_reg_200[] = {
    &hf_ecat_reg_ecat_mask_latchevt,
    &hf_ecat_reg_ecat_mask_escstatevt,
    &hf_ecat_reg_ecat_mask_alstatevt,
    &hf_ecat_reg_ecat_mask_sm0irq,
    &hf_ecat_reg_ecat_mask_sm1irq,
    &hf_ecat_reg_ecat_mask_sm2irq,
    &hf_ecat_reg_ecat_mask_sm3irq,
    &hf_ecat_reg_ecat_mask_sm4irq,
    &hf_ecat_reg_ecat_mask_sm5irq,
    &hf_ecat_reg_ecat_mask_sm6irq,
    &hf_ecat_reg_ecat_mask_sm7irq,
    NULL
};

static const int *ecat_esc_reg_204[] = {
    &hf_ecat_reg_pdiL_alctrl,
    &hf_ecat_reg_pdiL_latchin,
    &hf_ecat_reg_pdiL_sync0,
    &hf_ecat_reg_pdiL_sync1,
    &hf_ecat_reg_pdiL_smchg,
    &hf_ecat_reg_pdiL_eepromcmdpen,
    &hf_ecat_reg_pdiL_sm0,
    &hf_ecat_reg_pdiL_sm1,
    &hf_ecat_reg_pdiL_sm2,
    &hf_ecat_reg_pdiL_sm3,
    &hf_ecat_reg_pdiL_sm4,
    &hf_ecat_reg_pdiL_sm5,
    &hf_ecat_reg_pdiL_sm6,
    &hf_ecat_reg_pdiL_sm7,
    NULL
};

static const int *ecat_esc_reg_210[] = {
    &hf_ecat_reg_ecat_latchevt,
    &hf_ecat_reg_ecat_escstatevt,
    &hf_ecat_reg_ecat_alstatevt,
    &hf_ecat_reg_ecat_sm0irq,
    &hf_ecat_reg_ecat_sm1irq,
    &hf_ecat_reg_ecat_sm2irq,
    &hf_ecat_reg_ecat_sm3irq,
    &hf_ecat_reg_ecat_sm4irq,
    &hf_ecat_reg_ecat_sm5irq,
    &hf_ecat_reg_ecat_sm6irq,
    &hf_ecat_reg_ecat_sm7irq,
    NULL
};

static const int *ecat_esc_reg_220[] = {
    &hf_ecat_reg_pdi1_alctrl,
    &hf_ecat_reg_pdi1_latchin,
    &hf_ecat_reg_pdi1_sync0,
    &hf_ecat_reg_pdi1_sync1,
    &hf_ecat_reg_pdi1_smchg,
    &hf_ecat_reg_pdi1_eepromcmdpen,
    &hf_ecat_reg_pdi1_sm0,
    &hf_ecat_reg_pdi1_sm1,
    &hf_ecat_reg_pdi1_sm2,
    &hf_ecat_reg_pdi1_sm3,
    &hf_ecat_reg_pdi1_sm4,
    &hf_ecat_reg_pdi1_sm5,
    &hf_ecat_reg_pdi1_sm6,
    &hf_ecat_reg_pdi1_sm7,
    NULL
};

static const int *ecat_esc_reg_300[] = {
    &hf_ecat_reg_crc0_frame,
    &hf_ecat_reg_crc0_rx,
    NULL
};

static const int *ecat_esc_reg_302[] = {
    &hf_ecat_reg_crc1_frame,
    &hf_ecat_reg_crc1_rx,
    NULL
};

static const int *ecat_esc_reg_304[] = {
    &hf_ecat_reg_crc2_frame,
    &hf_ecat_reg_crc2_rx,
    NULL
};

static const int *ecat_esc_reg_306[] = {
    &hf_ecat_reg_crc3_frame,
    &hf_ecat_reg_crc3_rx,
    NULL
};

static const int *ecat_esc_reg_440[] = {
    &hf_ecat_reg_wd_status_pdwatchdog,
    NULL
};

static const true_false_string tfs_esc_reg_500_0 = {
    "Local uC", "ECAT"
};

static const true_false_string tfs_esc_reg_500_1 = {
    "Reset Bit 501.0 to 0", "Do not change Bit 501.0"
};

static const int *ecat_esc_reg_500[] = {
    &hf_ecat_reg_eeprom_assign_ctrl,
    &hf_ecat_reg_eeprom_assign_pdiaccess,
    &hf_ecat_reg_eeprom_assign_status,
    NULL
};

static const true_false_string tfs_esc_reg_502_5 = {
    "PDI emulates EEPROM", "Normal operation"
};

static const int *ecat_esc_reg_502[] = {
    &hf_ecat_reg_ctrlstat_wraccess,
    &hf_ecat_reg_ctrlstat_eepromemul,
    &hf_ecat_reg_ctrlstat_8bacc,
    &hf_ecat_reg_ctrlstat_2bacc,
    &hf_ecat_reg_ctrlstat_rdacc,
    &hf_ecat_reg_ctrlstat_wracc,
    &hf_ecat_reg_ctrlstat_reloadacc,
    &hf_ecat_reg_ctrlstat_crcerr,
    &hf_ecat_reg_ctrlstat_lderr,
    &hf_ecat_reg_ctrlstat_cmderr,
    &hf_ecat_reg_ctrlstat_wrerr,
    &hf_ecat_reg_ctrlstat_busy,
    NULL
};

static const int *ecat_esc_reg_510[] = {
    &hf_ecat_reg_mio_ctrlstat_wracc1,
    &hf_ecat_reg_mio_ctrlstat_offsphy,
    &hf_ecat_reg_mio_ctrlstat_rdacc,
    &hf_ecat_reg_mio_ctrlstat_wracc2,
    &hf_ecat_reg_mio_ctrlstat_wrerr,
    &hf_ecat_reg_mio_ctrlstat_busy,
    NULL
};

static const int *ecat_esc_reg_512[] = {
    &hf_ecat_reg_mio_addr_phyaddr,
    &hf_ecat_reg_mio_addr_mioaddr,
    NULL
};

static const int *ecat_esc_reg_516[] = {
    &hf_ecat_reg_mio_access_ecatacc,
    &hf_ecat_reg_mio_access_pdiacc,
    &hf_ecat_reg_mio_access_forcereset,
    NULL
};

static const int *ecat_esc_reg_518[] = {
    &hf_ecat_reg_mio_status0_physlink,
    &hf_ecat_reg_mio_status0_link,
    &hf_ecat_reg_mio_status0_linkstatuserr,
    &hf_ecat_reg_mio_status0_readerr,
    &hf_ecat_reg_mio_status0_linkpartnererr,
    &hf_ecat_reg_mio_status0_phycfgupdated,
    NULL
};

static const int *ecat_esc_reg_519[] = {
    &hf_ecat_reg_mio_status1_physlink,
    &hf_ecat_reg_mio_status1_link,
    &hf_ecat_reg_mio_status1_linkstatuserr,
    &hf_ecat_reg_mio_status1_readerr,
    &hf_ecat_reg_mio_status1_linkpartnererr,
    &hf_ecat_reg_mio_status1_phycfgupdated,
    NULL
};

static const int *ecat_esc_reg_51A[] = {
    &hf_ecat_reg_mio_status2_physlink,
    &hf_ecat_reg_mio_status2_link,
    &hf_ecat_reg_mio_status2_linkstatuserr,
    &hf_ecat_reg_mio_status2_readerr,
    &hf_ecat_reg_mio_status2_linkpartnererr,
    &hf_ecat_reg_mio_status2_phycfgupdated,
    NULL
};

static const int *ecat_esc_reg_51B[] = {
    &hf_ecat_reg_mio_status3_physlink,
    &hf_ecat_reg_mio_status3_link,
    &hf_ecat_reg_mio_status3_linkstatuserr,
    &hf_ecat_reg_mio_status3_readerr,
    &hf_ecat_reg_mio_status3_linkpartnererr,
    &hf_ecat_reg_mio_status3_phycfgupdated,
    NULL
};

static const true_false_string tfs_ecat_fmmu_activate =
{
   "activated", "deactivated"
};

static int ecat_reg_600(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item* item;
    proto_tree* subtree;

    item = proto_tree_add_item(tree, hf_ecat_reg_fmmu, tvb, offset, 16, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_ecat_reg_fmmu);

    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_lstart, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_llen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_lstartbit, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_lendbit, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_pstart, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_pstartbit, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_type, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_typeread, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_typewrite, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_activate, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_ecat_reg_fmmu_activate0, tvb, offset, 1, ENC_NA);

    return 16;
}

static int ecat_reg_800(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item* item;
    proto_tree* subtree;

    static const int *reg4[] = {
        &hf_ecat_reg_syncman_pmode,
        &hf_ecat_reg_syncman_access,
        &hf_ecat_reg_syncman_irq_ecat,
        &hf_ecat_reg_syncman_irq_pdi,
        &hf_ecat_reg_syncman_wdt,
        &hf_ecat_reg_syncman_irq_write,
        &hf_ecat_reg_syncman_irq_read,
        &hf_ecat_reg_syncman_1bufstate,
        &hf_ecat_reg_syncman_3bufstate,
        NULL
    };
    static const int *reg6[] = {
        &hf_ecat_reg_syncman_enable,
        &hf_ecat_reg_syncman_repeatreq,
        &hf_ecat_reg_syncman_latchsmchg_ecat,
        &hf_ecat_reg_syncman_latchsmchg_pdi,
        &hf_ecat_reg_syncman_deactivate,
        &hf_ecat_reg_syncman_repeatack,
        NULL
    };

    item = proto_tree_add_item(tree, hf_ecat_reg_syncman, tvb, offset, 8, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_ecat_reg_syncman);

    proto_tree_add_item(subtree, hf_ecat_reg_syncman_start, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_ecat_reg_syncman_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(subtree, tvb, offset, hf_ecat_reg_syncman_ctrlstatus, ett_ecat_reg_syncman_ctrlstatus, reg4, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(subtree, tvb, offset, hf_ecat_reg_syncman_sm_enable, ett_ecat_reg_syncman_sm_enable, reg6, ENC_LITTLE_ENDIAN);

    return 8;
}

static const value_string vals_esc_reg_8041[] = {
   { 0, "3 buffer" },
   { 2, "1 buffer" },
   { 3, "1 buffer direct" },
   { 0, NULL},
};

static const value_string vals_esc_reg_8042[] = {
   { 0, "Read" },
   { 1, "Write" },
   { 0, NULL},
};

static const true_false_string tfs_esc_reg_8051 = {
    "Written", "Read"
};

static const value_string vals_esc_reg_8052[] = {
   { 0, "1. buffer" },
   { 1, "2. buffer" },
   { 2, "3. buffer" },
   { 3, "blocked (start)" },
   { 0, NULL},
};


static const true_false_string tfs_esc_reg_9801 = {
    "PDI", "ECAT"
};

static const int *ecat_esc_reg_980[] = {
    &hf_ecat_reg_dc_cycunitctrl_access_cyclic,
    &hf_ecat_reg_dc_cycunitctrl_access_latch0,
    &hf_ecat_reg_dc_cycunitctrl_access_latch1,
    NULL
};

static const int *ecat_esc_reg_981[] = {
    &hf_ecat_reg_dc_activation_enablecyclic,
    &hf_ecat_reg_dc_activation_gen_sync0,
    &hf_ecat_reg_dc_activation_gen_sync1,
    &hf_ecat_reg_dc_activation_autoactivation,
    &hf_ecat_reg_dc_activation_stimeext,
    &hf_ecat_reg_dc_activation_stimecheck,
    &hf_ecat_reg_dc_activation_hlfrange,
    &hf_ecat_reg_dc_activation_dblrange,
    NULL
};

static const int *ecat_esc_reg_984[] = {
    &hf_ecat_reg_dc_activationstat_sync0pend,
    &hf_ecat_reg_dc_activationstat_sync1pend,
    &hf_ecat_reg_dc_activationstat_stimeoutofrange,
    NULL
};

static const int *ecat_esc_reg_98e[] = {
    &hf_ecat_reg_dc_sync0_status_triggered,
    NULL
};

static const int *ecat_esc_reg_98f[] = {
    &hf_ecat_reg_dc_sync1_status_triggered,
    NULL
};

static const true_false_string tfs_esc_reg_9A8E1 = {
    "Single event", "Continuous"
};

static const int *ecat_esc_reg_9a8[] = {
    &hf_ecat_reg_dc_latch0_ctrl_pos,
    &hf_ecat_reg_dc_latch0_ctrl_neg,
    NULL
};
static const int *ecat_esc_reg_9a9[] = {
    &hf_ecat_reg_dc_latch1_ctrl_pos,
    &hf_ecat_reg_dc_latch1_ctrl_neg,
    NULL
};

static const int *ecat_esc_reg_9ae[] = {
    &hf_ecat_reg_dc_latch0_status_eventpos,
    &hf_ecat_reg_dc_latch0_status_eventneg,
    &hf_ecat_reg_dc_latch0_status_pinstate,
    NULL
};
static const int *ecat_esc_reg_9af[] = {
    &hf_ecat_reg_dc_latch1_status_eventpos,
    &hf_ecat_reg_dc_latch1_status_eventneg,
    &hf_ecat_reg_dc_latch1_status_pinstate,
    NULL
};

typedef int register_dissect_func(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

/* esc registers */
typedef struct
{
   guint16								reg;
   guint16								length;
   guint16								repeat;
   int*									phf;
   const int**							bitmask_info;
   gint*								pett;
   register_dissect_func				*dissect;
} ecat_esc_reg_info;


#define NO_SUBTREE_FILL NULL, NULL, NULL

static ecat_esc_reg_info ecat_esc_registers [] =
{
   { 0x0000, 1, 1, &hf_ecat_reg_revision, NO_SUBTREE_FILL},
   { 0x0001, 1, 1, &hf_ecat_reg_esc_type, NO_SUBTREE_FILL},
   { 0x0002, 2, 1, &hf_ecat_reg_esc_build, NO_SUBTREE_FILL},
   { 0x0004, 1, 1, &hf_ecat_reg_esc_fmmucnt, NO_SUBTREE_FILL},
   { 0x0005, 1, 1, &hf_ecat_reg_esc_smcnt, NO_SUBTREE_FILL},
   { 0x0006, 1, 1, &hf_ecat_reg_esc_ports, NO_SUBTREE_FILL},
   { 0x0007, 1, 1, &hf_ecat_reg_esc_dpram, NO_SUBTREE_FILL},
   { 0x0008, 2, 1, &hf_ecat_reg_esc_features, ecat_esc_reg_8, &ett_ecat_reg_esc_features, NULL},
   { 0x0010, 2, 1, &hf_ecat_reg_physaddr, NO_SUBTREE_FILL},
   { 0x0012, 2, 1, &hf_ecat_reg_physaddr2, NO_SUBTREE_FILL},
   { 0x0100, 1, 1, &hf_ecat_reg_dlctrl1, ecat_esc_reg_100, &ett_ecat_reg_dlctrl1, NULL},
   { 0x0101, 1, 1, &hf_ecat_reg_dlctrl2, ecat_esc_reg_101, &ett_ecat_reg_dlctrl2, NULL},
   { 0x0102, 1, 1, &hf_ecat_reg_dlctrl3, ecat_esc_reg_102, &ett_ecat_reg_dlctrl3, NULL},
   { 0x0103, 1, 1, &hf_ecat_reg_dlctrl4, ecat_esc_reg_103, &ett_ecat_reg_dlctrl4, NULL},
   { 0x0110, 1, 1, &hf_ecat_reg_dlstatus1, ecat_esc_reg_110, &ett_ecat_reg_dlstatus1, NULL},
   { 0x0111, 1, 1, &hf_ecat_reg_dlstatus2, ecat_esc_reg_111, &ett_ecat_reg_dlstatus2, NULL},
   { 0x0020, 2, 1, &hf_ecat_reg_regprotect, NO_SUBTREE_FILL},
   { 0x0030, 2, 1, &hf_ecat_reg_accessprotect, NO_SUBTREE_FILL},
   { 0x0040, 1, 1, &hf_ecat_reg_resetecat, NO_SUBTREE_FILL},
   { 0x0041, 1, 1, &hf_ecat_reg_resetpdi, NO_SUBTREE_FILL},
   { 0x0108, 2, 1, &hf_ecat_reg_regphysrwoffs, NO_SUBTREE_FILL},
   { 0x0120, 2, 1, &hf_ecat_reg_alctrl, ecat_esc_reg_120, &ett_ecat_reg_alctrl, NULL},
   { 0x0130, 2, 1, &hf_ecat_reg_alstatus, ecat_esc_reg_130, &ett_ecat_reg_alstatus, NULL},
   { 0x0134, 2, 1, &hf_ecat_reg_alstatuscode, NO_SUBTREE_FILL},
   { 0x0140, 1, 1, &hf_ecat_reg_pdictrl1, ecat_esc_reg_140, &ett_ecat_reg_pdictrl1, NULL},
   { 0x0141, 1, 1, &hf_ecat_reg_pdictrl2, ecat_esc_reg_141, &ett_ecat_reg_pdictrl2, NULL},
   { 0x0200, 2, 1, &hf_ecat_reg_ecat_mask, ecat_esc_reg_200, &ett_ecat_reg_ecat_mask, NULL},
   { 0x0204, 2, 1, &hf_ecat_reg_pdiL, ecat_esc_reg_204, &ett_ecat_reg_pdiL, NULL},
   { 0x0206, 2, 1, &hf_ecat_reg_pdiH, NO_SUBTREE_FILL},
   { 0x0210, 2, 1, &hf_ecat_reg_ecat, ecat_esc_reg_210, &ett_ecat_reg_ecat, NULL},
   { 0x0220, 2, 1, &hf_ecat_reg_pdi1, ecat_esc_reg_220, &ett_ecat_reg_pdi1, NULL},
   { 0x0222, 2, 1, &hf_ecat_reg_pdi2, NO_SUBTREE_FILL},
   { 0x0300, 2, 1, &hf_ecat_reg_crc0, ecat_esc_reg_300, &ett_ecat_reg_crc0, NULL},
   { 0x0302, 2, 1, &hf_ecat_reg_crc1, ecat_esc_reg_302, &ett_ecat_reg_crc1, NULL},
   { 0x0304, 2, 1, &hf_ecat_reg_crc2, ecat_esc_reg_304, &ett_ecat_reg_crc2, NULL},
   { 0x0306, 2, 1, &hf_ecat_reg_crc3, ecat_esc_reg_306, &ett_ecat_reg_crc3, NULL},
   { 0x0308, 1, 1, &hf_ecat_reg_crc_fwd0, NO_SUBTREE_FILL},
   { 0x0309, 1, 1, &hf_ecat_reg_crc_fwd1, NO_SUBTREE_FILL},
   { 0x030A, 1, 1, &hf_ecat_reg_crc_fwd2, NO_SUBTREE_FILL},
   { 0x030B, 1, 1, &hf_ecat_reg_crc_fwd3, NO_SUBTREE_FILL},
   { 0x030C, 1, 1, &hf_ecat_reg_processuniterr, NO_SUBTREE_FILL},
   { 0x030D, 1, 1, &hf_ecat_reg_pdierr, NO_SUBTREE_FILL},
   { 0x0310, 1, 1, &hf_ecat_reg_linklost0, NO_SUBTREE_FILL},
   { 0x0311, 1, 1, &hf_ecat_reg_linklost1, NO_SUBTREE_FILL},
   { 0x0312, 1, 1, &hf_ecat_reg_linklost2, NO_SUBTREE_FILL},
   { 0x0313, 1, 1, &hf_ecat_reg_linklost3, NO_SUBTREE_FILL},
   { 0x0400, 2, 1, &hf_ecat_reg_wd_divisor, NO_SUBTREE_FILL},
   { 0x0410, 2, 1, &hf_ecat_reg_wd_timepdi, NO_SUBTREE_FILL},
   { 0x0420, 2, 1, &hf_ecat_reg_wd_timesm, NO_SUBTREE_FILL},
   { 0x0440, 1, 1, &hf_ecat_reg_wd_status, ecat_esc_reg_440, &ett_ecat_reg_wd_status, NULL},
   { 0x0442, 1, 1, &hf_ecat_reg_wd_cntsm, NO_SUBTREE_FILL},
   { 0x0443, 1, 1, &hf_ecat_reg_wd_cntpdi, NO_SUBTREE_FILL},
   { 0x0500, 2, 1, &hf_ecat_reg_eeprom_assign, ecat_esc_reg_500, &ett_ecat_reg_eeprom_assign, NULL},
   { 0x0502, 2, 1, &hf_ecat_reg_ctrlstat, ecat_esc_reg_502, &ett_ecat_reg_ctrlstat, NULL},
   { 0x0504, 2, 1, &hf_ecat_reg_addrl, NO_SUBTREE_FILL},
   { 0x0506, 2, 1, &hf_ecat_reg_addrh, NO_SUBTREE_FILL},
   { 0x0508, 2, 1, &hf_ecat_reg_data0, NO_SUBTREE_FILL},
   { 0x050a, 2, 1, &hf_ecat_reg_data1, NO_SUBTREE_FILL},
   { 0x050c, 2, 1, &hf_ecat_reg_data2, NO_SUBTREE_FILL},
   { 0x050e, 2, 1, &hf_ecat_reg_data3, NO_SUBTREE_FILL},
   { 0x0510, 2, 1, &hf_ecat_reg_mio_ctrlstat, ecat_esc_reg_510, &ett_ecat_reg_mio_ctrlstat, NULL},
   { 0x0512, 2, 1, &hf_ecat_reg_mio_addr, ecat_esc_reg_512, &ett_ecat_mio_addr, NULL},
   { 0x0514, 2, 1, &hf_ecat_reg_mio_data, NO_SUBTREE_FILL},
   { 0x0516, 2, 1, &hf_ecat_reg_mio_access, ecat_esc_reg_516, &ett_ecat_mio_access, NULL},
   { 0x0518, 1, 1, &hf_ecat_reg_mio_status0, ecat_esc_reg_518, &ett_ecat_mio_status0, NULL},
   { 0x0519, 1, 1, &hf_ecat_reg_mio_status1, ecat_esc_reg_519, &ett_ecat_mio_status1, NULL},
   { 0x051A, 1, 1, &hf_ecat_reg_mio_status2, ecat_esc_reg_51A, &ett_ecat_mio_status2, NULL},
   { 0x051B, 1, 1, &hf_ecat_reg_mio_status3, ecat_esc_reg_51B, &ett_ecat_mio_status3, NULL},
   { 0x0600, 16, 16, &hf_ecat_reg_fmmu, NULL, NULL, ecat_reg_600},
   { 0x0800, 8, 8, &hf_ecat_reg_syncman, NULL, NULL, ecat_reg_800},
   { 0x0900, 4, 1, &hf_ecat_reg_dc_recv0, NO_SUBTREE_FILL},
   { 0x0904, 4, 1, &hf_ecat_reg_dc_recv1, NO_SUBTREE_FILL},
   { 0x0908, 4, 1, &hf_ecat_reg_dc_recv2, NO_SUBTREE_FILL},
   { 0x090c, 4, 1, &hf_ecat_reg_dc_recv3, NO_SUBTREE_FILL},
   { 0x0910, 8, 1, &hf_ecat_reg_dc_systime, NO_SUBTREE_FILL},
   { 0x0910, 4, 1, &hf_ecat_reg_dc_systimeL, NO_SUBTREE_FILL},
   { 0x0914, 4, 1, &hf_ecat_reg_dc_systimeH, NO_SUBTREE_FILL},
   { 0x0918, 8, 1, &hf_ecat_reg_dc_recvtime64, NO_SUBTREE_FILL},
   { 0x0920, 8, 1, &hf_ecat_reg_dc_systimeoffs, NO_SUBTREE_FILL},
   { 0x0920, 4, 1, &hf_ecat_reg_dc_systimeoffsl, NO_SUBTREE_FILL},
   { 0x0924, 4, 1, &hf_ecat_reg_dc_systimeoffsh, NO_SUBTREE_FILL},
   { 0x0928, 4, 1, &hf_ecat_reg_dc_systimedelay, NO_SUBTREE_FILL},
   { 0x092c, 4, 1, &hf_ecat_reg_dc_ctrlerr, NO_SUBTREE_FILL},
   { 0x0930, 2, 1, &hf_ecat_reg_dc_speedstart, NO_SUBTREE_FILL},
   { 0x0932, 2, 1, &hf_ecat_reg_dc_speeddiff, NO_SUBTREE_FILL},
   { 0x0934, 1, 1, &hf_ecat_reg_dc_fltdepth_systimediff, NO_SUBTREE_FILL},
   { 0x0935, 1, 1, &hf_ecat_reg_dc_fltdepth_speedcnt, NO_SUBTREE_FILL},
   { 0x0980, 1, 1, &hf_ecat_reg_dc_cycunitctrl, ecat_esc_reg_980, &ett_ecat_reg_dc_cycunitctrl, NULL},
   { 0x0981, 1, 1, &hf_ecat_reg_dc_activation, ecat_esc_reg_981, &ett_ecat_dc_activation, NULL},
   { 0x0982, 2, 1, &hf_ecat_reg_dc_cycimpuls, NO_SUBTREE_FILL},
   { 0x0984, 1, 1, &hf_ecat_reg_dc_activationstat, ecat_esc_reg_984, &ett_ecat_dc_activationstat, NULL},
   { 0x098e, 1, 1, &hf_ecat_reg_dc_sync0_status, ecat_esc_reg_98e, &ett_ecat_dc_sync0_status, NULL},
   { 0x098f, 1, 1, &hf_ecat_reg_dc_sync1_status, ecat_esc_reg_98f, &ett_ecat_dc_sync1_status, NULL},
   { 0x0990, 8, 1, &hf_ecat_reg_dc_starttime0, NO_SUBTREE_FILL},
   { 0x0998, 8, 1, &hf_ecat_reg_dc_starttime1, NO_SUBTREE_FILL},
   { 0x09a0, 4, 1, &hf_ecat_reg_dc_cyctime0, NO_SUBTREE_FILL},
   { 0x09a4, 4, 1, &hf_ecat_reg_dc_cyctime1, NO_SUBTREE_FILL},
   { 0x09a8, 1, 1, &hf_ecat_reg_dc_latch0_ctrl, ecat_esc_reg_9a8, &ett_ecat_dc_latch0_ctrl, NULL},
   { 0x09a9, 1, 1, &hf_ecat_reg_dc_latch1_ctrl, ecat_esc_reg_9a9, &ett_ecat_dc_latch1_ctrl, NULL},
   { 0x09ae, 1, 1, &hf_ecat_reg_dc_latch0_status, ecat_esc_reg_9ae, &ett_ecat_dc_latch0_status, NULL},
   { 0x09af, 1, 1, &hf_ecat_reg_dc_latch1_status, ecat_esc_reg_9af, &ett_ecat_dc_latch1_status, NULL},
   { 0x09b0, 8, 1, &hf_ecat_reg_dc_latch0_pos, NO_SUBTREE_FILL},
   { 0x09b8, 8, 1, &hf_ecat_reg_dc_latch0_neg, NO_SUBTREE_FILL},
   { 0x09c0, 8, 1, &hf_ecat_reg_dc_latch1_pos, NO_SUBTREE_FILL},
   { 0x09c8, 8, 1, &hf_ecat_reg_dc_latch1_neg, NO_SUBTREE_FILL},
   { 0x09f0, 4, 1, &hf_ecat_reg_dc_rcvsyncmanchg, NO_SUBTREE_FILL},
   { 0x09f8, 4, 1, &hf_ecat_reg_dc_pdismstart, NO_SUBTREE_FILL},
   { 0x09fc, 4, 1, &hf_ecat_reg_dc_pdismchg, NO_SUBTREE_FILL},

};

/* esc dissector */
static int dissect_esc_register(packet_info* pinfo, proto_tree *tree, tvbuff_t *tvb, gint offset, guint32 len, EcParserHDR* hdr, guint16 cnt)
{
   guint i;
   gint r;
   gint res = -1;
   gint regOffset;
   gint read = 0;

   if (len > 0 )
   {
      switch ( hdr->cmd )
      {
      case EC_CMD_TYPE_APRD:
      case EC_CMD_TYPE_BRD:
      case EC_CMD_TYPE_FPRD:
         read = 1;
         /* Fall through */
      case EC_CMD_TYPE_APWR:
      case EC_CMD_TYPE_APRW:
      case EC_CMD_TYPE_FPWR:
      case EC_CMD_TYPE_FPRW:
      case EC_CMD_TYPE_BWR:
      case EC_CMD_TYPE_BRW:
      case EC_CMD_TYPE_ARMW:
      case EC_CMD_TYPE_FRMW:
         for ( i=0; i<array_length(ecat_esc_registers); i++ )
         {
            if ( hdr->anAddrUnion.a.ado + len< ecat_esc_registers[i].reg )
               break;

            regOffset = ecat_esc_registers[i].reg;
            for ( r=0; r<ecat_esc_registers[i].repeat; r++ )
            {
               if ( regOffset >= hdr->anAddrUnion.a.ado && regOffset+ecat_esc_registers[i].length <= (guint16)(hdr->anAddrUnion.a.ado + len) )
               {
                  if ( cnt > 0 || !read )
                  {
                      if (ecat_esc_registers[i].dissect != NULL)
                      {
                          ecat_esc_registers[i].dissect(pinfo, tree, tvb, offset+(regOffset-hdr->anAddrUnion.a.ado));
                      }
                      else if (ecat_esc_registers[i].bitmask_info != NULL)
                      {
                          proto_tree_add_bitmask(tree, tvb, offset+(regOffset-hdr->anAddrUnion.a.ado), *ecat_esc_registers[i].phf,
                                                 *ecat_esc_registers[i].pett, ecat_esc_registers[i].bitmask_info, ENC_LITTLE_ENDIAN);
                      }
                      else
                      {
                          proto_tree_add_item(tree, *ecat_esc_registers[i].phf, tvb, offset+(regOffset-hdr->anAddrUnion.a.ado), ecat_esc_registers[i].length, ENC_LITTLE_ENDIAN);
                      }
                  }
                  res = 0;
               }
               regOffset+=ecat_esc_registers[i].length;
            }
         }
         break;
      }
   }

   return res;
}
static void init_EcParserHDR(EcParserHDR* pHdr, tvbuff_t *tvb, gint offset)
{
   pHdr->cmd = tvb_get_guint8(tvb, offset++);
   pHdr->idx = tvb_get_guint8(tvb, offset++);
   pHdr->anAddrUnion.a.adp = tvb_get_letohs(tvb, offset); offset+=2;
   pHdr->anAddrUnion.a.ado = tvb_get_letohs(tvb, offset); offset+=2;
   pHdr->len = tvb_get_letohs(tvb, offset); offset+=2;
   pHdr->intr = tvb_get_letohs(tvb, offset);
}

static void init_dc_measure(guint32* pDC, tvbuff_t *tvb, gint offset)
{
   int i;
   for ( i=0; i<4; i++ )
   {
      pDC[i] = tvb_get_letohl(tvb, offset);
      offset+=4;
   }
}

static guint16 get_wc(EcParserHDR* pHdr, tvbuff_t *tvb, gint offset)
{
   return tvb_get_letohs(tvb, offset+EcParserHDR_Len+(pHdr->len&0x07ff));
}

static guint16 get_cmd_len(EcParserHDR* pHdr)
{
   return (EcParserHDR_Len+(pHdr->len&0x07ff)+2); /*Header + data + wc*/
}


static void EcSummaryFormater(guint32 datalength, tvbuff_t *tvb, gint offset, char *szText, gint nMax)
{
   guint nSub=0;
   guint nLen=0;
   guint8  nCmds[4];
   guint nLens[4];
   EcParserHDR ecFirst;
   EcParserHDR ecParser;

   guint suboffset=0;

   init_EcParserHDR(&ecFirst, tvb, offset);

   while ( suboffset < datalength )
   {
      PEcParserHDR pEcParser;
      if ( nSub > 0 )
      {
         init_EcParserHDR(&ecParser, tvb, offset+suboffset);
         pEcParser = &ecParser;
      }
      else
         pEcParser = &ecFirst;

      if ( nSub < 4 )
      {
         nCmds[nSub] = pEcParser->cmd;
         nLens[nSub] = pEcParser->len&0x07ff;
      }
      nSub++;
      nLen += (pEcParser->len&0x07ff);
      /* bit 14 -- roundtrip */

      if ( (pEcParser->len&0x8000) == 0 )
         break;

      suboffset+=get_cmd_len(pEcParser);
   }
   if ( nSub == 1 )
   {
      guint16 len = ecFirst.len&0x07ff;
      guint16 cnt = get_wc(&ecFirst, tvb, offset);
      g_snprintf ( szText, nMax, "'%s': Len: %d, Adp 0x%x, Ado 0x%x, Wc %d ",
         convertEcCmdToText(ecFirst.cmd, EcCmdShort), len, ecFirst.anAddrUnion.a.adp, ecFirst.anAddrUnion.a.ado, cnt );
   }
   else if ( nSub == 2 )
   {
      g_snprintf ( szText, nMax, "%d Cmds, '%s': len %d, '%s': len %d ",
         nSub, convertEcCmdToText(nCmds[0], EcCmdShort), nLens[0], convertEcCmdToText(nCmds[1], EcCmdShort), nLens[1]);
   }
   else if ( nSub == 3 )
   {
      g_snprintf ( szText, nMax, "%d Cmds, '%s': len %d, '%s': len %d, '%s': len %d",
         nSub, convertEcCmdToText(nCmds[0], EcCmdShort), nLens[0], convertEcCmdToText(nCmds[1], EcCmdShort), nLens[1], convertEcCmdToText(nCmds[2], EcCmdShort), nLens[2]);
   }
   else if ( nSub == 4 )
   {
      g_snprintf ( szText, nMax, "%d Cmds, '%s': len %d, '%s': len %d, '%s': len %d, '%s': len %d",
         nSub, convertEcCmdToText(nCmds[0], EcCmdShort), nLens[0], convertEcCmdToText(nCmds[1], EcCmdShort), nLens[1], convertEcCmdToText(nCmds[2], EcCmdShort), nLens[2], convertEcCmdToText(nCmds[3], EcCmdShort), nLens[3]);
   }
   else
      g_snprintf ( szText, nMax, "%d Cmds, SumLen %d, '%s'... ",
         nSub, nLen, convertEcCmdToText(ecFirst.cmd, EcCmdShort));
}

static void EcCmdFormatter(guint8 cmd, char *szText, gint nMax)
{
   gint idx=0;
   const gchar *szCmd = try_val_to_str_idx((guint32)cmd, EcCmdLong, &idx);

   if ( idx != -1 )
      g_snprintf(szText, nMax, "Cmd        : %d (%s)", cmd, szCmd);
   else
      g_snprintf(szText, nMax, "Cmd        : %d (Unknown command)", cmd);
}


static void EcSubFormatter(tvbuff_t *tvb, gint offset, char *szText, gint nMax)
{
   EcParserHDR ecParser;
   guint16 len, cnt;

   init_EcParserHDR(&ecParser, tvb, offset);
   len = ecParser.len&0x07ff;
   cnt = get_wc(&ecParser, tvb, offset);

   switch ( ecParser.cmd )
   {
   case EC_CMD_TYPE_NOP:
   case EC_CMD_TYPE_APRD:
   case EC_CMD_TYPE_APWR:
   case EC_CMD_TYPE_APRW:
   case EC_CMD_TYPE_FPRD:
   case EC_CMD_TYPE_FPWR:
   case EC_CMD_TYPE_FPRW:
   case EC_CMD_TYPE_BRD:
   case EC_CMD_TYPE_BWR:
   case EC_CMD_TYPE_BRW:
   case EC_CMD_TYPE_ARMW:
   case EC_CMD_TYPE_FRMW:
      g_snprintf ( szText, nMax, "EtherCAT datagram: Cmd: '%s' (%d), Len: %d, Adp 0x%x, Ado 0x%x, Cnt %d",
         convertEcCmdToText(ecParser.cmd, EcCmdShort), ecParser.cmd, len, ecParser.anAddrUnion.a.adp, ecParser.anAddrUnion.a.ado, cnt);
      break;
   case EC_CMD_TYPE_LRD:
   case EC_CMD_TYPE_LWR:
   case EC_CMD_TYPE_LRW:
      g_snprintf ( szText, nMax, "EtherCAT datagram: Cmd: '%s' (%d), Len: %d, Addr 0x%x, Cnt %d",
         convertEcCmdToText(ecParser.cmd, EcCmdShort), ecParser.cmd, len, ecParser.anAddrUnion.addr, cnt);
      break;
   case EC_CMD_TYPE_EXT:
      g_snprintf ( szText, nMax, "EtherCAT datagram: Cmd: 'EXT' (%d), Len: %d",  ecParser.cmd, len);
      break;
   default:
      g_snprintf ( szText, nMax, "EtherCAT datagram: Cmd: 'Unknown' (%d), Len: %d",  ecParser.cmd, len);
   }
}

/* Ethercat Datagram */
static int dissect_ecat_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   tvbuff_t *next_tvb;
   proto_item *ti, *aitem = NULL;
   proto_tree *ecat_datagrams_tree = NULL;
   guint offset = 0;
   char szText[200];
   int nMax = sizeof(szText)-1;

   guint ecLength=0;
   guint subCount = 0;
   const guint datagram_length = tvb_captured_length(tvb);
   guint datagram_padding_bytes = 0;
   EcParserHDR ecHdr;
   heur_dtbl_entry_t *hdtbl_entry;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "ECAT");

   col_clear(pinfo->cinfo, COL_INFO);

   /* If the data portion of an EtherCAT datagram is less than 44 bytes, then
      it must have been padded with an additional n number of bytes to reach a
      total Ethernet frame length of 64 bytes (Ethernet header + Ethernet Data +
      FCS). Hence at least 44 bytes data shall always be available in any
      EtherCAT datagram. */
   /* tvb_ensure_bytes_exist(tvb, offset, 44);
      this is not correct, because the frame might have been captured before the
      os added the padding bytes. E.g. in Windows the frames are captured on the
      protocol layer. When another protocol driver sends a frame this frame does
      not include the padding bytes.
   */

   /* Count the length of the individual EtherCAT datagrams (sub datagrams)
      that are part of this EtherCAT frame. Stop counting when the current
      sub datagram header tells that there are no more sub datagrams or when
      there is no more data available in the PDU. */
   do
   {
      init_EcParserHDR(&ecHdr, tvb, ecLength);
      ecLength += get_cmd_len(&ecHdr);
   } while ((ecLength < datagram_length) &&
            (ecHdr.len & 0x8000));

   /* Calculate the amount of padding data available in the PDU */
   datagram_padding_bytes = datagram_length - ecLength;

   EcSummaryFormater(ecLength, tvb, offset, szText, nMax);
   col_append_str(pinfo->cinfo, COL_INFO, szText);

   if( tree )
   {
      /* Create the EtherCAT datagram(s) subtree */
      ti = proto_tree_add_item(tree, proto_ecat_datagram, tvb, 0, -1, ENC_NA);
      ecat_datagrams_tree = proto_item_add_subtree(ti, ett_ecat);

      proto_item_append_text(ti,": %s", szText);
   }

   /* Dissect all sub frames of this EtherCAT PDU */
   do
   {
      proto_tree *ecat_datagram_tree = NULL, *ecat_header_tree = NULL, *ecat_dc_tree = NULL;

      proto_item *hidden_item;
      guint32 subsize;
      guint32 suboffset;
      guint32 len;
      guint16 cnt;
      ETHERCAT_MBOX_HEADER mbox;

      suboffset = offset;
      init_EcParserHDR(&ecHdr, tvb, suboffset);

      subsize = get_cmd_len(&ecHdr);
      len = ecHdr.len & 0x07ff;
      cnt = get_wc(&ecHdr, tvb, suboffset);

      if( tree )
      {
         /* Create the sub tree for the current datagram */
         EcSubFormatter(tvb, suboffset, szText, nMax);
         ecat_datagram_tree = proto_tree_add_subtree(ecat_datagrams_tree, tvb, suboffset, subsize, ett_ecat_datagram_subtree, NULL, szText);

         /* Create a subtree placeholder for the Header */
         ecat_header_tree = proto_tree_add_subtree(ecat_datagram_tree, tvb, offset, EcParserHDR_Len, ett_ecat_header, NULL, "Header");

         EcCmdFormatter(ecHdr.cmd, szText, nMax);
         aitem = proto_tree_add_item(ecat_header_tree, hf_ecat_cmd, tvb, suboffset, 1, ENC_LITTLE_ENDIAN);
         proto_item_set_text(aitem, "%s", szText);
         if( subCount < 10 ){
            aitem = proto_tree_add_item(ecat_header_tree, hf_ecat_sub_cmd[subCount], tvb, suboffset, 1, ENC_LITTLE_ENDIAN);
            PROTO_ITEM_SET_HIDDEN(aitem);
         }
         suboffset+=1;

         proto_tree_add_item(ecat_header_tree, hf_ecat_idx, tvb, suboffset, 1, ENC_LITTLE_ENDIAN);
         if( subCount < 10 ){
            aitem = proto_tree_add_item(ecat_header_tree, hf_ecat_sub_idx[subCount], tvb, suboffset, 1, ENC_LITTLE_ENDIAN);
            PROTO_ITEM_SET_HIDDEN(aitem);
         }
         suboffset+=1;

         switch ( ecHdr.cmd )
         {
         case 10:
         case 11:
         case 12:
            proto_tree_add_item(ecat_header_tree, hf_ecat_lad, tvb, suboffset, 4, ENC_LITTLE_ENDIAN);
            if( subCount < 10 ){
               aitem = proto_tree_add_item(ecat_header_tree, hf_ecat_sub_lad[subCount], tvb, suboffset, 4, ENC_LITTLE_ENDIAN);
               PROTO_ITEM_SET_HIDDEN(aitem);
            }

            suboffset+=4;
            break;
         default:
            proto_tree_add_item(ecat_header_tree, hf_ecat_adp, tvb, suboffset, 2, ENC_LITTLE_ENDIAN);
            if( subCount < 10 ){
               aitem = proto_tree_add_item(ecat_header_tree, hf_ecat_sub_adp[subCount], tvb, suboffset, 2, ENC_LITTLE_ENDIAN);
               PROTO_ITEM_SET_HIDDEN(aitem);
            }

            suboffset+=2;
            proto_tree_add_item(ecat_header_tree, hf_ecat_ado, tvb, suboffset, 2, ENC_LITTLE_ENDIAN);
            if( subCount < 10 ){
               aitem = proto_tree_add_item(ecat_header_tree, hf_ecat_sub_ado[subCount], tvb, suboffset, 2, ENC_LITTLE_ENDIAN);
               PROTO_ITEM_SET_HIDDEN(aitem);
            }

            suboffset+=2;
         }

         {
            proto_tree *length_sub_tree;

            /* Add information about the length field (11 bit length, 3 bits
               reserved, 1 bit circulating frame and 1 bit more in a sub tree */
            length_sub_tree = proto_tree_add_subtree_format(ecat_header_tree, tvb, suboffset, 2,
                                        ett_ecat_length, NULL, "Length     : %d (0x%x) - %s - %s",
                                        len, len, ecHdr.len & 0x4000 ? "Roundtrip" : "No Roundtrip", ecHdr.len & 0x8000 ? "More Follows..." : "Last Sub Command");

            proto_tree_add_item(length_sub_tree, hf_ecat_length_len, tvb, suboffset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(length_sub_tree, hf_ecat_length_r, tvb, suboffset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(length_sub_tree, hf_ecat_length_c, tvb, suboffset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(length_sub_tree, hf_ecat_length_m, tvb, suboffset, 2, ENC_LITTLE_ENDIAN);

            suboffset+=2;
         }

         proto_tree_add_item(ecat_header_tree, hf_ecat_int, tvb, suboffset, 2, ENC_LITTLE_ENDIAN);
         suboffset+=2;
      }
      else
      {
         suboffset+=EcParserHDR_Len;
      }

      if ( (ecHdr.cmd == 1 || ecHdr.cmd == 4) && ecHdr.anAddrUnion.a.ado == 0x900 && ecHdr.len >= 16 && cnt > 0 )
      {
         guint32 pDC[4];
         init_dc_measure(pDC, tvb, suboffset);

         ecat_dc_tree = proto_tree_add_subtree(ecat_datagram_tree, tvb, suboffset, len, ett_ecat_dc, NULL, "Dc");
         dissect_esc_register(pinfo, ecat_dc_tree, tvb, suboffset, len, &ecHdr, cnt);

         if( subCount < 10 ){
            aitem = proto_tree_add_item(ecat_datagram_tree, hf_ecat_sub_data[subCount], tvb, offset + EcParserHDR_Len, len, ENC_NA);
            PROTO_ITEM_SET_HIDDEN(aitem);
         }

         if ( pDC[3] != 0 )
         {
            proto_tree_add_uint(ecat_dc_tree, hf_ecat_dc_diff_da, tvb, suboffset, 4, pDC[3] - pDC[0]);
            if( subCount < 10 ){
               hidden_item = proto_tree_add_uint(ecat_dc_tree, hf_ecat_sub_dc_diff_da[subCount], tvb, suboffset, 4, pDC[3] - pDC[0]);
               PROTO_ITEM_SET_HIDDEN(hidden_item);
            }

            if ( pDC[1] != 0 )
            {
               proto_tree_add_uint(ecat_dc_tree, hf_ecat_dc_diff_bd, tvb, suboffset, 4, pDC[1] - pDC[3]);
               if( subCount < 10 ){
                  hidden_item = proto_tree_add_uint(ecat_dc_tree, hf_ecat_sub_dc_diff_bd[subCount], tvb, suboffset, 4, pDC[1] - pDC[3]);
                  PROTO_ITEM_SET_HIDDEN(hidden_item);
               }
            }
            else if ( pDC[2] != 0 )
            {
               proto_tree_add_uint(ecat_dc_tree, hf_ecat_dc_diff_cd, tvb, suboffset, 4, pDC[2] - pDC[3]);
               if( subCount < 10 ){
                  hidden_item = proto_tree_add_uint(ecat_dc_tree, hf_ecat_sub_dc_diff_cd[subCount], tvb, suboffset, 4, pDC[2] - pDC[3]);
                  PROTO_ITEM_SET_HIDDEN(hidden_item);
               }
            }
         }
         if ( pDC[1] != 0 )
         {
            proto_tree_add_uint(ecat_dc_tree, hf_ecat_dc_diff_ba, tvb, suboffset, 4, pDC[1] - pDC[0]);
            if( subCount < 10 ){
               hidden_item = proto_tree_add_uint(ecat_dc_tree, hf_ecat_sub_dc_diff_ba[subCount], tvb, suboffset, 4, pDC[1] - pDC[0]);
               PROTO_ITEM_SET_HIDDEN(hidden_item);
            }
            if ( pDC[2] != 0 )
            {
               proto_tree_add_uint(ecat_dc_tree, hf_ecat_dc_diff_cb, tvb, suboffset, 4, pDC[2] - pDC[1]);
               if( subCount < 10 ){
                  hidden_item = proto_tree_add_uint(ecat_dc_tree, hf_ecat_sub_dc_diff_cb[subCount], tvb, suboffset, 4, pDC[2] - pDC[1]);
                  PROTO_ITEM_SET_HIDDEN(hidden_item);
               }
            }
         }
         else if ( pDC[2] != 0 )
         {
            proto_tree_add_uint(ecat_dc_tree, hf_ecat_dc_diff_ca, tvb, suboffset, 4, pDC[2] - pDC[0]);
            if( subCount < 10 ){
               hidden_item = proto_tree_add_uint(ecat_dc_tree, hf_ecat_sub_dc_diff_ca[subCount], tvb, suboffset, 4, pDC[2] - pDC[0]);
               PROTO_ITEM_SET_HIDDEN(hidden_item);
            }
         }
      }
      else if (dissect_esc_register(pinfo, ecat_datagram_tree, tvb, suboffset, len, &ecHdr, cnt) != 0)
      {
         guint startOfData = offset + EcParserHDR_Len;
         guint dataLength = len;

         if ( len >= ETHERCAT_MBOX_HEADER_LEN &&
           ((ecHdr.cmd==EC_CMD_TYPE_FPWR || ecHdr.cmd == EC_CMD_TYPE_APWR) || ((ecHdr.cmd==EC_CMD_TYPE_FPRD  || ecHdr.cmd==EC_CMD_TYPE_APRD) && cnt==1) ) &&
           ecHdr.anAddrUnion.a.ado>=0x1000
         )
         {
            init_mbx_header(&mbox, tvb, startOfData);
            switch ( mbox.aControlUnion.v.Type )
            {
               case ETHERCAT_MBOX_TYPE_EOE:
               case ETHERCAT_MBOX_TYPE_ADS:
               case ETHERCAT_MBOX_TYPE_FOE:
               case ETHERCAT_MBOX_TYPE_COE:
               case ETHERCAT_MBOX_TYPE_SOE:
               if ( mbox.Length <= 1500 )
               {
                  guint MBoxLength = mbox.Length + ETHERCAT_MBOX_HEADER_LEN;
                  if ( MBoxLength > len )
                     MBoxLength = len;

                  next_tvb = tvb_new_subset_length(tvb, startOfData, MBoxLength);
                  call_dissector_only(ecat_mailbox_handle, next_tvb, pinfo, ecat_datagram_tree, NULL);

                  startOfData += MBoxLength;
                  dataLength -= MBoxLength;
               }
               break;
            }
         }
         if( dataLength > 0 )
         {
            /* Allow sub dissectors to have a chance with this data */
            if(!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, ecat_datagram_tree, &hdtbl_entry, NULL))
            {
               /* No sub dissector did recognize this data, dissect it as data only */
               proto_tree_add_item(ecat_datagram_tree, hf_ecat_data, tvb, startOfData, dataLength, ENC_NA);
            }

            if( subCount < 10 ){
               aitem = proto_tree_add_item(ecat_datagram_tree, hf_ecat_sub_data[subCount], tvb, startOfData, dataLength, ENC_NA);
               PROTO_ITEM_SET_HIDDEN(aitem);
            }
         }
      }

      if( tree )
      {
         proto_tree_add_item(ecat_datagram_tree, hf_ecat_cnt, tvb, offset + EcParserHDR_Len + len , 2, ENC_LITTLE_ENDIAN);
         if( subCount < 10 ){
            aitem = proto_tree_add_item(ecat_datagram_tree, hf_ecat_sub_cnt[subCount], tvb, offset + EcParserHDR_Len + len , 2, ENC_LITTLE_ENDIAN);
            PROTO_ITEM_SET_HIDDEN(aitem);
         }
      }

      offset+=subsize;
      subCount++;
   } while((offset < datagram_length) &&
           (ecHdr.len & 0x8000));

   /* Add information that states which portion of the PDU that is pad bytes.
      These are added just to get an Ethernet frame size of at least 64 bytes,
      which is required by the protocol specification */
   if(datagram_padding_bytes > 0)
   {
      proto_tree_add_item(tree, hf_ecat_padding, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
   }
   return tvb_captured_length(tvb);
}

void proto_register_ecat(void)
{
   static hf_register_info hf[] =
      {
         { &hf_ecat_sub,
           { "EtherCAT Frame", "ecat.sub", FT_BYTES, BASE_NONE, NULL, 0x0,
             NULL, HFILL }
         },
#if 0
         { &hf_ecat_header,
           { "eader", "ecat.header",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
#endif
         { &hf_ecat_sub_data[0],
           {  "Data", "ecat.sub1.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_data[1],
           {  "Data", "ecat.sub2.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_data[2],
           {  "Data", "ecat.sub3.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_data[3],
           {  "Data", "ecat.sub4.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_data[4],
           {  "Data", "ecat.sub5.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_data[5],
           {  "Data", "ecat.sub6.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_data[6],
           {  "Data", "ecat.sub7.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_data[7],
           {  "Data", "ecat.sub8.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_data[8],
           {  "Data", "ecat.sub9.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_data[9],
           {  "Data", "ecat.sub10.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_data,
           {  "Data", "ecat.data",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_cnt,
           { "Working Cnt", "ecat.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, "The working counter is increased once for each addressed device if at least one byte/bit of the data was successfully read and/or written by that device, it is increased once for every operation made by that device - read/write/read and write", HFILL }
         },
         { &hf_ecat_sub_cnt[0],
           { "Working Cnt", "ecat.sub1.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cnt[1],
           { "Working Cnt", "ecat.sub2.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cnt[2],
           { "Working Cnt", "ecat.sub3.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cnt[3],
           { "Working Cnt", "ecat.sub4.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cnt[4],
           { "Working Cnt", "ecat.sub5.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cnt[5],
           { "Working Cnt", "ecat.sub6.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cnt[6],
           { "Working Cnt", "ecat.sub7.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cnt[7],
           { "Working Cnt", "ecat.sub8.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cnt[8],
           { "Working Cnt", "ecat.sub9.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cnt[9],
           { "Working Cnt", "ecat.sub10.cnt",
             FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_cmd,
           { "Command", "ecat.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[0],
           { "Command", "ecat.sub1.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[1],
           { "Command", "ecat.sub2.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[2],
           { "Command", "ecat.sub3.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[3],
           { "Command", "ecat.sub4.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[4],
           { "Command", "ecat.sub5.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[5],
           { "Command", "ecat.sub6.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[6],
           { "Command", "ecat.sub7.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[7],
           { "Command", "ecat.sub8.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[8],
           { "Command", "ecat.sub9.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_cmd[9],
           { "Command", "ecat.sub10.cmd",
             FT_UINT8, BASE_HEX, VALS(EcCmdShort), 0x0, NULL, HFILL }
         },
         { &hf_ecat_idx,
           { "Index", "ecat.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[0],
           { "Index", "ecat.sub1.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[1],
           { "Index", "ecat.sub2.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[2],
           { "Index", "ecat.sub3.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[3],
           { "Index", "ecat.sub4.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[4],
           { "Index", "ecat.sub5.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[5],
           { "Index", "ecat.sub6.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[6],
           { "Index", "ecat.sub7.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[7],
           { "Index", "ecat.sub8.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[8],
           { "Index", "ecat.sub9.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_idx[9],
           { "Index", "ecat.sub10.idx",
             FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_adp,
           { "Slave Addr", "ecat.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[0],
           { "Slave Addr", "ecat.sub1.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[1],
           { "Slave Addr", "ecat.sub2.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[2],
           { "Slave Addr", "ecat.sub3.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[3],
           { "Slave Addr", "ecat.sub4.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[4],
           { "Slave Addr", "ecat.sub5.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[5],
           { "Slave Addr", "ecat.sub6.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[6],
           { "Slave Addr", "ecat.sub7.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[7],
           { "Slave Addr", "ecat.sub8.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[8],
           { "Slave Addr", "ecat.sub9.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_adp[9],
           { "Slave Addr", "ecat.sub10.adp",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_ado,
           { "Offset Addr", "ecat.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[0],
           { "Offset Addr", "ecat.sub1.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[1],
           { "Offset Addr", "ecat.sub2.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[2],
           { "Offset Addr", "ecat.sub3.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[3],
           { "Offset Addr", "ecat.sub4.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[4],
           { "Offset Addr", "ecat.sub5.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[5],
           { "Offset Addr", "ecat.sub6.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[6],
           { "Offset Addr", "ecat.sub7.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[7],
           { "Offset Addr", "ecat.sub8.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[8],
           { "Offset Addr", "ecat.sub9.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_ado[9],
           { "Offset Addr", "ecat.sub10.ado",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_lad,
           { "Log Addr", "ecat.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[0],
           { "Log Addr", "ecat.sub1.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[1],
           { "Log Addr", "ecat.sub2.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[2],
           { "Log Addr", "ecat.sub3.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[3],
           { "Log Addr", "ecat.sub4.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[4],
           { "Log Addr", "ecat.sub5.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[5],
           { "Log Addr", "ecat.sub6.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[6],
           { "Log Addr", "ecat.sub7.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[7],
           { "Log Addr", "ecat.sub8.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[8],
           { "Log Addr", "ecat.sub9.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_lad[9],
           { "Log Addr", "ecat.sub10.lad",
             FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
#if 0
         { &hf_ecat_len,
           { "Length", "ecat.len",
             FT_UINT16, BASE_DEC, NULL, 0x0,
             NULL, HFILL }
         },
#endif
         { &hf_ecat_int,
           { "Interrupt", "ecat.int",
             FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_dc_diff_da,
           { "DC D-A", "ecat.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_dc_diff_bd,
           { "DC B-D", "ecat.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_dc_diff_cb,
           { "DC C-B", "ecat.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_dc_diff_cd,
           { "DC C-D", "ecat.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_dc_diff_ba,
           { "DC B-A", "ecat.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_dc_diff_ca,
           { "DC C-A", "ecat.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0,
             NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[0],
           { "DC D-A", "ecat.sub1.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[1],
           { "DC D-A", "ecat.sub2.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[2],
           { "DC D-A", "ecat.sub3.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[3],
           { "DC D-A", "ecat.sub4.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[4],
           { "DC D-A", "ecat.sub5.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[5],
           { "DC D-A", "ecat.sub6.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[6],
           { "DC D-A", "ecat.sub7.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[7],
           { "DC D-A", "ecat.sub8.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[8],
           { "DC D-A", "ecat.sub9.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_da[9],
           { "DC D-A", "ecat.sub10.dc.dif.da",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },

         { &hf_ecat_sub_dc_diff_bd[0],
           { "DC B-C", "ecat.sub1.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_bd[1],
           { "DC B-C", "ecat.sub2.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_bd[2],
           { "DC B-C", "ecat.sub3.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_bd[3],
           { "DC B-C", "ecat.sub4.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_bd[4],
           { "DC B-C", "ecat.sub5.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_bd[5],
           { "DC B-C", "ecat.sub6.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_bd[6],
           { "DC B-C", "ecat.sub7.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_bd[7],
           { "DC B-C", "ecat.sub8.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_bd[8],
           { "DC B-C", "ecat.sub9.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_bd[9],
           { "DC B-D", "ecat.sub10.dc.dif.bd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },

         { &hf_ecat_sub_dc_diff_cb[0],
           { "DC C-B", "ecat.sub1.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cb[1],
           { "DC C-B", "ecat.sub2.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cb[2],
           { "DC C-B", "ecat.sub3.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cb[3],
           { "DC C-B", "ecat.sub4.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cb[4],
           { "DC C-B", "ecat.sub5.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cb[5],
           { "DC C-B", "ecat.sub6.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cb[6],
           { "DC C-B", "ecat.sub7.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cb[7],
           { "DC C-B", "ecat.sub8.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cb[8],
           { "DC C-B", "ecat.sub9.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cb[9],
           { "DC C-B", "ecat.sub10.dc.dif.cb",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },

         { &hf_ecat_sub_dc_diff_cd[0],
           { "DC C-D", "ecat.sub1.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cd[1],
           { "DC C-D", "ecat.sub2.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cd[2],
           { "DC C-D", "ecat.sub3.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cd[3],
           { "DC C-D", "ecat.sub4.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cd[4],
           { "DC C-D", "ecat.sub5.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cd[5],
           { "DC C-D", "ecat.sub6.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cd[6],
           { "DC C-D", "ecat.sub7.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cd[7],
           { "DC C-D", "ecat.sub8.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cd[8],
           { "DC C-D", "ecat.sub9.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_cd[9],
           { "DC C-D", "ecat.sub10.dc.dif.cd",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },

         { &hf_ecat_sub_dc_diff_ba[0],
           { "DC B-A", "ecat.sub1.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ba[1],
           { "DC B-A", "ecat.sub2.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ba[2],
           { "DC B-A", "ecat.sub3.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ba[3],
           { "DC B-A", "ecat.sub4.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ba[4],
           { "DC B-A", "ecat.sub5.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ba[5],
           { "DC B-A", "ecat.sub6.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ba[6],
           { "DC B-A", "ecat.sub7.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ba[7],
           { "DC B-A", "ecat.sub8.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ba[8],
           { "DC B-A", "ecat.sub9.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ba[9],
           { "DC B-A", "ecat.sub10.dc.dif.ba",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },

         { &hf_ecat_sub_dc_diff_ca[0],
           { "DC C-A", "ecat.sub1.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ca[1],
           { "DC C-A", "ecat.sub2.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ca[2],
           { "DC C-A", "ecat.sub3.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ca[3],
           { "DC C-A", "ecat.sub4.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ca[4],
           { "DC C-A", "ecat.sub5.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ca[5],
           { "DC C-A", "ecat.sub6.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ca[6],
           { "DC C-A", "ecat.sub7.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ca[7],
           { "DC C-A", "ecat.sub8.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ca[8],
           { "DC C-A", "ecat.sub9.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_sub_dc_diff_ca[9],
           { "DC C-A", "ecat.sub10.dc.dif.ca",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_length_len,
           { "Length", "ecat.subframe.length",
             FT_UINT16, BASE_DEC, NULL, 0x07ff, NULL, HFILL}
         },
         { &hf_ecat_length_r,
           { "Reserved", "ecat.subframe.reserved",
             FT_UINT16, BASE_DEC, VALS(ecat_subframe_reserved_vals), 0x3800, NULL, HFILL}
         },
         { &hf_ecat_length_c,
           { "Round trip", "ecat.subframe.circulating",
             FT_BOOLEAN, 16, TFS(&tfs_ecat_subframe_circulating_vals), 0x4000, NULL, HFILL}
         },
         { &hf_ecat_length_m,
           { "Last indicator", "ecat.subframe.more",
             FT_BOOLEAN, 16, TFS(&tfs_ecat_subframe_more_vals), 0x8000, NULL, HFILL}
         },
         { &hf_ecat_padding,
           { "Pad bytes", "ecat.subframe.pad_bytes",
             FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
         },

         /* Registers */
         { &hf_ecat_reg_revision,
           {"ESC Revision (0x0)", "ecat.reg.revision",
             FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_type,
           {"ESC Type (0x1)", "ecat.reg.type",
             FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_build,
           {"ESC Build (0x2)", "ecat.reg.build",
             FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_fmmucnt,
           {"ESC FMMU Cnt (0x4)", "ecat.reg.fmmucnt",
             FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_smcnt,
           {"ESC SM Cnt (0x5)", "ecat.reg.smcnt",
             FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_ports,
           {"ESC Ports (0x6)", "ecat.reg.ports",
             FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_dpram,
           {"ESC DPRAM (0x7)", "ecat.reg.dpram",
             FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_features,
           {"ESC Features (0x8)", "ecat.reg.features",
             FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_features_fmmurestrict,
           {"FMMU bytewise restriction",	"ecat.reg.features.fmmurestrict",
             FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0001, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_features_smaddrrestrict,
           {"SM adressing restriction",		"ecat.reg.features.smaddrrestrict",
             FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0002, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_features_dcsupport,
           {"DC support",					"ecat.reg.features.dcsupport",
             FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0004, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_features_dc64support,
           {"DC 64 bit support",			"ecat.reg.features.dc64support",
             FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0008, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_features_ebuslowjitter,
           {"E-Bus low jitter",				"ecat.reg.features.ebuslowjitter",
             FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0010, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_features_ebusextlinkdetect,
           {"E-Bus ext. link detection",	"ecat.reg.features.ebusextlinkdetect",
             FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0020, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_features_miiextlinkdetect,
           {"MII ext. link detection",		"ecat.reg.features.miiextlinkdetect",
             FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0040, NULL, HFILL }
         },
         { &hf_ecat_reg_esc_features_crcext,
           {"CRC ext. detection",			"ecat.reg.features.crcext",
             FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0080, NULL, HFILL }
         },
         { &hf_ecat_reg_physaddr,
           {"Phys Addr (0x10)", "ecat.reg.physaddr",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_physaddr2,
           {"Phys Addr 2nd (0x12)", "ecat.reg.physaddr2",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl1,
           {"ESC Ctrl (0x100)", "ecat.reg.dlctrl1",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl1_killnonecat,
           {"Kill non EtherCAT frames",	 "ecat.reg.dlctrl1.killnonecat",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl1_port0extlinkdetect,
           {"Port 0 ext. link detection", "ecat.reg.dlctrl1.port0extlinkdetect",
           FT_BOOLEAN, 8, TFS(&tfs_local_disabled_enabled), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl1_port1extlinkdetect,
           {"Port 1 ext. link detection", "ecat.reg.dlctrl1.port1extlinkdetect",
           FT_BOOLEAN, 8, TFS(&tfs_local_disabled_enabled), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl1_port2extlinkdetect,
           {"Port 2 ext. link detection", "ecat.reg.dlctrl1.port2extlinkdetect",
           FT_BOOLEAN, 8, TFS(&tfs_local_disabled_enabled), 0x40, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl1_port3extlinkdetect,
           {"Port 3 ext. link detection", "ecat.reg.dlctrl1.port3extlinkdetect",
           FT_BOOLEAN, 8, TFS(&tfs_local_disabled_enabled), 0x80, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl2,
           {"ESC Ctrl (0x101)", "ecat.reg.dlcrtl2",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl2_port0,
           {"Port 0", "ecat.reg.dlcrtl2.port0",
           FT_UINT8, BASE_HEX, VALS(vals_esc_reg_101), 0x03, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl2_port1,
           {"Port 1", "ecat.reg.dlcrtl2.port1",
           FT_UINT8, BASE_HEX, VALS(vals_esc_reg_101), 0x0C, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl2_port2,
           {"Port 2", "ecat.reg.dlcrtl2.port2",
           FT_UINT8, BASE_HEX, VALS(vals_esc_reg_101), 0x30, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl2_port3,
           {"Port 3", "ecat.reg.dlcrtl2.port3",
           FT_UINT8, BASE_HEX, VALS(vals_esc_reg_101), 0xC0, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl3,
           {"ESC Ctrl (0x102)", "ecat.reg.dlctrl3",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl3_fifosize,
           {"Fifo size", "ecat.reg.dlctrl3.fifosize",
           FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl3_lowebusjit,
           {"Low E-Bus jitter", "ecat.reg.dlctrl3.lowebusjit",
           FT_BOOLEAN, 8, TFS(&tfs_local_disabled_enabled), 0x08, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl4,
           {"ESC Ctrl (0x103)", "ecat.reg.dlctrl4",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dlctrl4_2ndaddress,
           {"Second address", "ecat.reg.dlctrl4.2ndaddress",
           FT_BOOLEAN, 8, TFS(&tfs_local_disabled_enabled), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus1,
           {"ESC Status (0x110)", "ecat.reg.dlstatus1",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus1_operation,
           {"Operation",	"ecat.reg.dlstatus1.operation",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus1_pdiwatchdog,
           {"PDI watchdog",			 "ecat.reg.dlstatus1.pdiwatchdog",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_watchdog), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus1_enhlinkdetect,
           {"Enh. Link Detection",  "ecat.reg.dlstatus1.enhlinkdetect",
           FT_BOOLEAN, 8, TFS(&tfs_local_disabled_enabled), 0x04, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus1_physlink_port0,
           {"Physical link Port 0", "ecat.reg.dlstatus1.physlink.port0",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus1_physlink_port1,
           {"Physical link Port 1", "ecat.reg.dlstatus1.physlink.port1",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus1_physlink_port2,
           {"Physical link Port 2", "ecat.reg.dlstatus1.physlink.port2",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x40, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus1_physlink_port3,
           {"Physical link Port 3", "ecat.reg.dlstatus1.physlink.port3",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x80, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus2,
           {"ESC Status (0x111)", "ecat.reg.dlstatus2",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus2_port0,
           {"Port 0", "ecat.reg.dlstatus2.port0",
           FT_UINT8, BASE_HEX, VALS(vals_esc_reg_111), 0x03, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus2_port1,
           {"Port 1", "ecat.reg.dlstatus2.port1",
           FT_UINT8, BASE_HEX, VALS(vals_esc_reg_111), 0x0C, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus2_port2,
           {"Port 2", "ecat.reg.dlstatus2.port2",
           FT_UINT8, BASE_HEX, VALS(vals_esc_reg_111), 0x30, NULL, HFILL }
         },
         { &hf_ecat_reg_dlstatus2_port3,
           {"Port 3", "ecat.reg.dlstatus2.port3",
           FT_UINT8, BASE_HEX, VALS(vals_esc_reg_111), 0xC0, NULL, HFILL }
         },
         { &hf_ecat_reg_regprotect,
           {"Write Register Protect (0x20)", "ecat.reg.regprotect",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_accessprotect,
           {"Access Protect (0x30)", "ecat.reg.accessprotect",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_resetecat,
           {"ESC reset Ecat (0x40)", "ecat.reg.resetecat",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_resetpdi,
           {"ESC reset Pdi (0x41)", "ecat.reg.resetpdi",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_regphysrwoffs,
           {"Phys. RW Offset (0x108)", "ecat.regphysrwoffs",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_alctrl,
           {"AL Ctrl (0x120)", "ecat.reg.alctrl",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_alctrl_ctrl,
           {"Al Ctrl", "ecat.reg.alctrl.ctrl",
           FT_UINT16, BASE_HEX, VALS(vals_esc_reg_120), 0x0f, NULL, HFILL }
         },
         { &hf_ecat_reg_alctrl_errack,
           {"Error Ack", "ecat.reg.alctrl.errack",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_alctrl_id,
           {"Id", "ecat.reg.alctrl.id",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_alstatus,
           {"AL Status (0x130)", "ecat.reg.alstatus",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_alstatus_status,
           {"Al Status", "ecat.reg.alstatus.status",
           FT_UINT16, BASE_HEX, VALS(vals_esc_reg_120), 0x0f, NULL, HFILL }
         },
         { &hf_ecat_reg_alstatus_err,
           {"Error", "ecat.reg.alstatus.err",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_alstatus_id,
           {"Id", "ecat.reg.alstatus.id",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_alstatuscode,
           {"AL Status Code (0x134)", "ecat.reg.alstatuscode",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl1,
           {"PDI Ctrl (0x140)", "ecat.reg.pdictrl1",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl1_pdi,
           {"PDI", "ecat.reg.pdictrl1.pdi",
           FT_UINT8, BASE_HEX, VALS(vals_esc_reg_140), 0xff, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl2,
           {"PDI Ctrl (0x141)", "ecat.reg.pdictrl2",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl2_devemul,
           {"Device emulation", "ecat.reg.pdictrl2.devemul",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl2_enhlnkdetect,
         {"Enhanced link detection", "ecat.reg.pdictrl2.enhlnkdetect",
           FT_BOOLEAN, 8, TFS(&tfs_local_disable_enable), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl2_dcsyncout,
           {"Enable DC sync out", "ecat.reg.pdictrl2.dcsyncout",
           FT_BOOLEAN, 8, TFS(&tfs_local_disable_enable), 0x04, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl2_dcsyncin,
           {"Enable DC latch in", "ecat.reg.pdictrl2.dcsyncin",
           FT_BOOLEAN, 8, TFS(&tfs_local_disable_enable), 0x08, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl2_enhlnkdetect0,
           {"Enhanced link detection port 0", "ecat.reg.pdictrl2.enhlnkdetect0",
           FT_BOOLEAN, 8, TFS(&tfs_local_disable_enable), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl2_enhlnkdetect1,
           {"Enhanced link detection port 1", "ecat.reg.pdictrl2.enhlnkdetect1",
           FT_BOOLEAN, 8, TFS(&tfs_local_disable_enable), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl2_enhlnkdetect2,
           {"Enhanced link detection port 2", "ecat.reg.pdictrl2.enhlnkdetect2",
           FT_BOOLEAN, 8, TFS(&tfs_local_disable_enable), 0x40, NULL, HFILL }
         },
         { &hf_ecat_reg_pdictrl2_enhlnkdetect3,
           {"Enhanced link detection port 3", "ecat.reg.pdictrl2.enhlnkdetect3",
           FT_BOOLEAN, 8, TFS(&tfs_local_disable_enable), 0x80, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask,
           {"ECAT IRQ Mask (0x200)", "ecat.reg.irqmask.ecat_mask",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_latchevt,
           {"Latch event", "ecat.reg.irqmask.ecat_mask.latchevt",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0001, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_escstatevt,
           {"ESC Status event", "ecat.reg.irqmask.ecat_mask.escstatevt",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0004, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_alstatevt,
           {"AL Status event", "ecat.reg.irqmask.ecat_mask.alstatevt",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0008, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_sm0irq,
           {"SM 0 IRQ", "ecat.reg.irqmask.ecat_mask.sm0irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0100, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_sm1irq,
           {"SM 1 IRQ", "ecat.reg.irqmask.ecat_mask.sm1irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0200, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_sm2irq,
           {"SM 2 IRQ", "ecat.reg.irqmask.ecat_mask.sm2irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0400, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_sm3irq,
           {"SM 3 IRQ", "ecat.reg.irqmask.ecat_mask.sm3irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0800, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_sm4irq,
           {"SM 4 IRQ", "ecat.reg.irqmask.ecat_mask.sm4irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x1000, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_sm5irq,
           {"SM 5 IRQ", "ecat.reg.irqmask.ecat_mask.sm5irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x2000, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_sm6irq,
           {"SM 6 IRQ", "ecat.reg.irqmask.ecat_mask.sm6irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x4000, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_mask_sm7irq,
           {"SM 7 IRQ", "ecat.reg.irqmask.ecat_mask.sm7irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x8000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL,
           {"PDI IRQ Mask L (0x204)", "ecat.reg.irqmask.pdiL",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_alctrl,
           {"AL Ctrl", "ecat.reg.irqmask.pdiL.alctrl",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x1, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_latchin,
           {"Latch input", "ecat.reg.irqmask.pdiL.latchin",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sync0,
           {"SYNC 0", "ecat.reg.irqmask.pdiL.sync0",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x04, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sync1,
           {"SYNC 1", "ecat.reg.irqmask.pdiL.sync1",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x08, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_smchg,
           {"SM changed", "ecat.reg.irqmask.pdiL.smchg",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_eepromcmdpen,
           {"EEPROM command pending", "ecat.reg.irqmask.pdiL.eepromcmdpen",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sm0,
           {"SM 0", "ecat.reg.irqmask.pdiL.sm0",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0100, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sm1,
           {"SM 1", "ecat.reg.irqmask.pdiL.sm1",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0200, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sm2,
           {"SM 2", "ecat.reg.irqmask.pdiL.sm2",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0400, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sm3,
           {"SM 3", "ecat.reg.irqmask.pdiL.sm3",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0800, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sm4,
           {"SM 4", "ecat.reg.irqmask.pdiL.sm4",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x1000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sm5,
           {"SM 5", "ecat.reg.irqmask.pdiL.sm5",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x2000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sm6,
           {"SM 6", "ecat.reg.irqmask.pdiL.sm6",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x4000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiL_sm7,
           {"SM 7", "ecat.reg.irqmask.pdiL.sm7",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x8000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdiH,
           {"PDI IRQ Mask H (0x206)", "ecat.reg.irqmask.pdiH",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat,
           {"ECAT IRQ (0x210)", "ecat.reg.irq.ecat",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_latchevt,
           {"Latch event", "ecat.reg.irq.ecat.latchevt",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0001, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_escstatevt,
           {"ESC Status event", "ecat.reg.irq.ecat.escstatevt",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0004, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_alstatevt,
           {"AL Status event", "ecat.reg.irq.ecat.alstatevt",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0008, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_sm0irq,
           {"SM 0 IRQ", "ecat.reg.irq.ecat.sm0irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0100, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_sm1irq,
           {"SM 1 IRQ", "ecat.reg.irq.ecat.sm1irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0200, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_sm2irq,
           {"SM 2 IRQ", "ecat.reg.irq.ecat.sm2irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0400, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_sm3irq,
           {"SM 3 IRQ", "ecat.reg.irq.ecat.sm3irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0800, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_sm4irq,
           {"SM 4 IRQ", "ecat.reg.irq.ecat.sm4irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x1000, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_sm5irq,
           {"SM 5 IRQ", "ecat.reg.irq.ecat.sm5irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x2000, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_sm6irq,
           {"SM 6 IRQ", "ecat.reg.irq.ecat.sm6irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x4000, NULL, HFILL }
         },
         { &hf_ecat_reg_ecat_sm7irq,
           {"SM 7 IRQ", "ecat.reg.irq.ecat.sm7irq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x8000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1,
           {"PDI IRQ 1 (0x220)", "ecat.reg.irq.pdi1",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_alctrl,
           {"AL Ctrl", "ecat.reg.irq.pdi1.alctrl",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x1, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_latchin,
           {"Latch input", "ecat.reg.irq.pdi1.latchin",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sync0,
           {"SYNC 0", "ecat.reg.irq.pdi1.sync0",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x04, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sync1,
           {"SYNC 1", "ecat.reg.irq.pdi1.sync1",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x08, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_smchg,
           {"SM changed", "ecat.reg.irq.pdi1.smchg",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_eepromcmdpen,
           {"EEPROM command pending", "ecat.reg.irq.pdi1.eepromcmdpen",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sm0,
           {"SM 0", "ecat.reg.irq.pdi1.sm0",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0100, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sm1,
           {"SM 1", "ecat.reg.irq.pdi1.sm1",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0200, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sm2,
           {"SM 2", "ecat.reg.irq.pdi1.sm2",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0400, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sm3,
           {"SM 3", "ecat.reg.irq.pdi1.sm3",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0800, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sm4,
           {"SM 4", "ecat.reg.irq.pdi1.sm4",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x1000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sm5,
           {"SM 5", "ecat.reg.irq.pdi1.sm5",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x2000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sm6,
           {"SM 6", "ecat.reg.irq.pdi1.sm6",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x4000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi1_sm7,
           {"SM 7", "ecat.reg.irq.pdi1.sm7",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x8000, NULL, HFILL }
         },
         { &hf_ecat_reg_pdi2,
           {"PDI IRQ 2 (0x222)", "ecat.reg.irq.pdi2",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_crc0,
           {"CRC 0 (0x300)", "ecat.reg.crc0",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_crc1,
           {"CRC 1 (0x302)", "ecat.reg.crc1",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_crc2,
           {"CRC 2 (0x304)", "ecat.reg.crc2",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_crc3,
           {"CRC 3 (0x306)", "ecat.reg.crc3",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_crc0_frame,
           {"Invalid frame", "ecat.reg.crc0.frame",
           FT_UINT16, BASE_HEX, NULL, 0x00ff, NULL, HFILL }
         },
         { &hf_ecat_reg_crc0_rx,
           {"RX error", "ecat.reg.crc0.rx",
           FT_UINT16, BASE_HEX, NULL, 0xff00, NULL, HFILL }
         },
         { &hf_ecat_reg_crc1_frame,
           {"Invalid frame", "ecat.reg.crc1.frame",
           FT_UINT16, BASE_HEX, NULL, 0x00ff, NULL, HFILL }
         },
         { &hf_ecat_reg_crc1_rx,
           {"RX error", "ecat.reg.crc1.rx",
           FT_UINT16, BASE_HEX, NULL, 0xff00, NULL, HFILL }
         },
         { &hf_ecat_reg_crc2_frame,
           {"Invalid frame", "ecat.reg.crc2.frame",
           FT_UINT16, BASE_HEX, NULL, 0x00ff, NULL, HFILL }
         },
         { &hf_ecat_reg_crc2_rx,
           {"RX error", "ecat.reg.crc2.rx",
           FT_UINT16, BASE_HEX, NULL, 0xff00, NULL, HFILL }
         },
         { &hf_ecat_reg_crc3_frame,
           {"Invalid frame", "ecat.reg.crc3.frame",
           FT_UINT16, BASE_HEX, NULL, 0x00ff, NULL, HFILL }
         },
         { &hf_ecat_reg_crc3_rx,
           {"RX error", "ecat.reg.crc3.rx",
           FT_UINT16, BASE_HEX, NULL, 0xff00, NULL, HFILL }
         },
         { &hf_ecat_reg_crc_fwd0,
           {"Forw. CRC 0 (0x308)", "ecat.reg.crc.fwd0",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_crc_fwd1,
           {"Forw. CRC 1 (0x309)", "ecat.reg.crc.fwd1",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_crc_fwd2,
           {"Forw. CRC 2 (0x30A)", "ecat.reg.crc.fwd2",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_crc_fwd3,
           {"Forw. CRC 3 (0x30C)", "ecat.reg.crc.fwd3",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_processuniterr,
           {"Process unit error (0x30C)", "ecat.reg.processuniterr",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_pdierr,
           {"PDI error (0x30D)", "ecat.reg.pdierr",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_linklost0,
           {"Link Lost 0 (0x310)", "ecat.reg.linklost0",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_linklost1,
           {"Link Lost 1 (0x311)", "ecat.reg.linklost1",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_linklost2,
           {"Link Lost 2 (0x312)", "ecat.reg.linklost2",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_linklost3,
           {"Link Lost 3 (0x313)", "ecat.reg.linklost3",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_wd_divisor,
           {"WD Divisor (0x400)", "ecat.reg.wd.divisor",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_wd_timepdi,
           {"WD Time PDI (0x410)", "ecat.reg.wd.timepdi",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_wd_timesm,
           {"WD Time SM (0x420)", "ecat.reg.wd.timesm",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_wd_status,
           {"WD Status (0x440)", "ecat.reg.wd.status",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_wd_status_pdwatchdog,
           {"PD watchdog", "ecat.reg.wd.status.pdwatchdog",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_watchdog), 0x1, NULL, HFILL }
         },
         { &hf_ecat_reg_wd_cntsm,
           {"WD SM Counter (0x442)", "ecat.reg.wd.cntsm",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_wd_cntpdi,
           {"WD PDI Counter (0x443)", "ecat.reg.wd.cntpdi",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_eeprom_assign,
           {"EEPROM Assign (0x500)", "ecat.reg.eeprom.assign",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_eeprom_assign_ctrl,
           {"EEPROM access ctrl", "ecat.reg.eeprom.assign.ctrl",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_500_0), 0x1, NULL, HFILL }
         },
         { &hf_ecat_reg_eeprom_assign_pdiaccess,
           {"Reset PDI access", "ecat.reg.eeprom.assign.pdiaccess",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_500_1), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_eeprom_assign_status,
           {"EEPROM access status", "ecat.reg.eeprom.assign.status",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_500_0), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat,
           {"EEPROM Ctrl/Status (0x502)", "ecat.reg.ctrlstat",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_wraccess,
           {"Write access", "ecat.reg.ctrlstat.wraccess",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x1, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_eepromemul,
           {"EEPROM emulation", "ecat.reg.ctrlstat.eepromemul",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_502_5), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_8bacc,
           {"8 byte access", "ecat.reg.ctrlstat.8bacc",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x40, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_2bacc,
           {"2 byte address", "ecat.reg.ctrlstat.2bacc",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x80, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_rdacc,
           {"Read access", "ecat.reg.ctrlstat.rdacc",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0100, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_wracc,
           {"Write access", "ecat.reg.ctrlstat.wracc",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0200, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_reloadacc,
           {"Reload access", "ecat.reg.ctrlstat.reloadacc",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0400, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_crcerr,
           {"CRC error", "ecat.reg.ctrlstat.crcerr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0800, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_lderr,
           {"Load error", "ecat.reg.ctrlstat.lderr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x1000, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_cmderr,
           {"Cmd error", "ecat.reg.ctrlstat.cmderr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x2000, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_wrerr,
           {"Write error", "ecat.reg.ctrlstat.wrerr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x4000, NULL, HFILL }
         },
         { &hf_ecat_reg_ctrlstat_busy,
           {"Busy", "ecat.reg.ctrlstat.busy",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x8000, NULL, HFILL }
         },
         { &hf_ecat_reg_addrl,
           {"EEPROM Address Lo (0x504)", "ecat.reg.addrl",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_addrh,
           {"EEPROM Address Hi (0x506)", "ecat.reg.addrh",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_data0,
           {"EEPROM Data 0 (0x508)", "ecat.reg.data0",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_data1,
           {"EEPROM Data 1 (0x50A)", "ecat.reg.data1",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_data2,
           {"EEPROM Data 2 (0x50c)", "ecat.reg.data2",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_data3,
           {"EEPROM Data 3 (0x50e)", "ecat.reg.data3",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_ctrlstat,
           {"Phy MIO Ctrl/Status (0x510)", "ecat.reg.mio.ctrlstat",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_ctrlstat_wracc1,
           {"Write access", "ecat.reg.mio.ctrlstat.wracc1",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x001, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_ctrlstat_offsphy,
           {"Offset Phy offset", "ecat.reg.mio.ctrlstat.offsphy",
           FT_UINT16, BASE_HEX, NULL, 0x008f, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_ctrlstat_rdacc,
           {"Read access", "ecat.reg.mio.ctrlstat.rdacc",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0100, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_ctrlstat_wracc2,
           {"Write access", "ecat.reg.mio.ctrlstat.wracc2",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0200, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_ctrlstat_wrerr,
           {"Write error", "ecat.reg.mio.ctrlstat.wrerr",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x4000, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_ctrlstat_busy,
           {"Busy", "ecat.reg.mio.ctrlstat.busy",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x8000, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_addr,
           {"Phy MIO Address (0x512)", "ecat.reg.mio.addr",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_addr_phyaddr,
           {"Phy address", "ecat.reg.mio.addr.phyaddr",
           FT_UINT16, BASE_HEX, NULL, 0x000F, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_addr_mioaddr,
           {"MIO address", "ecat.reg.mio.addr.mioaddr",
           FT_UINT16, BASE_HEX, NULL, 0x0F00, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_data,
           {"Phy MIO Data (0x514)", "ecat.reg.mio.data",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_access,
           {"MIO access (0x516)", "ecat.reg.mio.access",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_access_ecatacc,
           {"ECAT claims exclusive access", "ecat.reg.mio.access.ecatacc",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0001, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_access_pdiacc,
           {"PDI has access to MII management", "ecat.reg.mio.access.pdiacc",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0100, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_access_forcereset,
           {"Force PDI to reset 0517.0", "ecat.reg.mio.access.forcereset",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0200, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status0,
           {"MIO port status 0 (0x518)", "ecat.reg.mio.status0",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status0_physlink,
           {"Physical link detected", "ecat.reg.mio.status0.physlink",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x001, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status0_link,
           {"Link detected", "ecat.reg.mio.status0.link",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0002, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status0_linkstatuserr,
           {"Link status error", "ecat.reg.mio.status0.linkstatuserr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0004, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status0_readerr,
           {"Read error", "ecat.reg.mio.status0.readerr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0008, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status0_linkpartnererr,
           {"Link partner error", "ecat.reg.mio.status0.linkpartnererr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0010, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status0_phycfgupdated,
           {"Phy config updated", "ecat.reg.mio.status0.phycfgupdated",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0020, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status1,
           {"MIO port status 1 (0x519)", "ecat.reg.mio.status1",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status1_physlink,
           {"Physical link detected", "ecat.reg.mio.status1.physlink",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x001, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status1_link,
           {"Link detected", "ecat.reg.mio.status1.link",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0002, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status1_linkstatuserr,
           {"Link status error", "ecat.reg.mio.status1.linkstatuserr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0004, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status1_readerr,
           {"Read error", "ecat.reg.mio.status1.readerr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0008, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status1_linkpartnererr,
           {"Link partner error", "ecat.reg.mio.status1.linkpartnererr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0010, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status1_phycfgupdated,
           {"Phy config updated", "ecat.reg.mio.status1.phycfgupdated",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0020, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status2,
           {"MIO port status 2 (0x51A)", "ecat.reg.mio.status2",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status2_physlink,
           {"Physical link detected", "ecat.reg.mio.status2.physlink",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x001, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status2_link,
           {"Link detected", "ecat.reg.mio.status2.link",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0002, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status2_linkstatuserr,
           {"Link status error", "ecat.reg.mio.status2.linkstatuserr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0004, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status2_readerr,
           {"Read error", "ecat.reg.mio.status2.readerr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0008, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status2_linkpartnererr,
           {"Link partner error", "ecat.reg.mio.status2.linkpartnererr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0010, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status2_phycfgupdated,
           {"Phy config updated", "ecat.reg.mio.status2.phycfgupdated",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0020, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status3,
           {"MIO port status 3 (0x51B)", "ecat.reg.mio.status3",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status3_physlink,
           {"Physical link detected", "ecat.reg.mio.status3.physlink",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x001, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status3_link,
           {"Link detected", "ecat.reg.mio.status3.link",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0002, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status3_linkstatuserr,
           {"Link status error", "ecat.reg.mio.status3.linkstatuserr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0004, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status3_readerr,
           {"Read error", "ecat.reg.mio.status3.readerr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0008, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status3_linkpartnererr,
           {"Link partner error", "ecat.reg.mio.status3.linkpartnererr",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0010, NULL, HFILL }
         },
         { &hf_ecat_reg_mio_status3_phycfgupdated,
           {"Phy config updated", "ecat.reg.mio.status3.phycfgupdated",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x0020, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu,
           {"FMMU", "ecat.fmmu",
           FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_lstart,
           { "Log Start", "ecat.fmmu.lstart",
           FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_llen,
           { "Log Length", "ecat.fmmu.llen",
           FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_lstartbit,
           { "Log StartBit", "ecat.fmmu.lstartbit",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_lendbit,
           { "Log EndBit", "ecat.fmmu.lendbit",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_pstart,
           { "Phys Start", "ecat.fmmu.pstart",
           FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_pstartbit,
           { "Phys StartBit", "ecat.fmmu.pstartbit",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_type,
           { "Type", "ecat.fmmu.type",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_typeread,
           { "Type", "ecat.fmmu.typeread",
           FT_BOOLEAN, 8, TFS(&tfs_ecat_fmmu_typeread), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_typewrite,
           { "Type", "ecat.fmmu.typewrite",
           FT_BOOLEAN, 8, TFS(&tfs_ecat_fmmu_typewrite), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_activate,
           { "Activate", "ecat.fmmu.activate",
           FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_fmmu_activate0,
           { "FMMU", "ecat.fmmu.activate0",
           FT_BOOLEAN, 8, TFS(&tfs_ecat_fmmu_activate), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman,
           {"SyncManager", "ecat.syncman",
           FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_start,
           {"SM Start", "ecat.syncman.start",
           FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_len,
           {"SM Length", "ecat.syncman.len",
           FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_ctrlstatus,
           {"SM Ctrl/Status", "ecat.syncman.ctrlstatus",
           FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_pmode,
           {"OpMode", "ecat.syncman.opmode",
           FT_UINT16, BASE_HEX, VALS(vals_esc_reg_8041), 0x0003, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_access,
           {"Access", "ecat.syncman.access",
           FT_UINT16, BASE_HEX, VALS(vals_esc_reg_8042), 0x000c, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_irq_ecat,
           {"ECAT IRQ", "ecat.syncman.irq.ecat",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0010, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_irq_pdi,
           {"PDI IRQ", "ecat.syncman.irq.pdi",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0020, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_wdt,
           {"Watchdog trigger", "ecat.syncman.wdt",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0040, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_irq_write,
           {"IRQ write", "ecat.syncman.irq.write",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0100, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_irq_read,
           {"IRQ read", "ecat.syncman.irq.read",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0200, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_1bufstate,
           {"1 buffer state", "ecat.syncman.1bufstate",
           FT_BOOLEAN, 16, TFS(&tfs_esc_reg_8051), 0x0800, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_3bufstate,
           {"3 buffer state", "ecat.syncman.3bufstate",
           FT_UINT16, BASE_HEX, VALS(vals_esc_reg_8052), 0x3000, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_sm_enable,
           {"SM Enable", "ecat.syncman.smenable",
           FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_enable,
           {"Enable", "ecat.syncman.enable",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x1, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_repeatreq,
           {"Repeat request", "ecat.syncman.repeatreq",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_latchsmchg_ecat,
           {"Latch SyncMan Change ECAT", "ecat.syncman.latchsmchg.ecat",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x40, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_latchsmchg_pdi,
           {"Latch SyncMan Change PDI", "ecat.syncman.latchsmchg.pdi",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x80, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_deactivate,
           {"Deactivate", "ecat.syncman.deactivate",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0100, NULL, HFILL }
         },
         { &hf_ecat_reg_syncman_repeatack,
           {"Repeat acknowledge", "ecat.syncman.repeatack",
           FT_BOOLEAN, 16, TFS(&tfs_local_true_false), 0x0200, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_recv0,
           {"DC RecvTime_0 (0x900)", "ecat.reg.dc.recv0",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_recv1,
           {"DC RecvTime_1 (0x904)", "ecat.reg.dc.recv1",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_recv2,
           {"DC RecvTime_2 (0x908)", "ecat.reg.dc.recv2",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_recv3,
           {"DC RecvTime_3 (0x90c)", "ecat.reg.dc.recv3",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_systime,
           {"DC SysTime (0x910)", "ecat.reg.dc.systime",
           FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_systimeL,
           {"DC SysTime L (0x910)", "ecat.reg.dc.systimeL",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_systimeH,
           {"DC SysTime H (0x914)", "ecat.reg.dc.systimeH",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_recvtime64,
           {"DC RecvTime (0x918)", "ecat.reg.dc.recvtime64",
           FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_systimeoffs,
           {"DC SysTimeOffs (0x920)", "ecat.reg.dc.systimeoffs",
           FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_systimeoffsl,
           {"DC SysTimeOffs L (0x920)", "ecat.reg.dc.systimeoffsl",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_systimeoffsh,
           {"DC SysTimeOffs H (0x924)", "ecat.reg.dc.systimeoffsh",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_systimedelay,
           {"DC SysTimeDelay (0x928)", "ecat.reg.dc.systimedelay",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_ctrlerr,
           {"DC CtrlError (0x92c)", "ecat.reg.dc.ctrlerr",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_speedstart,
           {"DC SpeedStart (0x930)", "ecat.reg.dc.speedstart",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_speeddiff,
           {"DC SpeedDiff (0x932)", "ecat.reg.dc.speeddiff",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_fltdepth_systimediff,
           {"DC Filter Depth System Time difference (0x934)", "ecat.reg.dc.fltdepth.systimediff",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_fltdepth_speedcnt,
           {"DC Filter Depth Speed counter (0x935)", "ecat.reg.dc.fltdepth.speedcnt",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_cycunitctrl,
           {"DC Cyclic Unit Control (0x980)", "ecat.reg.dc.cycunitctrl",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_cycunitctrl_access_cyclic,
           {"Write access cyclic", "ecat.reg.dc.cycunitctrl.access_cyclic",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_9801), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_cycunitctrl_access_latch0,
           {"Write access latch 0", "ecat.reg.dc.cycunitctrl.access_latch0",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_9801), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_cycunitctrl_access_latch1,
           {"Write access latch 1", "ecat.reg.dc.cycunitctrl.access_latch1",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_9801), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activation,
           {"DC Activation (0x981)", "ecat.reg.dc.activation",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activation_enablecyclic,
           {"Enable cyclic", "ecat.reg.dc.activation.enablecyclic",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activation_gen_sync0,
           {"Generate SYNC 0", "ecat.reg.dc.activation.gen_sync0",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activation_gen_sync1,
           {"Generate SYNC 1", "ecat.reg.dc.activation.gen_sync1",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x04, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activation_autoactivation,
           {"Auto activation", "ecat.reg.dc.activation.autoactivation",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x08, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activation_stimeext,
           {"Start time extension 32->64", "ecat.reg.dc.activation.stimeext",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x10, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activation_stimecheck,
           {"Start time chheck", "ecat.reg.dc.activation.stimecheck",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x20, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activation_hlfrange,
           {"Half range", "ecat.reg.dc.activation.hlfrange",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x40, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activation_dblrange,
           {"Debug pulse", "ecat.reg.dc.activation.dblrange",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x80, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_cycimpuls,
           {"DC CycImpulse (0x982)", "ecat.reg.dc.cycimpuls",
           FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activationstat,
           {"DC Activation status (0x984)", "ecat.reg.dc.activationstat",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activationstat_sync0pend,
           {"SYNC 0 pending", "ecat.reg.dc.activationstat.sync0pend",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activationstat_sync1pend,
           {"SYNC 1 pending", "ecat.reg.dc.activationstat.sync1pend",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_activationstat_stimeoutofrange,
           {"Start time out of range", "ecat.reg.dc.activationstat.stimeoutofrange",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x04, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_sync0_status,
           {"DC Sync0 Status (0x98e)", "ecat.reg.dc.sync0.status",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_sync0_status_triggered,
           {"triggered", "ecat.reg.dc.sync0.status.triggered",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_sync1_status,
           {"DC Sync0 Status1 (0x98f)", "ecat.reg.dc.sync1.status",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_sync1_status_triggered,
           {"triggered", "ecat.reg.dc.sync1.status.triggered",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_starttime0,
           {"DC StartTime0 (0x990)", "ecat.reg.dc.starttime0",
           FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_starttime1,
           {"DC StartTime1 (0x998)", "ecat.reg.dc.starttime1",
           FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_cyctime0,
           {"DC CycTime0 (0x9a0)", "ecat.reg.dc.cyctime0",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_cyctime1,
           {"DC CycTime1 (0x9a4)", "ecat.reg.dc.cyctime1",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch0_ctrl,
           {"DC Latch0 Ctrl (0x9a8)", "ecat.reg.dc.latch0.ctrl",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch0_ctrl_pos,
           {"pos", "ecat.reg.dc.latch0.ctrl.pos",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_9A8E1), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch0_ctrl_neg,
           {"neg", "ecat.reg.dc.latch0.ctrl.neg",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_9A8E1), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch1_ctrl,
           {"DC Latch1 Ctrl (0x9a9)", "ecat.reg.dc.latch1.ctrl",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch1_ctrl_pos,
           {"pos", "ecat.reg.dc.latch1.ctrl.pos",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_9A8E1), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch1_ctrl_neg,
           {"neg", "ecat.reg.dc.latch1.ctrl.neg",
           FT_BOOLEAN, 8, TFS(&tfs_esc_reg_9A8E1), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch0_status,
           {"DC Latch0 Status (0x9ae)", "ecat.reg.dc.latch0.status",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch0_status_eventpos,
           {"Event pos", "ecat.reg.dc.latch0.status.eventpos",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch0_status_eventneg,
           {"Event neg", "ecat.reg.dc.latch0.status.eventneg",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch0_status_pinstate,
           {"pin state", "ecat.reg.dc.latch0.status.pinstate",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x04, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch1_status,
           {"DC Latch1 Status (0x9ae)", "ecat.reg.dc.latch1.status",
           FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch1_status_eventpos,
           {"Event pos", "ecat.reg.dc.latch1.status.eventpos",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x01, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch1_status_eventneg,
           {"Event neg", "ecat.reg.dc.latch1.status.eventneg",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x02, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch1_status_pinstate,
           {"pin state", "ecat.reg.dc.latch1.status.pinstate",
           FT_BOOLEAN, 8, TFS(&tfs_local_true_false), 0x04, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch0_pos,
           {"DC Latch0 Pos (0x9b0)", "ecat.reg.dc.latch0.pos",
           FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch0_neg,
           {"DC Latch0 Neg (0x9b8)", "ecat.reg.dc.latch0.neg",
           FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch1_pos,
           {"DC Latch1 Pos (0x9c0)", "ecat.reg.dc.latch1.pos",
           FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_latch1_neg,
           {"DC Latch1 Neg (0x9c8)", "ecat.reg.dc.latch1.neg",
           FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_rcvsyncmanchg,
           {"DC RecvSyncManChange (0x9f0)", "ecat.reg.dc.rcvsyncmanchg",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_pdismstart,
           {"DC PdiSyncManStart (0x9f8)", "ecat.reg.dc.pdismstart",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
         { &hf_ecat_reg_dc_pdismchg,
           {"DC PdiSyncManChange (0x9fc)", "ecat.reg.dc.pdismchg",
           FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
         },
      };

   static gint *ett[] =
      {
         &ett_ecat,
         &ett_ecat_header,
         &ett_ecat_dc,
         &ett_ecat_length,
         &ett_ecat_padding,
         &ett_ecat_datagram_subtree,
         &ett_ecat_reg_esc_features,
         &ett_ecat_reg_dlctrl1,
         &ett_ecat_reg_dlctrl2,
         &ett_ecat_reg_dlctrl3,
         &ett_ecat_reg_dlctrl4,
         &ett_ecat_reg_dlstatus1,
         &ett_ecat_reg_dlstatus2,
         &ett_ecat_reg_alctrl,
         &ett_ecat_reg_alstatus,
         &ett_ecat_reg_pdictrl1,
         &ett_ecat_reg_pdictrl2,
         &ett_ecat_reg_ecat_mask,
         &ett_ecat_reg_pdiL,
         &ett_ecat_reg_ecat,
         &ett_ecat_reg_pdi1,
         &ett_ecat_reg_crc0,
         &ett_ecat_reg_crc1,
         &ett_ecat_reg_crc2,
         &ett_ecat_reg_crc3,
         &ett_ecat_reg_wd_status,
         &ett_ecat_reg_eeprom_assign,
         &ett_ecat_reg_ctrlstat,
         &ett_ecat_reg_mio_ctrlstat,
         &ett_ecat_mio_addr,
         &ett_ecat_mio_access,
         &ett_ecat_mio_status0,
         &ett_ecat_mio_status1,
         &ett_ecat_mio_status2,
         &ett_ecat_mio_status3,
         &ett_ecat_reg_fmmu,
         &ett_ecat_reg_syncman,
         &ett_ecat_reg_syncman_ctrlstatus,
         &ett_ecat_reg_syncman_sm_enable,
         &ett_ecat_reg_dc_cycunitctrl,
         &ett_ecat_dc_activation,
         &ett_ecat_dc_activationstat,
         &ett_ecat_dc_sync0_status,
         &ett_ecat_dc_sync1_status,
         &ett_ecat_dc_latch0_ctrl,
         &ett_ecat_dc_latch1_ctrl,
         &ett_ecat_dc_latch0_status,
         &ett_ecat_dc_latch1_status,
      };

   proto_ecat_datagram = proto_register_protocol("EtherCAT datagram(s)", "ECAT", "ecat");
   proto_register_field_array(proto_ecat_datagram, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   /* Sub dissector code */
   heur_subdissector_list = register_heur_dissector_list("ecat.data", proto_ecat_datagram);
}

/* The registration hand-off routing */
void proto_reg_handoff_ecat(void)
{
   dissector_handle_t ecat_handle;

   /* Register this dissector as a sub dissector to EtherCAT frame based on
      ether type. */
   ecat_handle = create_dissector_handle(dissect_ecat_datagram, proto_ecat_datagram);
   dissector_add_uint("ecatf.type", 1 /* EtherCAT type */, ecat_handle);

   ecat_mailbox_handle = find_dissector_add_dependency("ecat_mailbox", proto_ecat_datagram);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
