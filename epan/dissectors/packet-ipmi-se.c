/* packet-ipmi-se.c
 * Sub-dissectors for IPMI messages (netFn=Sensor/Event)
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

/* Data types for sensor-specific info */
struct sensor_info;
typedef gboolean (*intrp_t)(proto_tree *, tvbuff_t *, const struct sensor_info *,
		guint32, guint32, guint32);

struct sensor_info {
	const value_string *offsets;
	intrp_t intrp2;
	intrp_t intrp3;
	const char *desc;
};

struct evtype_info {
	const value_string *byte2;
	const value_string *byte3;
	const value_string *offsets;
	intrp_t intrp2;
	intrp_t intrp3;
	const char *desc;
};

static gint ett_ipmi_se_evt_byte3 = -1;
static gint ett_ipmi_se_evt_evd_byte1 = -1;
static gint ett_ipmi_se_evt_evd_byte2 = -1;
static gint ett_ipmi_se_evt_evd_byte3 = -1;

static gint ett_ipmi_se_cp06_byte1 = -1;
static gint ett_ipmi_se_cp07_byte1 = -1;
static gint ett_ipmi_se_cp09_byte1 = -1;
static gint ett_ipmi_se_cp10_byte1 = -1;
static gint ett_ipmi_se_cp12_byte1 = -1;
static gint ett_ipmi_se_cp12_byte2 = -1;
static gint ett_ipmi_se_cp12_byte3 = -1;
static gint ett_ipmi_se_cp13_byte1 = -1;
static gint ett_ipmi_se_cp15_byte1 = -1;
static gint ett_ipmi_se_cp15_byte2 = -1;
static gint ett_ipmi_se_cp15_member = -1;
static gint ett_ipmi_se_cp15_byte11 = -1;

static gint ett_ipmi_se_00_byte2 = -1;
static gint ett_ipmi_se_01_byte2 = -1;
static gint ett_ipmi_se_10_action = -1;
static gint ett_ipmi_se_12_byte1 = -1;
static gint ett_ipmi_se_13_byte1 = -1;
static gint ett_ipmi_se_13_rev = -1;
static gint ett_ipmi_se_14_byte1 = -1;
static gint ett_ipmi_se_16_byte1 = -1;
static gint ett_ipmi_se_16_byte2 = -1;
static gint ett_ipmi_se_16_byte3 = -1;
static gint ett_ipmi_se_20_rq_byte1 = -1;
static gint ett_ipmi_se_20_rs_byte2 = -1;
static gint ett_ipmi_se_23_readingfactors = -1;
static gint ett_ipmi_se_23_byte1 = -1;
static gint ett_ipmi_se_23_byte2 = -1;
static gint ett_ipmi_se_23_byte3 = -1;
static gint ett_ipmi_se_23_byte4 = -1;
static gint ett_ipmi_se_23_byte5 = -1;
static gint ett_ipmi_se_23_byte6 = -1;
static gint ett_ipmi_se_XX_mask = -1;
static gint ett_ipmi_se_XX_b1 = -1;
static gint ett_ipmi_se_XX_b2 = -1;
static gint ett_ipmi_se_XX_b3 = -1;
static gint ett_ipmi_se_XX_b4 = -1;
static gint ett_ipmi_se_28_byte2 = -1;
static gint ett_ipmi_se_29_byte1 = -1;
static gint ett_ipmi_se_2a_byte2 = -1;
static gint ett_ipmi_se_2b_byte1 = -1;
static gint ett_ipmi_se_2d_byte2 = -1;
static gint ett_ipmi_se_2d_b1 = -1;
static gint ett_ipmi_se_2d_b2 = -1;
static gint ett_ipmi_se_2e_evtype = -1;
static gint ett_ipmi_se_2f_evtype = -1;

static gint hf_ipmi_se_evt_rev = -1;
static gint hf_ipmi_se_evt_sensor_type = -1;
static gint hf_ipmi_se_evt_sensor_num = -1;
static gint hf_ipmi_se_evt_byte3 = -1;
static gint hf_ipmi_se_evt_dir = -1;
static gint hf_ipmi_se_evt_type = -1;
static gint hf_ipmi_se_evt_data1 = -1;
static gint hf_ipmi_se_evt_data1_b2 = -1;
static gint hf_ipmi_se_evt_data1_b3 = -1;
static gint hf_ipmi_se_evt_data1_offs = -1;
static gint hf_ipmi_se_evt_data2 = -1;
static gint hf_ipmi_se_evt_data3 = -1;

static gint hf_ipmi_se_cp00_sip = -1;
static gint hf_ipmi_se_cp01_alert_startup = -1;
static gint hf_ipmi_se_cp01_startup = -1;
static gint hf_ipmi_se_cp01_event_msg = -1;
static gint hf_ipmi_se_cp01_pef = -1;
static gint hf_ipmi_se_cp02_diag_intr = -1;
static gint hf_ipmi_se_cp02_oem_action = -1;
static gint hf_ipmi_se_cp02_pwr_cycle = -1;
static gint hf_ipmi_se_cp02_reset = -1;
static gint hf_ipmi_se_cp02_pwr_down = -1;
static gint hf_ipmi_se_cp02_alert = -1;
static gint hf_ipmi_se_cp03_startup = -1;
static gint hf_ipmi_se_cp04_alert_startup = -1;
static gint hf_ipmi_se_cp05_num_evfilters = -1;
static gint hf_ipmi_se_cp06_filter = -1;
static gint hf_ipmi_se_cp06_data = -1;
static gint hf_ipmi_se_cp07_filter = -1;
static gint hf_ipmi_se_cp07_data = -1;
static gint hf_ipmi_se_cp08_policies = -1;
static gint hf_ipmi_se_cp09_entry = -1;
static gint hf_ipmi_se_cp09_data = -1;
static gint hf_ipmi_se_cp10_useval = -1;
static gint hf_ipmi_se_cp10_guid = -1;
static gint hf_ipmi_se_cp11_num_alertstr = -1;
static gint hf_ipmi_se_cp12_byte1 = -1;
static gint hf_ipmi_se_cp12_alert_stringsel = -1;
static gint hf_ipmi_se_cp12_evfilter = -1;
static gint hf_ipmi_se_cp12_alert_stringset = -1;
static gint hf_ipmi_se_cp13_stringsel = -1;
static gint hf_ipmi_se_cp13_blocksel = -1;
static gint hf_ipmi_se_cp13_string = -1;
static gint hf_ipmi_se_cp14_num_gct = -1;
static gint hf_ipmi_se_cp15_gctsel = -1;
static gint hf_ipmi_se_cp15_force = -1;
static gint hf_ipmi_se_cp15_delayed = -1;
static gint hf_ipmi_se_cp15_channel = -1;
static gint hf_ipmi_se_cp15_group = -1;
static gint hf_ipmi_se_cp15_member_check = -1;
static gint hf_ipmi_se_cp15_member_id = -1;
static gint hf_ipmi_se_cp15_retries = -1;
static gint hf_ipmi_se_cp15_operation = -1;

static gint hf_ipmi_se_00_addr = -1;
static gint hf_ipmi_se_00_lun = -1;

static gint hf_ipmi_se_01_addr = -1;
static gint hf_ipmi_se_01_lun = -1;

static gint hf_ipmi_se_10_pef_version = -1;
static gint hf_ipmi_se_10_action_oem_filter = -1;
static gint hf_ipmi_se_10_action_diag_intr = -1;
static gint hf_ipmi_se_10_action_oem_action = -1;
static gint hf_ipmi_se_10_action_pwr_cycle = -1;
static gint hf_ipmi_se_10_action_reset = -1;
static gint hf_ipmi_se_10_action_pwr_down = -1;
static gint hf_ipmi_se_10_action_alert = -1;
static gint hf_ipmi_se_10_entries = -1;

static gint hf_ipmi_se_11_rq_timeout = -1;
static gint hf_ipmi_se_11_rs_timeout = -1;

static gint hf_ipmi_se_12_byte1 = -1;
static gint hf_ipmi_se_12_param = -1;
static gint hf_ipmi_se_12_data = -1;

static gint hf_ipmi_se_13_byte1 = -1;
static gint hf_ipmi_se_13_getrev = -1;
static gint hf_ipmi_se_13_param = -1;
static gint hf_ipmi_se_13_set = -1;
static gint hf_ipmi_se_13_block = -1;
static gint hf_ipmi_se_13_rev_present = -1;
static gint hf_ipmi_se_13_rev_compat = -1;
static gint hf_ipmi_se_13_data = -1;

static gint hf_ipmi_se_14_processed_by = -1;
static gint hf_ipmi_se_14_rid = -1;

static gint hf_ipmi_se_15_tstamp = -1;
static gint hf_ipmi_se_15_lastrec = -1;
static gint hf_ipmi_se_15_proc_sw = -1;
static gint hf_ipmi_se_15_proc_bmc = -1;

static gint hf_ipmi_se_16_chan = -1;
static gint hf_ipmi_se_16_op = -1;
static gint hf_ipmi_se_16_dst = -1;
static gint hf_ipmi_se_16_send_string = -1;
static gint hf_ipmi_se_16_string_sel = -1;
static gint hf_ipmi_se_16_gen = -1;
static gint hf_ipmi_se_16_status = -1;

static gint hf_ipmi_se_17_seq = -1;
static gint hf_ipmi_se_17_tstamp = -1;
static gint hf_ipmi_se_17_evsrc = -1;
static gint hf_ipmi_se_17_sensor_dev = -1;
static gint hf_ipmi_se_17_sensor_num = -1;
static gint hf_ipmi_se_17_evdata1 = -1;
static gint hf_ipmi_se_17_evdata2 = -1;
static gint hf_ipmi_se_17_evdata3 = -1;

static gint hf_ipmi_se_20_rq_op = -1;
static gint hf_ipmi_se_20_rs_num = -1;
static gint hf_ipmi_se_20_rs_sdr = -1;
static gint hf_ipmi_se_20_rs_population = -1;
static gint hf_ipmi_se_20_rs_lun3 = -1;
static gint hf_ipmi_se_20_rs_lun2 = -1;
static gint hf_ipmi_se_20_rs_lun1 = -1;
static gint hf_ipmi_se_20_rs_lun0 = -1;
static gint hf_ipmi_se_20_rs_change = -1;

static gint hf_ipmi_se_21_rid = -1;
static gint hf_ipmi_se_21_record = -1;
static gint hf_ipmi_se_21_offset = -1;
static gint hf_ipmi_se_21_len = -1;
static gint hf_ipmi_se_21_next = -1;
static gint hf_ipmi_se_21_recdata = -1;

static gint hf_ipmi_se_22_resid = -1;

static gint hf_ipmi_se_23_rq_sensor = -1;
static gint hf_ipmi_se_23_rq_reading = -1;
static gint hf_ipmi_se_23_rs_next_reading = -1;

static gint hf_ipmi_se_24_sensor = -1;
static gint hf_ipmi_se_24_mask = -1;
static gint hf_ipmi_se_24_hyst_pos = -1;
static gint hf_ipmi_se_24_hyst_neg = -1;

static gint hf_ipmi_se_25_sensor = -1;
static gint hf_ipmi_se_25_mask = -1;
static gint hf_ipmi_se_25_hyst_pos = -1;
static gint hf_ipmi_se_25_hyst_neg = -1;

static gint hf_ipmi_se_26_sensor = -1;
static gint hf_ipmi_se_XX_m_unr = -1;
static gint hf_ipmi_se_XX_m_uc = -1;
static gint hf_ipmi_se_XX_m_unc = -1;
static gint hf_ipmi_se_XX_m_lnr = -1;
static gint hf_ipmi_se_XX_m_lc = -1;
static gint hf_ipmi_se_XX_m_lnc = -1;
static gint hf_ipmi_se_XX_thr_lnc = -1;
static gint hf_ipmi_se_XX_thr_lc = -1;
static gint hf_ipmi_se_XX_thr_lnr = -1;
static gint hf_ipmi_se_XX_thr_unc = -1;
static gint hf_ipmi_se_XX_thr_uc = -1;
static gint hf_ipmi_se_XX_thr_unr = -1;

static gint hf_ipmi_se_27_sensor = -1;

static gint hf_ipmi_se_XX_b1_7 = -1;
static gint hf_ipmi_se_XX_b1_6 = -1;
static gint hf_ipmi_se_XX_b1_5 = -1;
static gint hf_ipmi_se_XX_b1_4 = -1;
static gint hf_ipmi_se_XX_b1_3 = -1;
static gint hf_ipmi_se_XX_b1_2 = -1;
static gint hf_ipmi_se_XX_b1_1 = -1;
static gint hf_ipmi_se_XX_b1_0 = -1;
static gint hf_ipmi_se_XX_b2_6 = -1;
static gint hf_ipmi_se_XX_b2_5 = -1;
static gint hf_ipmi_se_XX_b2_4 = -1;
static gint hf_ipmi_se_XX_b2_3 = -1;
static gint hf_ipmi_se_XX_b2_2 = -1;
static gint hf_ipmi_se_XX_b2_1 = -1;
static gint hf_ipmi_se_XX_b2_0 = -1;
static gint hf_ipmi_se_XX_b3_7 = -1;
static gint hf_ipmi_se_XX_b3_6 = -1;
static gint hf_ipmi_se_XX_b3_5 = -1;
static gint hf_ipmi_se_XX_b3_4 = -1;
static gint hf_ipmi_se_XX_b3_3 = -1;
static gint hf_ipmi_se_XX_b3_2 = -1;
static gint hf_ipmi_se_XX_b3_1 = -1;
static gint hf_ipmi_se_XX_b3_0 = -1;
static gint hf_ipmi_se_XX_b4_6 = -1;
static gint hf_ipmi_se_XX_b4_5 = -1;
static gint hf_ipmi_se_XX_b4_4 = -1;
static gint hf_ipmi_se_XX_b4_3 = -1;
static gint hf_ipmi_se_XX_b4_2 = -1;
static gint hf_ipmi_se_XX_b4_1 = -1;
static gint hf_ipmi_se_XX_b4_0 = -1;

static gint hf_ipmi_se_28_sensor = -1;
static gint hf_ipmi_se_28_fl_evm = -1;
static gint hf_ipmi_se_28_fl_scan = -1;
static gint hf_ipmi_se_28_fl_action = -1;

static gint hf_ipmi_se_29_sensor = -1;
static gint hf_ipmi_se_29_fl_evm = -1;
static gint hf_ipmi_se_29_fl_scan = -1;

static gint hf_ipmi_se_2a_sensor = -1;
static gint hf_ipmi_se_2a_fl_sel = -1;

static gint hf_ipmi_se_2b_sensor = -1;
static gint hf_ipmi_se_2b_fl_evm = -1;
static gint hf_ipmi_se_2b_fl_scan = -1;
static gint hf_ipmi_se_2b_fl_unavail = -1;

static gint hf_ipmi_se_2d_sensor = -1;
static gint hf_ipmi_se_2d_reading = -1;
static gint hf_ipmi_se_2d_b1_7 = -1;
static gint hf_ipmi_se_2d_b1_6 = -1;
static gint hf_ipmi_se_2d_b1_5 = -1;
static gint hf_ipmi_se_2d_b1_4 = -1;
static gint hf_ipmi_se_2d_b1_3 = -1;
static gint hf_ipmi_se_2d_b1_2 = -1;
static gint hf_ipmi_se_2d_b1_1 = -1;
static gint hf_ipmi_se_2d_b1_0 = -1;
static gint hf_ipmi_se_2d_b2_6 = -1;
static gint hf_ipmi_se_2d_b2_5 = -1;
static gint hf_ipmi_se_2d_b2_4 = -1;
static gint hf_ipmi_se_2d_b2_3 = -1;
static gint hf_ipmi_se_2d_b2_2 = -1;
static gint hf_ipmi_se_2d_b2_1 = -1;
static gint hf_ipmi_se_2d_b2_0 = -1;

static gint hf_ipmi_se_2e_sensor = -1;
static gint hf_ipmi_se_2e_stype = -1;
static gint hf_ipmi_se_2e_evtype = -1;

static gint hf_ipmi_se_2f_sensor = -1;
static gint hf_ipmi_se_2f_stype = -1;
static gint hf_ipmi_se_2f_evtype = -1;

/* Platform Event parsing. Common for Platform Event and Alert Immediate.
 */
static const value_string evt_evm_rev_vals[] = {
	{ 0x03, "IPMI 1.0" },
	{ 0x04, "IPMI 1.5+" },
	{ 0, NULL },
};

static const struct true_false_string evt_evdir_tfs = {
	"Deassertion event",
	"Assertion event"
};

static const value_string et_empty[] = {
	{ 0, NULL }
};

static const value_string etb2_thr[] = {
	{ 0x00, "Unspecified" },
	{ 0x01, "Trigger reading" },
	{ 0x02, "OEM code" },
	{ 0x03, "Sensor-specific" },
	{ 0, NULL }
};

static const value_string etb3_thr[] = {
	{ 0x00, "Unspecified" },
	{ 0x01, "Trigger threshold" },
	{ 0x02, "OEM code" },
	{ 0x03, "Sensor-specific" },
	{ 0, NULL }
};

static const value_string etb2_dscr[] = {
	{ 0x00, "Unspecified" },
	{ 0x01, "Previous state and/or severity" },
	{ 0x02, "OEM code" },
	{ 0x03, "Sensor-specific" },
	{ 0, NULL }
};

static const value_string etb3_dscr[] = {
	{ 0x00, "Unspecified" },
	{ 0x02, "OEM code" },
	{ 0x03, "Sensor-specific" },
	{ 0, NULL }
};

static const value_string etb2_oem[] = {
	{ 0x00, "Unspecified" },
	{ 0x01, "Previous state and/or severity" },
	{ 0x02, "OEM code" },
	{ 0, NULL }
};

static const value_string etb3_oem[] = {
	{ 0x00, "Unspecified" },
	{ 0x02, "OEM code" },
	{ 0, NULL }
};

static const value_string etoff_01[] = {
	{ 0x00, "Lower Non-Critical: going low" },
	{ 0x01, "Lower Non-Critical: going high" },
	{ 0x02, "Lower Critical: going low" },
	{ 0x03, "Lower Critical: going high" },
	{ 0x04, "Lower Non-Recoverable: going low" },
	{ 0x05, "Lower Non-Recoverable: going high" },
	{ 0x06, "Upper Non-Critical: going low" },
	{ 0x07, "Upper Non-Critical: going high" },
	{ 0x08, "Upper Critical: going low" },
	{ 0x09, "Upper Critical: going high" },
	{ 0x0a, "Upper Non-Recoverable: going low" },
	{ 0x0b, "Upper Non-Recoverable: going high" },
	{ 0, NULL }
};

static const value_string etoff_02[] = {
	{ 0x00, "Transition to Idle" },
	{ 0x01, "Transition to Active" },
	{ 0x02, "Transition to Busy" },
	{ 0, NULL }
};

static const value_string etoff_03[] = {
	{ 0x00, "State Deasserted" },
	{ 0x01, "State Asserted" },
	{ 0, NULL }
};

static const value_string etoff_04[] = {
	{ 0x00, "Predictive Failure Deasserted" },
	{ 0x01, "Predictive Failure Asserted" },
	{ 0, NULL }
};

static const value_string etoff_05[] = {
	{ 0x00, "Limit Not Exceeded" },
	{ 0x01, "Limit Exceeded" },
	{ 0, NULL }
};

static const value_string etoff_06[] = {
	{ 0x00, "Performance Met" },
	{ 0x01, "Performance Lags" },
	{ 0, NULL }
};

static const value_string etoff_07[] = {
	{ 0x00, "Transition to OK" },
	{ 0x01, "Transition to Non-Critical from OK" },
	{ 0x02, "Transition to Critical from less severe" },
	{ 0x03, "Transition to Non-Recoverable from less severe" },
	{ 0x04, "Transition to Non-Critical from more severe" },
	{ 0x05, "Transition to Critical from Non-Recoverable" },
	{ 0x06, "Transition to Non-Recoverable" },
	{ 0x07, "Monitor" },
	{ 0x08, "Informational" },
	{ 0, NULL }
};

static const value_string etoff_08[] = {
	{ 0x00, "Device Removed/Absent" },
	{ 0x01, "Device Inserted/Present" },
	{ 0, NULL }
};

static const value_string etoff_09[] = {
	{ 0x00, "Device Disabled" },
	{ 0x01, "Device Enabled" },
	{ 0, NULL }
};

static const value_string etoff_0a[] = {
	{ 0x00, "Transition to Running" },
	{ 0x01, "Transition to In Test" },
	{ 0x02, "Transition to Power Off" },
	{ 0x03, "Transition to On Line" },
	{ 0x04, "Transition to Off Line" },
	{ 0x05, "Transition to Off Duty" },
	{ 0x06, "Transition to Degraded" },
	{ 0x07, "Transition to Power Save" },
	{ 0x08, "Install Error" },
	{ 0, NULL }
};

static const value_string etoff_0b[] = {
	{ 0x00, "Fully Redundant" },
	{ 0x01, "Redundancy Lost" },
	{ 0x02, "Redundancy Degraded" },
	{ 0x03, "Non-Redundant: Sufficient Resources from Redundant" },
	{ 0x04, "Non-Redundant: Sufficient Resources from Insufficient Resources" },
	{ 0x05, "Non-Redundant: Insufficient Resources" },
	{ 0x06, "Redundancy Degraded from Fully Redundant" },
	{ 0x07, "Redundancy Degraded from Non-Redundant" },
	{ 0, NULL }
};

static const value_string etoff_0c[] = {
	{ 0x00, "D0 Power State" },
	{ 0x01, "D1 Power State" },
	{ 0x02, "D2 Power State" },
	{ 0x03, "D3 Power State" },
	{ 0, NULL }
};

static gboolean
eti_thr_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	if (b == 0x1) {
		proto_tree_add_text(tree, tvb, 0, 1, "Trigger reading: %d%s",
				d, d == 0xff ? " (unspecified)" : "");
		return TRUE;
	}
	return FALSE;
}

static gboolean
eti_thr_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	if (b == 0x1) {
		proto_tree_add_text(tree, tvb, 0, 1, "Trigger threshold: %d%s",
				d, d == 0xff ? " (unspecified)" : "");
		return TRUE;
	}
	return FALSE;
}

static gboolean
eti_2_pst_sev(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si,
		guint32 b, guint32 offs _U_, guint32 d)
{
	proto_item *ti;
	proto_tree *s_tree;
	guint32 tmp;
	const char *desc;

	if (b == 0x1) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Previous state/severity");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		tmp = d >> 4;
		desc = (tmp == 0x0f) ? "Unspecified" : val_to_str(tmp, etoff_07, "Unknown");
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sSeverity: %s (0x%02x)",
				ipmi_dcd8(d, 0xf0), desc, tmp);
		tmp = d & 0xf;
		desc = (tmp == 0x0f) ? "Unspecified" : val_to_str(tmp, si->offsets, "Unknown");
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPrevious state: %s (0x%02x)",
				ipmi_dcd8(d, 0x0f), desc, tmp);
		return TRUE;
	}
	return FALSE;
}

static const struct evtype_info *
get_evtype_info(unsigned int evtype)
{
	static const struct {
		unsigned int id;
		struct evtype_info eti;
	} eti_tab[] = {
		{ 0x01, { etb2_thr,  etb3_thr,  etoff_01, eti_thr_2,  eti_thr_3,  "Threshold" }},
		{ 0x02, { etb2_dscr, etb3_dscr, etoff_02, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x03, { etb2_dscr, etb3_dscr, etoff_03, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x04, { etb2_dscr, etb3_dscr, etoff_04, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x05, { etb2_dscr, etb3_dscr, etoff_05, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x06, { etb2_dscr, etb3_dscr, etoff_06, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x07, { etb2_dscr, etb3_dscr, etoff_07, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x08, { etb2_dscr, etb3_dscr, etoff_08, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x09, { etb2_dscr, etb3_dscr, etoff_09, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x0a, { etb2_dscr, etb3_dscr, etoff_0a, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x0b, { etb2_dscr, etb3_dscr, etoff_0b, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x0c, { etb2_dscr, etb3_dscr, etoff_0c, eti_2_pst_sev, NULL,    "Discrete" }},
		{ 0x6f, { etb2_dscr, etb3_dscr, NULL,     eti_2_pst_sev, NULL,    "Sensor-specific" }}
	};
	static const struct evtype_info eti_oem = {
		etb2_oem, etb3_oem, et_empty, eti_2_pst_sev, NULL, "OEM-specific"
	};
	static const struct evtype_info eti_rsrv = {
		et_empty, et_empty, et_empty, NULL, NULL, "Reserved"
	};
	unsigned int i;

	/* Look for explicitly specified event/reading type */
	for (i = 0; i < array_length(eti_tab); i++) {
		if (eti_tab[i].id == evtype) {
			return &eti_tab[i].eti;
		}
	}

	/* Falls in OEM range? */
	if (evtype >= 0x70 && evtype <= 0x7f) {
		return &eti_oem;
	}

	return &eti_rsrv;
}

static const value_string ssoff_05[] = {
	{ 0x00, "General Chassis Intrusion" },
	{ 0x01, "Drive Bay Intrusion" },
	{ 0x02, "I/O Card Area Intrusion" },
	{ 0x03, "Processor Area Intrusion" },
	{ 0x04, "LAN Leash Lost" },
	{ 0x05, "Unauthorized dock" },
	{ 0x06, "FAN Area Intrusion" },
	{ 0, NULL }
};

static const value_string ssoff_06[] = {
	{ 0x00, "Secure Mode (Front Panel Lockout) Violation Attempt" },
	{ 0x01, "Pre-boot Password Violation: user password" },
	{ 0x02, "Pre-boot Password Violation: setup password" },
	{ 0x03, "Pre-boot Password Violation: network boot password" },
	{ 0x04, "Other pre-boot password violation" },
	{ 0x05, "Out-of-band password violation" },
	{ 0, NULL }
};

static const value_string ssoff_07[] = {
	{ 0x00, "IERR" },
	{ 0x01, "Thermal Trip" },
	{ 0x02, "FRB1/BIST Failure" },
	{ 0x03, "FRB2/Hang in POST Failure" },
	{ 0x04, "FRB3/Processor Startup/Initialization Failure" },
	{ 0x05, "Configuration Error" },
	{ 0x06, "SM BIOS Uncorrectable CPU-complex error" },
	{ 0x07, "Processor Presence Detected" },
	{ 0x08, "Processor Disabled" },
	{ 0x09, "Terminator Presence Detected" },
	{ 0x0a, "Processor Automatically Throttled" },
	{ 0, NULL }
};

static const value_string ssoff_08[] = {
	{ 0x00, "Presence Detected" },
	{ 0x01, "Power Supply Failure Detected" },
	{ 0x02, "Predictive Failure" },
	{ 0x03, "Power Supply input lost (AC/DC)" },
	{ 0x04, "Power Supply input lost or out-of-range" },
	{ 0x05, "Power Supply out-of-range, but present" },
	{ 0x06, "Configuration error" },
	{ 0, NULL }
};

static const value_string ssoff_09[] = {
	{ 0x00, "Power Off / Power Down" },
	{ 0x01, "Power Cycle" },
	{ 0x02, "240VA Power Down" },
	{ 0x03, "Interlock Power Down" },
	{ 0x04, "AC Lost" },
	{ 0x05, "Soft Power Control Failure" },
	{ 0x06, "Power Unit Failure Detected" },
	{ 0x07, "Predictive Failure" },
	{ 0, NULL }
};

static const value_string ssoff_0c[] = {
	{ 0x00, "Correctable ECC/other correctable memory error" },
	{ 0x01, "Uncorrectable ECC/other uncorrectable memory error" },
	{ 0x02, "Parity" },
	{ 0x03, "Memory Scrub Failed" },
	{ 0x04, "Memory Device Disabled" },
	{ 0x05, "Correctable ECC/other correctable memory error: logging limit reached" },
	{ 0x06, "Presence Detected" },
	{ 0x07, "Configuration Error" },
	{ 0x08, "Spare" },
	{ 0x09, "Memory Automatically Throttled" },
	{ 0x0a, "Critical Overtemperature" },
	{ 0, NULL }
};

static const value_string ssoff_0d[] = {
	{ 0x00, "Drive Presence" },
	{ 0x01, "Drive Fault" },
	{ 0x02, "Predictive Failure" },
	{ 0x03, "Hot Spare" },
	{ 0x04, "Consistency Check / Parity Check in progress" },
	{ 0x05, "In Critical Array" },
	{ 0x06, "In Failed Array" },
	{ 0x07, "Rebuild/Remap in progress" },
	{ 0x08, "Rebuild/Remap aborted" },
	{ 0, NULL }
};

static const value_string ssoff_0f[] = {
	{ 0x00, "System Firmware Error (POST Error)" },
	{ 0x01, "System Firmware Hang" },
	{ 0x02, "System Firmware Progress" },
	{ 0, NULL }
};

static const value_string ssoff_10[] = {
	{ 0x00, "Correctable Memory Error Logging Disabled" },
	{ 0x01, "Event type Logging Disabled" },
	{ 0x02, "Log Area Reset/Cleared" },
	{ 0x03, "All Event Logging Disabled" },
	{ 0x04, "SEL Full" },
	{ 0x05, "SEL Almost Full" },
	{ 0, NULL }
};

static const value_string ssoff_11[] = {
	{ 0x00, "BIOS Watchdog Reset" },
	{ 0x01, "OS Watchdog Reset" },
	{ 0x02, "OS Watchdog Shutdown" },
	{ 0x03, "OS Watchdog Power Down" },
	{ 0x04, "OS Watchdog Power Cycle" },
	{ 0x05, "OS Watchdog NMI/Diagnostic Interrupt" },
	{ 0x06, "OS Watchdog Expired, status only" },
	{ 0x07, "OS Watchdog pre-timeout interrupt, non-NMI" },
	{ 0, NULL }
};

static const value_string ssoff_12[] = {
	{ 0x00, "System Reconfigured" },
	{ 0x01, "OEM System Boot Event" },
	{ 0x02, "Undetermined system hardware failure" },
	{ 0x03, "Entry added to Auxiliary Log" },
	{ 0x04, "PEF Action" },
	{ 0x05, "Timestamp Clock Synch" },
	{ 0, NULL }
};

static const value_string ssoff_13[] = {
	{ 0x00, "Front Panel NMI/Diagnostic Interrupt" },
	{ 0x01, "Bus Timeout" },
	{ 0x02, "I/O Channel Check NMI" },
	{ 0x03, "Software NMI" },
	{ 0x04, "PCI PERR" },
	{ 0x05, "PCI SERR" },
	{ 0x06, "EISA Fail Safe Timeout" },
	{ 0x07, "Bus Correctable Error" },
	{ 0x08, "Bus Uncorrectable Error" },
	{ 0x09, "Fatal NMI" },
	{ 0x0a, "Bus Fatal Error" },
	{ 0x0b, "Bus Degraded" },
	{ 0, NULL }
};

static const value_string ssoff_14[] = {
	{ 0x00, "Power Button Pressed" },
	{ 0x01, "Sleep Button Pressed" },
	{ 0x02, "Reset Button Pressed" },
	{ 0x03, "FRU Latch open" },
	{ 0x04, "FRU Service Request Button Pressed" },
	{ 0, NULL }
};

static const value_string ssoff_19[] = {
	{ 0x00, "Soft Power Control Failure" },
	{ 0, NULL }
};

static const value_string ssoff_1b[] = {
	{ 0x00, "Cable/Interconnect is connected" },
	{ 0x01, "Configuration error - Incorrect cable connected / Incorrect interconnection" },
	{ 0, NULL }
};

static const value_string ssoff_1d[] = {
	{ 0x00, "Initiated by Power Up" },
	{ 0x01, "Initiated by hard reset" },
	{ 0x02, "Initiated by warm reset" },
	{ 0x03, "User requested PXE boot" },
	{ 0x04, "Automatic boot to diagnostic" },
	{ 0x05, "OS / run-time software initiated hard reset" },
	{ 0x06, "OS / run-time software initiated warm reset" },
	{ 0x07, "System Restart" },
	{ 0, NULL }
};

static const value_string ssoff_1e[] = {
	{ 0x00, "No bootable media" },
	{ 0x01, "No bootable diskette left in drive" },
	{ 0x02, "PXE Server not found" },
	{ 0x03, "Invalid boot sector" },
	{ 0x04, "Timeout waiting for user selection of boot source" },
	{ 0, NULL }
};

static const value_string ssoff_1f[] = {
	{ 0x00, "A: boot completed" },
	{ 0x01, "C: boot completed" },
	{ 0x02, "PXE boot completed" },
	{ 0x03, "Diagnostic boot completed" },
	{ 0x04, "CD-ROM boot completed" },
	{ 0x05, "ROM boot completed" },
	{ 0x06, "Boot completed - boot device not specified" },
	{ 0, NULL }
};

static const value_string ssoff_20[] = {
	{ 0x00, "Critical stop during OS load/initialization" },
	{ 0x01, "Run-time critical stop" },
	{ 0x02, "OS Graceful Stop" },
	{ 0x03, "OS Graceful Shutdown" },
	{ 0x04, "Soft Shutdown initiated by PEF" },
	{ 0x05, "Agent Not Responding" },
	{ 0, NULL }
};

static const value_string ssoff_21[] = {
	{ 0x00, "Fault Status asserted" },
	{ 0x01, "Identify Status asserted" },
	{ 0x02, "Slot/Connector Device installed/attached" },
	{ 0x03, "Slot/Connector Ready for Device Installation" },
	{ 0x04, "Slot/Connector Ready for Device Removal" },
	{ 0x05, "Slot Power is Off" },
	{ 0x06, "Slot/Connector Device Removal Request" },
	{ 0x07, "Interlock Asserted" },
	{ 0x08, "Slot is Disabled" },
	{ 0x09, "Slot holds spare device" },
	{ 0, NULL }
};

static const value_string ssoff_22[] = {
	{ 0x00, "S0/G0 'working'" },
	{ 0x01, "S1 'sleeping with system h/w & processor context maintained'" },
	{ 0x02, "S2 'sleeping, processor context lost'" },
	{ 0x03, "S3 'sleeping, processor & h/w, memory retained'" },
	{ 0x04, "S4 'non-volatile sleep / suspend-to-disk'" },
	{ 0x05, "S5/G2 'soft-off'" },
	{ 0x06, "S4/S5 'soft-off', particular S4/S5 state cannot be determined" },
	{ 0x07, "G3 / Mechanical Off" },
	{ 0x08, "Sleeping in S1, S2 or S3 states" },
	{ 0x09, "G1 sleeping" },
	{ 0x0a, "S5 entered by override" },
	{ 0x0b, "Legacy ON state" },
	{ 0x0c, "Legacy OFF state" },
	{ 0x0e, "Unknown" },
	{ 0, NULL }
};

static const value_string ssoff_23[] = {
	{ 0x00, "Timer expired, status only" },
	{ 0x01, "Hard Reset" },
	{ 0x02, "Power Down" },
	{ 0x03, "Power Cycle" },
	{ 0x08, "Timer Interrupt" },
	{ 0, NULL }
};

static const value_string ssoff_24[] = {
	{ 0x00, "Platform Generated Page" },
	{ 0x01, "Platform Generated LAN Event" },
	{ 0x02, "Platform Event Trap generated" },
	{ 0x03, "Platform generated SNMP trap" },
	{ 0, NULL }
};

static const value_string ssoff_25[] = {
	{ 0x00, "Entity Present" },
	{ 0x01, "Entity Absent" },
	{ 0x02, "Entity Disabled" },
	{ 0, NULL }
};

static const value_string ssoff_27[] = {
	{ 0x00, "LAN Heartbeat Lost" },
	{ 0x01, "LAN Heartbeat" },
	{ 0, NULL }
};

static const value_string ssoff_28[] = {
	{ 0x00, "Sensor access degraded or unavailable" },
	{ 0x01, "Controller access degraded or unavailable" },
	{ 0x02, "Management controller off-line" },
	{ 0x03, "Management controller unavailable" },
	{ 0x04, "Sensor failure" },
	{ 0x05, "FRU failure" },
	{ 0, NULL }
};

static const value_string ssoff_29[] = {
	{ 0x00, "Battery low" },
	{ 0x01, "Battery failed" },
	{ 0x02, "Battery presence detected" },
	{ 0, NULL }
};

static const value_string ssoff_2a[] = {
	{ 0x00, "Session Activated" },
	{ 0x01, "Session Deactivated" },
	{ 0, NULL }
};

static const value_string ssoff_2b[] = {
	{ 0x00, "Hardware change detected with associated Entity" },
	{ 0x01, "Firmware or software change detected with associated Entity" },
	{ 0x02, "Hardware incompatibility detected with associated Entity" },
	{ 0x03, "Firmware or software incompatibility detected with associated Entity" },
	{ 0x04, "Entity is of an invalid or unsupported hardware version" },
	{ 0x05, "Entity contains an invalid or unsupported firmware or software version" },
	{ 0x06, "Hardware Change detected with associated Entity was successful" },
	{ 0x07, "Software or Firmware Change detected with associated Entity was successful" },
	{ 0, NULL }
};

static const value_string ssoff_2c[] = {
	{ 0x00, "M0 - FRU Not Installed" },
	{ 0x01, "M1 - FRU Inactive" },
	{ 0x02, "M2 - FRU Activation Requested" },
	{ 0x03, "M3 - FRU Activation In Progress" },
	{ 0x04, "M4 - FRU Active" },
	{ 0x05, "M5 - FRU Deactivation Requested" },
	{ 0x06, "M6 - FRU Deactivation In Progress" },
	{ 0x07, "M7 - FRU Communication Lost" },
	{ 0, NULL }
};

static const value_string ssoff_f0[] = {
	{ 0x00, "M0 - FRU Not Installed" },
	{ 0x01, "M1 - FRU Inactive" },
	{ 0x02, "M2 - FRU Activation Requested" },
	{ 0x03, "M3 - FRU Activation In Progress" },
	{ 0x04, "M4 - FRU Active" },
	{ 0x05, "M5 - FRU Deactivation Requested" },
	{ 0x06, "M6 - FRU Deactivation In Progress" },
	{ 0x07, "M7 - FRU Communication Lost" },
	{ 0, NULL }
};

static const value_string ssoff_f1[] = {
	{ 0x00, "IPMB-A disabled, IPMB-B disabled" },
	{ 0x01, "IPMB-A enabled, IPMB-B disabled" },
	{ 0x02, "IPMB-A disabled, IPMB-B enabled" },
	{ 0x03, "IPMB-A enabled, IPMB-B enabled" },
	{ 0, NULL }
};

static const value_string ssoff_f2[] = {
	{ 0x00, "Module handle closed" },
	{ 0x01, "Module handle open" },
	{ 0x02, "Quiesced" },
	{ 0x03, "Backend Power Failure" },
	{ 0x04, "Backend Power Shut Down" },
	{ 0, NULL }
};

static const value_string ssoff_f3[] = {
	{ 0x00, "Global status change" },
	{ 0x01, "Channel status change" },
	{ 0, NULL }
};

static const value_string ssoff_f4[] = {
	{ 0x00, "Minor Reset" },
	{ 0x01, "Major Reset" },
	{ 0x02, "Alarm Cutoff" },
	{ 0, NULL }
};

static gboolean
ssi_05_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	if (b == 0x3 && offs == 0x04) {
		/* LAN Leash Lost */
		proto_tree_add_text(tree, tvb, 0, 1, "Network controller #: %d", d);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_08_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	static const value_string err_vals[] = {
		{ 0x00, "Vendor mismatch" },
		{ 0x01, "Revision mismatch" },
		{ 0x02, "Processor missing" },
		{ 0, NULL }
	};
	proto_item *ti;
	proto_tree *s_tree;
	guint32 tmp;

	if (b == 0x3 && offs == 0x06) {
		/* Configuration error */
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Error type");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte3);
		tmp = d & 0x0f;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sError type: %s (0x%02x)",
				ipmi_dcd8(d, 0x0f), val_to_str(tmp, err_vals, "Reserved"), tmp);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_0c_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	if (b == 0x3) {
		proto_tree_add_text(tree, tvb, 0, 1, "Memory module/device ID: %d", d);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_0f_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	static const value_string err_vals[] = {
		{ 0x00, "Unspecified" },
		{ 0x01, "No system memory is physically installed" },
		{ 0x02, "No usable system memory" },
		{ 0x03, "Unrecoverable hard-disk/ATAPI/IDE device failure" },
		{ 0x04, "Unrecoverable system board failure" },
		{ 0x05, "Unrecoverable diskette subsystem failure" },
		{ 0x06, "Unrecoverable hard-disk controller failure" },
		{ 0x07, "Unrecoverable PS/2 or USB keyboard failure" },
		{ 0x08, "Removable boot media not found" },
		{ 0x09, "Unrecoverable video controller failure" },
		{ 0x0a, "No video device detected" },
		{ 0x0b, "Firmware (BIOS) ROM corruption detected" },
		{ 0x0c, "CPU voltage mismatch" },
		{ 0x0d, "CPU speed matching failure" },
		{ 0, NULL }
	};
	static const value_string progress_vals[] = {
		{ 0x00, "Unspecified" },
		{ 0x01, "Memory initialization" },
		{ 0x02, "Hard-disk initialization" },
		{ 0x03, "Secondary processor(s) initialization" },
		{ 0x04, "User authentication" },
		{ 0x05, "User-initiated system setup" },
		{ 0x06, "USB resource configuration" },
		{ 0x07, "PCI resource configuration" },
		{ 0x08, "Option ROM initialization" },
		{ 0x09, "Video initialization" },
		{ 0x0a, "Cache initialization" },
		{ 0x0b, "SM Bus initialization" },
		{ 0x0c, "Keyboard controller initialization" },
		{ 0x0d, "Embedded controller / management controller initialization" },
		{ 0x0e, "Docking station attachment" },
		{ 0x0f, "Enabling docking station" },
		{ 0x10, "Docking station ejection" },
		{ 0x11, "Disabling docking station" },
		{ 0x12, "Calling operating system wake-up vector" },
		{ 0x13, "Starting operating system boot process" },
		{ 0x14, "Baseboard or motherboard initialization" },
		{ 0x16, "Floppy initialization" },
		{ 0x17, "Keyboard test" },
		{ 0x18, "Pointing device test" },
		{ 0x19, "Primary processor initialization" },
		{ 0, NULL }
	};

	if (b == 0x3 && offs == 0x00) {
		proto_tree_add_text(tree, tvb, 0, 1, "Extension code: %s (0x%02x)",
				val_to_str(d, err_vals, "Reserved"), d);
		return TRUE;
	}
	if (b == 0x3 && (offs == 0x01 || offs == 0x02)) {
		proto_tree_add_text(tree, tvb, 0, 1, "Extension code: %s (0x%02x)",
				val_to_str(d, progress_vals, "Reserved"), d);
		return TRUE;
	}
	return FALSE;
}

static const struct evtype_info *ssi_10_saveptr;

static gboolean
ssi_10_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	if (b == 0x3 && offs == 0x00) {
		proto_tree_add_text(tree, tvb, 0, 1, "Memory module/device ID: %d", d);
		return TRUE;
	}
	if (b == 0x3 && offs == 0x01) {
		ssi_10_saveptr = get_evtype_info(d);
		proto_tree_add_text(tree, tvb, 0, 1, "Event/reading type: %s (0x%02x)",
				ssi_10_saveptr->desc, d);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_10_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	proto_item *ti;
	proto_tree *s_tree;
	const value_string *off_vals;

	if (b == 0x3 && offs == 0x01) {
		if (!ssi_10_saveptr) {
			return FALSE; /* something went wrong */
		}
		off_vals = ssi_10_saveptr->offsets ? ssi_10_saveptr->offsets : et_empty;
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Logging details/Offset");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte3);
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sLogging disable for all events of given type: %s",
				ipmi_dcd8(d, 0x20), (d & 0x20) ? "True" : "False");
		proto_tree_add_text(s_tree, tvb, 0, 1, "%s%s event",
				ipmi_dcd8(d, 0x10), (d & 0x10) ? "Deassertion" : "Assertion");
		d &= 0x0f;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sEvent Offset: %s (0x%02x)",
				ipmi_dcd8(d, 0x0f), val_to_str(d, off_vals, "Unknown"), d);
		return TRUE;
	}
	if (b == 0x3 && offs == 0x05) {
		proto_tree_add_text(tree, tvb, 0, 1, "SEL filled: %d%%", d);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_12_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	static const value_string act_vals[] = {
		{ 0x00, "Entry added" },
		{ 0x01, "Entry added because event did not map to standard IPMI event" },
		{ 0x02, "Entry added along with one or more corresponding SEL entries" },
		{ 0x03, "Log cleared" },
		{ 0x04, "Log disabled" },
		{ 0x05, "Log enabled" },
		{ 0, NULL }
	};
	static const value_string type_vals[] = {
		{ 0x00, "MCA Log" },
		{ 0x01, "OEM 1" },
		{ 0x02, "OEM 2" },
		{ 0, NULL }
	};
	static const value_string clock_vals[] = {
		{ 0x00, "SEL Timestamp Clock updated" },
		{ 0x01, "SDR Timestamp Clock updated" },
		{ 0, NULL }
	};
	proto_item *ti;
	proto_tree *s_tree;
	guint32 tmp;

	if (b == 0x3 && offs == 0x03) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Log action/type");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		tmp = d >> 4;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sLog entry action: %s (0x%02x)",
				ipmi_dcd8(d, 0xf0), val_to_str(tmp, act_vals, "Reserved"), tmp);
		tmp = d & 0x0f;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sLog type: %s (0x%02x)",
				ipmi_dcd8(d, 0x0f), val_to_str(tmp, type_vals, "Reserved"), tmp);
		return TRUE;
	}
	if (b == 0x3 && offs == 0x04) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "PEF Actions to be taken");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sDiagnostic interrupt (NMI): %s",
				ipmi_dcd8(d, 0x20), (d & 0x20) ? "True" : "False");
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sOEM Action: %s",
				ipmi_dcd8(d, 0x10), (d & 0x10) ? "True" : "False");
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPower Cycle: %s",
				ipmi_dcd8(d, 0x08), (d & 0x08) ? "True" : "False");
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sReset: %s",
				ipmi_dcd8(d, 0x04), (d & 0x04) ? "True" : "False");
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPower Off: %s",
				ipmi_dcd8(d, 0x02), (d & 0x02) ? "True" : "False");
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sAlert: %s",
				ipmi_dcd8(d, 0x01), (d & 0x01) ? "True" : "False");
		return TRUE;
	}
	if (b == 0x3 && offs == 0x05) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Details");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sEvent is %s of pair",
				ipmi_dcd8(d, 0x80), (d & 0x80) ? "second" : "first");
		tmp = d & 0x0f;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sTimestamp clock type: %s (0x%02x)",
				ipmi_dcd8(d, 0x0f), val_to_str(tmp, clock_vals, "Reserved"), tmp);
	}
	return FALSE;
}

static gboolean
ssi_19_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	if (b == 0x3 && offs == 0x00) {
		proto_tree_add_text(tree, tvb, 0, 1, "Requested power state: %s (0x%02x)",
				val_to_str(d, ssoff_22, "Reserved"), d);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_19_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	if (b == 0x3 && offs == 0x00) {
		proto_tree_add_text(tree, tvb, 0, 1, "Power state at time of request: %s (0x%02x)",
				val_to_str(d, ssoff_22, "Reserved"), d);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_1d_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	/* Copied from ipmi_chassis.c */
	static const value_string cause_vals[] = {
		{ 0x00, "Unknown" },
		{ 0x01, "Chassis Control command" },
		{ 0x02, "Reset via pushbutton" },
		{ 0x03, "Power-up via pushbutton" },
		{ 0x04, "Watchdog expiration" },
		{ 0x05, "OEM" },
		{ 0x06, "Automatic power-up on AC being applied due to 'always restore' power restore policy" },
		{ 0x07, "Automatic power-up on AC being applied due to 'restore previous power state' power restore policy" },
		{ 0x08, "Reset via PEF" },
		{ 0x09, "Power-cycle via PEF" },
		{ 0x0a, "Soft reset" },
		{ 0x0b, "Power-up via RTC wakeup" },
		{ 0, NULL }
	};
	proto_item *ti;
	proto_tree *s_tree;
	guint32 tmp;

	if (b == 0x3 && offs == 0x07) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Restart cause");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		tmp = d & 0x0f;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sRestart cause: %s (0x%02x)",
				ipmi_dcd8(d, 0x0f), val_to_str(tmp, cause_vals, "Reserved"), tmp);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_1d_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	gchar s[ITEM_LABEL_LENGTH];

	ipmi_fmt_channel(s, d);
	if (b == 0x3 && offs == 0x07) {
		proto_tree_add_text(tree, tvb, 0, 1, "Channel: %s", s);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_21_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	static const value_string type_vals[] = {
		{ 0x00, "PCI" },
		{ 0x01, "Drive Array" },
		{ 0x02, "External Peripheral Connector" },
		{ 0x03, "Docking" },
		{ 0x04, "Other standard internal expansion slot" },
		{ 0x05, "Slot associated with entity specified by Entity ID for sensor" },
		{ 0x06, "AdvancedTCA" },
		{ 0x07, "DIMM/Memory device" },
		{ 0x08, "FAN" },
		{ 0x09, "PCI Express" },
		{ 0x0a, "SCSI (parallel)" },
		{ 0x0b, "SATA/SAS" },
		{ 0, NULL }
	};

	if (b == 0x3) {
		proto_tree_add_text(tree, tvb, 0, 1, "Slot/connector type: %s (0x%02x)",
				val_to_str(d, type_vals, "Reserved"), d);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_21_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	if (b == 0x3) {
		proto_tree_add_text(tree, tvb, 0, 1, "Slot/connector #: %d", d);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_23_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	static const value_string intr_vals[] = {
		{ 0x00, "None" },
		{ 0x01, "SMI" },
		{ 0x02, "NMI" },
		{ 0x03, "Messaging interrupt" },
		{ 0x0f, "Unspecified" },
		{ 0, NULL }
	};
	static const value_string use_vals[] = {
		{ 0x01, "BIOS FRB2" },
		{ 0x02, "BIOS/POST" },
		{ 0x03, "OS Load" },
		{ 0x04, "SMS/OS" },
		{ 0x05, "OEM" },
		{ 0x0f, "Unspecified" },
		{ 0, NULL }
	};
	proto_item *ti;
	proto_tree *s_tree;
	guint32 tmp;

	if (b == 0x3) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Timer use/interrupt");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		tmp = d >> 4;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sInterrupt type: %s (0x%02x)",
				ipmi_dcd8(d, 0xf0), val_to_str(tmp, intr_vals, "Reserved"), tmp);
		tmp = d & 0x0f;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sTimer use at expiration: %s (0x%02x)",
				ipmi_dcd8(d, 0x0f), val_to_str(tmp, use_vals, "Reserved"), tmp);

		return TRUE;
	}
	return FALSE;
}

static int ssi28_is_logical_fru;

static gboolean
ssi_28_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	proto_item *ti;
	proto_tree *s_tree;
	guint32 tmp;

	if (b == 0x3 && (offs == 0x00 || offs == 0x04)) {
		proto_tree_add_text(tree, tvb, 0, 1, "Sensor number: %d", d);
		return TRUE;
	}
	if (b == 0x3 && offs == 0x05) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "FRU details");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		ssi28_is_logical_fru = (d & 0x80) ? 1 : 0;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sLogical FRU device: %s",
				ipmi_dcd8(d, 0x80), ssi28_is_logical_fru ? "True" : "False");
		tmp = (d & 0x18) >> 3;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sLUN for Master Read-Write command: 0x%02x",
				ipmi_dcd8(d, 0x18), tmp);
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPrivate Bus ID: 0x%02x",
				ipmi_dcd8(d, 0x07), d & 0x07);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_28_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	if (b == 0x3 && offs == 0x05) {
		if (ssi28_is_logical_fru == -1) {
			return FALSE; /* something went wrong */
		}
		if (ssi28_is_logical_fru) {
			proto_tree_add_text(tree, tvb, 0, 1, "FRU Device ID within controller: 0x%02x", d);
		} else {
			proto_tree_add_text(tree, tvb, 0, 1, "I2C Slave Address: 0x%02x", d);
		}
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_2a_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	proto_item *ti;
	proto_tree *s_tree;

	if (b == 0x3) {
		d &= 0x3f;
		ti = proto_tree_add_text(tree, tvb, 0, 1, "User ID: %d", d);
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		if (d) {
			proto_tree_add_text(s_tree, tvb, 0, 1, "%sUser ID: %d",
					ipmi_dcd8(d, 0x3f), d);
		} else {
			proto_tree_add_text(s_tree, tvb, 0, 1, "%sUser ID: unspecified (%d)",
					ipmi_dcd8(d, 0x3f), d);
		}
	}
	return FALSE;
}

static gboolean
ssi_2a_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	static const value_string deact_vals[] = {
		{ 0x00, "Unspecified cause" },
		{ 0x01, "Close Session command" },
		{ 0x02, "Timeout" },
		{ 0x03, "Configuration change" },
		{ 0, NULL }
	};
	proto_item *ti;
	proto_tree *s_tree;
	gchar s[ITEM_LABEL_LENGTH];
	guint32 tmp;

	if (b == 0x3) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Deactivation cause/Channel #");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte3);
		tmp = (d >> 4) & 0x3;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sSession deactivated by: %s (0x%02x)",
				ipmi_dcd8(d, 0x30), val_to_str(tmp, deact_vals, "Reserved"), tmp);
		ipmi_fmt_channel(s, d & 0xf);
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sChannel: %s",
				ipmi_dcd8(d, 0x0f), s);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_2b_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	static const value_string vctype_vals[] = {
		{ 0x00, "Unspecified" },
		{ 0x01, "Management controller device ID" },
		{ 0x02, "Management controller firmware revision" },
		{ 0x03, "Management controller device revision" },
		{ 0x04, "Management controller manufacturer ID" },
		{ 0x05, "Management controller IPMI version" },
		{ 0x06, "Management controller auxiliary firmware ID" },
		{ 0x07, "Management controller firmware boot block" },
		{ 0x08, "Other management controller firmware" },
		{ 0x09, "System firmware (EFI/BIOS) change" },
		{ 0x0a, "SMBIOS change" },
		{ 0x0b, "Operating system change" },
		{ 0x0c, "Operating system loader change" },
		{ 0x0d, "Service or diagnostic partition change" },
		{ 0x0e, "Management software agent change" },
		{ 0x0f, "Management software application change" },
		{ 0x10, "Management software middleware change" },
		{ 0x11, "Programmable hardware change" },
		{ 0x12, "Board/FRU module change" },
		{ 0x13, "Board/FRU component change" },
		{ 0x14, "Board/FRU replaced with equivalent version" },
		{ 0x15, "Board/FRU replaced with newer version" },
		{ 0x16, "Board/FRU replaced with older version" },
		{ 0x17, "Board/FRU configuration change" },
		{ 0, NULL }
	};

	if (b == 0x3) {
		proto_tree_add_text(tree, tvb, 0, 1, "Version change type: %s",
				val_to_str(d, vctype_vals, "Reserved"));
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_2c_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si,
		guint32 b, guint32 offs _U_, guint32 d)
{
	static const value_string cause_vals[] = {
		{ 0x00, "Normal State Change" },
		{ 0x01, "Change commanded by software external to FRU" },
		{ 0x02, "State Change due to operator changing a handle latch" },
		{ 0x03, "State Change due to operator pressing the hot swap push button" },
		{ 0x04, "State Change due to FRU programmatic action" },
		{ 0x05, "Communication lost" },
		{ 0x06, "Communication lost due to local failure" },
		{ 0x07, "State Change due to unexpected extraction" },
		{ 0x08, "State Change due to operator intervention/update" },
		{ 0x09, "Unable to compute IPMB address" },
		{ 0x0a, "Unexpected Deactivation" },
		{ 0x0f, "State Change, Cause Unknown" },
		{ 0, NULL }
	};
	proto_item *ti;
	proto_tree *s_tree;
	guint32 tmp;

	if (b == 0x3) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Previous state/Cause");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		tmp = d >> 4;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sCause: %s (0x%02x)",
				ipmi_dcd8(d, 0xf0), val_to_str(tmp, cause_vals, "Reserved"), tmp);
		tmp = d & 0xf;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPrevious state: %s (0x%02x)",
				ipmi_dcd8(d, 0x0f), val_to_str(tmp, si->offsets, "Reserved"), tmp);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_f0_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si,
		guint32 b, guint32 offs _U_, guint32 d)
{
	static const value_string cause_vals[] = {
		{ 0x00, "Normal State Change" },
		{ 0x01, "Change Commanded by Shelf Manager with Set FRU Activation" },
		{ 0x02, "State Change due to operator changing a Handle Switch" },
		{ 0x03, "State Change due to FRU programmatic action" },
		{ 0x04, "Communication Lost or Regained" },
		{ 0x05, "Communication Lost or Regained - locally detected" },
		{ 0x06, "Surprise State Change due to extraction" },
		{ 0x07, "State Change due to provided information" },
		{ 0x08, "Invalid Hardware Address Detected" },
		{ 0x09, "Unexpected Deactivation" },
		{ 0x0f, "State Change, Cause Unknown" },
		{ 0, NULL }
	};
	proto_item *ti;
	proto_tree *s_tree;
	guint32 tmp;

	if (b == 0x2) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Previous state/Cause");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		tmp = d >> 4;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sCause: %s (0x%02x)",
				ipmi_dcd8(d, 0xf0), val_to_str(tmp, cause_vals, "Reserved"), tmp);
		tmp = d & 0xf;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPrevious state: %s (0x%02x)",
				ipmi_dcd8(d, 0x0f), val_to_str(tmp, si->offsets, "Reserved"), tmp);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_f0_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	if (b == 0x2) {
		proto_tree_add_text(tree, tvb, 0, 1, "FRU Id: %d", d);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_f1_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	proto_item *ti;
	proto_tree *s_tree;
	gchar s[ITEM_LABEL_LENGTH];

	if (b == 0x02) {
		ipmi_fmt_channel(s, d >> 4);
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Channel: %s", s);
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sChannel: %s",
				ipmi_dcd8(d, 0xf0), s);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_f1_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs _U_, guint32 d)
{
	static const char *override_state[2] = {
		"Override state, bus isolated",
		"Local control state"
	};
	static const value_string status_vals[] = {
		{ 0x00, "No failure" },
		{ 0x01, "Unable to drive clock HI" },
		{ 0x02, "Unable to drive data HI" },
		{ 0x03, "Unable to drive clock LO" },
		{ 0x04, "Unable to drive data LO" },
		{ 0x05, "Clock low timeout" },
		{ 0x06, "Under test" },
		{ 0x07, "Undiagnosed communications failure" },
		{ 0, NULL }
	};
	proto_item *ti;
	proto_tree *s_tree;
	guint32 tmp;

	if (b == 0x02) {
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Override state / Local status");
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte3);
		tmp = d & 0x80;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sIPMB-B Override state: %s",
				ipmi_dcd8(d, 0x80), override_state[!!tmp]);
		tmp = (d & 0x70) >> 4;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sIPMB-B Local status: %s (0x%02x)",
				ipmi_dcd8(d, 0x70), val_to_str(tmp, status_vals, "Reserved"), tmp);
		tmp = d & 0x08;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sIPMB-A Override state: %s",
				ipmi_dcd8(d, 0x08), override_state[!!tmp]);
		tmp = d & 0x07;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sIPMB-A Local status: %s (0x%02x)",
				ipmi_dcd8(d, 0x07), val_to_str(tmp, status_vals, "Reserved"), tmp);
		return TRUE;
	}
	return FALSE;
}

static gboolean
ssi_f3_2(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	proto_tree *s_tree;
	proto_item *ti;
	guint32 tmp;

	if (b == 0x02 && offs == 0x00) {
		/* Global status change */
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Global Status: 0x%02x", d);
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		tmp = d & 0x08;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sRedundant PM: %s",
				ipmi_dcd8(d, 0x08),
				tmp ? "providing Payload Current" :
				"not providing Payload Current (or this is Primary PM)");
		tmp = d & 0x04;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPayload Power: %s",
				ipmi_dcd8(d, 0x04), tmp ? "is good" : "is not good");
		tmp = d & 0x02;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sManagement Power: %s",
				ipmi_dcd8(d, 0x02), tmp ? "is good" : "is not good");
		tmp = d & 0x01;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sRole: %s",
				ipmi_dcd8(d, 0x01), tmp ? "Primary" : "Redundant");
		return TRUE;
	} else if (b == 0x02 && offs == 0x01) {
		/* Channel status change */
		ti = proto_tree_add_text(tree, tvb, 0, 1, "Channel Status: 0x%02x", d);
		s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte2);
		tmp = d & 0x40;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPWR_ON: %s",
				ipmi_dcd8(d, 0x40), tmp ? "asserted" : "not asserted/not supported");
		tmp = d & 0x20;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPayload Power Overcurrent: %s",
				ipmi_dcd8(d, 0x20), tmp ? "has been detected" : "has not been detected");
		tmp = d & 0x10;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPayload Power: %s",
				ipmi_dcd8(d, 0x10), tmp ? "is enabled" : "is disabled");
		tmp = d & 0x08;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sENABLE#: %s",
				ipmi_dcd8(d, 0x08), tmp ? "asserted" : "not asserted");
		tmp = d & 0x04;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sManagement Power Overcurrent: %s",
				ipmi_dcd8(d, 0x04), tmp ? "has been detected" : "has not been detected");
		tmp = d & 0x02;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sManagement Power: %s",
				ipmi_dcd8(d, 0x02), tmp ? "is enabled" : "is disabled");
		tmp = d & 0x01;
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sPS1#: %s",
				ipmi_dcd8(d, 0x01), tmp ? "asserted" : "not asserted");
		return TRUE;
	}

	return FALSE;
}

static gboolean
ssi_f3_3(proto_tree *tree, tvbuff_t *tvb, const struct sensor_info *si _U_,
		guint32 b, guint32 offs, guint32 d)
{
	if (b == 0x02 && offs == 0x01) {
		/* Channel status change */
		proto_tree_add_text(tree, tvb, 0, 1, "Power Channel number: %d", d);
		return TRUE;
	}

	return FALSE;
}

static void
reinit_statics(void)
{
	ssi_10_saveptr = NULL;
	ssi28_is_logical_fru = -1;
}

static const struct sensor_info *
get_sensor_info(unsigned int stype)
{
	static const struct {
		unsigned int id;
		struct sensor_info si;
	} si_tab[] = {
		{ 0x01, { NULL,     NULL,     NULL,     "Temperature" }},
		{ 0x02, { NULL,     NULL,     NULL,     "Voltage" }},
		{ 0x03, { NULL,     NULL,     NULL,     "Current" }},
		{ 0x04, { NULL,     NULL,     NULL,     "Fan" }},
		{ 0x05, { ssoff_05, ssi_05_2, NULL,     "Physical Security (Chassis Intrusion)" }},
		{ 0x06, { ssoff_06, NULL,     NULL,     "Platform Security Violation Attempt" }},
		{ 0x07, { ssoff_07, NULL,     NULL,     "Processor" }},
		{ 0x08, { ssoff_08, NULL,     ssi_08_3, "Power Supply" }},
		{ 0x09, { ssoff_09, NULL,     NULL,     "Power Unit" }},
		{ 0x0a, { NULL,     NULL,     NULL,     "Cooling Device" }},
		{ 0x0b, { NULL,     NULL,     NULL,     "Other Units-based Sensor (per units given in SDR)" }},
		{ 0x0c, { ssoff_0c, NULL,     ssi_0c_3, "Memory" }},
		{ 0x0d, { ssoff_0d, NULL,     NULL,     "Drive Slot (Bay)" }},
		{ 0x0e, { NULL,     NULL,     NULL,     "POST Memory Resize" }},
		{ 0x0f, { ssoff_0f, ssi_0f_2, NULL,     "System Firmware Progress (formerly POST Error)" }},
		{ 0x10, { ssoff_10, ssi_10_2, ssi_10_3, "Event Logging Disabled" }},
		{ 0x11, { ssoff_11, NULL,     NULL,     "Watchdog 1" }},
		{ 0x12, { ssoff_12, ssi_12_2, NULL,     "System Event" }},
		{ 0x13, { ssoff_13, NULL,     NULL,     "Critical Interrupt" }},
		{ 0x14, { ssoff_14, NULL,     NULL,     "Button" }},
		{ 0x15, { NULL,     NULL,     NULL,     "Module / Board" }},
		{ 0x16, { NULL,     NULL,     NULL,     "Microcontroller / Coprocessor" }},
		{ 0x17, { NULL,     NULL,     NULL,     "Add-in Card" }},
		{ 0x18, { NULL,     NULL,     NULL,     "Chassis" }},
		{ 0x19, { ssoff_19, ssi_19_2, ssi_19_3, "Chip Set" }},
		{ 0x1a, { NULL,     NULL,     NULL,     "Other FRU" }},
		{ 0x1b, { ssoff_1b, NULL,     NULL,     "Cable / Interconnect" }},
		{ 0x1c, { NULL,     NULL,     NULL,     "Terminator" }},
		{ 0x1d, { ssoff_1d, ssi_1d_2, ssi_1d_3, "System Boot / Restart Initiated" }},
		{ 0x1e, { ssoff_1e, NULL,     NULL,     "Boot Error" }},
		{ 0x1f, { ssoff_1f, NULL,     NULL,     "OS Boot" }},
		{ 0x20, { ssoff_20, NULL,     NULL,     "OS Critical Stop" }},
		{ 0x21, { ssoff_21, ssi_21_2, ssi_21_3, "Slot / Connector" }},
		{ 0x22, { ssoff_22, NULL,     NULL,     "System ACPI Power State" }},
		{ 0x23, { ssoff_23, ssi_23_2, NULL,     "Watchdog 2" }},
		{ 0x24, { ssoff_24, NULL,     NULL,     "Platform Alert" }},
		{ 0x25, { ssoff_25, NULL,     NULL,     "Entity Presence" }},
		{ 0x26, { NULL,     NULL,     NULL,     "Monitor ASIC / IC" }},
		{ 0x27, { ssoff_27, NULL,     NULL,     "LAN" }},
		{ 0x28, { ssoff_28, ssi_28_2, ssi_28_3, "Management Subsystem Health" }},
		{ 0x29, { ssoff_29, NULL,     NULL,     "Battery" }},
		{ 0x2a, { ssoff_2a, ssi_2a_2, ssi_2a_3, "Session Audit" }},
		{ 0x2b, { ssoff_2b, ssi_2b_2, NULL,     "Version Change" }},
		{ 0x2c, { ssoff_2c, ssi_2c_2, NULL,     "FRU State" }},
		{ 0xf0, { ssoff_f0, ssi_f0_2, ssi_f0_3, "Hot Swap (ATCA)" }},
		{ 0xf1, { ssoff_f1, ssi_f1_2, ssi_f1_3, "IPMB Physical State (ATCA)" }},
		{ 0xf2, { ssoff_f2, NULL,     NULL,     "Module Hot Swap (AMC.0)" }},
		{ 0xf3, { ssoff_f3, ssi_f3_2, ssi_f3_3, "Power Channel Notification" }},
		{ 0xf4, { ssoff_f4, NULL,     NULL,     "Telco Alarm Input" }}
	};
	static const struct sensor_info si_oem = {
		NULL, NULL, NULL, "OEM Reserved"
	};
	static const struct sensor_info si_rsrv = {
		NULL, NULL, NULL, "Reserved"
	};
	unsigned int i;

	/* Look for explicitly defined ones */
	for (i = 0; i < array_length(si_tab); i++) {
		if (si_tab[i].id == stype) {
			return &si_tab[i].si;
		}
	}

	if (stype >= 0xc0 && stype <= 0xff) {
		return &si_oem;
	}

	return &si_rsrv;
}

static void
parse_platform_event(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *s_tree;
	tvbuff_t *next_tvb;
	unsigned int stype, evtype;
	const struct sensor_info *si;
	const struct evtype_info *eti;
	unsigned int d, b2, b3, offs;
	const value_string *off_vals;

	stype = tvb_get_guint8(tvb, 1);
	si = get_sensor_info(stype);
	evtype = tvb_get_guint8(tvb, 3) & 0x7f;
	eti = get_evtype_info(evtype);

	proto_tree_add_item(tree, hf_ipmi_se_evt_rev, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint_format_value(tree, hf_ipmi_se_evt_sensor_type, tvb, 1, 1, stype,
			"%s (0x%02x)", si->desc, stype);
	proto_tree_add_item(tree, hf_ipmi_se_evt_sensor_num, tvb, 2, 1, TRUE);
	ti = proto_tree_add_item(tree, hf_ipmi_se_evt_byte3, tvb, 3, 1, ENC_LITTLE_ENDIAN);
	s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_byte3);
	proto_tree_add_item(s_tree, hf_ipmi_se_evt_dir, tvb, 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint_format(s_tree, hf_ipmi_se_evt_type, tvb, 3, 1, evtype,
			"%sEvent/Reading type: %s (0x%02x)", ipmi_dcd8(evtype, 0x7f),
			eti->desc, evtype);

	offs = tvb_get_guint8(tvb, 4);
	b2 = offs >> 6;
	b3 = (offs >> 4) & 0x3;
	off_vals = eti->offsets ? eti->offsets : si->offsets ? si->offsets : et_empty;

	ti = proto_tree_add_item(tree, hf_ipmi_se_evt_data1, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	s_tree = proto_item_add_subtree(ti, ett_ipmi_se_evt_evd_byte1);
	proto_tree_add_uint_format(s_tree, hf_ipmi_se_evt_data1_b2, tvb, 4, 1, b2 << 6,
			"%sByte 2: %s (0x%02x)",
			ipmi_dcd8(offs, 0xc0), val_to_str(b2, eti->byte2, "Reserved"), b2);
	proto_tree_add_uint_format(s_tree, hf_ipmi_se_evt_data1_b3, tvb, 4, 1, b3 << 4,
			"%sByte 3: %s (0x%02x)",
			ipmi_dcd8(offs, 0x30), val_to_str(b3, eti->byte3, "Reserved"), b3);
	offs &= 0x0f;
	proto_tree_add_uint_format(s_tree, hf_ipmi_se_evt_data1_offs, tvb, 4, 1, offs,
			"%sOffset: %s (0x%02x)",
			ipmi_dcd8(offs, 0x0f), val_to_str(offs, off_vals, "Reserved"), offs);

	/* This is tricky. First, bytes 2-3 are optional and may be absent.
	   Second, the necessity to interpret them either in a generic way or in
	   sensor-specific way depends on the value in byte 1. And at last,
	   there could be mixture of both ways: the byte 2 can relate to
	   'previous state', which could be sensor-specific.

	   Thus, intrp() methods return whether they actually handled the
	   value. If the 'generic' (related to event/reading type) method fails
	   to handle the value, we call the 'specific' one. If that fails as
	   well, we just output it as a hex value.

	   This is further complicated by the fact that in some events, the
	   interpretation of the byte 3 depends on the 2nd byte - which could
	   be specified as having some generic type. Thus, we check it and
	   fall back to "default" display in such weird cases.
	*/
	reinit_statics();
	if (tvb_length(tvb) <= 5) {
		return;
	}

	next_tvb = tvb_new_subset(tvb, 5, 1, 1);
	d = tvb_get_guint8(next_tvb, 0);
	if ((eti->intrp2 && eti->intrp2(tree, next_tvb, si, b2, offs, d))
			|| (si->intrp2 && si->intrp2(tree, next_tvb, si, b2, offs, d))) {
		/* One of them succeeded. */
		ti = proto_tree_add_item(tree, hf_ipmi_se_evt_data2, next_tvb, 0, 1, ENC_LITTLE_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(ti);
	} else {
		/* Just add as hex */
		proto_tree_add_item(tree, hf_ipmi_se_evt_data2, next_tvb, 0, 1, ENC_LITTLE_ENDIAN);
	}

	/* Now the same for byte 3 */
	if (tvb_length(tvb) <= 6) {
		return;
	}

	next_tvb = tvb_new_subset(tvb, 6, 1, 1);
	d = tvb_get_guint8(next_tvb, 0);
	if ((eti->intrp3 && eti->intrp3(tree, next_tvb, si, b3, offs, d))
			|| (si->intrp3 && si->intrp3(tree, next_tvb, si, b3, offs, d))) {
		/* One of them succeeded. */
		ti = proto_tree_add_item(tree, hf_ipmi_se_evt_data3, next_tvb, 0, 1, ENC_LITTLE_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(ti);
	} else {
		/* Just add as hex */
		proto_tree_add_item(tree, hf_ipmi_se_evt_data3, next_tvb, 0, 1, ENC_LITTLE_ENDIAN);
	}
}

/* Common for set/get config parameters */
static const value_string cp00_sip_vals[] = {
	{ 0x00, "Set complete" },
	{ 0x01, "Set in progress" },
	{ 0x02, "Commit write" },
	{ 0x03, "Reserved" },
	{ 0, NULL }
};

static const struct true_false_string cp10_use_tfs = {
	"BMC uses the following value",
	"BMC uses the value returned from Get System GUID command"
};

static const struct true_false_string cp15_rq_frc_tfs = {
	"Force control operation",
	"Request control operation"
};

static const struct true_false_string cp15_imm_delay_tfs = {
	"Delayed control",
	"Immediate control"
};

static const value_string cp15_op_vals[] = {
	{ 0x00, "Power down" },
	{ 0x01, "Power up" },
	{ 0x02, "Power cycle" },
	{ 0x03, "Hard reset" },
	{ 0x04, "Pulse diagnostic interrupt" },
	{ 0x05, "Initiate a soft-shutdown of OS via ACPI by emulating a fatal overtemperature" },
	{ 0, NULL }
};

static void
cfgparam_00(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_cp00_sip, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
cfgparam_01(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_cp01_alert_startup, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_cp01_startup, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_cp01_event_msg, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_cp01_pef, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
cfgparam_02(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_cp02_diag_intr, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_cp02_oem_action, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_cp02_pwr_cycle, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_cp02_reset, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_cp02_pwr_down, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_cp02_alert, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}


static void
cfgparam_03(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_cp03_startup, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
cfgparam_04(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_cp04_alert_startup, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
cfgparam_05(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_cp05_num_evfilters, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
cfgparam_06(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_cp06_filter, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_cp06_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_se_cp06_data, tvb, 1, 20, ENC_NA);
}

static void
cfgparam_07(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_cp07_filter, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_cp07_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_se_cp06_data, tvb, 1, 1, ENC_NA);
}

static void
cfgparam_08(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_cp08_policies, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
cfgparam_09(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_cp09_entry, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_cp09_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_se_cp09_data, tvb, 1, 3, ENC_NA);
}

static void
cfgparam_10(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_cp10_useval, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_cp10_byte1, byte1, TRUE, 0);
	ipmi_add_guid(tree, hf_ipmi_se_cp10_guid, tvb, 1);
}

static void
cfgparam_11(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_cp11_num_alertstr, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
cfgparam_12(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte2[] = { &hf_ipmi_se_cp12_evfilter, NULL };
	static const int *byte3[] = { &hf_ipmi_se_cp12_alert_stringset, NULL };
	proto_item *ti;
	proto_tree *s_tree;
	guint8 tmp;

	ti = proto_tree_add_item(tree, hf_ipmi_se_cp12_byte1, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	s_tree = proto_item_add_subtree(ti, ett_ipmi_se_cp12_byte1);
	tmp = tvb_get_guint8(tvb, 0) & 0x7f;
	if (tmp) {
		proto_tree_add_item(s_tree, hf_ipmi_se_cp12_alert_stringsel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	} else {
		proto_tree_add_uint_format(s_tree, hf_ipmi_se_cp12_alert_stringsel, tvb, 0, 1,
				tmp, "%sSelects volatile string parameters", ipmi_dcd8(tmp, 0x7f));
	}

	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_se_cp12_byte2, byte2, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL, ett_ipmi_se_cp12_byte3, byte3, TRUE, 0);
}

static void
cfgparam_13(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_cp13_stringsel, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_cp13_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_se_cp13_blocksel, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_cp13_string, tvb, 2, tvb_length(tvb) - 2, TRUE);
}

static void
cfgparam_14(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_cp14_num_gct, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
cp15_add_group_and_member(proto_tree *tree, tvbuff_t *tvb, guint offs, guint num)
{
	static const int *byte2[] = { &hf_ipmi_se_cp15_member_check, &hf_ipmi_se_cp15_member_id, NULL };
	const char *gdesc;
	guint8 tmp;

	tmp = tvb_get_guint8(tvb, offs);
	if (tmp == 0x00) {
		gdesc = " (unspecified)";
	} else if (tmp == 0xff) {
		gdesc = " (all groups)";
	} else {
		gdesc = "";
	}

	proto_tree_add_uint_format(tree, hf_ipmi_se_cp15_group, tvb, offs, 1, tmp,
			"Group ID %d: %d%s", num, tmp, gdesc);
	proto_tree_add_bitmask_text(tree, tvb, offs + 1, 1, NULL, NULL, ett_ipmi_se_cp15_member, byte2, TRUE, 0);
}

static void
cfgparam_15(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_cp15_gctsel, NULL };
	static const int *byte2[] = { &hf_ipmi_se_cp15_force, &hf_ipmi_se_cp15_delayed, &hf_ipmi_se_cp15_channel, NULL };
	static const int *byte11[] = { &hf_ipmi_se_cp15_retries, &hf_ipmi_se_cp15_operation, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_cp15_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_se_cp15_byte2, byte2, TRUE, 0);
	cp15_add_group_and_member(tree, tvb, 2, 0);
	cp15_add_group_and_member(tree, tvb, 4, 1);
	cp15_add_group_and_member(tree, tvb, 6, 2);
	cp15_add_group_and_member(tree, tvb, 8, 3);
	proto_tree_add_bitmask_text(tree, tvb, 10, 1, NULL, NULL, ett_ipmi_se_cp15_byte11, byte11, TRUE, 0);
}

static struct {
	void (*intrp)(tvbuff_t *tvb, proto_tree *tree);
	const char *name;
} conf_params[] = {
	{ cfgparam_00, "Set In Progress" },
	{ cfgparam_01, "PEF Control" },
	{ cfgparam_02, "PEF Action global control" },
	{ cfgparam_03, "PEF Startup Delay" },
	{ cfgparam_04, "PEF Alert Startup Delay" },
	{ cfgparam_05, "Number of Event Filters" },
	{ cfgparam_06, "Event Filter Table" },
	{ cfgparam_07, "Event Filter Table Data 1" },
	{ cfgparam_08, "Number of Alert Policy Entries" },
	{ cfgparam_09, "Alert Policy Table" },
	{ cfgparam_10, "System GUID" },
	{ cfgparam_11, "Number of Alert Strings" },
	{ cfgparam_12, "Alert String Keys" },
	{ cfgparam_13, "Alert Strings" },
	{ cfgparam_14, "Number of Group Control Table Entries" },
	{ cfgparam_15, "Group Control Table" }
};

static const value_string vals_11_pef_timer[] = {
	{ 0x00, "Disable Postpone Timer" },
	{ 0xfe, "Temporary PEF disable" },
	{ 0xff, "Get Present Countdown Value" },
	{ 0, NULL }
};

static const struct true_false_string tfs_14_processed = {
	"BMC",
	"software"
};

static const value_string vals_16_op[] = {
	{ 0x00, "Initiate Alert" },
	{ 0x01, "Get Alert Immediate status" },
	{ 0x02, "Clear Alert Immediate status" },
	{ 0x03, "Reserved" },
	{ 0, NULL }
};

static const value_string vals_16_status[] = {
	{ 0x00, "No status" },
	{ 0x01, "Alert was Normal End" },
	{ 0x02, "`Call Retry' retries failed" },
	{ 0x03, "Alert failed due to timeouts waiting for acknowledge on all retries" },
	{ 0xFF, "Alert by this command is in progress" },
	{ 0, NULL }
};

static const struct true_false_string tfs_20_op = {
	"Get SDR Count", "Get sensor count"
};

static const struct true_false_string tfs_20_pop = {
	"Dynamic", "Static"
};

static const value_string vals_28_act[] = {
	{ 0x00, "Do not change individual enables" },
	{ 0x01, "Enable selected event messages" },
	{ 0x02, "Disable selected event messages" },
	{ 0x03, "Reserved" },
	{ 0, NULL }
};

static const struct true_false_string tfs_28_enable = {
	"Enable", "Disable"
};

static const struct true_false_string tfs_29_enabled = {
	"Enabled", "Disabled"
};

static const struct true_false_string tfs_2a_sel = {
	"Selected", "All"
};

static const struct true_false_string tfs_2b_enabled = {
	"Enabled", "Disabled"
};

/* Set event receiver.
 */
static void
rq00(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte2[] = { &hf_ipmi_se_00_lun, NULL };
	unsigned int addr;

	addr = tvb_get_guint8(tvb, 0);
	if (addr == 0xff) {
		proto_tree_add_uint_format(tree, hf_ipmi_se_00_addr, tvb, 0, 1,
				addr, "Disable Message Generation (0xFF)");
	} else {
		proto_tree_add_item(tree, hf_ipmi_se_00_addr, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	}

	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_se_00_byte2, byte2, TRUE, 0);
}

/* Get event receiver.
 */
static void
rs01(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte2[] = { &hf_ipmi_se_01_lun, NULL };
	unsigned int addr;

	addr = tvb_get_guint8(tvb, 0);
	if (addr == 0xff) {
		proto_tree_add_uint_format(tree, hf_ipmi_se_01_addr, tvb, 0, 1,
				addr, "Message Generation Disabled (0xFF)");
	} else {
		proto_tree_add_item(tree, hf_ipmi_se_01_addr, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	}

	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_se_01_byte2, byte2, TRUE, 0);
}

/* Platform event.
 */
static void
rq02(tvbuff_t *tvb, proto_tree *tree)
{
	parse_platform_event(tvb, tree);
}

/* Get PEF capabilities.
 */
static void
rs10(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte2[] = { &hf_ipmi_se_10_action_oem_filter, &hf_ipmi_se_10_action_diag_intr,
		&hf_ipmi_se_10_action_oem_action, &hf_ipmi_se_10_action_pwr_cycle, &hf_ipmi_se_10_action_reset,
		&hf_ipmi_se_10_action_pwr_down, &hf_ipmi_se_10_action_alert, NULL };

	proto_tree_add_item(tree, hf_ipmi_se_10_pef_version, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, "Action support: ", "None", ett_ipmi_se_10_action,
			byte2, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_se_10_entries, tvb, 2, 1, ENC_LITTLE_ENDIAN);
}

/* Arm PEF Postpone Timer.
 */
static void
rq11(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 val;

	val = tvb_get_guint8(tvb, 0);
	proto_tree_add_uint_format(tree, hf_ipmi_se_11_rq_timeout, tvb, 0, 1,
			val, "%s", val_to_str(val, vals_11_pef_timer, "Arm Timer for: %d sec"));
}

static void
rs11(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 val;

	val = tvb_get_guint8(tvb, 0);
	proto_tree_add_uint_format(tree, hf_ipmi_se_11_rs_timeout, tvb, 0, 1,
			val, "%s", val_to_str(val, vals_11_pef_timer, "Present Timer Countdown value: %d sec"));
}

/* Set PEF Configuration Parameters.
 */
static void
rq12(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *s_tree;
	tvbuff_t *sub;
	guint8 pno;
	const char *desc;

	pno = tvb_get_guint8(tvb, 0) & 0x7f;
	if (pno < array_length(conf_params)) {
		desc = conf_params[pno].name;
	} else if (pno >= 96 && pno <= 127) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}
	ti = proto_tree_add_uint_format(tree, hf_ipmi_se_12_byte1, tvb, 0, 1,
			pno, "Parameter selector: %s (0x%02x)", desc, pno);
	s_tree = proto_item_add_subtree(ti, ett_ipmi_se_12_byte1);
	proto_tree_add_uint_format(s_tree, hf_ipmi_se_12_param, tvb, 0, 1,
			pno, "%sParameter selector: %s (0x%02x)",
			ipmi_dcd8(pno, 0x7f), desc, pno);

	if (pno < array_length(conf_params)) {
		sub = tvb_new_subset(tvb, 1, tvb_length(tvb) - 1, tvb_length(tvb) - 1);
		conf_params[pno].intrp(sub, tree);
	} else {
		proto_tree_add_none_format(tree, hf_ipmi_se_12_data, tvb, 1, tvb_length(tvb) - 1,
				"Configuration parameter data: %s", desc);
	}
}

static const value_string cc12[] = {
	{ 0x80, "Parameter not supported" },
	{ 0x81, "Attempt to set the 'set in progress' value (in parameter #0) when not in the 'set complete' state" },
	{ 0x82, "Attempt to write read-only parameter" },
	{ 0x83, "Attempt to read write-only parameter" },
	{ 0, NULL }
};

/* Get PEF Configuration Parameters.
 */
static void
rq13(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *s_tree;
	guint32 pno;
	const char *desc;

	pno = tvb_get_guint8(tvb, 0);

	if (!tree) {
		/* Just cache parameter selector */
		ipmi_setsaveddata(0, pno);
		return;
	}

	pno &= 0x7f;

	if (pno < array_length(conf_params)) {
		desc = conf_params[pno].name;
	} else if (pno >= 96 && pno <= 127) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}
	ti = proto_tree_add_uint_format(tree, hf_ipmi_se_13_byte1, tvb, 0, 1,
			pno, "Parameter selector: %s (0x%02x)", desc, pno);
	s_tree = proto_item_add_subtree(ti, ett_ipmi_se_13_byte1);
	proto_tree_add_item(s_tree, hf_ipmi_se_13_getrev, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint_format(s_tree, hf_ipmi_se_13_param, tvb, 0, 1,
			pno, "%sParameter selector: %s (0x%02x)",
			ipmi_dcd8(pno, 0x7f), desc, pno);

	proto_tree_add_item(tree, hf_ipmi_se_13_set, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_13_block, tvb, 2, 1, ENC_LITTLE_ENDIAN);
}

static void
rs13(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_13_rev_present, &hf_ipmi_se_13_rev_compat, NULL };
	proto_item *ti;
	tvbuff_t *sub;
	guint32 pno;
	const char *desc;

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Parameter revision", NULL,
			ett_ipmi_se_13_rev, byte1, TRUE, 0);

	if (!ipmi_getsaveddata(0, &pno)) {
		/* No request found - cannot parse further */
		if (tvb_length(tvb) > 1) {
			proto_tree_add_item(tree, hf_ipmi_se_13_data, tvb, 1, tvb_length(tvb) - 1, ENC_NA);
		}
		return;
	}

	if ((pno & 0x80) && tvb_length(tvb) > 1) {
		ti = proto_tree_add_text(tree, tvb, 0, 0, "Requested parameter revision; parameter data returned");
		PROTO_ITEM_SET_GENERATED(ti);
	} else if (!(pno & 0x80) && tvb_length(tvb) == 1) {
		ti = proto_tree_add_text(tree, tvb, 0, 0, "Requested parameter data; only parameter version returned");
		PROTO_ITEM_SET_GENERATED(ti);
	}

	pno &= 0x7f;
	if (pno < array_length(conf_params)) {
		desc = conf_params[pno].name;
	} else if (pno >= 96 && pno <= 127) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}

	ti = proto_tree_add_text(tree, tvb, 0, 0, "Parameter: %s", desc);
	PROTO_ITEM_SET_GENERATED(ti);

	if (tvb_length(tvb) > 1) {
		if (pno < array_length(conf_params)) {
			sub = tvb_new_subset(tvb, 1, tvb_length(tvb) - 1, tvb_length(tvb) - 1);
			conf_params[pno].intrp(sub, tree);
		} else {
			proto_tree_add_item(tree, hf_ipmi_se_13_data, tvb, 1, tvb_length(tvb) - 1, ENC_NA);
		}
	}
}

static const value_string cc13[] = {
	{ 0x80, "Parameter not supported" },
	{ 0, NULL }
};

/* Set Last Processed Event ID Command.
 */
static void
rq14(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_se_14_processed_by, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_14_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_se_14_rid, tvb, 1, 2, ENC_LITTLE_ENDIAN);
}

static const value_string cc14[] = {
	{ 0x81, "Cannot execute command, SEL erase in progress" },
	{ 0, NULL }
};

/* Get Last Processed Event ID Command.
 */
static void
rs15(tvbuff_t *tvb, proto_tree *tree)
{
	guint16 tmp;

	ipmi_add_timestamp(tree, hf_ipmi_se_15_tstamp, tvb, 0);
	tmp = tvb_get_letohs(tvb, 4);
	if (tmp != 0xffff) {
		proto_tree_add_item(tree, hf_ipmi_se_15_lastrec, tvb, 4, 2, ENC_LITTLE_ENDIAN);
	} else {
		proto_tree_add_uint_format_value(tree, hf_ipmi_se_15_lastrec, tvb, 4, 2,
				tmp, "SEL is empty (0x%04x)", tmp);
	}
	proto_tree_add_item(tree, hf_ipmi_se_15_proc_sw, tvb, 6, 2, ENC_LITTLE_ENDIAN);
	tmp = tvb_get_letohs(tvb, 8);
	if (tmp != 0x0000) {
		proto_tree_add_item(tree, hf_ipmi_se_15_proc_bmc, tvb, 8, 2, ENC_LITTLE_ENDIAN);
	} else {
		proto_tree_add_uint_format_value(tree, hf_ipmi_se_15_proc_bmc, tvb, 8, 2,
				tmp, "Event processed but cannot be logged (0x%04x)", tmp);
	}
}

static const value_string cc15[] = {
	{ 0x81, "Cannot execute command, SEL erase in progress" },
	{ 0, NULL }
};

/* Alert Immediate.
 */
static void
rq16(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_se_16_chan, NULL };
	static const gint *byte2[] = { &hf_ipmi_se_16_op, &hf_ipmi_se_16_dst, NULL };
	static const gint *byte3[] = { &hf_ipmi_se_16_send_string, &hf_ipmi_se_16_string_sel, NULL };
	tvbuff_t *sub;

	if (!tree) {
		/* Save the operation */
		ipmi_setsaveddata(0, (tvb_get_guint8(tvb, 1) & 0xc0) >> 6);
		return;
	}

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_16_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_se_16_byte2, byte2, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL, ett_ipmi_se_16_byte3, byte3, TRUE, 0);
	if (tvb_length(tvb) > 3) {
		proto_tree_add_item(tree, hf_ipmi_se_16_gen, tvb, 3, 1, ENC_LITTLE_ENDIAN);
		sub = tvb_new_subset(tvb, 4, tvb_length(tvb) - 4, tvb_length(tvb) - 4);
		parse_platform_event(sub, tree);
	}
}

static void
rs16(tvbuff_t *tvb, proto_tree *tree)
{
	guint32 val;

	if (ipmi_getsaveddata(0, &val) && val == 0x01) {
		/* Operation == Get Alert Immediate Status */
		proto_tree_add_item(tree, hf_ipmi_se_16_status, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	}
}

static const value_string cc16[] = {
	{ 0x81, "Alert Immediate rejected due to alert already in progress" },
	{ 0x82, "Alert Immediate rejected due to IPMI messaging session active on this channel" },
	{ 0x83, "Platform Event parameters not supported" },
	{ 0, NULL }
};

/* PET Acknowledge.
 */
static void
rq17(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_17_seq, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	ipmi_add_timestamp(tree, hf_ipmi_se_17_tstamp, tvb, 2);
	proto_tree_add_item(tree, hf_ipmi_se_17_evsrc, tvb, 6, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_17_sensor_dev, tvb, 7, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_17_sensor_num, tvb, 8, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_17_evdata1, tvb, 9, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_17_evdata2, tvb, 10, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_17_evdata3, tvb, 11, 1, ENC_LITTLE_ENDIAN);
}

/* Get Device SDR Info.
 */
static void
rq20(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_20_rq_op, NULL };

	if (tvb_length(tvb) > 0) {
		proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
				ett_ipmi_se_20_rq_byte1, byte1, TRUE, 0);
		ipmi_setsaveddata(0, tvb_get_guint8(tvb, 0) & 0x01);
	}
}

static void
rs20(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte2[] = { &hf_ipmi_se_20_rs_population, &hf_ipmi_se_20_rs_lun3,
		&hf_ipmi_se_20_rs_lun2, &hf_ipmi_se_20_rs_lun1, &hf_ipmi_se_20_rs_lun0, NULL };
	guint32 val;

	if (ipmi_getsaveddata(0, &val) && val) {
		proto_tree_add_item(tree, hf_ipmi_se_20_rs_sdr, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_ipmi_se_20_rs_num, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	}
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_se_20_rs_byte2,
			byte2, TRUE, 0);
	if (tvb_get_guint8(tvb, 1) & 0x80) {
		/* Dynamic sensor population */
		proto_tree_add_item(tree, hf_ipmi_se_20_rs_change, tvb, 2, 4, ENC_LITTLE_ENDIAN);
	}
}


/* Get Device SDR.
 */
static void
rq21(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 len;

	len = tvb_get_guint8(tvb, 5);

	proto_tree_add_item(tree, hf_ipmi_se_21_rid, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_21_record, tvb, 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_21_offset, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint_format_value(tree, hf_ipmi_se_21_len, tvb, 5, 1, len,
			"%u%s", len, len == 0xff ? "(entire record)" : "");
}

static void
rs21(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_21_next, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_21_recdata, tvb, 2, tvb_length(tvb) - 2, ENC_NA);
}

static const value_string cc21[] = {
	{ 0x80, "Record changed" },
	{ 0, NULL }
};

/* Reserve Device SDR Repository.
 */
static void
rs22(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_22_resid, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

/* Get Sensor Reading Factors.
 */
static void
rq23(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_23_rq_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_23_rq_reading, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

static inline gint16
sign_extend(gint16 v, int bits)
{
	if ((v & (1 << (bits - 1))) == 0) {
		return v;
	}

	return v | (0xffff << bits);
}

static void
rs23(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *s_tree, *st2;
	guint16 tol, acc, accexp, tmp;
	gint16 m, b, bexp, rexp;

	proto_tree_add_item(tree, hf_ipmi_se_23_rs_next_reading, tvb, 0, 1, ENC_LITTLE_ENDIAN);

	m = tvb_get_guint8(tvb, 1);
	tmp = tvb_get_guint8(tvb, 2);
	m |= (tmp & 0xc0) << 2;
	tol = tmp & 0x3f;
	b = tvb_get_guint8(tvb, 3);
	tmp = tvb_get_guint8(tvb, 4);
	b |= (tmp & 0xc0) << 2;
	acc = tmp & 0x3f;
	tmp = tvb_get_guint8(tvb, 5);
	acc |= (tmp & 0xf0) << 4;
	accexp = (tmp & 0x0c) >> 2;
	tmp = tvb_get_guint8(tvb, 6);
	rexp = (tmp & 0xf0) >> 4;
	bexp = tmp & 0x0f;

	m = sign_extend(m, 10);
	b = sign_extend(b, 10);
	bexp = sign_extend(bexp, 4);
	rexp = sign_extend(rexp, 4);

	ti = proto_tree_add_text(tree, tvb, 1, 6, "Factors: M=%d B=%d K1=%d K2=%d Acc=%u*10^%u Tol=%u",
			m, b, bexp, rexp, acc, accexp, tol);
	s_tree = proto_item_add_subtree(ti, ett_ipmi_se_23_readingfactors);

	tmp = tvb_get_guint8(tvb, 1);
	ti = proto_tree_add_text(s_tree, tvb, 1, 1, "Byte 1");
	st2 = proto_item_add_subtree(ti, ett_ipmi_se_23_byte1);
	proto_tree_add_text(st2, tvb, 1, 1, "%sM (LS 8bits)", ipmi_dcd8(tmp, 0xff));

	tmp = tvb_get_guint8(tvb, 2);
	ti = proto_tree_add_text(s_tree, tvb, 2, 1, "Byte 2");
	st2 = proto_item_add_subtree(ti, ett_ipmi_se_23_byte2);
	proto_tree_add_text(st2, tvb, 2, 1, "%sM (MS 2bits)", ipmi_dcd8(tmp, 0xc0));
	proto_tree_add_text(st2, tvb, 2, 1, "%sTolerance", ipmi_dcd8(tmp, 0x3f));

	tmp = tvb_get_guint8(tvb, 3);
	ti = proto_tree_add_text(s_tree, tvb, 3, 1, "Byte 3");
	st2 = proto_item_add_subtree(ti, ett_ipmi_se_23_byte3);
	proto_tree_add_text(st2, tvb, 3, 1, "%sB (LS 8bits)", ipmi_dcd8(tmp, 0xff));

	tmp = tvb_get_guint8(tvb, 4);
	ti = proto_tree_add_text(s_tree, tvb, 4, 1, "Byte 4");
	st2 = proto_item_add_subtree(ti, ett_ipmi_se_23_byte4);
	proto_tree_add_text(st2, tvb, 4, 1, "%sB (MS 2bits)", ipmi_dcd8(tmp, 0xc0));
	proto_tree_add_text(st2, tvb, 4, 1, "%sAccuracy (LS 6bits)", ipmi_dcd8(tmp, 0x3f));

	tmp = tvb_get_guint8(tvb, 5);
	ti = proto_tree_add_text(s_tree, tvb, 5, 1, "Byte 5");
	st2 = proto_item_add_subtree(ti, ett_ipmi_se_23_byte5);
	proto_tree_add_text(st2, tvb, 5, 1, "%sAccuracy (MS 4bits)", ipmi_dcd8(tmp, 0xf0));
	proto_tree_add_text(st2, tvb, 5, 1, "%sAccuracy exponent", ipmi_dcd8(tmp, 0x0c));

	tmp = tvb_get_guint8(tvb, 6);
	ti = proto_tree_add_text(s_tree, tvb, 6, 1, "Byte 6");
	st2 = proto_item_add_subtree(ti, ett_ipmi_se_23_byte6);
	proto_tree_add_text(st2, tvb, 6, 1, "%sR exponent", ipmi_dcd8(tmp, 0xf0));
	proto_tree_add_text(st2, tvb, 6, 1, "%sB exponent", ipmi_dcd8(tmp, 0x0f));
}

/* Set Sensor Hysteresis.
 */
static void
rq24(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_24_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_24_mask, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_24_hyst_pos, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_24_hyst_neg, tvb, 3, 1, ENC_LITTLE_ENDIAN);
}

/* Get Sensor Hysteresis.
 */
static void
rq25(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_25_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_25_mask, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

static void
rs25(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_25_hyst_pos, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_25_hyst_neg, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

/* Common for Get/Set Thresholds */
static void
add_thresholds(tvbuff_t *tvb, int offs, proto_tree *tree, const char *desc)
{
	static const int *threshold_mask[] = { &hf_ipmi_se_XX_m_unr, &hf_ipmi_se_XX_m_uc, &hf_ipmi_se_XX_m_unc,
		&hf_ipmi_se_XX_m_lnr, &hf_ipmi_se_XX_m_lc, &hf_ipmi_se_XX_m_lnc, NULL };

	proto_tree_add_bitmask_text(tree, tvb, offs, 1, desc, "None",
			ett_ipmi_se_XX_mask, threshold_mask, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_se_XX_thr_lnc, tvb, offs + 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_XX_thr_lc, tvb, offs + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_XX_thr_lnr, tvb, offs + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_XX_thr_unc, tvb, offs + 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_XX_thr_uc, tvb, offs + 5, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_se_XX_thr_unr, tvb, offs + 6, 1, ENC_LITTLE_ENDIAN);
}

/* Set Sensor Thresholds.
 */
static void
rq26(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_26_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	add_thresholds(tvb, 1, tree, "Set thresholds: ");
}

/* Get Sensor Thresholds.
 */
static void
rq27(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_27_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
rs27(tvbuff_t *tvb, proto_tree *tree)
{
	add_thresholds(tvb, 0, tree, "Readable thresholds: ");
}

/* Common for Get EE/Set EE/Rearm
 */
static void
add_events(tvbuff_t *tvb, int offs, proto_tree *tree, const struct true_false_string *tfs,
		const char *desc)
{
	static const int *bsel[4][8] = {
		{ &hf_ipmi_se_XX_b1_0, &hf_ipmi_se_XX_b1_1, &hf_ipmi_se_XX_b1_2, &hf_ipmi_se_XX_b1_3,
			&hf_ipmi_se_XX_b1_4, &hf_ipmi_se_XX_b1_5, &hf_ipmi_se_XX_b1_6, &hf_ipmi_se_XX_b1_7 },
		{ &hf_ipmi_se_XX_b2_0, &hf_ipmi_se_XX_b2_1, &hf_ipmi_se_XX_b2_2, &hf_ipmi_se_XX_b2_3,
			&hf_ipmi_se_XX_b2_4, &hf_ipmi_se_XX_b2_5, &hf_ipmi_se_XX_b2_6, NULL },
		{ &hf_ipmi_se_XX_b3_0, &hf_ipmi_se_XX_b3_1, &hf_ipmi_se_XX_b3_2, &hf_ipmi_se_XX_b3_3,
			&hf_ipmi_se_XX_b3_4, &hf_ipmi_se_XX_b3_5, &hf_ipmi_se_XX_b3_6, &hf_ipmi_se_XX_b3_7 },
		{ &hf_ipmi_se_XX_b4_0, &hf_ipmi_se_XX_b4_1, &hf_ipmi_se_XX_b4_2, &hf_ipmi_se_XX_b4_3,
			&hf_ipmi_se_XX_b4_4, &hf_ipmi_se_XX_b4_5, &hf_ipmi_se_XX_b4_6, NULL }
	};
	static const int *tsel[] = { &ett_ipmi_se_XX_b1, &ett_ipmi_se_XX_b2, &ett_ipmi_se_XX_b3, &ett_ipmi_se_XX_b4 };
	proto_item *ti;
	proto_tree *s_tree;
	int len = tvb_length(tvb);
	int i, j, val, msk;

	for (i = 0; (offs < len) && (i < 4); i++, offs++) {
		val = tvb_get_guint8(tvb, offs);
		ti = proto_tree_add_text(tree, tvb, offs, 1, "%s (byte %d)", desc, i);
		s_tree = proto_item_add_subtree(ti, *tsel[i]);
		for (j = 7; j >= 0; j--) {
			if (!bsel[i][j]) {
				continue;
			}
			msk = 1 << j;
			proto_tree_add_boolean_format_value(s_tree, *bsel[i][j], tvb, offs, 1,
					val & msk, "%s", (val & msk) ? tfs->true_string : tfs->false_string);
		}
	}
}


/* Set Sensor Event Enable.
 */
static void
rq28(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte2[] = { &hf_ipmi_se_28_fl_evm, &hf_ipmi_se_28_fl_scan, &hf_ipmi_se_28_fl_action, NULL };
	static const struct true_false_string tfs_lect = { "Select", "Do not select" };

	proto_tree_add_item(tree, hf_ipmi_se_28_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_se_28_byte2, byte2, TRUE, 0);
	add_events(tvb, 2, tree, &tfs_lect, "Selected events");
}

/* Get Sensor Event Enable.
 */
static void
rq29(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_29_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
rs29(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_29_fl_evm, &hf_ipmi_se_29_fl_scan, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_29_byte1, byte1, TRUE, 0);
	add_events(tvb, 1, tree, &tfs_29_enabled, "Enabled events");
}

/* Re-arm Sensor Events.
 */
static void
rq2a(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte2[] = { &hf_ipmi_se_2a_fl_sel, NULL };
	static const struct true_false_string rearm_tfs = { "Re-arm", "Do not re-arm" };

	proto_tree_add_item(tree, hf_ipmi_se_2a_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_se_2a_byte2, byte2, TRUE, 0);
	add_events(tvb, 2, tree, &rearm_tfs, "Re-arm Events");
}

/* Get Sensor Event Status.
 */
static void
rq2b(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_2b_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
rs2b(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_se_2b_fl_evm, &hf_ipmi_se_2b_fl_scan, &hf_ipmi_se_2b_fl_unavail, NULL };
	static const struct true_false_string occur_tfs = { "Occurred", "Did not occur" };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_se_2b_byte1, byte1, TRUE, 0);
	add_events(tvb, 1, tree, &occur_tfs, "Event Status");
}

/* Get Sensor Reading.
 */
static void
rq2d(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_2d_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
rs2d(tvbuff_t *tvb, proto_tree *tree)
{
	/* Reuse flags from Event Status message */
	static const int *byte2[] = { &hf_ipmi_se_2b_fl_evm, &hf_ipmi_se_2b_fl_scan, &hf_ipmi_se_2b_fl_unavail, NULL };
	static const int *bsel[2][8] = {
		{ &hf_ipmi_se_2d_b1_0, &hf_ipmi_se_2d_b1_1, &hf_ipmi_se_2d_b1_2, &hf_ipmi_se_2d_b1_3,
			&hf_ipmi_se_2d_b1_4, &hf_ipmi_se_2d_b1_5, &hf_ipmi_se_2d_b1_6, &hf_ipmi_se_2d_b1_7 },
		{ &hf_ipmi_se_2d_b2_0, &hf_ipmi_se_2d_b2_1, &hf_ipmi_se_2d_b2_2, &hf_ipmi_se_2d_b2_3,
			&hf_ipmi_se_2d_b2_4, &hf_ipmi_se_2d_b2_5, &hf_ipmi_se_2d_b2_6, NULL }
	};
	static const int *tsel[2] = { &ett_ipmi_se_2d_b1, &ett_ipmi_se_2d_b2 };
	proto_item *ti;
	proto_tree *s_tree;
	int i, j, len;

	proto_tree_add_item(tree, hf_ipmi_se_2d_reading, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_se_2d_byte2, byte2, TRUE, 0);
	len = tvb_length(tvb);
	for (i = 0; i < 2 && i < len - 2; i++) {
		ti = proto_tree_add_text(tree, tvb, i + 2, 1, "Threshold comparisons/assertions (byte %d)", i);
		s_tree = proto_item_add_subtree(ti, *tsel[i]);
		for (j = 7; j >= 0; j--) {
			if (bsel[i][j]) {
				proto_tree_add_item(s_tree, *bsel[i][j], tvb, i + 2, 1, TRUE);
			}
		}
	}
}

/* Set Sensor Type.
 */
static void
rq2e(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 stype, evtype;
	const struct sensor_info *si;
	const struct evtype_info *eti;
	proto_item *ti;
	proto_tree *s_tree;

	stype = tvb_get_guint8(tvb, 1);
	si = get_sensor_info(stype);
	evtype = tvb_get_guint8(tvb, 2) & 0x7f;
	eti = get_evtype_info(evtype);

	proto_tree_add_item(tree, hf_ipmi_se_2e_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint_format_value(tree, hf_ipmi_se_2e_stype, tvb, 1, 1,
			stype, "%s (0x%02x)", si->desc, stype);

	ti = proto_tree_add_text(tree, tvb, 2, 1, "Event/reading type: %s", eti->desc);
	s_tree = proto_item_add_subtree(ti, ett_ipmi_se_2e_evtype);
	proto_tree_add_uint_format_value(s_tree, hf_ipmi_se_2e_evtype, tvb, 2, 1,
			evtype, "%s (0x%02x)", eti->desc, evtype);
}

/* Get Sensor Type.
 */
static void
rq2f(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_se_2f_sensor, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
rs2f(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 stype, evtype;
	const struct sensor_info *si;
	const struct evtype_info *eti;
	proto_item *ti;
	proto_tree *s_tree;

	stype = tvb_get_guint8(tvb, 0);
	si = get_sensor_info(stype);
	evtype = tvb_get_guint8(tvb, 1) & 0x7f;
	eti = get_evtype_info(evtype);

	proto_tree_add_uint_format_value(tree, hf_ipmi_se_2f_stype, tvb, 0, 1,
			stype, "%s (0x%02x)", si->desc, stype);

	ti = proto_tree_add_text(tree, tvb, 2, 1, "Event/reading type: %s", eti->desc);
	s_tree = proto_item_add_subtree(ti, ett_ipmi_se_2f_evtype);
	proto_tree_add_uint_format_value(s_tree, hf_ipmi_se_2f_evtype, tvb, 1, 1,
			evtype, "%s (0x%02x)", eti->desc, evtype);
}

static const value_string cc30[] = {
	{ 0x80, "Attempt to change not-settable reading/status bits" },
	{ 0x81, "Setting Event Data Bytes not supported" },
	{ 0, NULL }
};

static ipmi_cmd_t cmd_se[] = {
  /* Event commands */
  { 0x00, rq00, NULL, NULL, NULL, "Set Event Receiver", 0 },
  { 0x01, NULL, rs01, NULL, NULL, "Get Event Receiver", 0 },
  { 0x02, rq02, NULL, NULL, NULL, "Platform Event", 0 },

  /* PEF and Alerting Commands */
  { 0x10, NULL, rs10, NULL, NULL, "Get PEF Capabilities", 0 },
  { 0x11, rq11, rs11, NULL, NULL, "Arm PEF Postpone Timer", 0 },
  { 0x12, rq12, NULL, cc12, NULL, "Set PEF Configuration Parameters", 0 },
  { 0x13, rq13, rs13, cc13, NULL, "Get PEF Configuration Parameters", CMD_CALLRQ },
  { 0x14, rq14, NULL, cc14, NULL, "Set Last Processed Event ID", 0 },
  { 0x15, NULL, rs15, cc15, NULL, "Get Last Processed Event ID", 0 },
  { 0x16, rq16, rs16, cc16, NULL, "Alert Immediate", CMD_CALLRQ },
  { 0x17, rq17, NULL, NULL, NULL, "PET Acknowledge", 0 },

  /* Sensor Device Commands */
  { 0x20, rq20, rs20, NULL, NULL, "Get Device SDR Info", CMD_CALLRQ },
  { 0x21, rq21, rs21, cc21, NULL, "Get Device SDR", 0 },
  { 0x22, NULL, rs22, NULL, NULL, "Reserve Device SDR Repository", 0 },
  { 0x23, rq23, rs23, NULL, NULL, "Get Sensor Reading Factors", 0 },
  { 0x24, rq24, NULL, NULL, NULL, "Set Sensor Hysteresis", 0 },
  { 0x25, rq25, rs25, NULL, NULL, "Get Sensor Hysteresis", 0 },
  { 0x26, rq26, NULL, NULL, NULL, "Set Sensor Threshold", 0 },
  { 0x27, rq27, rs27, NULL, NULL, "Get Sensor Threshold", 0 },
  { 0x28, rq28, NULL, NULL, NULL, "Set Sensor Event Enable", 0 },
  { 0x29, rq29, rs29, NULL, NULL, "Get Sensor Event Enable", 0 },
  { 0x2a, rq2a, NULL, NULL, NULL, "Re-arm Sensor Events", 0 },
  { 0x2b, rq2b, rs2b, NULL, NULL, "Get Sensor Event Status", 0 },
  { 0x2d, rq2d, rs2d, NULL, NULL, "Get Sensor Reading", 0 },
  { 0x2e, rq2e, NULL, NULL, NULL, "Set Sensor Type", 0 },
  { 0x2f, rq2f, rs2f, NULL, NULL, "Get Sensor Type", 0 },
  { 0x30, IPMI_TBD,   cc30, NULL, "Set Sensor Reading and Event Status", 0 },
};

void
ipmi_register_se(gint proto_ipmi)
{
	static hf_register_info hf[] = {
		{ &hf_ipmi_se_evt_rev,
			{ "Event Message Revision",
				"ipmi.evt.evmrev", FT_UINT8, BASE_HEX, evt_evm_rev_vals, 0, NULL, HFILL }},
		{ &hf_ipmi_se_evt_sensor_type,
			{ "Sensor Type",
				"ipmi.evt.sensor_type", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_evt_sensor_num,
			{ "Sensor #",
				"ipmi.evt.sensor_num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_evt_byte3,
			{ "Event Dir/Type",
				"ipmi.evt.byte3", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_evt_dir,
			{ "Event Direction",
				"ipmi.evt.evdir", FT_BOOLEAN, 8, TFS(&evt_evdir_tfs), 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_evt_type,
			{ "Event Type",
				"ipmi.evt.evtype", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_evt_data1,
			{ "Event Data 1",
				"ipmi.evt.data1", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_evt_data1_b2,
			{ "Byte 2",
				"ipmi.evt.data1.b2", FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL }},
		{ &hf_ipmi_se_evt_data1_b3,
			{ "Byte 3",
				"ipmi.evt.data1.b3", FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL }},
		{ &hf_ipmi_se_evt_data1_offs,
			{ "Offset",
				"ipmi.evt.data1.offs", FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_se_evt_data2,
			{ "Event Data 2",
				"ipmi.evt.data2", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_evt_data3,
			{ "Event Data 3",
				"ipmi.evt.data3", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_cp00_sip,
			{ "Set In Progress",
				"ipmi.cp00.sip", FT_UINT8, BASE_HEX, cp00_sip_vals, 0x03, NULL, HFILL }},
		{ &hf_ipmi_se_cp01_alert_startup,
			{ "PEF Alert Startup Delay disable",
				"ipmi.cp01.alert_startup", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_cp01_startup,
			{ "PEF Startup Delay disable",
				"ipmi.cp01.startup", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_cp01_event_msg,
			{ "Enable Event Messages for PEF actions",
				"ipmi.cp01.event_msg", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_cp01_pef,
			{ "Enable PEF",
				"ipmi.cp01.pef", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_cp02_diag_intr,
			{ "Enable Diagnostic Interrupt",
				"ipmi.cp02.diag_intr", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_cp02_oem_action,
			{ "Enable OEM action",
				"ipmi.cp02.oem_action", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_cp02_pwr_cycle,
			{ "Enable Power Cycle action",
				"ipmi.cp02.pwr_cycle", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_cp02_reset,
			{ "Enable Reset action",
				"ipmi.cp02.reset", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_cp02_pwr_down,
			{ "Enable Power Down action",
				"ipmi.cp02.pwr_down", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_cp02_alert,
			{ "Enable Alert action",
				"ipmi.cp02.alert", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_cp03_startup,
			{ "PEF Startup delay",
				"ipmi.cp03.startup", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp04_alert_startup,
			{ "PEF Alert Startup delay",
				"ipmi.cp04.alert_startup", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp05_num_evfilters,
			{ "Number of Event Filters",
				"ipmi.cp05.num_evfilters", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp06_filter,
			{ "Filter number (set selector)",
				"ipmi.cp06.filter", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp06_data,
			{ "Filter data",
				"ipmi.cp06.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp07_filter,
			{ "Filter number (set selector)",
				"ipmi.cp07.filter", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp07_data,
			{ "Filter data (byte 1)",
				"ipmi.cp07.data", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp08_policies,
			{ "Number of Alert Policy Entries",
				"ipmi.cp08.policies", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp09_entry,
			{ "Entry number (set selector)",
				"ipmi.cp09.entry", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp09_data,
			{ "Entry data",
				"ipmi.cp09.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp10_useval,
			{ "Used to fill the GUID field in PET Trap",
				"ipmi.cp10.useval", FT_BOOLEAN, 8, TFS(&cp10_use_tfs), 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_cp10_guid,
			{ "GUID",
				"ipmi.cp10.guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp11_num_alertstr,
			{ "Number of Alert Strings",
				"ipmi.cp11.num_alertstr", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp12_byte1,
			{ "Alert String Selector",
				"ipmi.cp12.byte1", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp12_alert_stringsel,
			{ "Alert String Selector (set selector)",
				"ipmi.cp12.alert_stringsel", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp12_evfilter,
			{ "Filter Number",
				"ipmi.cp12.evfilter", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp12_alert_stringset,
			{ "Set number for string",
				"ipmi.cp12.alert_stringset", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp13_stringsel,
			{ "String selector (set selector)",
				"ipmi.cp13.stringsel", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp13_blocksel,
			{ "Block selector",
				"ipmi.cp13.blocksel", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp13_string,
			{ "String data",
				"ipmi.cp13.string", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp14_num_gct,
			{ "Number of Group Control Table entries",
				"ipmi.cp14.num_gct", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp15_gctsel,
			{ "Group control table entry selector (set selector)",
				"ipmi.cp15.gctsel", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_cp15_force,
			{ "Request/Force",
				"ipmi.cp15.force", FT_BOOLEAN, 8, TFS(&cp15_rq_frc_tfs), 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_cp15_delayed,
			{ "Immediate/Delayed",
				"ipmi.cp15.delayed", FT_BOOLEAN, 8, TFS(&cp15_imm_delay_tfs), 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_cp15_channel,
			{ "Channel",
				"ipmi.cp15.channel", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_se_cp15_group,
			{ "Group ID",
				"ipmi.cp15.group_id", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_cp15_member_check,
			{ "Member ID check disabled",
				"ipmi.cp15.member_check", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_cp15_member_id,
			{ "Member ID",
				"ipmi.cp15_member_id", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_se_cp15_retries,
			{ "Retries",
				"ipmi.cp15.retries", FT_UINT8, BASE_DEC, NULL, 0x70, NULL, HFILL }},
		{ &hf_ipmi_se_cp15_operation,
			{ "Operation",
				"ipmi.cp15.operation", FT_UINT8, BASE_HEX, cp15_op_vals, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_se_00_addr,
			{ "Event Receiver slave address",
				"ipmi.se00.addr", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_00_lun,
			{ "Event Receiver LUN",
				"ipmi.se00.lun", FT_UINT8, BASE_HEX, NULL, 0x3, NULL, HFILL }},

		{ &hf_ipmi_se_01_addr,
			{ "Event Receiver slave address",
				"ipmi.se01.addr", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_01_lun,
			{ "Event Receiver LUN",
				"ipmi.se01.lun", FT_UINT8, BASE_HEX, NULL, 0x3, NULL, HFILL }},

		{ &hf_ipmi_se_10_pef_version,
			{ "PEF Version",
				"ipmi.se10.pef_version", FT_UINT8, BASE_CUSTOM, ipmi_fmt_version, 0, NULL, HFILL }},
		{ &hf_ipmi_se_10_action_oem_filter,
			{ "OEM Event Record Filtering supported",
				"ipmi.se10.action.oem_filter", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_10_action_diag_intr,
			{ "Diagnostic Interrupt",
				"ipmi.se10.action.diag_intr", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_10_action_oem_action,
			{ "OEM Action",
				"ipmi.se10.action.oem_action", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_10_action_pwr_cycle,
			{ "Power Cycle",
				"ipmi.se10.action.pwr_cycle", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_10_action_reset,
			{ "Reset",
				"ipmi.se10.action.reset", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_10_action_pwr_down,
			{ "Power Down",
				"ipmi.se10.action.pwr_down", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_10_action_alert,
			{ "Alert",
				"ipmi.se10.action.alert", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_10_entries,
			{ "Number of event filter table entries",
				"ipmi.se10.entries", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_11_rq_timeout,
			{ "Timeout value",
				"ipmi.se11.rq_timeout", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_11_rs_timeout,
			{ "Timeout value",
				"ipmi.se11.rs_timeout", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_12_byte1,
			{ "Parameter selector",
				"ipmi.se12.byte1", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_12_param,
			{ "Parameter selector",
				"ipmi.se12.param", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_12_data,
			{ "Parameter data",
				"ipmi.se12.data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_13_byte1,
			{ "Parameter selector",
				"ipmi.se13.byte1", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_13_getrev,
			{ "Get Parameter Revision only",
				"ipmi.se13.getrev", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_13_param,
			{ "Parameter selector",
				"ipmi.se13.param", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_13_set,
			{ "Set Selector",
				"ipmi.se13.set", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_13_block,
			{ "Block Selector",
				"ipmi.se13.block", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_13_rev_present,
			{ "Present",
				"ipmi.se13.rev.present", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
		{ &hf_ipmi_se_13_rev_compat,
			{ "Oldest forward-compatible",
				"ipmi.se13.rev.compat", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_se_13_data,
			{ "Parameter data",
				"ipmi.se13.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_14_processed_by,
			{ "Set Record ID for last record processed by",
				"ipmi.se14.processed_by", FT_BOOLEAN, 8, TFS(&tfs_14_processed), 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_14_rid,
			{ "Record ID",
				"ipmi.se14.rid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_15_tstamp,
			{ "Most recent addition timestamp",
				"ipmi.se15.tstamp", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_15_lastrec,
			{ "Record ID for last record in SEL",
				"ipmi.se15.lastrec", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_15_proc_sw,
			{ "Last SW Processed Event Record ID",
				"ipmi.se15.proc_sw", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_15_proc_bmc,
			{ "Last BMC Processed Event Record ID",
				"ipmi.se15.proc_bmc", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_16_chan,
			{ "Channel",
				"ipmi.se16.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_se_16_op,
			{ "Operation",
				"ipmi.se16.op", FT_UINT8, BASE_HEX, vals_16_op, 0xc0, NULL, HFILL }},
		{ &hf_ipmi_se_16_dst,
			{ "Destination",
				"ipmi.se16.dst", FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_se_16_send_string,
			{ "Send Alert String",
				"ipmi.se16.send_string", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_16_string_sel,
			{ "String selector",
				"ipmi.se16.string_sel", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_se_16_gen,
			{ "Generator ID",
				"ipmi.se16.gen", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_16_status,
			{ "Alert Immediate Status",
				"ipmi.se16.status", FT_UINT8, BASE_HEX, vals_16_status, 0, NULL, HFILL }},

		{ &hf_ipmi_se_17_seq,
			{ "Sequence Number",
				"ipmi.se17.seq", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_17_tstamp,
			{ "Local Timestamp",
				"ipmi.se17.tstamp", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_17_evsrc,
			{ "Event Source Type",
				"ipmi.se17.evsrc", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_17_sensor_dev,
			{ "Sensor Device",
				"ipmi.se17.sensor_dev", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_17_sensor_num,
			{ "Sensor Number",
				"ipmi.se17.sensor_num", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_17_evdata1,
			{ "Event Data 1",
				"ipmi.se17.evdata1", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_17_evdata2,
			{ "Event Data 2",
				"ipmi.se17.evdata2", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_17_evdata3,
			{ "Event Data 3",
				"ipmi.se17.evdata3", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_20_rq_op,
			{ "Operation",
				"ipmi.se20.rq_op", FT_BOOLEAN, 8, TFS(&tfs_20_op), 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_20_rs_num,
			{ "Number of sensors in device for LUN",
				"ipmi.se20.rs_num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_20_rs_sdr,
			{ "Total Number of SDRs in the device",
				"ipmi.se20.rs_sdr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_20_rs_population,
			{ "Sensor population",
				"ipmi.se20.rs_population", FT_BOOLEAN, 8, TFS(&tfs_20_pop), 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_20_rs_lun3,
			{ "LUN3 has sensors",
				"ipmi.se20.rs_lun3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_20_rs_lun2,
			{ "LUN2 has sensors",
				"ipmi.se20.rs_lun2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_20_rs_lun1,
			{ "LUN1 has sensors",
				"ipmi.se20.rs_lun1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_20_rs_lun0,
			{ "LUN0 has sensors",
				"ipmi.se20.rs_lun0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_20_rs_change,
			{ "Sensor Population Change Indicator",
				"ipmi.se20.rs_change", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_21_rid,
			{ "Reservation ID",
				"ipmi.se21.rid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_21_record,
			{ "Record ID",
				"ipmi.se21.record", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_21_offset,
			{ "Offset into data",
				"ipmi.se21.offset", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_21_len,
			{ "Bytes to read",
				"ipmi.se21.len", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_21_next,
			{ "Next record ID",
				"ipmi.se21.next", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_21_recdata,
			{ "Record data",
				"ipmi.se21.recdata", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_22_resid,
			{ "Reservation ID",
				"ipmi.se22.resid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_23_rq_sensor,
			{ "Sensor Number",
				"ipmi.se23.rq_sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_23_rq_reading,
			{ "Reading",
				"ipmi.se23.rq_reading", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_23_rs_next_reading,
			{ "Next reading",
				"ipmi.se23.rs_next_reading", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_24_sensor,
			{ "Sensor Number",
				"ipmi.se24.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_24_mask,
			{ "Reserved for future 'hysteresis mask'",
				"ipmi.se24.mask", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_24_hyst_pos,
			{ "Positive-going hysteresis",
				"ipmi.se24.hyst_pos", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_24_hyst_neg,
			{ "Negative-going hysteresis",
				"ipmi.se24.hyst_neg", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_25_sensor,
			{ "Sensor Number",
				"ipmi.se25.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_25_mask,
			{ "Reserved for future 'hysteresis mask'",
				"ipmi.se25.mask", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_25_hyst_pos,
			{ "Positive-going hysteresis",
				"ipmi.se25.hyst_pos", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_25_hyst_neg,
			{ "Negative-going hysteresis",
				"ipmi.se25.hyst_neg", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_26_sensor,
			{ "Sensor Number",
				"ipmi.seXX.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_XX_m_unr,
			{ "Upper Non-Recoverable",
				"ipmi.seXX.mask.unr", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_XX_m_uc,
			{ "Upper Critical",
				"ipmi.seXX.mask.uc", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_XX_m_unc,
			{ "Upper Non-Critical",
				"ipmi.seXX.mask.unc", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_XX_m_lnr,
			{ "Lower Non-Recoverable",
				"ipmi.seXX.mask.lnr", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_XX_m_lc,
			{ "Lower Critical",
				"ipmi.seXX.mask.lc", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_XX_m_lnc,
			{ "Lower Non-Critical",
				"ipmi.seXX.mask.lnc", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_XX_thr_lnc,
			{ "Lower Non-Critical Threshold",
				"ipmi.seXX.lnc", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_XX_thr_lc,
			{ "Lower Critical Threshold",
				"ipmi.seXX.lc", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_XX_thr_lnr,
			{ "Lower Non-Recoverable Threshold",
				"ipmi.seXX.lnr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_XX_thr_unc,
			{ "Upper Non-Critical Threshold",
				"ipmi.seXX.unc", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_XX_thr_uc,
			{ "Upper Critical Threshold",
				"ipmi.seXX.uc", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_XX_thr_unr,
			{ "Upper Non-Recoverable Threshold",
				"ipmi.seXX.unr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_27_sensor,
			{ "Sensor Number",
				"ipmi.se27.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_se_XX_b1_7,
			{ "Assertion for UNC (going high) / state bit 7",
				"ipmi.seXX.a_7", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b1_6,
			{ "Assertion for UNC (going low) / state bit 6",
				"ipmi.seXX.a_6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b1_5,
			{ "Assertion for LNR (going high) / state bit 5",
				"ipmi.seXX.a_5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b1_4,
			{ "Assertion for LNR (going low) / state bit 4",
				"ipmi.seXX.a_4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b1_3,
			{ "Assertion for LC (going high) / state bit 3",
				"ipmi.seXX.a_3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b1_2,
			{ "Assertion for LC (going low) / state bit 2",
				"ipmi.seXX.a_2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b1_1,
			{ "Assertion for LNC (going high) / state bit 1",
				"ipmi.seXX.a_1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b1_0,
			{ "Assertion for LNC (going low) / state bit 0",
				"ipmi.seXX.a_0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b2_6,
			{ "Reserved / Assertion for state bit 14",
				"ipmi.seXX.a_14", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b2_5,
			{ "Reserved / Assertion for state bit 13",
				"ipmi.seXX.a_13", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b2_4,
			{ "Reserved / Assertion for state bit 12",
				"ipmi.seXX.a_12", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b2_3,
			{ "Assertion for UNR (going high) / state bit 11",
				"ipmi.seXX.a_11", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b2_2,
			{ "Assertion for UNR (going low) / state bit 10",
				"ipmi.seXX.a_10", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b2_1,
			{ "Assertion for UC (going high) / state bit 9",
				"ipmi.seXX.a_9", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b2_0,
			{ "Assertion for UC (going low) / state bit 8",
				"ipmi.seXX.a_8", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b3_7,
			{ "Deassertion for UNC (going high) / state bit 7",
				"ipmi.seXX.d_7", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b3_6,
			{ "Deassertion for UNC (going low) / state bit 6",
				"ipmi.seXX.d_6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b3_5,
			{ "Deassertion for LNR (going high) / state bit 5",
				"ipmi.seXX.d_5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b3_4,
			{ "Deassertion for LNR (going low) / state bit 4",
				"ipmi.seXX.d_4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b3_3,
			{ "Deassertion for LC (going high) / state bit 3",
				"ipmi.seXX.d_3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b3_2,
			{ "Deassertion for LC (going low) / state bit 2",
				"ipmi.seXX.d_2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b3_1,
			{ "Deassertion for LNC (going high) / state bit 1",
				"ipmi.seXX.d_1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b3_0,
			{ "Deassertion for LNC (going low) / state bit 0",
				"ipmi.seXX.d_0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b4_6,
			{ "Reserved / Deassertion for state bit 14",
				"ipmi.seXX.d_14", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b4_5,
			{ "Reserved / Deassertion for state bit 13",
				"ipmi.seXX.d_13", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b4_4,
			{ "Reserved / Deassertion for state bit 12",
				"ipmi.seXX.d_12", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b4_3,
			{ "Deassertion for UNR (going high) / state bit 11",
				"ipmi.seXX.d_11", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b4_2,
			{ "Deassertion for UNR (going low) / state bit 10",
				"ipmi.seXX.d_10", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b4_1,
			{ "Deassertion for UC (going high) / state bit 9",
				"ipmi.seXX.d_9", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_XX_b4_0,
			{ "Deassertion for UC (going low) / state bit 8",
				"ipmi.seXX.d_8", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

		{ &hf_ipmi_se_28_sensor,
			{ "Sensor Number",
				"ipmi.se28.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_28_fl_evm,
			{ "Event Messages",
				"ipmi.se28.fl_evm", FT_BOOLEAN, 8, TFS(&tfs_28_enable), 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_28_fl_scan,
			{ "Scanning",
				"ipmi.se28.fl_scan", FT_BOOLEAN, 8, TFS(&tfs_28_enable), 0x40, NULL, HFILL }},
		{ &hf_ipmi_se_28_fl_action,
			{ "Action",
				"ipmi.se28.fl_action", FT_UINT8, BASE_HEX, vals_28_act, 0x30, NULL, HFILL }},

		{ &hf_ipmi_se_29_sensor,
			{ "Sensor Number",
				"ipmi.se29.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_29_fl_evm,
			{ "Event Messages",
				"ipmi.se29.fl_evm", FT_BOOLEAN, 8, TFS(&tfs_29_enabled), 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_29_fl_scan,
			{ "Scanning",
				"ipmi.se29.fl_scan", FT_BOOLEAN, 8, TFS(&tfs_29_enabled), 0x40, NULL, HFILL }},

		{ &hf_ipmi_se_2a_sensor,
			{ "Sensor Number",
				"ipmi.se2a.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_2a_fl_sel,
			{ "Re-arm Events",
				"ipmi.se2a.fl_sel", FT_BOOLEAN, 8, TFS(&tfs_2a_sel), 0x80, NULL, HFILL }},

		{ &hf_ipmi_se_2b_sensor,
			{ "Sensor Number",
				"ipmi.se2b.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_2b_fl_evm,
			{ "Event Messages",
				"ipmi.se2b.fl_evm", FT_BOOLEAN, 8, TFS(&tfs_2b_enabled), 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_2b_fl_scan,
			{ "Sensor scanning",
				"ipmi.se2b.fl_scan", FT_BOOLEAN, 8, TFS(&tfs_2b_enabled), 0x40, NULL, HFILL }},
		{ &hf_ipmi_se_2b_fl_unavail,
			{ "Reading/status unavailable",
				"ipmi.se2b.fl_unavail", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},

		{ &hf_ipmi_se_2d_sensor,
			{ "Sensor Number",
				"ipmi.se2d.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_2d_reading,
			{ "Sensor Reading",
				"ipmi.se2d.reading", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b1_7,
			{ "Reserved / State 7 asserted",
				"ipmi.se2d.b1_7", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b1_6,
			{ "Reserved / State 6 asserted",
				"ipmi.se2d.b1_6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b1_5,
			{ "At or above UNR threshold / State 5 asserted",
				"ipmi.se2d.b1_5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b1_4,
			{ "At or above UC threshold / State 4 asserted",
				"ipmi.se2d.b1_4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b1_3,
			{ "At or above UNC threshold / State 3 asserted",
				"ipmi.se2d.b1_3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b1_2,
			{ "At or below LNR threshold / State 2 asserted",
				"ipmi.se2d.b1_2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b1_1,
			{ "At or below LC threshold / State 1 asserted",
				"ipmi.se2d.b1_1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b1_0,
			{ "At or below LNC threshold / State 0 asserted",
				"ipmi.se2d.b1_0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b2_6,
			{ "Reserved / State 14 asserted",
				"ipmi.se2d.b1_6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b2_5,
			{ "Reserved / State 13 asserted",
				"ipmi.se2d.b1_5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b2_4,
			{ "Reserved / State 12 asserted",
				"ipmi.se2d.b1_4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b2_3,
			{ "Reserved / State 11 asserted",
				"ipmi.se2d.b1_3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b2_2,
			{ "Reserved / State 10 asserted",
				"ipmi.se2d.b1_2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b2_1,
			{ "Reserved / State 9 asserted",
				"ipmi.se2d.b1_1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_se_2d_b2_0,
			{ "Reserved / State 8 asserted",
				"ipmi.se2d.b1_0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

		{ &hf_ipmi_se_2e_sensor,
			{ "Sensor number",
				"ipmi.se2e.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_2e_stype,
			{ "Sensor type",
				"ipmi.se2e.stype", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_2e_evtype,
			{ "Event/Reading type",
				"ipmi.se2e.evtype", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},

		{ &hf_ipmi_se_2f_sensor,
			{ "Sensor number",
				"ipmi.se2f.sensor", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_2f_stype,
			{ "Sensor type",
				"ipmi.se2f.stype", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_se_2f_evtype,
			{ "Event/Reading type",
				"ipmi.se2f.evtype", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_ipmi_se_evt_byte3,
		&ett_ipmi_se_evt_evd_byte1,
		&ett_ipmi_se_evt_evd_byte2,
		&ett_ipmi_se_evt_evd_byte3,
		&ett_ipmi_se_cp06_byte1,
		&ett_ipmi_se_cp07_byte1,
		&ett_ipmi_se_cp09_byte1,
		&ett_ipmi_se_cp10_byte1,
		&ett_ipmi_se_cp12_byte1,
		&ett_ipmi_se_cp12_byte2,
		&ett_ipmi_se_cp12_byte3,
		&ett_ipmi_se_cp13_byte1,
		&ett_ipmi_se_cp15_byte1,
		&ett_ipmi_se_cp15_byte2,
		&ett_ipmi_se_cp15_member,
		&ett_ipmi_se_cp15_byte11,
		&ett_ipmi_se_00_byte2,
		&ett_ipmi_se_01_byte2,
		&ett_ipmi_se_10_action,
		&ett_ipmi_se_12_byte1,
		&ett_ipmi_se_13_byte1,
		&ett_ipmi_se_13_rev,
		&ett_ipmi_se_14_byte1,
		&ett_ipmi_se_16_byte1,
		&ett_ipmi_se_16_byte2,
		&ett_ipmi_se_16_byte3,
		&ett_ipmi_se_20_rq_byte1,
		&ett_ipmi_se_20_rs_byte2,
		&ett_ipmi_se_23_readingfactors,
		&ett_ipmi_se_23_byte1,
		&ett_ipmi_se_23_byte2,
		&ett_ipmi_se_23_byte3,
		&ett_ipmi_se_23_byte4,
		&ett_ipmi_se_23_byte5,
		&ett_ipmi_se_23_byte6,
		&ett_ipmi_se_XX_mask,
		&ett_ipmi_se_XX_b1,
		&ett_ipmi_se_XX_b2,
		&ett_ipmi_se_XX_b3,
		&ett_ipmi_se_XX_b4,
		&ett_ipmi_se_28_byte2,
		&ett_ipmi_se_29_byte1,
		&ett_ipmi_se_2a_byte2,
		&ett_ipmi_se_2b_byte1,
		&ett_ipmi_se_2d_byte2,
		&ett_ipmi_se_2d_b1,
		&ett_ipmi_se_2d_b2,
		&ett_ipmi_se_2e_evtype,
		&ett_ipmi_se_2f_evtype,
	};

	proto_register_field_array(proto_ipmi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	ipmi_register_netfn_cmdtab(IPMI_SE_REQ, IPMI_OEM_NONE, NULL, 0, NULL,
			cmd_se, array_length(cmd_se));
}
