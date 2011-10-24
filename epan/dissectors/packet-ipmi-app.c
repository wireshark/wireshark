/* packet-ipmi-app.c
 * Sub-dissectors for IPMI messages (netFn=Application)
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
#include <string.h>

#include <epan/packet.h>

#include "packet-ipmi.h"

static gint ett_ipmi_app_01_byte2 = -1;
static gint ett_ipmi_app_01_byte3 = -1;
static gint ett_ipmi_app_01_byte6 = -1;

static gint ett_ipmi_app_04_byte2 = -1;

static gint ett_ipmi_app_06_syspwr = -1;
static gint ett_ipmi_app_06_devpwr = -1;

static gint ett_ipmi_app_07_syspwr = -1;
static gint ett_ipmi_app_07_devpwr = -1;

static gint ett_ipmi_app_24_timer_use = -1;
static gint ett_ipmi_app_24_timer_action = -1;
static gint ett_ipmi_app_24_expiration_flags = -1;

static gint ett_ipmi_app_25_timer_use = -1;
static gint ett_ipmi_app_25_timer_action = -1;
static gint ett_ipmi_app_25_expiration_flags = -1;

static gint ett_ipmi_app_2e_byte1 = -1;
static gint ett_ipmi_app_2f_byte1 = -1;
static gint ett_ipmi_app_30_byte1 = -1;
static gint ett_ipmi_app_31_byte1 = -1;
static gint ett_ipmi_app_32_rq_byte1 = -1;
static gint ett_ipmi_app_32_rq_byte2 = -1;
static gint ett_ipmi_app_32_rs_byte1 = -1;
static gint ett_ipmi_app_32_rs_byte2 = -1;
static gint ett_ipmi_app_34_byte1 = -1;
static gint ett_ipmi_app_34_msg = -1;

static gint ett_ipmi_app_38_rq_byte1 = -1;
static gint ett_ipmi_app_38_rq_byte2 = -1;
static gint ett_ipmi_app_38_rs_byte1 = -1;
static gint ett_ipmi_app_38_rs_byte2 = -1;
static gint ett_ipmi_app_38_rs_byte3 = -1;
static gint ett_ipmi_app_38_rs_byte4 = -1;

static gint ett_ipmi_app_39_byte1 = -1;

static gint ett_ipmi_app_3a_rq_byte1 = -1;
static gint ett_ipmi_app_3a_rq_byte2 = -1;
static gint ett_ipmi_app_3a_rs_byte1 = -1;
static gint ett_ipmi_app_3a_rs_byte10 = -1;

static gint ett_ipmi_app_3b_rq_byte1 = -1;
static gint ett_ipmi_app_3b_rs_byte1 = -1;

static gint hf_ipmi_app_01_dev_id = -1;
static gint hf_ipmi_app_01_dev_prov_sdr = -1;
static gint hf_ipmi_app_01_dev_rev = -1;
static gint hf_ipmi_app_01_dev_avail = -1;
static gint hf_ipmi_app_01_fw_rev_maj = -1;
static gint hf_ipmi_app_01_fw_rev_min = -1;
static gint hf_ipmi_app_01_ipmi_version = -1;
static gint hf_ipmi_app_01_ipmi_ads_chassis = -1;
static gint hf_ipmi_app_01_ipmi_ads_bridge = -1;
static gint hf_ipmi_app_01_ipmi_ads_ipmb_ev_gen = -1;
static gint hf_ipmi_app_01_ipmi_ads_ipmb_ev_recv = -1;
static gint hf_ipmi_app_01_ipmi_ads_fru = -1;
static gint hf_ipmi_app_01_ipmi_ads_sel = -1;
static gint hf_ipmi_app_01_ipmi_ads_sdr = -1;
static gint hf_ipmi_app_01_ipmi_ads_sensor = -1;
static gint hf_ipmi_app_01_manufacturer = -1;
static gint hf_ipmi_app_01_product = -1;
static gint hf_ipmi_app_01_fw_aux = -1;

static gint hf_ipmi_app_04_result = -1;
static gint hf_ipmi_app_04_fail = -1;
static gint hf_ipmi_app_04_fail_sel = -1;
static gint hf_ipmi_app_04_fail_sdr = -1;
static gint hf_ipmi_app_04_fail_bmc_fru = -1;
static gint hf_ipmi_app_04_fail_ipmb_sig = -1;
static gint hf_ipmi_app_04_fail_sdr_empty = -1;
static gint hf_ipmi_app_04_fail_iua = -1;
static gint hf_ipmi_app_04_fail_bb_fw = -1;
static gint hf_ipmi_app_04_fail_oper_fw = -1;

static gint hf_ipmi_app_05_devspec = -1;

static gint hf_ipmi_app_06_syspwr_set = -1;
static gint hf_ipmi_app_06_syspwr_enum = -1;
static gint hf_ipmi_app_06_devpwr_set = -1;
static gint hf_ipmi_app_06_devpwr_enum = -1;

static gint hf_ipmi_app_07_syspwr_enum = -1;
static gint hf_ipmi_app_07_devpwr_enum = -1;

static gint hf_ipmi_app_08_guid = -1;

static gint hf_ipmi_app_24_timer_use_dont_log = -1;
static gint hf_ipmi_app_24_timer_use_dont_stop = -1;
static gint hf_ipmi_app_24_timer_use_timer_use = -1;
static gint hf_ipmi_app_24_timer_action_interrupt = -1;
static gint hf_ipmi_app_24_timer_action_timeout_action = -1;
static gint hf_ipmi_app_24_pretimeout = -1;
static gint hf_ipmi_app_24_expiration_flags_oem = -1;
static gint hf_ipmi_app_24_expiration_flags_smsos = -1;
static gint hf_ipmi_app_24_expiration_flags_osload = -1;
static gint hf_ipmi_app_24_expiration_flags_biospost = -1;
static gint hf_ipmi_app_24_expiration_flags_biosfrb2 = -1;
static gint hf_ipmi_app_24_initial_countdown = -1;

static gint hf_ipmi_app_25_timer_use_dont_log = -1;
static gint hf_ipmi_app_25_timer_use_started = -1;
static gint hf_ipmi_app_25_timer_use_timer_use = -1;
static gint hf_ipmi_app_25_timer_action_interrupt = -1;
static gint hf_ipmi_app_25_timer_action_timeout_action = -1;
static gint hf_ipmi_app_25_pretimeout = -1;
static gint hf_ipmi_app_25_expiration_flags_oem = -1;
static gint hf_ipmi_app_25_expiration_flags_smsos = -1;
static gint hf_ipmi_app_25_expiration_flags_osload = -1;
static gint hf_ipmi_app_25_expiration_flags_biospost = -1;
static gint hf_ipmi_app_25_expiration_flags_biosfrb2 = -1;
static gint hf_ipmi_app_25_initial_countdown = -1;
static gint hf_ipmi_app_25_present_countdown = -1;

static gint hf_ipmi_app_2e_byte1_oem2 = -1;
static gint hf_ipmi_app_2e_byte1_oem1 = -1;
static gint hf_ipmi_app_2e_byte1_oem0 = -1;
static gint hf_ipmi_app_2e_byte1_sel = -1;
static gint hf_ipmi_app_2e_byte1_emb = -1;
static gint hf_ipmi_app_2e_byte1_emb_full_intr = -1;
static gint hf_ipmi_app_2e_byte1_rmq_intr = -1;

static gint hf_ipmi_app_2f_byte1_oem2 = -1;
static gint hf_ipmi_app_2f_byte1_oem1 = -1;
static gint hf_ipmi_app_2f_byte1_oem0 = -1;
static gint hf_ipmi_app_2f_byte1_sel = -1;
static gint hf_ipmi_app_2f_byte1_emb = -1;
static gint hf_ipmi_app_2f_byte1_emb_full_intr = -1;
static gint hf_ipmi_app_2f_byte1_rmq_intr = -1;

static gint hf_ipmi_app_30_byte1_oem2 = -1;
static gint hf_ipmi_app_30_byte1_oem1 = -1;
static gint hf_ipmi_app_30_byte1_oem0 = -1;
static gint hf_ipmi_app_30_byte1_wd_pretimeout = -1;
static gint hf_ipmi_app_30_byte1_emb = -1;
static gint hf_ipmi_app_30_byte1_rmq = -1;

static gint hf_ipmi_app_31_byte1_oem2 = -1;
static gint hf_ipmi_app_31_byte1_oem1 = -1;
static gint hf_ipmi_app_31_byte1_oem0 = -1;
static gint hf_ipmi_app_31_byte1_wd_pretimeout = -1;
static gint hf_ipmi_app_31_byte1_emb = -1;
static gint hf_ipmi_app_31_byte1_rmq = -1;

static gint hf_ipmi_app_32_rq_chno = -1;
static gint hf_ipmi_app_32_rq_state = -1;
static gint hf_ipmi_app_32_rs_chno = -1;
static gint hf_ipmi_app_32_rs_state = -1;

static gint hf_ipmi_app_34_track = -1;
static gint hf_ipmi_app_34_encrypt = -1;
static gint hf_ipmi_app_34_auth = -1;
static gint hf_ipmi_app_34_chan = -1;

static gint hf_ipmi_app_38_rq_ipmi20 = -1;
static gint hf_ipmi_app_38_rq_chan = -1;
static gint hf_ipmi_app_38_rq_priv = -1;
static gint hf_ipmi_app_38_rs_chan = -1;
static gint hf_ipmi_app_38_rs_ipmi20 = -1;
static gint hf_ipmi_app_38_rs_auth_oem = -1;
static gint hf_ipmi_app_38_rs_auth_straight = -1;
static gint hf_ipmi_app_38_rs_auth_md5 = -1;
static gint hf_ipmi_app_38_rs_auth_md2 = -1;
static gint hf_ipmi_app_38_rs_auth_none = -1;
static gint hf_ipmi_app_38_rs_kg = -1;
static gint hf_ipmi_app_38_rs_permsg = -1;
static gint hf_ipmi_app_38_rs_userauth = -1;
static gint hf_ipmi_app_38_rs_user_nonnull = -1;
static gint hf_ipmi_app_38_rs_user_null = -1;
static gint hf_ipmi_app_38_rs_user_anon = -1;
static gint hf_ipmi_app_38_rs_ipmi20_conn = -1;
static gint hf_ipmi_app_38_rs_ipmi15_conn = -1;
static gint hf_ipmi_app_38_rs_oem_iana = -1;
static gint hf_ipmi_app_38_rs_oem_aux = -1;

static gint hf_ipmi_app_39_authtype = -1;
static gint hf_ipmi_app_39_user = -1;
static gint hf_ipmi_app_39_temp_session = -1;
static gint hf_ipmi_app_39_challenge = -1;

static gint hf_ipmi_app_3a_authtype = -1;
static gint hf_ipmi_app_3a_privlevel = -1;
static gint hf_ipmi_app_3a_authcode = -1;
static gint hf_ipmi_app_3a_outbound_seq = -1;
static gint hf_ipmi_app_3a_authtype_session = -1;
static gint hf_ipmi_app_3a_session_id = -1;
static gint hf_ipmi_app_3a_inbound_seq = -1;
static gint hf_ipmi_app_3a_maxpriv_session = -1;

static gint hf_ipmi_app_3b_req_priv = -1;
static gint hf_ipmi_app_3b_new_priv = -1;

static gint hf_ipmi_app_3c_session_id = -1;
static gint hf_ipmi_app_3c_session_handle = -1;

static const struct true_false_string tfs_01_dev_avail = {
	"Device firmware, SDR Repository update or self-initialization in progress",
	"Normal operation"
};

static const value_string vals_04_result[] = {
	{ 0x55, "No error. All Self Tests Passed" },
	{ 0x56, "Self Test function not implemented in this controller" },
	{ 0x57, "Corrupted or inaccessible data or devices" },
	{ 0x58, "Fatal hardware error" },
	{ 0xff, "Reserved" },
	{ 0, NULL }
};

static const struct true_false_string tfs_04_fail_unknown = {
	"Test failed",
	"Unknown"
};

static const struct true_false_string tfs_06_pwr = {
	"Set",
	"Do not change"
};

static const value_string vals_06_syspwr[] = {
	{ 0x00, "Set S0 / G0" },
	{ 0x01, "Set S1" },
	{ 0x02, "Set S2" },
	{ 0x03, "Set S3" },
	{ 0x04, "Set S4" },
	{ 0x05, "Set S5 / G2" },
	{ 0x06, "Set S4/S5" },
	{ 0x07, "Set G3" },
	{ 0x08, "Sleeping" },
	{ 0x09, "G1 sleeping" },
	{ 0x0a, "Set override" },
	{ 0x20, "Set Legacy On" },
	{ 0x21, "Set Legacy Off" },
	{ 0x2a, "Set unknown" },
	{ 0x7f, "No change" },
	{ 0, NULL }
};

static const value_string vals_06_devpwr[] = {
	{ 0x00, "Set D0" },
	{ 0x01, "Set D1" },
	{ 0x02, "Set D2" },
	{ 0x03, "Set D3" },
	{ 0x2a, "Set unknown" },
	{ 0x7f, "No change" },
	{ 0, NULL }
};

static const value_string vals_07_syspwr[] = {
	{ 0x00, "S0 / G0" },
	{ 0x01, "S1" },
	{ 0x02, "S2" },
	{ 0x03, "S3" },
	{ 0x04, "S4" },
	{ 0x05, "S5 / G2" },
	{ 0x06, "S4/S5" },
	{ 0x07, "G3" },
	{ 0x08, "Sleeping" },
	{ 0x09, "G1 sleeping" },
	{ 0x0a, "Override" },
	{ 0x20, "Legacy On" },
	{ 0x21, "Legacy Off" },
	{ 0x2a, "unknown" },
	{ 0, NULL }
};

static const value_string vals_07_devpwr[] = {
	{ 0x00, "D0" },
	{ 0x01, "D1" },
	{ 0x02, "D2" },
	{ 0x03, "D3" },
	{ 0x2a, "unknown" },
	{ 0, NULL }
};

static const value_string vals_24_timer_use[] = {
	{ 0x00, "reserved" },
	{ 0x01, "BIOS FRB2" },
	{ 0x02, "BIOS/POST" },
	{ 0x03, "OS Load" },
	{ 0x04, "SMS/OS" },
	{ 0x05, "OEM" },
	{ 0x06, "reserved" },
	{ 0x07, "reserved" },

	{ 0, NULL }
};

static const value_string vals_24_timer_action_interrupt[] = {
	{ 0x00, "none" },
	{ 0x01, "SMI" },
	{ 0x02, "NMI / Diagnostic interrupt" },
	{ 0x03, "Messaging interrupt" },
	{ 0x04, "reserved" },
	{ 0x05, "reserved" },
	{ 0x06, "reserved" },
	{ 0x07, "reserved" },

	{ 0, NULL }
};

static const value_string vals_24_timer_action_timeout[] = {
	{ 0x00, "no action" },
	{ 0x01, "Hard Reset" },
	{ 0x02, "Power Down" },
	{ 0x03, "Power Cycle" },
	{ 0x04, "reserved" },
	{ 0x05, "reserved" },
	{ 0x06, "reserved" },
	{ 0x07, "reserved" },

	{ 0, NULL }
};

static const struct true_false_string tfs_24_exp_flags = {
	"clear timer use expiration bit",
	"leave alone"
};

static const struct true_false_string tfs_2e_enable = { "Enable", "Disable" };
static const struct true_false_string tfs_2f_enabled = { "Enabled", "Disabled" };

static const struct true_false_string tfs_30_clear = {
	"clear",
	"leave alone"
};

static const value_string vals_32_state[] = {
	{ 0x00, "Disable channel" },
	{ 0x01, "Enable channel" },
	{ 0x02, "Get channel enable/disable state" },
	{ 0x03, "Reserved" },

	{ 0, NULL }
};

static const struct true_false_string tfs_32_state = {
	"Channel enabled",
	"Channel disabled"
};

static const value_string vals_34_track[] = {
	{ 0x00, "No tracking" },
	{ 0x01, "Track Request" },
	{ 0x02, "Send Raw" },
	{ 0, NULL }
};

static const value_string vals_38_ipmi20[] = {
	{ 0x00, "Backward compatible with IPMI 1.5" },
	{ 0x01, "IPMI v2.0+ extended data" },
	{ 0, NULL }
};

static const value_string vals_XX_priv[] = {
	{ 0x00, "None / No change" },
	{ 0x01, "Callback" },
	{ 0x02, "User" },
	{ 0x03, "Operator" },
	{ 0x04, "Administrator" },
	{ 0x05, "OEM Proprietary" },
	{ 0, NULL }
};

static const struct true_false_string tfs_38_supp = { "Supported", "Not supported" };
static const struct true_false_string tfs_38_kg = { "Set to non-zero", "Set to default (0)" };

static const value_string vals_XX_auth[] = {
	{ 0x00, "None" },
	{ 0x01, "MD2" },
	{ 0x02, "MD5" },
	{ 0x04, "straight password" },
	{ 0x05, "OEM" },
	{ 0, NULL }
};


/* Get Device ID.
 */
static void
rs01(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte2[] = { &hf_ipmi_app_01_dev_prov_sdr, &hf_ipmi_app_01_dev_rev, NULL };
	static const gint *byte3[] = { &hf_ipmi_app_01_dev_avail, &hf_ipmi_app_01_fw_rev_maj, NULL };
	static const gint *byte6[] = { &hf_ipmi_app_01_ipmi_ads_chassis, &hf_ipmi_app_01_ipmi_ads_bridge,
		&hf_ipmi_app_01_ipmi_ads_ipmb_ev_gen, &hf_ipmi_app_01_ipmi_ads_ipmb_ev_recv,
		&hf_ipmi_app_01_ipmi_ads_fru, &hf_ipmi_app_01_ipmi_ads_sel, &hf_ipmi_app_01_ipmi_ads_sdr,
		&hf_ipmi_app_01_ipmi_ads_sensor, NULL };
	size_t len;

	len = tvb_length(tvb);

	proto_tree_add_item(tree, hf_ipmi_app_01_dev_id, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_app_01_byte2, byte2, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL, ett_ipmi_app_01_byte3, byte3, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_app_01_fw_rev_min, tvb, 3, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(tree, hf_ipmi_app_01_ipmi_version, tvb, 4, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_bitmask_text(tree, tvb, 5, 1, "Additional device support: ", "None",
			ett_ipmi_app_01_byte6, byte6, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_app_01_manufacturer, tvb, 6, 3, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_app_01_product, tvb, 9, 2, ENC_LITTLE_ENDIAN);
	if (len > 11) {
		/* IPMI states that Aux Revision should be displayed in MSB order */
		proto_tree_add_item(tree, hf_ipmi_app_01_fw_aux, tvb, 11, 4, ENC_NA);
	}
}

/* Get Self Test Results.
 */
static void
rs04(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte2[] = { &hf_ipmi_app_04_fail_sel, &hf_ipmi_app_04_fail_sdr,
		&hf_ipmi_app_04_fail_bmc_fru, &hf_ipmi_app_04_fail_ipmb_sig, &hf_ipmi_app_04_fail_sdr_empty,
		&hf_ipmi_app_04_fail_iua, &hf_ipmi_app_04_fail_bb_fw, &hf_ipmi_app_04_fail_oper_fw, NULL };
	int res, fail;

	res = tvb_get_guint8(tvb, 0);
	fail = tvb_get_guint8(tvb, 1);

	proto_tree_add_uint_format(tree, hf_ipmi_app_04_result, tvb, 0, 1,
			res, "Self test result: %s (0x%02x)",
			val_to_str(res, vals_04_result, "Device-specific internal failure"),
			res);

	if (res == 0x55 || res == 0x56 || res == 0xff) {
		proto_tree_add_uint_format_value(tree, hf_ipmi_app_04_fail, tvb, 1, 1,
				fail, "0x%02x (must be 0x00)",
				fail);
		return;
	}

	if (res != 0x57) {
		proto_tree_add_uint_format_value(tree, hf_ipmi_app_04_fail, tvb, 1, 1,
				fail, "0x%02x (device-specific)",
				fail);
		return;
	}

	proto_tree_add_bitmask(tree, tvb, 1, hf_ipmi_app_04_fail, ett_ipmi_app_04_byte2, byte2, ENC_LITTLE_ENDIAN);
}

/* Manufacturing Test On.
 */
static void
rq05(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_app_05_devspec, tvb, 0, tvb_length(tvb), ENC_NA);
}

/* Set ACPI Power State.
 */
static void
rq06(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_06_syspwr_set, &hf_ipmi_app_06_syspwr_enum, NULL };
	static const gint *byte2[] = { &hf_ipmi_app_06_devpwr_set, &hf_ipmi_app_06_devpwr_enum, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "ACPI System Power State: ", NULL,
			ett_ipmi_app_06_syspwr, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, "ACPI Device Power State: ", NULL,
			ett_ipmi_app_06_devpwr, byte2, TRUE, 0);
}

/* Get ACPI Power State.
 */
static void
rs07(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_07_syspwr_enum, NULL };
	static const gint *byte2[] = { &hf_ipmi_app_07_devpwr_enum, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "ACPI System Power State: ", NULL,
			ett_ipmi_app_07_syspwr, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, "ACPI Device Power State: ", NULL,
			ett_ipmi_app_07_devpwr, byte2, TRUE, 0);
}

/* Get Device GUID.
 */
static void
rs08(tvbuff_t *tvb, proto_tree *tree)
{
	ipmi_add_guid(tree, hf_ipmi_app_08_guid, tvb, 0);
}

/* Reset Watchdog Timer.
 */
static const value_string cc22[] = {
	{ 0x80, "Attempt to start un-initialized watchdog" },
	{ 0, NULL }
};

/* Set Watchdog Timer.
 */
static void
rq24(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_24_timer_use_dont_log,
		&hf_ipmi_app_24_timer_use_dont_stop, &hf_ipmi_app_24_timer_use_timer_use, NULL };
	static const gint *byte2[] = { &hf_ipmi_app_24_timer_action_interrupt,
		&hf_ipmi_app_24_timer_action_timeout_action, NULL };
	static const gint *byte4[] = { &hf_ipmi_app_24_expiration_flags_oem,
		&hf_ipmi_app_24_expiration_flags_smsos, &hf_ipmi_app_24_expiration_flags_osload,
		&hf_ipmi_app_24_expiration_flags_biospost, &hf_ipmi_app_24_expiration_flags_biosfrb2, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Timer Use: ", NULL, ett_ipmi_app_24_timer_use,
			byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_app_24_timer_action,
			byte2, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_app_24_pretimeout, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 3, 1, "Timer Use Expiration flags clear: ", "None",
			ett_ipmi_app_24_expiration_flags, byte4, TRUE, BMT_NO_TFS);
	proto_tree_add_item(tree, hf_ipmi_app_24_initial_countdown, tvb, 4, 2, ENC_LITTLE_ENDIAN);
}

/* Get Watchdog Timer.
 */
static void
rs25(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_25_timer_use_dont_log, 
		&hf_ipmi_app_25_timer_use_started, &hf_ipmi_app_25_timer_use_timer_use, NULL };
	static const gint *byte2[] = { &hf_ipmi_app_25_timer_action_interrupt,
		&hf_ipmi_app_25_timer_action_timeout_action, NULL };
	static const gint *byte4[] = { &hf_ipmi_app_25_expiration_flags_oem, &hf_ipmi_app_25_expiration_flags_smsos,
		&hf_ipmi_app_25_expiration_flags_osload, &hf_ipmi_app_25_expiration_flags_biospost,
		&hf_ipmi_app_25_expiration_flags_biosfrb2, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Timer Use: ", NULL, ett_ipmi_app_25_timer_use,
			byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_app_25_timer_action,
			byte2, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_app_25_pretimeout, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 3, 1, "Timer Use Expiration flags: ", "None",
			ett_ipmi_app_25_expiration_flags, byte4, TRUE, BMT_NO_TFS);
	proto_tree_add_item(tree, hf_ipmi_app_25_initial_countdown, tvb, 4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_app_25_present_countdown, tvb, 6, 2, ENC_LITTLE_ENDIAN);
}

/* Set BMC Global Enables.
 */
static void
rq2e(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_2e_byte1_oem2, &hf_ipmi_app_2e_byte1_oem1,
		&hf_ipmi_app_2e_byte1_oem0, &hf_ipmi_app_2e_byte1_sel, &hf_ipmi_app_2e_byte1_emb,
		&hf_ipmi_app_2e_byte1_emb_full_intr, &hf_ipmi_app_2e_byte1_rmq_intr, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Enables: ", "None", ett_ipmi_app_2e_byte1,
			byte1, TRUE, BMT_NO_TFS);
}

/* Get BMC Global Enables.
 */
static void
rs2f(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_2f_byte1_oem2, &hf_ipmi_app_2f_byte1_oem1,
		&hf_ipmi_app_2f_byte1_oem0, &hf_ipmi_app_2f_byte1_sel, &hf_ipmi_app_2f_byte1_emb,
		&hf_ipmi_app_2f_byte1_emb_full_intr, &hf_ipmi_app_2f_byte1_rmq_intr, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Enables: ", "None", ett_ipmi_app_2f_byte1,
			byte1, TRUE, BMT_NO_TFS);
}

/* Clear Message Flags.
 */
static void
rq30(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_30_byte1_oem2, &hf_ipmi_app_30_byte1_oem1,
		&hf_ipmi_app_30_byte1_oem0, &hf_ipmi_app_30_byte1_wd_pretimeout,
		&hf_ipmi_app_30_byte1_emb, &hf_ipmi_app_30_byte1_rmq, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Clear Message Flags: ", "None",
			ett_ipmi_app_30_byte1, byte1, TRUE, BMT_NO_TFS);
}

/* Get Message Flags.
 */
static void
rs31(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_31_byte1_oem2, &hf_ipmi_app_31_byte1_oem1,
		&hf_ipmi_app_31_byte1_oem0, &hf_ipmi_app_31_byte1_wd_pretimeout,
		&hf_ipmi_app_31_byte1_emb, &hf_ipmi_app_31_byte1_rmq, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Flags: ", "None",
			ett_ipmi_app_31_byte1, byte1, TRUE, BMT_NO_TFS);
}

/* Enable Message Channel Receive.
 */
static void
rq32(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_32_rq_chno, NULL };
	static const gint *byte2[] = { &hf_ipmi_app_32_rq_state, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_app_32_rq_byte1,
			byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_app_32_rq_byte2,
			byte2, TRUE, 0);
}

static void
rs32(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_32_rs_chno, NULL };
	static const gint *byte2[] = { &hf_ipmi_app_32_rs_state, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_app_32_rs_byte1,
			byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_app_32_rs_byte2,
			byte2, TRUE, 0);
}

/* Get Message
 */
static const value_string cc33[] = {
	{ 0x80, "Data not available (queue/buffer empty)" },
	{ 0, NULL }
};

/* Send Message
 */
static void
rq34(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_34_track, &hf_ipmi_app_34_encrypt,
		&hf_ipmi_app_34_auth, &hf_ipmi_app_34_chan, NULL };
	ipmi_dissect_format_t dfmt;
	proto_tree *s_tree;
	proto_item *ti;
	tvbuff_t *next;

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_app_34_byte1, byte1, TRUE, 0);

	next = tvb_new_subset(tvb, 1, tvb_length(tvb) - 1, tvb_length(tvb) - 1);
	ti = proto_tree_add_text(tree, next, 0, tvb_length(next), "Message");
	s_tree = proto_item_add_subtree(ti, ett_ipmi_app_34_msg);

	memset(&dfmt, 0, sizeof(dfmt));
	dfmt.flags = ipmi_guess_dissect_flags(next);
	dfmt.arg = ipmi_current_hdr;
	dfmt.getmoreheaders = ipmi_sendmsg_getheaders;
	dfmt.whichresponse = ipmi_sendmsg_whichresponse;
	dfmt.otheridx = ipmi_sendmsg_otheridx;
	ipmi_do_dissect(next, s_tree, &dfmt);
	proto_item_set_text(ti, "%s", dfmt.info);
}

static void
rs34(tvbuff_t *tvb, proto_tree *tree)
{
	ipmi_dissect_format_t dfmt;
	proto_tree *s_tree;
	proto_item *ti;

	ti = proto_tree_add_text(tree, tvb, 0, tvb_length(tvb), "Message");
	s_tree = proto_item_add_subtree(ti, ett_ipmi_app_34_msg);

	if (tvb_length(tvb)) {
		memset(&dfmt, 0, sizeof(dfmt));
		dfmt.flags = ipmi_guess_dissect_flags(tvb);
		ipmi_do_dissect(tvb, s_tree, &dfmt);
		proto_item_set_text(ti, "%s", dfmt.info);
	}
}

static const value_string cc34[] = {
	{ 0x80, "Invalid Session Handle" },
	{ 0x81, "Lost Arbitration" },
	{ 0x82, "Bus Error" },
	{ 0x83, "NAK on Write" },
	{ 0, NULL }
};

/* Read Event Message Buffer
 */
static const value_string cc35[] = {
	{ 0x80, "Data not available (queue/buffer empty)" },
	{ 0, NULL }
};

/* Get Channel Authentication Capabilities
 */
static void
rq38(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_38_rq_ipmi20, &hf_ipmi_app_38_rq_chan, NULL };
	static const gint *byte2[] = { &hf_ipmi_app_38_rq_priv, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_app_38_rq_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_app_38_rq_byte2, byte2, TRUE, 0);
}

static void
rs38(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_38_rs_chan, NULL };
	static const gint *byte2[] = { &hf_ipmi_app_38_rs_ipmi20, &hf_ipmi_app_38_rs_auth_oem,
		&hf_ipmi_app_38_rs_auth_straight, &hf_ipmi_app_38_rs_auth_md5, &hf_ipmi_app_38_rs_auth_md2,
		&hf_ipmi_app_38_rs_auth_none, NULL };
	static const gint *byte3[] = { &hf_ipmi_app_38_rs_kg, &hf_ipmi_app_38_rs_permsg, &hf_ipmi_app_38_rs_userauth,
		&hf_ipmi_app_38_rs_user_nonnull, &hf_ipmi_app_38_rs_user_null, &hf_ipmi_app_38_rs_user_anon, NULL };
	static const gint *byte4[] = { &hf_ipmi_app_38_rs_ipmi20_conn, &hf_ipmi_app_38_rs_ipmi15_conn, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_app_38_rs_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL, ett_ipmi_app_38_rs_byte2, byte2, TRUE, BMT_NO_FALSE);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL, ett_ipmi_app_38_rs_byte3, byte3, TRUE, BMT_NO_FALSE);
	proto_tree_add_bitmask_text(tree, tvb, 3, 1, "Supported connections: ", "None",
			ett_ipmi_app_38_rs_byte4, byte4, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_app_38_rs_oem_iana, tvb, 4, 3, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_app_38_rs_oem_aux, tvb, 7, 1, ENC_LITTLE_ENDIAN);
}

/* Get Session Challenge
 */
static void
rq39(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_39_authtype, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_app_39_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_app_39_user, tvb, 1, 16, ENC_ASCII|ENC_NA);
}

static void
rs39(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_app_39_temp_session, tvb, 0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_app_39_challenge, tvb, 4, 16, ENC_NA);
}

static const value_string cc39[] = {
	{ 0x81, "Invalid user name" },
	{ 0x82, "Null user name (User 1) not enabled" },
	{ 0, NULL }
};

/* Activate Session
 */
static void
rq3a(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_3a_authtype, NULL };
	static const gint *byte2[] = { &hf_ipmi_app_3a_privlevel, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_app_3a_rq_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_app_3a_rq_byte2, byte2, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_app_3a_authcode, tvb, 2, 16, ENC_NA);
	proto_tree_add_item(tree, hf_ipmi_app_3a_outbound_seq, tvb, 18, 4, ENC_LITTLE_ENDIAN);
}

static void
rs3a(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_3a_authtype_session, NULL };
	static const gint *byte10[] = { &hf_ipmi_app_3a_maxpriv_session, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_app_3a_rs_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_app_3a_session_id, tvb, 1, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_app_3a_inbound_seq, tvb, 5, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 9, 1, NULL, NULL,
			ett_ipmi_app_3a_rs_byte10, byte10, TRUE, 0);
}

static const value_string cc3a[] = {
	{ 0x81, "No session slot available" },
	{ 0x82, "No slot available for given user" },
	{ 0x83, "No slot available to support user due to maximum privilege capability" },
	{ 0x84, "Session sequence number out-of-range" },
	{ 0x85, "Invalid session ID in request" },
	{ 0x86, "Requested maximum privilege level exceeds user and/or channel privilege limit" },
	{ 0, NULL }
};

/* Set Session Privilege Level
 */
static void
rq3b(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_3b_req_priv, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_app_3b_rq_byte1, byte1, TRUE, 0);
}

static void
rs3b(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_app_3b_new_priv, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_app_3b_rs_byte1, byte1, TRUE, 0);
}

static const value_string cc3b[] = {
	{ 0x80, "Requested level not available for this user" },
	{ 0x81, "Requested level exceeds Channel and/or User Privilege Limit" },
	{ 0x82, "Cannot disable User Level authentication" },
	{ 0, NULL }
};

/* Close Session
 */
static void
rq3c(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_app_3c_session_id, tvb, 0, 4, ENC_LITTLE_ENDIAN);
	if (tvb_length(tvb) > 4) {
		proto_tree_add_item(tree, hf_ipmi_app_3c_session_handle, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	}
}

static const value_string cc3c[] = {
	{ 0x87, "Invalid Session ID in request" },
	{ 0x88, "Invalid Session Handle in request" },
	{ 0, NULL }
};

static const value_string cc40[] = {
	{ 0x82, "Set not supported on selected channel" },
	{ 0x83, "Access mode not supported" },
	{ 0, NULL }
};

static const value_string cc41[] = {
	{ 0x82, "Command not supported for selected channel" },
	{ 0, NULL }
};

static const value_string cc47[] = {
	{ 0x80, "Password test failed: password data does not match stored value" },
	{ 0x81, "Password test failed: wrong password size was used" },
	{ 0, NULL }
};

static const value_string cc48[] = {
	{ 0x80, "Payload already active on another session" },
	{ 0x81, "Payload type is disabled" },
	{ 0x82, "Payload activation limit reached" },
	{ 0x83, "Cannot activate payload with encryption" },
	{ 0x84, "Cannot activate payload without encryption" },
	{ 0, NULL }
};

static const value_string cc49[] = {
	{ 0x80, "Payload already deactivated" },
	{ 0x81, "Payload type is disabled" },
	{ 0, NULL }
};

static const value_string cc4f[] = {
	{ 0x80, "Payload type not available on given channel" },
	{ 0, NULL }
};

static const value_string cc50[] = {
	{ 0x80, "OEM Payload IANA and/or Payload ID not supported" },
	{ 0, NULL }
};

static const value_string cc52[] = {
	{ 0x81, "Lost Arbitration" },
	{ 0x82, "Bus Error" },
	{ 0x83, "NAK on Write" },
	{ 0x84, "Truncated Read" },
	{ 0, NULL }
};

static const value_string cc55[] = {
	{ 0x80, "Operation not supported for given payload type" },
	{ 0x81, "Operation not allowed under present configuration" },
	{ 0x82, "Encryption not available for session that payload type is active under" },
	{ 0x83, "Payload instance is not presently active" },
	{ 0, NULL }
};

static const value_string cc56[] = {
	{ 0x80, "Cannot perform set/confirm, key is locked" },
	{ 0x81, "Insufficient key bytes" },
	{ 0x82, "Too many key bytes" },
	{ 0x83, "Key value does not meet criteria for specified type" },
	{ 0x84, "KR is not used" },
	{ 0, NULL }
};

static const value_string cc58[] = {
	{ 0x80, "Parameter not supported" },
	{ 0x81, "Attempt to set the set-in-progress when not in set-complete state" },
	{ 0x82, "Attempt to write read-only parameter" },
	{ 0, NULL }
};

static const value_string cc59[] = {
	{ 0x80, "Parameter not supported" },
	{ 0, NULL }
};

static const value_string cc60[] = {
	{ 0x80, "Attempt to enable unsupported/unconfigurable command" },
	{ 0, NULL }
};

static const value_string cc62[] = {
	{ 0x80, "Attempt to enable unsupported/unconfigurable sub-function" },
	{ 0, NULL }
};

static ipmi_cmd_t cmd_app[] = {
  /* IPM Device Global Commands */
  { 0x01, NULL, rs01, NULL, NULL, "Get Device ID", CMD_MAYBROADCAST },
  { 0x02, NULL, NULL, NULL, NULL, "Cold Reset", 0 },
  { 0x03, NULL, NULL, NULL, NULL, "Warm Reset", 0 },
  { 0x04, NULL, rs04, NULL, NULL, "Get Self Test Results", 0 },
  { 0x05, rq05, NULL, NULL, NULL, "Manufacturing Test On", 0 },
  { 0x06, rq06, NULL, NULL, NULL, "Set ACPI Power State", 0 },
  { 0x07, NULL, rs07, NULL, NULL, "Get ACPI Power State", 0 },
  { 0x08, NULL, rs08, NULL, NULL, "Get Device GUID", 0 },
  { 0x09, IPMI_TBD,   NULL, NULL, "Get NetFn Support", 0 },
  { 0x0a, IPMI_TBD,   NULL, NULL, "Get Command Support", 0 },
  { 0x0b, IPMI_TBD,   NULL, NULL, "Get Command Sub-function Support", 0 },
  { 0x0c, IPMI_TBD,   NULL, NULL, "Get Configurable Commands", 0 },
  { 0x0d, IPMI_TBD,   NULL, NULL, "Get Configurable Command Sub-functions", 0 },

  /* BMC Watchdog Timer Commands */
  { 0x22, NULL, NULL, cc22, NULL, "Reset Watchdog Timer", 0 },
  { 0x24, rq24, NULL, NULL, NULL, "Set Watchdog Timer", 0 },
  { 0x25, NULL, rs25, NULL, NULL, "Get Watchdog Timer", 0 },

  /* BMC Device and Messaging Commands */
  { 0x2e, rq2e, NULL, NULL, NULL, "Set BMC Global Enables", 0 },
  { 0x2f, NULL, rs2f, NULL, NULL, "Get BMC Global Enables", 0 },
  { 0x30, rq30, NULL, NULL, NULL, "Clear Message Flags", 0 },
  { 0x31, NULL, rs31, NULL, NULL, "Get Message Flags", 0 },
  { 0x32, rq32, rs32, NULL, NULL, "Enable Message Channel Receive", 0 },
  { 0x33, IPMI_TBD,   cc33, NULL, "Get Message", 0 },
  { 0x34, rq34, rs34, cc34, NULL, "Send Message", CMD_CALLRQ },
  { 0x35, IPMI_TBD,   cc35, NULL, "Read Event Message Buffer", 0 },
  { 0x36, IPMI_TBD,   NULL, NULL, "Get BT Interface Capabilities", 0 },
  { 0x37, IPMI_TBD,   NULL, NULL, "Get System GUID", 0 },
  { 0x38, rq38, rs38, NULL, NULL, "Get Channel Authentication Capabilities", 0 },
  { 0x39, rq39, rs39, cc39, NULL, "Get Session Challenge", 0 },
  { 0x3a, rq3a, rs3a, cc3a, NULL, "Activate Session", 0 },
  { 0x3b, rq3b, rs3b, cc3b, NULL, "Set Session Privilege Level", 0 },
  { 0x3c, rq3c, NULL, cc3c, NULL, "Close Session", 0 },
  { 0x3d, IPMI_TBD,   NULL, NULL, "Get Session Info", 0 },
  { 0x3f, IPMI_TBD,   NULL, NULL, "Get AuthCode", 0 },
  { 0x40, IPMI_TBD,   cc40, NULL, "Set Channel Access", 0 },
  { 0x41, IPMI_TBD,   cc41, NULL, "Get Channel Access", 0 },
  { 0x42, IPMI_TBD,   NULL, NULL, "Get Channel Info", 0 },
  { 0x43, IPMI_TBD,   NULL, NULL, "Set User Access", 0 },
  { 0x44, IPMI_TBD,   NULL, NULL, "Get User Access", 0 },
  { 0x45, IPMI_TBD,   NULL, NULL, "Set User Name", 0 },
  { 0x46, IPMI_TBD,   NULL, NULL, "Get User Name", 0 },
  { 0x47, IPMI_TBD,   cc47, NULL, "Set User Password", 0 },
  { 0x48, IPMI_TBD,   cc48, NULL, "Activate Payload", 0 },
  { 0x49, IPMI_TBD,   cc49, NULL, "Deactivate Payload", 0 },
  { 0x4a, IPMI_TBD,   NULL, NULL, "Get Payload Activation Status", 0 },
  { 0x4b, IPMI_TBD,   NULL, NULL, "Get Payload Instance Info", 0 },
  { 0x4c, IPMI_TBD,   NULL, NULL, "Set User Payload Access", 0 },
  { 0x4d, IPMI_TBD,   NULL, NULL, "Get User Payload Access", 0 },
  { 0x4e, IPMI_TBD,   NULL, NULL, "Get Channel Payload Support", 0 },
  { 0x4f, IPMI_TBD,   cc4f, NULL, "Get Channel Payload Version", 0 },
  { 0x50, IPMI_TBD,   cc50, NULL, "Get Channel OEM Payload Info", 0 },
  { 0x52, IPMI_TBD,   cc52, NULL, "Master Write-Read", 0 },
  { 0x54, IPMI_TBD,   NULL, NULL, "Get Channel Cipher Suites", 0 },
  { 0x55, IPMI_TBD,   cc55, NULL, "Suspend/Resume Payload Encryption", 0 },
  { 0x56, IPMI_TBD,   cc56, NULL, "Set Channel Security Keys", 0 },
  { 0x57, IPMI_TBD,   NULL, NULL, "Get System Interface Capabilities", 0 },
  { 0x58, IPMI_TBD,   cc58, NULL, "Set System Info Parameters", 0 },
  { 0x59, IPMI_TBD,   cc59, NULL, "Get System Info Parameters", 0 },

  /* Device "Global" commands, continued */
  { 0x60, IPMI_TBD,   cc60, NULL, "Set Command Enables", 0 },
  { 0x61, IPMI_TBD,   NULL, NULL, "Get Command Enables", 0 },
  { 0x62, IPMI_TBD,   cc62, NULL, "Set Command Sub-function Enables", 0 },
  { 0x63, IPMI_TBD,   NULL, NULL, "Get Command Sub-function Enables", 0 },
  { 0x64, IPMI_TBD,   NULL, NULL, "Get OEM NetFn IANA Support", 0 },
};

void
ipmi_register_app(gint proto_ipmi)
{
	static hf_register_info hf[] = {
		{ &hf_ipmi_app_01_dev_id,
			{ "Device ID",
				"ipmi.app00.dev.id", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_01_dev_prov_sdr,
			{ "Device provides Device SDRs",
				"ipmi.app00.dev.provides_dev_sdr", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_01_dev_rev,
			{ "Device Revision (binary encoded)",
				"ipmi.app00.dev.rev", FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_01_dev_avail,
			{ "Device availability",
				"ipmi.app01.dev.avail", FT_BOOLEAN, 8, TFS(&tfs_01_dev_avail), 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_01_fw_rev_maj,
			{ "Major Firmware Revision (binary encoded)",
				"ipmi.app01.fw.major", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_app_01_fw_rev_min,
			{ "Minor Firmware Revision (BCD encoded)",
				"ipmi.app01.fw.minor", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_01_ipmi_version,
			{ "IPMI version",
				"ipmi.app01.ipmi.version", FT_UINT8, BASE_CUSTOM, ipmi_fmt_version, 0, NULL, HFILL }},
		{ &hf_ipmi_app_01_ipmi_ads_chassis,
			{ "Chassis",
				"ipmi.app01.ads.chassis", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_01_ipmi_ads_bridge,
			{ "Bridge",
				"ipmi.app01.ads.bridge", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_app_01_ipmi_ads_ipmb_ev_gen,
			{ "Event Generator",
				"ipmi.app01.ads.ipmb_ev_gen", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_01_ipmi_ads_ipmb_ev_recv,
			{ "Event Receiver",
				"ipmi.app01.ads.ipmb_ev_recv", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_app_01_ipmi_ads_fru,
			{ "FRU Inventory",
				"ipmi.app01.ads.fru", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_app_01_ipmi_ads_sel,
			{ "SEL",
				"ipmi.app01.ads.sel", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_app_01_ipmi_ads_sdr,
			{ "SDR Repository",
				"ipmi.app01.ads.sdr", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_01_ipmi_ads_sensor,
			{ "Sensor",
				"ipmi.app01.ads.sensor", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_app_01_manufacturer,
			{ "Manufacturer ID",
				"ipmi.app01.manufacturer", FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_01_product,
			{ "Product ID",
				"ipmi.app01.product", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_01_fw_aux,
			{ "Auxiliary Firmware Revision Information",
				"ipmi.app01.fw.aux", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_app_04_result,
			{ "Self test result",
				"ipmi.app04.self_test_result", FT_UINT8, BASE_HEX, vals_04_result, 0, NULL, HFILL }},
		{ &hf_ipmi_app_04_fail,
			{ "Self-test error bitfield",
				"ipmi.app04.fail", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_04_fail_sel,
			{ "Cannot access SEL device",
				"ipmi.app04.fail.sel", FT_BOOLEAN, 8, TFS(&tfs_04_fail_unknown), 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_04_fail_sdr,
			{ "Cannot access SDR Repository",
				"ipmi.app04.fail.sdr", FT_BOOLEAN, 8, TFS(&tfs_04_fail_unknown), 0x40, NULL, HFILL }},
		{ &hf_ipmi_app_04_fail_bmc_fru,
			{ "Cannot access BMC FRU device",
				"ipmi.app04.fail.bmc_fru", FT_BOOLEAN, 8, TFS(&tfs_04_fail_unknown), 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_04_fail_ipmb_sig,
			{ "IPMB signal lines do not respond",
				"ipmi.app04.fail.ipmb_sig", FT_BOOLEAN, 8, TFS(&tfs_04_fail_unknown), 0x10, NULL, HFILL }},
		{ &hf_ipmi_app_04_fail_sdr_empty,
			{ "SDR Repository is empty",
				"ipmi.app04.fail.sdr_empty", FT_BOOLEAN, 8, TFS(&tfs_04_fail_unknown), 0x08, NULL, HFILL }},
		{ &hf_ipmi_app_04_fail_iua,
			{ "Internal Use Area of BMC FRU corrupted",
				"ipmi.app04.fail.iua", FT_BOOLEAN, 8, TFS(&tfs_04_fail_unknown), 0x04, NULL, HFILL }},
		{ &hf_ipmi_app_04_fail_bb_fw,
			{ "Controller update boot block firmware corrupted",
				"ipmi.app04.fail.bb_fw", FT_BOOLEAN, 8, TFS(&tfs_04_fail_unknown), 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_04_fail_oper_fw,
			{ "Controller operational firmware corrupted",
				"ipmi.app04.fail.oper_fw", FT_BOOLEAN, 8, TFS(&tfs_04_fail_unknown), 0x01, NULL, HFILL }},

		{ &hf_ipmi_app_05_devspec,
			{ "Device-specific parameters",
				"ipmi.app05.devspec", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_app_06_syspwr_set,
			{ "System Power State",
				"ipmi.app06.syspwr.set", FT_BOOLEAN, 8, TFS(&tfs_06_pwr), 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_06_syspwr_enum,
			{ "System Power State enumeration",
				"ipmi.app06.syspwr.enum", FT_UINT8, BASE_HEX, vals_06_syspwr, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_app_06_devpwr_set,
			{ "Device Power State",
				"ipmi.app06.devpwr.set", FT_BOOLEAN, 8, TFS(&tfs_06_pwr), 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_06_devpwr_enum,
			{ "Device Power State enumeration",
				"ipmi.app06.devpwr.enum", FT_UINT8, BASE_HEX, vals_06_devpwr, 0x7f, NULL, HFILL }},

		{ &hf_ipmi_app_07_syspwr_enum,
			{ "ACPI System Power State",
				"ipmi.app07.syspwr", FT_UINT8, BASE_HEX, vals_07_syspwr, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_app_07_devpwr_enum,
			{ "ACPI Device Power State",
				"ipmi.app07.devpwr", FT_UINT8, BASE_HEX, vals_07_devpwr, 0x7f, NULL, HFILL }},

		{ &hf_ipmi_app_08_guid,
			{ "GUID",
				"ipmi.app08.guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_app_24_timer_use_dont_log,
			{ "Don't log",
				"ipmi.app24.timer_use.dont_log", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_24_timer_use_dont_stop,
			{ "Don't stop timer on Set Watchdog command",
				"ipmi.app24.timer_use.dont_stop", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_app_24_timer_use_timer_use,
			{ "Timer use",
				"ipmi.app24.timer_use.timer_use", FT_UINT8, BASE_HEX, vals_24_timer_use, 0x07, NULL, HFILL }},
		{ &hf_ipmi_app_24_timer_action_interrupt,
			{ "Pre-timeout interrupt",
				"ipmi.app24.timer_action.interrupt", FT_UINT8, BASE_HEX, vals_24_timer_action_interrupt, 0x70, NULL, HFILL }},
		{ &hf_ipmi_app_24_timer_action_timeout_action,
			{ "Timeout action",
				"ipmi.app24.timer_action.timeout", FT_UINT8, BASE_HEX, vals_24_timer_action_timeout, 0x07, NULL, HFILL }},
		{ &hf_ipmi_app_24_pretimeout,
			{ "Pre-timeout interval",
				"ipmi.app24.pretimeout", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_app_24_expiration_flags_oem,
			{ "OEM",
				"ipmi.app24.exp_flags.oem", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_24_expiration_flags_smsos,
			{ "SMS/OS",
				"ipmi.app24.exp_flags.sms_os", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x10, NULL, HFILL }},
		{ &hf_ipmi_app_24_expiration_flags_osload,
			{ "OS Load",
				"ipmi.app24.exp_flags.osload", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x08, NULL, HFILL }},
		{ &hf_ipmi_app_24_expiration_flags_biospost,
			{ "BIOS/POST",
				"ipmi.app24.exp_flags.biospost", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x04, NULL, HFILL }},
		{ &hf_ipmi_app_24_expiration_flags_biosfrb2,
			{ "BIOS FRB2",
				"ipmi.app24.exp_flags.biosfrb2", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_24_initial_countdown,
			{ "Initial countdown value (100ms/count)",
				"ipmi.app24.initial_countdown", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_app_25_timer_use_dont_log,
			{ "Don't log",
				"ipmi.app25.timer_use.dont_log", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_25_timer_use_started,
			{ "Started",
				"ipmi.app25.timer_use.started", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_app_25_timer_use_timer_use,
			{ "Timer user",
				"ipmi.app25.timer_use.timer_use", FT_UINT8, BASE_HEX, vals_24_timer_use, 0x07, NULL, HFILL }},
		{ &hf_ipmi_app_25_timer_action_interrupt,
			{ "Pre-timeout interrupt",
				"ipmi.app25.timer_action.interrupt", FT_UINT8, BASE_HEX, vals_24_timer_action_interrupt, 0x70, NULL, HFILL }},
		{ &hf_ipmi_app_25_timer_action_timeout_action,
			{ "Timeout action",
				"ipmi.app25.timer_action.timeout", FT_UINT8, BASE_HEX, vals_24_timer_action_timeout, 0x07, NULL, HFILL }},
		{ &hf_ipmi_app_25_pretimeout,
			{ "Pre-timeout interval",
				"ipmi.app25.pretimeout", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_app_25_expiration_flags_oem,
			{ "OEM",
				"ipmi.app25.exp_flags.oem", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_25_expiration_flags_smsos,
			{ "SMS/OS",
				"ipmi.app25.exp_flags.sms_os", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x10, NULL, HFILL }},
		{ &hf_ipmi_app_25_expiration_flags_osload,
			{ "OS Load",
				"ipmi.app25.exp_flags.osload", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x08, NULL, HFILL }},
		{ &hf_ipmi_app_25_expiration_flags_biospost,
			{ "BIOS/POST",
				"ipmi.app25.exp_flags.biospost", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x04, NULL, HFILL }},
		{ &hf_ipmi_app_25_expiration_flags_biosfrb2,
			{ "BIOS FRB2",
				"ipmi.app25.exp_flags.biosfrb2", FT_BOOLEAN, 8, TFS(&tfs_24_exp_flags), 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_25_initial_countdown,
			{ "Initial countdown value (100ms/count)",
				"ipmi.app25.initial_countdown", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_25_present_countdown,
			{ "Present countdown value (100ms/count)",
				"ipmi.app25.initial_countdown", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_app_2e_byte1_oem2,
			{ "OEM 2",
				"ipmi.app2e.bmc_global_enables.oem2", FT_BOOLEAN, 8, TFS(&tfs_2e_enable), 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_2e_byte1_oem1,
			{ "OEM 1",
				"ipmi.app2e.bmc_global_enables.oem1", FT_BOOLEAN, 8, TFS(&tfs_2e_enable), 0x40, NULL, HFILL }},
		{ &hf_ipmi_app_2e_byte1_oem0,
			{ "OEM 0",
				"ipmi.app2e.bmc_global_enables.oem0", FT_BOOLEAN, 8, TFS(&tfs_2e_enable), 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_2e_byte1_sel,
			{ "System Event Logging",
				"ipmi.app2e.bmc_global_enables.sel", FT_BOOLEAN, 8, TFS(&tfs_2e_enable), 0x08, NULL, HFILL }},
		{ &hf_ipmi_app_2e_byte1_emb,
			{ "Event Message Buffer",
				"ipmi.app2e.bmc_global_enables.emb", FT_BOOLEAN, 8, TFS(&tfs_2e_enable), 0x04, NULL, HFILL }},
		{ &hf_ipmi_app_2e_byte1_emb_full_intr,
			{ "Event Message Buffer Full Interrupt",
				"ipmi.app2e.bmc_global_enables.emb_full_intr", FT_BOOLEAN, 8, TFS(&tfs_2e_enable), 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_2e_byte1_rmq_intr,
			{ "Receive Message Queue Interrupt",
				"ipmi.app2e.bmc_global_enables.rmq_intr", FT_BOOLEAN, 8, TFS(&tfs_2e_enable), 0x01, NULL, HFILL }},

		{ &hf_ipmi_app_2f_byte1_oem2,
			{ "OEM 2",
				"ipmi.app2f.bmc_global_enables.oem2", FT_BOOLEAN, 8, TFS(&tfs_2f_enabled), 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_2f_byte1_oem1,
			{ "OEM 1",
				"ipmi.app2f.bmc_global_enables.oem1", FT_BOOLEAN, 8, TFS(&tfs_2f_enabled), 0x40, NULL, HFILL }},
		{ &hf_ipmi_app_2f_byte1_oem0,
			{ "OEM 0",
				"ipmi.app2f.bmc_global_enables.oem0", FT_BOOLEAN, 8, TFS(&tfs_2f_enabled), 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_2f_byte1_sel,
			{ "System Event Logging",
				"ipmi.app2f.bmc_global_enables.sel", FT_BOOLEAN, 8, TFS(&tfs_2f_enabled), 0x08, NULL, HFILL }},
		{ &hf_ipmi_app_2f_byte1_emb,
			{ "Event Message Buffer",
				"ipmi.app2f.bmc_global_enables.emb", FT_BOOLEAN, 8, TFS(&tfs_2f_enabled), 0x04, NULL, HFILL }},
		{ &hf_ipmi_app_2f_byte1_emb_full_intr,
			{ "Event Message Buffer Full Interrupt",
				"ipmi.app2f.bmc_global_enables.emb_full_intr", FT_BOOLEAN, 8, TFS(&tfs_2f_enabled), 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_2f_byte1_rmq_intr,
			{ "Receive Message Queue Interrupt",
				"ipmi.app2f.bmc_global_enables.rmq_intr", FT_BOOLEAN, 8, TFS(&tfs_2f_enabled), 0x01, NULL, HFILL }},

		{ &hf_ipmi_app_30_byte1_oem2,
			{ "OEM 2",
				"ipmi.app30.byte1.oem2", FT_BOOLEAN, 8, TFS(&tfs_30_clear), 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_30_byte1_oem1,
			{ "OEM 1",
				"ipmi.app30.byte1.oem1", FT_BOOLEAN, 8, TFS(&tfs_30_clear), 0x40, NULL, HFILL }},
		{ &hf_ipmi_app_30_byte1_oem0,
			{ "OEM 0",
				"ipmi.app30.byte1.oem0", FT_BOOLEAN, 8, TFS(&tfs_30_clear), 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_30_byte1_wd_pretimeout,
			{ "Watchdog pre-timeout interrupt flag",
				"ipmi.app30.byte1.wd_pretimeout", FT_BOOLEAN, 8, TFS(&tfs_30_clear), 0x08, NULL, HFILL }},
		{ &hf_ipmi_app_30_byte1_emb,
			{ "Event Message Buffer",
				"ipmi.app30.byte1.emb", FT_BOOLEAN, 8, TFS(&tfs_30_clear), 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_30_byte1_rmq,
			{ "Receive Message Queue",
				"ipmi.app30.byte1.rmq", FT_BOOLEAN, 8, TFS(&tfs_30_clear), 0x01, NULL, HFILL }},

		{ &hf_ipmi_app_31_byte1_oem2,
			{ "OEM 2 data available",
				"ipmi.app31.byte1.oem2", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_31_byte1_oem1,
			{ "OEM 1 data available",
				"ipmi.app31.byte1.oem1", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_app_31_byte1_oem0,
			{ "OEM 0 data available",
				"ipmi.app31.byte1.oem0", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_31_byte1_wd_pretimeout,
			{ "Watchdog pre-timeout interrupt occurred",
				"ipmi.app31.byte1.wd_pretimeout", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_app_31_byte1_emb,
			{ "Event Message Buffer Full",
				"ipmi.app31.byte1.emb", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_31_byte1_rmq,
			{ "Receive Message Available",
				"ipmi.app31.byte1.rmq", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

		{ &hf_ipmi_app_32_rq_chno,
			{ "Channel",
				"ipmi.app32.rq_chno", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_32_rq_state,
			{ "Channel State",
				"ipmi.app32.rq_state", FT_UINT8, BASE_HEX, vals_32_state, 0x03, NULL, HFILL }},
		{ &hf_ipmi_app_32_rs_chno,
			{ "Channel",
				"ipmi.app32.rs_chno", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_32_rs_state,
			{ "Channel State",
				"ipmi.app32.rs_state", FT_BOOLEAN, 8, TFS(&tfs_32_state), 0x01, NULL, HFILL }},

		{ &hf_ipmi_app_34_track,
			{ "Tracking",
				"ipmi.app34.track", FT_UINT8, BASE_HEX, vals_34_track, 0xc0, NULL, HFILL }},
		{ &hf_ipmi_app_34_encrypt,
			{ "Encryption required",
				"ipmi.app34.encrypt", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_34_auth,
			{ "Authentication required",
				"ipmi.app34.auth", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_app_34_chan,
			{ "Channel",
				"ipmi.app34.chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_app_38_rq_ipmi20,
			{ "Version compatibility",
				"ipmi.app38.rq_ipmi20", FT_UINT8, BASE_DEC, &vals_38_ipmi20, 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_38_rq_chan,
			{ "Channel",
				"ipmi.app38.rq_chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_38_rq_priv,
			{ "Requested privilege level",
				"ipmi.app38.rq_priv", FT_UINT8, BASE_HEX, vals_XX_priv, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_chan,
			{ "Channel",
				"ipmi.app38.rs_chan", FT_UINT8, BASE_CUSTOM, ipmi_fmt_channel, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_ipmi20,
			{ "Version compatibility",
				"ipmi.app38.rs_ipmi20", FT_UINT8, BASE_DEC, vals_38_ipmi20, 0x80, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_auth_oem,
			{ "OEM Proprietary authentication",
				"ipmi.app38.rs_auth_oem", FT_BOOLEAN, 8, TFS(&tfs_38_supp), 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_auth_straight,
			{ "Straight password/key",
				"ipmi.app38.rs_auth_straight", FT_BOOLEAN, 8, TFS(&tfs_38_supp), 0x10, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_auth_md5,
			{ "MD5",
				"ipmi.app38.rs_auth_md5", FT_BOOLEAN, 8, TFS(&tfs_38_supp), 0x04, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_auth_md2,
			{ "MD2",
				"ipmi.app38.rs_auth_md2", FT_BOOLEAN, 8, TFS(&tfs_38_supp), 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_auth_none,
			{ "No auth",
				"ipmi.app38.rs_auth_none", FT_BOOLEAN, 8, TFS(&tfs_38_supp), 0x01, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_kg,
			{ "KG",
				"ipmi.app38.rs_kg_status", FT_BOOLEAN, 8, TFS(&tfs_38_kg), 0x20, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_permsg,
			{ "Per-message Authentication disabled",
				"ipmi.app38.rs_permsg", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_userauth,
			{ "User-level Authentication disabled",
				"ipmi.app38.rs_userauth", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_user_nonnull,
			{ "Non-null usernames enabled",
				"ipmi.app38.rs_user_nonnull", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_user_null,
			{ "Null usernames enabled",
				"ipmi.app38.rs_user_null", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_user_anon,
			{ "Anonymous login enabled",
				"ipmi.app38.rs_user_anon", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_ipmi20_conn,
			{ "IPMI v2.0",
				"ipmi.app38.rs_ipmi20_conn", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_ipmi15_conn,
			{ "IPMI v1.5",
				"ipmi.app38.rs_ipmi15_conn", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_oem_iana,
			{ "OEM ID",
				"ipmi.app38.rs_oem_iana", FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_38_rs_oem_aux,
			{ "OEM Auxiliary data",
				"ipmi.app38.rs_oem_aux", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_app_39_authtype,
			{ "Authentication Type",
				"ipmi.app39.authtype", FT_UINT8, BASE_HEX, vals_XX_auth, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_39_user,
			{ "User Name",
				"ipmi.app39.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_39_temp_session,
			{ "Temporary Session ID",
				"ipmi.app39.temp_session", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_39_challenge,
			{ "Challenge",
				"ipmi.app39.challenge", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_app_3a_authtype,
			{ "Authentication Type",
				"ipmi.app3a.authtype", FT_UINT8, BASE_HEX, vals_XX_auth, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_3a_privlevel,
			{ "Requested Maximum Privilege Level",
				"ipmi.app3a.privlevel", FT_UINT8, BASE_HEX, vals_XX_priv, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_3a_authcode,
			{ "Challenge string/Auth Code",
				"ipmi.app3a.authcode", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_3a_outbound_seq,
			{ "Initial Outbound Sequence Number",
				"ipmi.app3a.outbound_seq", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_3a_authtype_session,
			{ "Authentication Type for session",
				"ipmi.app3a.authtype_session", FT_UINT8, BASE_HEX, vals_XX_auth, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_3a_session_id,
			{ "Session ID",
				"ipmi.app3a.session_id", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_3a_inbound_seq,
			{ "Initial Inbound Sequence Number",
				"ipmi.app3a.inbound_seq", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_3a_maxpriv_session,
			{ "Maximum Privilege Level for session",
				"ipmi.app3a.maxpriv_session", FT_UINT8, BASE_HEX, vals_XX_priv, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_app_3b_req_priv,
			{ "Requested Privilege Level",
				"ipmi.app3b.req_priv", FT_UINT8, BASE_HEX, vals_XX_priv, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_app_3b_new_priv,
			{ "New Privilege Level",
				"ipmi.app3b.new_priv", FT_UINT8, BASE_HEX, vals_XX_priv, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_app_3c_session_id,
			{ "Session ID",
				"ipmi.app3c.session_id", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_app_3c_session_handle,
			{ "Session handle",
				"ipmi.app3c.session_handle", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_ipmi_app_01_byte2,
		&ett_ipmi_app_01_byte3,
		&ett_ipmi_app_01_byte6,
		&ett_ipmi_app_04_byte2,
		&ett_ipmi_app_06_syspwr,
		&ett_ipmi_app_06_devpwr,
		&ett_ipmi_app_07_syspwr,
		&ett_ipmi_app_07_devpwr,
		&ett_ipmi_app_24_timer_use,
		&ett_ipmi_app_24_timer_action,
		&ett_ipmi_app_24_expiration_flags,
		&ett_ipmi_app_25_timer_use,
		&ett_ipmi_app_25_timer_action,
		&ett_ipmi_app_25_expiration_flags,
		&ett_ipmi_app_2e_byte1,
		&ett_ipmi_app_2f_byte1,
		&ett_ipmi_app_30_byte1,
		&ett_ipmi_app_31_byte1,
		&ett_ipmi_app_32_rq_byte1,
		&ett_ipmi_app_32_rq_byte2,
		&ett_ipmi_app_32_rs_byte1,
		&ett_ipmi_app_32_rs_byte2,
		&ett_ipmi_app_34_byte1,
		&ett_ipmi_app_34_msg,
		&ett_ipmi_app_38_rq_byte1,
		&ett_ipmi_app_38_rq_byte2,
		&ett_ipmi_app_38_rs_byte1,
		&ett_ipmi_app_38_rs_byte2,
		&ett_ipmi_app_38_rs_byte3,
		&ett_ipmi_app_38_rs_byte4,
		&ett_ipmi_app_39_byte1,
		&ett_ipmi_app_3a_rq_byte1,
		&ett_ipmi_app_3a_rq_byte2,
		&ett_ipmi_app_3a_rs_byte1,
		&ett_ipmi_app_3a_rs_byte10,
		&ett_ipmi_app_3b_rq_byte1,
		&ett_ipmi_app_3b_rs_byte1,
	};

	proto_register_field_array(proto_ipmi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	ipmi_register_netfn_cmdtab(IPMI_APP_REQ, IPMI_OEM_NONE, NULL, 0, NULL,
			cmd_app, array_length(cmd_app));
}
