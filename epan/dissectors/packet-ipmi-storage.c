/* packet-ipmi-storage.c
 * Sub-dissectors for IPMI messages (netFn=Storage)
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

static gint ett_ipmi_stor_10_flags = -1;
static gint ett_ipmi_stor_20_ops = -1;
static gint ett_ipmi_stor_25_byte6 = -1;
static gint ett_ipmi_stor_27_status = -1;
static gint ett_ipmi_stor_2c_rq_byte1 = -1;
static gint ett_ipmi_stor_2c_rs_byte1 = -1;
static gint ett_ipmi_stor_40_ops = -1;
static gint ett_ipmi_stor_45_byte6 = -1;
static gint ett_ipmi_stor_47_status = -1;
static gint ett_ipmi_stor_5a_byte1 = -1;
static gint ett_ipmi_stor_5b_byte1 = -1;

static gint hf_ipmi_stor_10_fruid = -1;
static gint hf_ipmi_stor_10_size = -1;
static gint hf_ipmi_stor_10_access = -1;

static gint hf_ipmi_stor_11_fruid = -1;
static gint hf_ipmi_stor_11_offset = -1;
static gint hf_ipmi_stor_11_count = -1;
static gint hf_ipmi_stor_11_ret_count = -1;
static gint hf_ipmi_stor_11_data = -1;

static gint hf_ipmi_stor_12_fruid = -1;
static gint hf_ipmi_stor_12_offset = -1;
static gint hf_ipmi_stor_12_data = -1;
static gint hf_ipmi_stor_12_ret_count = -1;

static gint hf_ipmi_stor_20_sdr_version = -1;
static gint hf_ipmi_stor_20_rec_count = -1;
static gint hf_ipmi_stor_20_free_space = -1;
static gint hf_ipmi_stor_20_ts_add = -1;
static gint hf_ipmi_stor_20_ts_erase = -1;
static gint hf_ipmi_stor_20_op_overflow = -1;
static gint hf_ipmi_stor_20_op_update = -1;
static gint hf_ipmi_stor_20_op_delete = -1;
static gint hf_ipmi_stor_20_op_partial_add = -1;
static gint hf_ipmi_stor_20_op_reserve = -1;
static gint hf_ipmi_stor_20_op_allocinfo = -1;

static gint hf_ipmi_stor_21_units = -1;
static gint hf_ipmi_stor_21_size = -1;
static gint hf_ipmi_stor_21_free = -1;
static gint hf_ipmi_stor_21_largest = -1;
static gint hf_ipmi_stor_21_maxrec = -1;

static gint hf_ipmi_stor_22_rsrv_id = -1;

static gint hf_ipmi_stor_23_rsrv_id = -1;
static gint hf_ipmi_stor_23_rec_id = -1;
static gint hf_ipmi_stor_23_offset = -1;
static gint hf_ipmi_stor_23_count = -1;
static gint hf_ipmi_stor_23_next = -1;
static gint hf_ipmi_stor_23_data = -1;

static gint hf_ipmi_stor_24_data = -1;
static gint hf_ipmi_stor_24_added_rec_id = -1;

static gint hf_ipmi_stor_25_rsrv_id = -1;
static gint hf_ipmi_stor_25_rec_id = -1;
static gint hf_ipmi_stor_25_offset = -1;
static gint hf_ipmi_stor_25_inprogress = -1;
static gint hf_ipmi_stor_25_data = -1;
static gint hf_ipmi_stor_25_added_rec_id = -1;

static gint hf_ipmi_stor_26_rsrv_id = -1;
static gint hf_ipmi_stor_26_rec_id = -1;
static gint hf_ipmi_stor_26_del_rec_id = -1;

static gint hf_ipmi_stor_27_rsrv_id = -1;
static gint hf_ipmi_stor_27_clr = -1;
static gint hf_ipmi_stor_27_action = -1;
static gint hf_ipmi_stor_27_status = -1;

static gint hf_ipmi_stor_28_time = -1;

static gint hf_ipmi_stor_29_time = -1;

static gint hf_ipmi_stor_2c_init_agent = -1;
static gint hf_ipmi_stor_2c_init_state = -1;

static gint hf_ipmi_stor_40_sel_version = -1;
static gint hf_ipmi_stor_40_entries = -1;
static gint hf_ipmi_stor_40_free_space = -1;
static gint hf_ipmi_stor_40_ts_add = -1;
static gint hf_ipmi_stor_40_ts_erase = -1;
static gint hf_ipmi_stor_40_op_overflow = -1;
static gint hf_ipmi_stor_40_op_delete = -1;
static gint hf_ipmi_stor_40_op_partial_add = -1;
static gint hf_ipmi_stor_40_op_reserve = -1;
static gint hf_ipmi_stor_40_op_allocinfo = -1;

static gint hf_ipmi_stor_41_units = -1;
static gint hf_ipmi_stor_41_size = -1;
static gint hf_ipmi_stor_41_free = -1;
static gint hf_ipmi_stor_41_largest = -1;
static gint hf_ipmi_stor_41_maxrec = -1;

static gint hf_ipmi_stor_42_rsrv_id = -1;

static gint hf_ipmi_stor_43_rsrv_id = -1;
static gint hf_ipmi_stor_43_rec_id = -1;
static gint hf_ipmi_stor_43_offset = -1;
static gint hf_ipmi_stor_43_count = -1;
static gint hf_ipmi_stor_43_next = -1;
static gint hf_ipmi_stor_43_data = -1;

static gint hf_ipmi_stor_44_data = -1;
static gint hf_ipmi_stor_44_added_rec_id = -1;

static gint hf_ipmi_stor_45_rsrv_id = -1;
static gint hf_ipmi_stor_45_rec_id = -1;
static gint hf_ipmi_stor_45_offset = -1;
static gint hf_ipmi_stor_45_inprogress = -1;
static gint hf_ipmi_stor_45_data = -1;
static gint hf_ipmi_stor_45_added_rec_id = -1;

static gint hf_ipmi_stor_46_rsrv_id = -1;
static gint hf_ipmi_stor_46_rec_id = -1;
static gint hf_ipmi_stor_46_del_rec_id = -1;

static gint hf_ipmi_stor_47_rsrv_id = -1;
static gint hf_ipmi_stor_47_clr = -1;
static gint hf_ipmi_stor_47_action = -1;
static gint hf_ipmi_stor_47_status = -1;

static gint hf_ipmi_stor_48_time = -1;

static gint hf_ipmi_stor_49_time = -1;

static gint hf_ipmi_stor_5a_log_type = -1;
static gint hf_ipmi_stor_5a_ts_add = -1;
static gint hf_ipmi_stor_5a_num_entries = -1;
static gint hf_ipmi_stor_5a_iana = -1;
static gint hf_ipmi_stor_5a_bytes = -1;
static gint hf_ipmi_stor_5a_unknown = -1;

static gint hf_ipmi_stor_5b_log_type = -1;
static gint hf_ipmi_stor_5b_ts_add = -1;
static gint hf_ipmi_stor_5b_num_entries = -1;
static gint hf_ipmi_stor_5b_iana = -1;
static gint hf_ipmi_stor_5b_bytes = -1;
static gint hf_ipmi_stor_5b_unknown = -1;

static const struct true_false_string tfs_10_access = {
	"by words", "by bytes"
};

static const value_string vals_20_update[] = {
	{ 0x00, "Unspecified" },
	{ 0x01, "Supported non-modal" },
	{ 0x02, "Supported modal" },
	{ 0x03, "Supported both modal and non-modal" },
	{ 0, NULL }
};

static const value_string vals_25_inprogress[] = {
	{ 0x00, "Partial add in progress" },
	{ 0x01, "Last record data being transferred" },
	{ 0, NULL }
};

static const value_string vals_27_action[] = {
	{ 0x00, "Get Erasure Status" },
	{ 0xaa, "Initiate Erase" },
	{ 0, NULL }
};

static const value_string vals_27_status[] = {
	{ 0x00, "Erasure in progress" },
	{ 0x01, "Erase completed" },
	{ 0, NULL }
};

static const struct true_false_string tfs_2c_init_agent = {
	"Run", "Get status"
};

static const struct true_false_string tfs_2c_init_state = {
	"Completed", "In progress"
};

static const value_string vals_45_inprogress[] = {
	{ 0x00, "Partial add in progress" },
	{ 0x01, "Last record data being transferred" },
	{ 0, NULL }
};

static const value_string vals_47_action[] = {
	{ 0x00, "Get Erasure Status" },
	{ 0xaa, "Initiate Erase" },
	{ 0, NULL }
};

static const value_string vals_47_status[] = {
	{ 0x00, "Erasure in progress" },
	{ 0x01, "Erase completed" },
	{ 0, NULL }
};

static const value_string log_type_vals[] = {
	{ 0x00, "MCA Log" },
	{ 0x01, "OEM 1" },
	{ 0x02, "OEM 2" },
	{ 0, NULL }
};

/* Get FRU Inventory Area Info
 */
static void
rq10(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_10_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void
rs10(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *flags[] = { &hf_ipmi_stor_10_access, NULL };

	proto_tree_add_item(tree, hf_ipmi_stor_10_size, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL, ett_ipmi_stor_10_flags, flags, TRUE, 0);
}

/* Read FRU Data
 */
static void
rq11(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_11_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_11_offset, tvb, 1, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_11_count, tvb, 3, 1, ENC_LITTLE_ENDIAN);
}

static void
rs11(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_11_ret_count, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_11_data, tvb, 1, tvb_length(tvb) - 1, ENC_NA);
}

static const value_string cc11[] = {
	{ 0x81, "FRU Device Busy" },
	{ 0, NULL }
};

/* Write FRU Data
 */
static void
rq12(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_12_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_12_offset, tvb, 1, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_12_data, tvb, 1, tvb_length(tvb) - 1, ENC_NA);
}

static void
rs12(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_12_ret_count, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static const value_string cc12[] = {
	{ 0x80, "Write-protected offset" },
	{ 0x81, "FRU Device Busy" },
	{ 0, NULL }
};

/* Get SDR Repository Info
 */
static void
rs20(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *ops[] = { &hf_ipmi_stor_20_op_overflow, &hf_ipmi_stor_20_op_update,
		&hf_ipmi_stor_20_op_delete, &hf_ipmi_stor_20_op_partial_add, &hf_ipmi_stor_20_op_reserve,
		&hf_ipmi_stor_20_op_allocinfo, NULL };

	proto_tree_add_item(tree, hf_ipmi_stor_20_sdr_version, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_20_rec_count, tvb, 1, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_20_free_space, tvb, 3, 2, ENC_LITTLE_ENDIAN);
	ipmi_add_timestamp(tree, hf_ipmi_stor_20_ts_add, tvb, 5);
	ipmi_add_timestamp(tree, hf_ipmi_stor_20_ts_erase, tvb, 9);
	proto_tree_add_bitmask_text(tree, tvb, 13, 1, "Operation Support: ", NULL,
			ett_ipmi_stor_20_ops, ops, TRUE, 0);
}

/* Get SDR Repository Allocation Info
 */
static void
rs21(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_21_units, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_21_size, tvb, 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_21_free, tvb, 4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_21_largest, tvb, 6, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_21_maxrec, tvb, 8, 1, ENC_LITTLE_ENDIAN);
}

/* Reserve SDR Repository
 */
static void
rs22(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_22_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

/* Get SDR
 */
static void
rq23(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 v = tvb_get_guint8(tvb, 5);

	proto_tree_add_item(tree, hf_ipmi_stor_23_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_23_rec_id, tvb, 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_23_offset, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint_format_value(tree, hf_ipmi_stor_23_count, tvb, 5, 1,
			v, "%d%s", v, v == 0xff ? " (entire record)" : "");
}

static void
rs23(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_23_next, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_23_data, tvb, 2, tvb_length(tvb) - 2, ENC_NA);
}

/* Add SDR
 */
static void
rq24(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_24_data, tvb, 0, tvb_length(tvb), ENC_NA);
}

static void
rs24(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_24_added_rec_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

/* Partial Add SDR
 */
static void
rq25(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte6[] = { &hf_ipmi_stor_25_inprogress, NULL };

	proto_tree_add_item(tree, hf_ipmi_stor_25_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_25_rec_id, tvb, 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_25_offset, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 5, 1, NULL, NULL,
			ett_ipmi_stor_25_byte6, byte6, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_stor_25_data, tvb, 6, tvb_length(tvb) - 6, ENC_NA);
}

static void
rs25(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_25_added_rec_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static const value_string cc25[] = {
	{ 0x80, "Record rejected due to length mismatch" },
	{ 0, NULL }
};

/* Delete SDR
 */
static void
rq26(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_25_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_25_rec_id, tvb, 2, 2, ENC_LITTLE_ENDIAN);
}

static void
rs26(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_26_del_rec_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

/* Clear SDR Repository
 */
static void
rq27(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_27_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_27_clr, tvb, 2, 3, TRUE);
	proto_tree_add_item(tree, hf_ipmi_stor_27_action, tvb, 5, 1, ENC_LITTLE_ENDIAN);
}

static void
rs27(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *status[] = { &hf_ipmi_stor_27_status, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_stor_27_status, status, TRUE, 0);
}

/* Get SDR Repository Time
 */
static void
rs28(tvbuff_t *tvb, proto_tree *tree)
{
	ipmi_add_timestamp(tree, hf_ipmi_stor_28_time, tvb, 0);
}

/* Set SDR Repository Time
 */
static void
rq29(tvbuff_t *tvb, proto_tree *tree)
{
	ipmi_add_timestamp(tree, hf_ipmi_stor_29_time, tvb, 0);
}

/* Run Initialization Agent
 */
static void
rq2c(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_stor_2c_init_agent, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_stor_2c_rq_byte1, byte1, TRUE, 0);
}

static void
rs2c(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_stor_2c_init_state, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_stor_2c_rs_byte1, byte1, TRUE, 0);
}

/* Get SEL Info
 */
static void
rs40(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *ops[] = { &hf_ipmi_stor_40_op_overflow, &hf_ipmi_stor_40_op_delete,
		&hf_ipmi_stor_40_op_partial_add, &hf_ipmi_stor_40_op_reserve, &hf_ipmi_stor_40_op_allocinfo, NULL };

	proto_tree_add_item(tree, hf_ipmi_stor_40_sel_version, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_40_entries, tvb, 1, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_40_free_space, tvb, 3, 2, ENC_LITTLE_ENDIAN);
	ipmi_add_timestamp(tree, hf_ipmi_stor_40_ts_add, tvb, 5);
	ipmi_add_timestamp(tree, hf_ipmi_stor_40_ts_erase, tvb, 9);
	proto_tree_add_bitmask_text(tree, tvb, 13, 1, "Operation Support: ", NULL,
			ett_ipmi_stor_40_ops, ops, TRUE, 0);
}

static const value_string cc40[] = {
	{ 0x81, "Cannot execute command, SEL erase in progress" },
	{ 0, NULL }
};

/* Get SEL Allocation Info
 */
static void
rs41(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_41_units, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_41_size, tvb, 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_41_free, tvb, 4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_41_largest, tvb, 6, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_41_maxrec, tvb, 8, 1, ENC_LITTLE_ENDIAN);
}

/* Reserve SEL
 */
static void
rs42(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_42_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static const value_string cc42[] = {
	{ 0x81, "Cannot execute command, SEL erase in progress" },
	{ 0, NULL }
};

/* Get SEL Entry
 */
static void
rq43(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 v = tvb_get_guint8(tvb, 5);

	proto_tree_add_item(tree, hf_ipmi_stor_43_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_43_rec_id, tvb, 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_43_offset, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint_format_value(tree, hf_ipmi_stor_43_count, tvb, 5, 1,
			v, "%d%s", v, v == 0xff ? " (entire record)" : "");
}

static void
rs43(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_43_next, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_43_data, tvb, 2, tvb_length(tvb) - 2, ENC_NA);
}

static const value_string cc43[] = {
	{ 0x81, "Cannot execute command, SEL erase in progress" },
	{ 0, NULL }
};

/* Add SEL Entry
 */

static void
rq44(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_44_data, tvb, 0, tvb_length(tvb), ENC_NA);
}

static void
rs44(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_44_added_rec_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static const value_string cc44[] = {
	{ 0x80, "Operation not supported for this Record Type" },
	{ 0x81, "Cannot execute command, SEL erase in progress" },
	{ 0, NULL }
};

/* Partial Add SEL Entry
 */
static void
rq45(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte6[] = { &hf_ipmi_stor_45_inprogress, NULL };

	proto_tree_add_item(tree, hf_ipmi_stor_45_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_45_rec_id, tvb, 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_45_offset, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask_text(tree, tvb, 5, 1, NULL, NULL,
			ett_ipmi_stor_45_byte6, byte6, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_stor_45_data, tvb, 6, tvb_length(tvb) - 6, ENC_NA);
}

static void
rs45(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_45_added_rec_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static const value_string cc45[] = {
	{ 0x80, "Record rejected due to length mismatch" },
	{ 0x81, "Cannot execute command, SEL erase in progress" },
	{ 0, NULL }
};

/* Delete SEL Entry
 */
static void
rq46(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_45_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_45_rec_id, tvb, 2, 2, ENC_LITTLE_ENDIAN);
}

static void
rs46(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_46_del_rec_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

static const value_string cc46[] = {
	{ 0x80, "Operation not supported for this Record Type" },
	{ 0x81, "Cannot execute command, SEL erase in progress" },
	{ 0, NULL }
};

/* Clear SEL
 */
static void
rq47(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_stor_47_rsrv_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ipmi_stor_47_clr, tvb, 2, 3, TRUE);
	proto_tree_add_item(tree, hf_ipmi_stor_47_action, tvb, 5, 1, ENC_LITTLE_ENDIAN);
}

static void
rs47(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *status[] = { &hf_ipmi_stor_47_status, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_stor_47_status, status, TRUE, 0);
}

/* Get SEL Time
 */
static void
rs48(tvbuff_t *tvb, proto_tree *tree)
{
	ipmi_add_timestamp(tree, hf_ipmi_stor_48_time, tvb, 0);
}

/* Set SEL Time
 */
static void
rq49(tvbuff_t *tvb, proto_tree *tree)
{
	ipmi_add_timestamp(tree, hf_ipmi_stor_49_time, tvb, 0);
}

/* Get Auxiliary Log Status
 */
static void
rq5a(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_stor_5a_log_type, NULL };

	if (!tree) {
		ipmi_setsaveddata(0, tvb_get_guint8(tvb, 0) & 0x0f);
		return;
	}

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_stor_5a_byte1, byte1, TRUE, 0);
}

static void
rs5a(tvbuff_t *tvb, proto_tree *tree)
{
	guint32 v;

	if (!ipmi_getsaveddata(0, &v) || v > 2) {
		proto_tree_add_item(tree, hf_ipmi_stor_5a_unknown, tvb, 0, tvb_length(tvb), ENC_NA);
		return;
	}

	ipmi_add_timestamp(tree, hf_ipmi_stor_5a_ts_add, tvb, 0);
	if (v  == 0) {
		proto_tree_add_item(tree, hf_ipmi_stor_5a_num_entries, tvb, 4, 4, ENC_LITTLE_ENDIAN);
	} else if (v == 1 || v == 2) {
		proto_tree_add_item(tree, hf_ipmi_stor_5a_iana, tvb, 4, 3, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_ipmi_stor_5a_bytes, tvb, 7, 7, ENC_NA);
	}
}

/* Set Auxiliary Log Status
 */
static void
rq5b(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_stor_5b_log_type, NULL };
	guint8 v = tvb_get_guint8(tvb, 0);

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_stor_5b_byte1, byte1, TRUE, 0);

	if (v > 2) {
		proto_tree_add_item(tree, hf_ipmi_stor_5b_unknown, tvb, 1, tvb_length(tvb) - 1, ENC_NA);
		return;
	}

	ipmi_add_timestamp(tree, hf_ipmi_stor_5b_ts_add, tvb, 1);
	if (v  == 0) {
		proto_tree_add_item(tree, hf_ipmi_stor_5b_num_entries, tvb, 5, 4, ENC_LITTLE_ENDIAN);
	} else if (v == 1 || v == 2) {
		proto_tree_add_item(tree, hf_ipmi_stor_5b_iana, tvb, 5, 3, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_ipmi_stor_5b_bytes, tvb, 8, 8, ENC_NA);
	}
}

static ipmi_cmd_t cmd_storage[] = {
  /* FRU Device Commands */
  { 0x10, rq10, rs10, NULL, NULL, "Get FRU Inventory Area Info", 0 },
  { 0x11, rq11, rs11, cc11, NULL, "Read FRU Data", 0 },
  { 0x12, rq12, rs12, cc12, NULL, "Write FRU Data", 0 },

  /* SDR Device Commands */
  { 0x20, NULL, rs20, NULL, NULL, "Get SDR Repository Info", 0 },
  { 0x21, NULL, rs21, NULL, NULL, "Get SDR Repository Allocation Info", 0 },
  { 0x22, NULL, rs22, NULL, NULL, "Reserve SDR Repository", 0 },
  { 0x23, rq23, rs23, NULL, NULL, "Get SDR", 0 },
  { 0x24, rq24, rs24, NULL, NULL, "Add SDR", 0 },
  { 0x25, rq25, rs25, cc25, NULL, "Partial Add SDR", 0 },
  { 0x26, rq26, rs26, NULL, NULL, "Delete SDR", 0 },
  { 0x27, rq27, rs27, NULL, NULL, "Clear SDR Repository", 0 },
  { 0x28, NULL, rs28, NULL, NULL, "Get SDR Repository Time", 0 },
  { 0x29, rq29, NULL, NULL, NULL, "Set SDR Repository Time", 0 },
  { 0x2a, NULL, NULL, NULL, NULL, "Enter SDR Repository Update Mode", 0 },
  { 0x2b, NULL, NULL, NULL, NULL, "Exit SDR Repository Update Mode", 0 },
  { 0x2c, rq2c, rs2c, NULL, NULL, "Run Initialization Agent", 0 },

  /* SEL Device Commands */
  { 0x40, NULL, rs40, cc40, NULL, "Get SEL Info", 0 },
  { 0x41, NULL, rs41, NULL, NULL, "Get SEL Allocation Info", 0 },
  { 0x42, NULL, rs42, cc42, NULL, "Reserve SEL", 0 },
  { 0x43, rq43, rs43, cc43, NULL, "Get SEL Entry", 0 },
  { 0x44, rq44, rs44, cc44, NULL, "Add SEL Entry", 0 },
  { 0x45, rq45, rs45, cc45, NULL, "Partial Add SEL Entry", 0 },
  { 0x46, rq46, rs46, cc46, NULL, "Delete SEL Entry", 0 },
  { 0x47, rq47, rs47, NULL, NULL, "Clear SEL", 0 },
  { 0x48, NULL, rs48, NULL, NULL, "Get SEL Time", 0 },
  { 0x49, rq49, NULL, NULL, NULL, "Set SEL Time", 0 },
  { 0x5a, rq5a, rs5a, NULL, NULL, "Get Auxiliary Log Status", CMD_CALLRQ },
  { 0x5b, rq5b, NULL, NULL, NULL, "Set Auxiliary Log Status", 0 },
  { 0x5c, IPMI_TBD,   NULL, NULL, "Get SEL Time UTC Offset", 0 },
  { 0x5d, IPMI_TBD,   NULL, NULL, "Set SEL Time UTC Offset", 0 },
};

void
ipmi_register_storage(gint proto_ipmi)
{
	static hf_register_info hf[] = {
		{ &hf_ipmi_stor_10_fruid,
			{ "FRU ID",
				"ipmi.st10.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_10_size,
			{ "FRU Inventory area size",
				"ipmi.st10.size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_10_access,
			{ "Device is accessed",
				"ipmi.st10.access", FT_BOOLEAN, 8, TFS(&tfs_10_access), 0x01, NULL, HFILL }},

		{ &hf_ipmi_stor_11_fruid,
			{ "FRU ID",
				"ipmi.st11.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_11_offset,
			{ "Offset to read",
				"ipmi.st11.offset", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_11_count,
			{ "Count to read",
				"ipmi.st11.count", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_11_ret_count,
			{ "Returned count",
				"ipmi.st11.ret_count", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_11_data,
			{ "Requested data",
				"ipmi.st11.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_12_fruid,
			{ "FRU ID",
				"ipmi.st12.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_12_offset,
			{ "Offset to read",
				"ipmi.st12.offset", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_12_data,
			{ "Requested data",
				"ipmi.st12.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_12_ret_count,
			{ "Returned count",
				"ipmi.st12.ret_count", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_20_sdr_version,
			{ "SDR Version",
				"ipmi.st20.sdr_version", FT_UINT8, BASE_CUSTOM, ipmi_fmt_version, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_20_rec_count,
			{ "Record Count",
				"ipmi.st20.rec_count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_20_free_space,
			{ "Free Space",
				"ipmi.st20.free_space", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_20_ts_add,
			{ "Most recent addition timestamp",
				"ipmi.st20.ts_add", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_20_ts_erase,
			{ "Most recent erase timestamp",
				"ipmi.st20.ts_erase", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_20_op_overflow,
			{ "Overflow",
				"ipmi.st20.op_overflow", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_stor_20_op_update,
			{ "SDR Repository Update",
				"ipmi.st20.op_update", FT_UINT8, BASE_HEX, vals_20_update, 0x60, NULL, HFILL }},
		{ &hf_ipmi_stor_20_op_delete,
			{ "Delete SDR",
				"ipmi.st20.op_delete", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_stor_20_op_partial_add,
			{ "Partial Add SDR",
				"ipmi.st20.op_partial_add", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_stor_20_op_reserve,
			{ "Reserve SDR Repository",
				"ipmi.st20.op_reserve", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_stor_20_op_allocinfo,
			{ "Get SDR Repository Allocation Info",
				"ipmi.st20.op_allocinfo", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

		{ &hf_ipmi_stor_21_units,
			{ "Number of allocation units",
				"ipmi.st21.units", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_21_size,
			{ "Allocation unit size",
				"ipmi.st21.size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_21_free,
			{ "Number of free units",
				"ipmi.st21.free", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_21_largest,
			{ "Largest free block (in units)",
				"ipmi.st21.largest", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_21_maxrec,
			{ "Maximum record size (in units)",
				"ipmi.st21.maxrec", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_22_rsrv_id,
			{ "Reservation ID",
				"ipmi.st22.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_23_rsrv_id,
			{ "Reservation ID",
				"ipmi.st23.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_23_rec_id,
			{ "Record ID",
				"ipmi.st23.rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_23_offset,
			{ "Offset into record",
				"ipmi.st23.offset", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_23_count,
			{ "Bytes to read",
				"ipmi.st23.count", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_23_next,
			{ "Next Record ID",
				"ipmi.st23.next", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_23_data,
			{ "Record Data",
				"ipmi.st23.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_24_data,
			{ "SDR Data",
				"ipmi.st24.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_24_added_rec_id,
			{ "Record ID for added record",
				"ipmi.st23.added_rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_25_rsrv_id,
			{ "Reservation ID",
				"ipmi.st25.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_25_rec_id,
			{ "Record ID",
				"ipmi.st25.rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_25_offset,
			{ "Offset into record",
				"ipmi.st25.offset", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_25_inprogress,
			{ "In progress",
				"ipmi.st25.inprogress", FT_UINT8, BASE_HEX, vals_25_inprogress, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_stor_25_data,
			{ "SDR Data",
				"ipmi.st25.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_25_added_rec_id,
			{ "Record ID for added record",
				"ipmi.st25.added_rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_26_rsrv_id,
			{ "Reservation ID",
				"ipmi.st26.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_26_rec_id,
			{ "Record ID",
				"ipmi.st26.rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_26_del_rec_id,
			{ "Deleted Record ID",
				"ipmi.st26.del_rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_27_rsrv_id,
			{ "Reservation ID",
				"ipmi.st27.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_27_clr,
			{ "Confirmation (should be CLR)",
				"ipmi.st27.clr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_27_action,
			{ "Action",
				"ipmi.st27.action", FT_UINT8, BASE_HEX, vals_27_action, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_27_status,
			{ "Erasure Status",
				"ipmi.st27.status", FT_UINT8, BASE_HEX, vals_27_status, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_stor_28_time,
			{ "Time",
				"ipmi.st28.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_29_time,
			{ "Time",
				"ipmi.st29.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_2c_init_agent,
			{ "Initialization agent",
				"ipmi.st2c.init_agent", FT_BOOLEAN, 8, TFS(&tfs_2c_init_agent), 0x01, NULL, HFILL }},
		{ &hf_ipmi_stor_2c_init_state,
			{ "Initialization",
				"ipmi.st2c.init_state", FT_BOOLEAN, 8, TFS(&tfs_2c_init_state), 0x01, NULL, HFILL }},

		{ &hf_ipmi_stor_40_sel_version,
			{ "SEL Version",
				"ipmi.st40.sel_version", FT_UINT8, BASE_CUSTOM, ipmi_fmt_version, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_40_entries,
			{ "Entries",
				"ipmi.st40.rec_count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_40_free_space,
			{ "Free Space",
				"ipmi.st40.free_space", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_40_ts_add,
			{ "Most recent addition timestamp",
				"ipmi.st40.ts_add", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_40_ts_erase,
			{ "Most recent erase timestamp",
				"ipmi.st40.ts_erase", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_40_op_overflow,
			{ "Overflow",
				"ipmi.st40.op_overflow", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_stor_40_op_delete,
			{ "Delete SEL",
				"ipmi.st40.op_delete", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_stor_40_op_partial_add,
			{ "Partial Add SEL Entry",
				"ipmi.st40.op_partial_add", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_stor_40_op_reserve,
			{ "Reserve SEL",
				"ipmi.st40.op_reserve", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_stor_40_op_allocinfo,
			{ "Get SEL Allocation Info",
				"ipmi.st40.op_allocinfo", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

		{ &hf_ipmi_stor_41_units,
			{ "Number of allocation units",
				"ipmi.st41.units", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_41_size,
			{ "Allocation unit size",
				"ipmi.st41.size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_41_free,
			{ "Number of free units",
				"ipmi.st41.free", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_41_largest,
			{ "Largest free block (in units)",
				"ipmi.st41.largest", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_41_maxrec,
			{ "Maximum record size (in units)",
				"ipmi.st41.maxrec", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_42_rsrv_id,
			{ "Reservation ID",
				"ipmi.st42.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_43_rsrv_id,
			{ "Reservation ID",
				"ipmi.st43.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_43_rec_id,
			{ "Record ID",
				"ipmi.st43.rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_43_offset,
			{ "Offset into record",
				"ipmi.st43.offset", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_43_count,
			{ "Bytes to read",
				"ipmi.st43.count", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_43_next,
			{ "Next Record ID",
				"ipmi.st43.next", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_43_data,
			{ "Record Data",
				"ipmi.st43.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_44_data,
			{ "SDR Data",
				"ipmi.st44.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_44_added_rec_id,
			{ "Record ID for added record",
				"ipmi.st43.added_rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_45_rsrv_id,
			{ "Reservation ID",
				"ipmi.st45.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_45_rec_id,
			{ "Record ID",
				"ipmi.st45.rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_45_offset,
			{ "Offset into record",
				"ipmi.st45.offset", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_45_inprogress,
			{ "In progress",
				"ipmi.st45.inprogress", FT_UINT8, BASE_HEX, vals_45_inprogress, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_stor_45_data,
			{ "Record Data",
				"ipmi.st45.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_45_added_rec_id,
			{ "Record ID for added record",
				"ipmi.st45.added_rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_46_rsrv_id,
			{ "Reservation ID",
				"ipmi.st46.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_46_rec_id,
			{ "Record ID",
				"ipmi.st46.rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_46_del_rec_id,
			{ "Deleted Record ID",
				"ipmi.st46.del_rec_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_47_rsrv_id,
			{ "Reservation ID",
				"ipmi.st47.rsrv_id", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_47_clr,
			{ "Confirmation (should be CLR)",
				"ipmi.st47.clr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_47_action,
			{ "Action",
				"ipmi.st47.action", FT_UINT8, BASE_HEX, vals_47_action, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_47_status,
			{ "Erasure Status",
				"ipmi.st47.status", FT_UINT8, BASE_HEX, vals_47_status, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_stor_48_time,
			{ "Time",
				"ipmi.st48.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_49_time,
			{ "Time",
				"ipmi.st49.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_5a_log_type,
			{ "Log type",
				"ipmi.st5a.log_type", FT_UINT8, BASE_HEX, log_type_vals, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_stor_5a_ts_add,
			{ "Last addition timestamp",
				"ipmi.st5a.ts_add", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_5a_num_entries,
			{ "Number of entries in MCA Log",
				"ipmi.st5a.num_entries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_5a_iana,
			{ "OEM IANA",
				"ipmi.st5a.iana", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_5a_bytes,
			{ "Log status bytes",
				"ipmi.st5a.bytes", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_5a_unknown,
			{ "Unknown log format (cannot parse data)",
				"ipmi.st5a.unknown", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_stor_5b_log_type,
			{ "Log type",
				"ipmi.st5b.log_type", FT_UINT8, BASE_HEX, log_type_vals, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_stor_5b_ts_add,
			{ "Last addition timestamp",
				"ipmi.st5b.ts_add", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_5b_num_entries,
			{ "Number of entries in MCA Log",
				"ipmi.st5b.num_entries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_5b_iana,
			{ "OEM IANA",
				"ipmi.st5b.iana", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_5b_bytes,
			{ "Log status bytes",
				"ipmi.st5b.bytes", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_stor_5b_unknown,
			{ "Unknown log format (cannot parse data)",
				"ipmi.st5b.unknown", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

	};
	static gint *ett[] = {
		&ett_ipmi_stor_10_flags,
		&ett_ipmi_stor_20_ops,
		&ett_ipmi_stor_25_byte6,
		&ett_ipmi_stor_27_status,
		&ett_ipmi_stor_2c_rq_byte1,
		&ett_ipmi_stor_2c_rs_byte1,
		&ett_ipmi_stor_40_ops,
		&ett_ipmi_stor_45_byte6,
		&ett_ipmi_stor_47_status,
		&ett_ipmi_stor_5a_byte1,
		&ett_ipmi_stor_5b_byte1,
	};

	proto_register_field_array(proto_ipmi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	ipmi_register_netfn_cmdtab(IPMI_STORAGE_REQ, IPMI_OEM_NONE, NULL, 0, NULL,
			cmd_storage, array_length(cmd_storage));
}
