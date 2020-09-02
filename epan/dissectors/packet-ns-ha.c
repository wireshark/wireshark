/* packet-ns-ha.c
 * Routines for Netscaler HA heartbeat protocol dissection
 * Copyright 2008, Sandhya Gopinath <Sandhya.Gopinath@citrix.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_ns_ha(void);
void proto_reg_handoff_ns_ha(void);

static int proto_ns_ha = -1;
static gint ett_nsha = -1;
static gint ett_nsha_flags = -1;

static int hf_nsha_signature = -1;
static int hf_nsha_version = -1;
static int hf_nsha_app = -1;
static int hf_nsha_type = -1;
static int hf_nsha_state = -1;
static int hf_nsha_startime = -1;
static int hf_nsha_masterstate = -1;
static int hf_nsha_release = -1;
static int hf_nsha_inc = -1;
static int hf_nsha_syncstate = -1;
static int hf_nsha_drinc = -1;
static int hf_nsha_flags = -1;
static int hf_nsha_flags_vm = -1;
static int hf_nsha_flags_sp = -1;
static int hf_nsha_flags_propdis = -1;
static int hf_nsha_flags_inc = -1;
static int hf_nsha_flags_sslfail = -1;
static int hf_nsha_flags_nossl = -1;

static const value_string ns_ha_app_vals[] = {
	{ 0x00, "BASE" },
	{ 0x01, "REMOTE IOCTL" },

	{ 0, NULL }
};

static const value_string ns_ha_type_vals[] = {
	{ 0x00, "MSG" },
	{ 0x01, "REQ_INIT" },

	{ 0, NULL }
};

static const value_string ns_ha_state_vals[] = {
	{ 0x00, "UNKNOWN" },
	{ 0x01, "INIT" },
	{ 0x02, "DOWN" },
	{ 0x03, "UP" },
	{ 0x04, "PARTIAL_FAIL" },
	{ 0x05, "MONITOR_FAIL" },
	{ 0x06, "MONITOR_OK" },
	{ 0x07, "COMPLETE_FAIL" },
	{ 0x08, "DUMB" },
	{ 0x09, "DISABLED" },
	{ 0x0A, "PARTIAL_FAIL_SSL" },
	{ 0x0B, "ROUTEMONITOR_FAIL" },

	{ 0, NULL }
};

static const value_string ns_ha_masterstate_vals[] = {
	{ 0x00, "INACTIVE" },
	{ 0x01, "CLAIMING" },
	{ 0x02, "ACTIVE" },
	{ 0x03, "ALWAYS_SECONDARY" },
	{ 0x04, "FORCE_CHANGE" },

	{ 0, NULL }
};

static const value_string ns_ha_syncstate_vals[] = {
	{ 0x00, "ENABLED" },
	{ 0x04, "FAILED" },
	{ 0x10, "SUCCESS" },
	{ 0x40, "DISABLED" },
	{ 0x20, "IN PROGRESS" },

	{ 0, NULL }
};

#define NSAHA_SSLCARD_DOWN		0x100
#define NSAHA_NO_DEVICES		0x200
#define NSAHA_INC_STATE			0x1000
#define NSAHA_PROP_DISABLED		0x2000
#define NSAHA_STAY_PRIMARY		0x4000
#define NSAHA_VERSION_MISMATCH	0x8000

static int * const ha_flags[] = {
	&hf_nsha_flags_vm,
	&hf_nsha_flags_sp,
	&hf_nsha_flags_inc,
	&hf_nsha_flags_propdis,
	&hf_nsha_flags_sslfail,
	&hf_nsha_flags_nossl,
	NULL
};

static int
dissect_ns_ha(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint32 offset = 0, master_state=0;
	proto_item *ti;
	proto_tree *ns_ha_tree;
	guint32 version, state;

	/* It is Netscaler HA heartbeat packet. */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NS-HA");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_protocol_format(tree, proto_ns_ha, tvb, 0, -1, "NS HA Protocol");
	ns_ha_tree = proto_item_add_subtree(ti, ett_nsha);

	proto_tree_add_item(ns_ha_tree, hf_nsha_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item_ret_uint(ns_ha_tree, hf_nsha_version, tvb, offset, 1, ENC_LITTLE_ENDIAN, &version);
	offset += 1;
	proto_tree_add_item(ns_ha_tree, hf_nsha_app, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(ns_ha_tree, hf_nsha_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item_ret_uint(ns_ha_tree, hf_nsha_state, tvb, offset, 1, ENC_LITTLE_ENDIAN, &state);
	offset += 1;

	switch(version) {
		/* all releases from 7.0 */
		case 10:
			proto_tree_add_item(ns_ha_tree, hf_nsha_startime, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 8; /* startime and rx_sn */
			proto_tree_add_item_ret_uint(ns_ha_tree, hf_nsha_masterstate, tvb, offset, 4, ENC_LITTLE_ENDIAN, &master_state);
			offset += 4;
			proto_tree_add_item(ns_ha_tree, hf_nsha_release, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_bitmask(ns_ha_tree, tvb, offset, hf_nsha_flags, ett_nsha_flags, ha_flags, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(ns_ha_tree, hf_nsha_inc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(ns_ha_tree, hf_nsha_syncstate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			offset += 96; /* interface information */
			proto_tree_add_item(ns_ha_tree, hf_nsha_drinc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			break;

		case 8:	/* 6.0 */
		case 9:	/* 6.1 */
			proto_tree_add_item(ns_ha_tree, hf_nsha_startime, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 8; /* startime and rx_sn */
			proto_tree_add_item_ret_uint(ns_ha_tree, hf_nsha_masterstate, tvb, offset, 4, ENC_LITTLE_ENDIAN, &master_state);
			offset += 4;
			proto_tree_add_item(ns_ha_tree, hf_nsha_inc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(ns_ha_tree, hf_nsha_syncstate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_bitmask(ns_ha_tree, tvb, offset, hf_nsha_flags, ett_nsha_flags, ha_flags, ENC_LITTLE_ENDIAN);
			if (version == 9) {
				offset += 4;
				offset += 96; /* interface information */
				proto_tree_add_item(ns_ha_tree, hf_nsha_drinc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			}
			break;

		/* 5.2 */
		case 3:
		case 4:
			offset += 8; /* sn and rx_sn */
			proto_tree_add_item_ret_uint(ns_ha_tree, hf_nsha_masterstate, tvb, offset, 4, ENC_LITTLE_ENDIAN, &master_state);
			offset += 4;
			proto_tree_add_item(ns_ha_tree, hf_nsha_inc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			break;

		default:
			break;

	}

	col_add_fstr(pinfo->cinfo, COL_INFO, "Node state: %s Master State: %s",
		val_to_str(state, ns_ha_state_vals, "Unknown (%u)"),
		val_to_str(master_state, ns_ha_masterstate_vals, "Unknown(%u)"));

	return tvb_captured_length(tvb);
}

void
proto_register_ns_ha(void)
{
	static hf_register_info hf_nsha[] = {
		{ &hf_nsha_signature,
		  { "Signature", "nstrace.ha.signature", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsha_version,
		  { "Version", "nstrace.ha.version", FT_UINT8, BASE_DEC,  NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsha_app,
		  { "App", "nstrace.ha.app", FT_UINT8, BASE_DEC, VALS(ns_ha_app_vals), 0x0,
			NULL, HFILL }},

		{ &hf_nsha_type,
		  { "Type", "nstrace.ha.type", FT_UINT8, BASE_DEC, VALS(ns_ha_type_vals), 0x0,
			NULL, HFILL }},

		{ &hf_nsha_state,
		  { "State", "nstrace.ha.state", FT_UINT8, BASE_DEC, VALS(ns_ha_state_vals), 0x0,
			NULL, HFILL }},

		{ &hf_nsha_startime,
		  { "Start Time", "nstrace.ha.startime", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsha_masterstate,
		  { "Master State", "nstrace.ha.masterstate", FT_UINT32, BASE_DEC, VALS(ns_ha_masterstate_vals), 0x0,
			NULL, HFILL }},

		{ &hf_nsha_release,
		  { "Release", "nstrace.ha.release", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsha_inc,
		  { "Incarnation Number", "nstrace.ha.inc", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsha_syncstate,
		  { "Sync State", "nstrace.ha.syncstate", FT_UINT32, BASE_DEC, VALS(ns_ha_syncstate_vals), 0x0,
			NULL, HFILL }},

		{ &hf_nsha_drinc,
		  { "DR Incarnation Number", "nstrace.ha.drinc", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsha_flags,
		  { "Flags", "nstrace.ha.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_nsha_flags_vm,
		  { "Version Mismatch", "nstrace.ha.flags.versionmismatch", FT_BOOLEAN, 32, TFS(&tfs_yes_no), NSAHA_VERSION_MISMATCH,
			NULL, HFILL }},

		{ &hf_nsha_flags_sp,
		  { "Stay Primary", "nstrace.ha.flags.stayprimary", FT_BOOLEAN, 32, TFS(&tfs_yes_no), NSAHA_STAY_PRIMARY,
			NULL, HFILL }},

		{ &hf_nsha_flags_propdis,
		  { "Propagation Disabled", "nstrace.ha.flags.propdis", FT_BOOLEAN, 32, TFS(&tfs_yes_no), NSAHA_PROP_DISABLED,
			NULL, HFILL }},

		{ &hf_nsha_flags_inc,
		  { "INC Enabled", "nstrace.ha.flags.inc", FT_BOOLEAN, 32, TFS(&tfs_yes_no), NSAHA_INC_STATE,
			NULL, HFILL }},

		{ &hf_nsha_flags_sslfail,
		  { "SSL Card Failure", "nstrace.ha.flags.sslfail", FT_BOOLEAN, 32, TFS(&tfs_yes_no), NSAHA_SSLCARD_DOWN,
			NULL, HFILL }},

		{ &hf_nsha_flags_nossl,
		  { "SSL Card Absent", "nstrace.ha.flags.nossl", FT_BOOLEAN, 32, TFS(&tfs_yes_no), NSAHA_NO_DEVICES,
			NULL, HFILL }},

	};

	static gint *ett[] = {
		&ett_nsha,
		&ett_nsha_flags,
	};

	proto_ns_ha = proto_register_protocol("NetScaler HA Protocol", "NetScaler HA", "nstrace.ha");
	proto_register_field_array(proto_ns_ha, hf_nsha, array_length(hf_nsha));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_ns_ha(void)
{
	dissector_handle_t nsha_handle;

	nsha_handle = create_dissector_handle(dissect_ns_ha, proto_ns_ha);
	dissector_add_for_decode_as("udp.port", nsha_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
