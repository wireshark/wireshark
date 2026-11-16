/* packet-i2c.c
 * Routines for I2C captures (using libpcap extensions)
 *
 * Pigeon Point Systems <www.pigeonpoint.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>
#include <epan/tfs.h>
#include <epan/proto_data.h>
#include "packet-i2c.h"

void proto_register_i2c(void);
void proto_reg_handoff_i2c(void);

static dissector_handle_t i2c_linux_handle;
static capture_dissector_handle_t i2c_linux_cap_handle;
static dissector_handle_t i2c_kontron_handle;

static int proto_i2c;
static int proto_i2c_event;
static int proto_i2c_data;


static int hf_i2c_bus;
static int hf_i2c_event;
static int hf_i2c_flags;
static int hf_i2c_flags_rd;
static int hf_i2c_addr;

static int ett_i2c;
static int ett_i2c_flags;

static expert_field ei_i2c_record_too_short;

static dissector_table_t subdissector_table;
static heur_dissector_list_t i2c_heur_subdissector_list;

static dissector_handle_t ipmb_handle;

#define I2C_PROTO_DATA_MESSAGE 0

const i2c_message_data *
i2c_message_data_get(packet_info *pinfo)
{
	return (const i2c_message_data *)p_get_proto_data(pinfo->pool, pinfo,
			proto_i2c, I2C_PROTO_DATA_MESSAGE);
}

#define I2C_FLAG_RD			0x00000001

/* I2C events.  */
#define I2C_EVENT_PROM_ON		(1 << 0)	/* Promiscuous mode: on      */
#define I2C_EVENT_PROM_OFF		(1 << 1)	/* Promiscuous mode: off     */
#define I2C_EVENT_ONLINE_ON		(1 << 2)	/* Online state: on          */
#define I2C_EVENT_ONLINE_OFF		(1 << 3)	/* Online state: off         */
#define I2C_EVENT_ATTACHED_ON		(1 << 4)	/* Attached state: on        */
#define I2C_EVENT_ATTACHED_OFF		(1 << 5)	/* Attached state: off       */
#define I2C_EVENT_PROM_OVFL_ON		(1 << 6)	/* Prom. queue overflow: on  */
#define I2C_EVENT_PROM_OVFL_OFF		(1 << 7)	/* Prom. queue overflow: off */
#define I2C_EVENT_OVFL_ON		(1 << 8)	/* Queue overflow: on        */
#define I2C_EVENT_OVFL_OFF		(1 << 9)	/* Queue overflow: off       */

/* I2C errors.  */
#define I2C_EVENT_ERR_DATA_LO		(1 << 16)	/* Unable to drive data LO   */
#define I2C_EVENT_ERR_DATA_HI		(1 << 17)	/* Unable to drive data HI   */
#define I2C_EVENT_ERR_CLOCK_LO		(1 << 18)	/* Unable to drive clock LO  */
#define I2C_EVENT_ERR_CLOCK_HI		(1 << 19)	/* Unable to drive clock HI  */
#define I2C_EVENT_ERR_CLOCK_TO		(1 << 20)	/* Clock low timeout         */
#define I2C_EVENT_ERR_PHYS		(1 << 21)	/* The I2C bus controller
							   has been physically
							   disconnected from the bus */
#define I2C_EVENT_ERR_FAIL		(1 << 22)	/* Undiagnosed failure       */

static void i2c_prompt(packet_info *pinfo _U_, char* result)
{
	snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Interpret I2C messages as");
}

static bool
capture_i2c_linux(const unsigned char *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
	if (pseudo_header->i2c.is_event) {
		capture_dissector_increment_count(cpinfo, proto_i2c_event);
	} else {
		capture_dissector_increment_count(cpinfo, proto_i2c_data);
	}

	return true;
}

static const char *
i2c_linux_get_event_desc(uint32_t event)
{
	const char *desc;

	switch (event & 0x0000ffff) {
		case I2C_EVENT_PROM_ON:
			desc = "Promiscuous mode is enabled";
			break;
		case I2C_EVENT_PROM_OFF:
			desc = "Promiscuous mode is disabled";
			break;
		case I2C_EVENT_ONLINE_ON:
			desc = "The I2C controller is operational";
			break;
		case I2C_EVENT_ONLINE_OFF:
			desc = "The I2C controller is non-operational";
			/* The upper-order error bits belong to the offline event. */
			if (event & I2C_EVENT_ERR_DATA_LO) {
				desc = "The I2C controller is non-operational: "
				       "unable to drive data LO";
			} else if (event & I2C_EVENT_ERR_DATA_HI) {
				desc = "The I2C controller is non-operational: "
				       "unable to drive data HI";
			} else if (event & I2C_EVENT_ERR_CLOCK_LO) {
				desc = "The I2C controller is non-operational: "
				       "unable to drive clock LO";
			} else if (event & I2C_EVENT_ERR_CLOCK_HI) {
				desc = "The I2C controller is non-operational: "
				       "unable to drive clock HI";
			} else if (event & I2C_EVENT_ERR_CLOCK_TO) {
				desc = "The I2C controller is non-operational: "
				       "clock low timeout";
			} else if (event & I2C_EVENT_ERR_PHYS) {
				desc = "The I2C controller is non-operational: "
				       "the I2C bus controller has been "
				       "physically disconnected from the bus";
			} else if (event & I2C_EVENT_ERR_FAIL) {
				desc = "The I2C controller is non-operational: "
				       "undiagnosed failure";
			}
			break;
		case I2C_EVENT_ATTACHED_ON:
			desc = "The I2C controller is attached to an I2C bus";
			break;
		case I2C_EVENT_ATTACHED_OFF:
			desc = "The I2C controller is detached from an I2C bus";
			break;
		case I2C_EVENT_PROM_OVFL_ON:
			desc = "The incoming promiscuous data buffer has been overrun; "
			       "some data is lost";
			break;
		case I2C_EVENT_PROM_OVFL_OFF:
			desc = "The incoming promiscuous data buffer is available";
			break;
		case I2C_EVENT_OVFL_ON:
			desc = "The incoming I2C data buffer has been overrun; "
			       "some data is lost";
			break;
		case I2C_EVENT_OVFL_OFF:
			desc = "The incoming I2C data buffer is available";
			break;
		default:
			desc = "<unknown state event>";
			break;
	}

	return desc;
}

/* Address 00h: the General Call when writing, the START byte when reading. */
static const char *
i2c_addr_zero_suffix(uint8_t addr, bool read)
{
	if (addr != 0)
		return "";
	return read ? " (START byte)" : " (General Call)";
}

static int
dissect_i2c_linux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti, *flags_ti;
	proto_tree *i2c_tree, *flags_tree;
	heur_dtbl_entry_t *hdtbl_entry;
	uint8_t     is_event;
	uint8_t     bus, addr;
	uint32_t    flags;
	bool        addr_reported;
	bool        addr_captured;

	flags = pinfo->pseudo_header->i2c.flags;

	bus = pinfo->pseudo_header->i2c.bus;
	col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "I2C-%d", bus);

	is_event = pinfo->pseudo_header->i2c.is_event;
	addr_reported = is_event || tvb_reported_length(tvb) >= 1;
	addr_captured = is_event || tvb_captured_length(tvb) >= 1;

	if (is_event) {
		addr = 0;
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "I2C Event");
		col_set_str(pinfo->cinfo, COL_DEF_DST, "----");
		col_add_str(pinfo->cinfo, COL_INFO,
				i2c_linux_get_event_desc(flags));
	} else if (!addr_reported) {
		addr = 0;
		col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "I2C %s",
				(flags & I2C_FLAG_RD) ? "Read" : "Write");
		col_set_str(pinfo->cinfo, COL_DEF_DST, "----");
		col_set_str(pinfo->cinfo, COL_INFO,
				"Record too short to contain a hardware address");
	} else if (!addr_captured) {
		addr = 0;
		col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "I2C %s",
				(flags & I2C_FLAG_RD) ? "Read" : "Write");
		col_set_str(pinfo->cinfo, COL_DEF_DST, "----");
		col_add_fstr(pinfo->cinfo, COL_INFO, "I2C %s, %d bytes",
				(flags & I2C_FLAG_RD) ? "Read" : "Write",
				tvb_captured_length(tvb));
	} else {
		/* Report 7-bit hardware address */
		addr = tvb_get_uint8(tvb, 0) >> 1;
		col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "I2C %s",
				(flags & I2C_FLAG_RD) ? "Read" : "Write");
		col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%02x", addr);
		col_add_fstr(pinfo->cinfo, COL_INFO, "I2C %s, %d bytes",
					(flags & I2C_FLAG_RD) ? "Read" : "Write", tvb_captured_length(tvb));
	}

	pinfo->ptype = PT_I2C;

	ti = proto_tree_add_protocol_format(tree, proto_i2c, tvb, 0, -1,
			"Inter-Integrated Circuit (%s)",
			is_event ? "Event" : "Data");

	i2c_tree = proto_item_add_subtree(ti, ett_i2c);
	proto_tree_add_uint_format(i2c_tree, hf_i2c_bus, tvb, 0, 0, bus,
			"Bus: I2C-%d", bus);

	if (is_event) {
		proto_tree_add_uint_format_value(i2c_tree, hf_i2c_event, tvb, 0, 0,
				flags, "%s (0x%08x)",
				i2c_linux_get_event_desc(flags), flags);
	} else {
		if (addr_captured) {
			proto_tree_add_uint_format_value(i2c_tree, hf_i2c_addr, tvb, 0, 1,
					addr, "0x%02x%s", addr,
					i2c_addr_zero_suffix(addr,
							     (flags & I2C_FLAG_RD) != 0));
		}
		flags_ti = proto_tree_add_uint(i2c_tree, hf_i2c_flags, tvb, 0, 0, flags);
		flags_tree = proto_item_add_subtree(flags_ti, ett_i2c_flags);
		proto_tree_add_boolean(flags_tree, hf_i2c_flags_rd, tvb, 0, 0,
				flags & I2C_FLAG_RD);

		if (!addr_reported) {
			proto_tree_add_expert(i2c_tree, pinfo,
					&ei_i2c_record_too_short, tvb, 0, 0);
			return tvb_captured_length(tvb);
		}
		if (!addr_captured) {
			tvb_ensure_bytes_exist(tvb, 0, 1);
			return tvb_captured_length(tvb);
		}

		i2c_message_data *message_data = wmem_new(pinfo->pool, i2c_message_data);
		message_data->bus = bus;
		p_set_proto_data(pinfo->pool, pinfo, proto_i2c,
				I2C_PROTO_DATA_MESSAGE, message_data);

		if (!dissector_try_payload_with_data(subdissector_table, tvb, pinfo, tree, true, NULL) &&
		    !dissector_try_heuristic(i2c_heur_subdissector_list, tvb, pinfo, tree, &hdtbl_entry, NULL))
		{
			call_data_dissector(tvb, pinfo, tree);
		}
	}
	return tvb_captured_length(tvb);
}

/* DLT199 capture header (data length, port) plus the address octet. */
#define I2C_KONTRON_MIN_LEN	3

/* The shortest IPMB frame packet-ipmi.c decodes with a responder address. */
#define I2C_KONTRON_MIN_IPMB_LEN	7

/* IPMB-over-I2C, with Kontron pseudo-header */
static int
dissect_i2c_kontron(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *i2c_tree;
	int         offset = 0;
	unsigned    reported;
	unsigned    captured;
	uint8_t     addr_octet;
	uint8_t     addr;
	bool        read;
	tvbuff_t   *new_tvb;

	col_set_str(pinfo->cinfo, COL_DEF_SRC, "I2C");
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "I2C");

	reported = tvb_reported_length(tvb);
	captured = tvb_captured_length(tvb);

	if (reported < I2C_KONTRON_MIN_LEN) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
				"Bogus length %u, minimum %u", reported,
				(unsigned)I2C_KONTRON_MIN_LEN);
		ti = proto_tree_add_protocol_format(tree, proto_i2c, tvb, 0, -1,
				"Inter-Integrated Circuit");
		i2c_tree = proto_item_add_subtree(ti, ett_i2c);
		proto_tree_add_expert(i2c_tree, pinfo, &ei_i2c_record_too_short,
				tvb, 0, -1);
		return tvb_captured_length(tvb);
	}
	if (captured < I2C_KONTRON_MIN_LEN) {
		ti = proto_tree_add_protocol_format(tree, proto_i2c, tvb, 0, -1,
				"Inter-Integrated Circuit");
		tvb_ensure_bytes_exist(tvb, 0, I2C_KONTRON_MIN_LEN);
		return tvb_captured_length(tvb);
	}

	/* Data length field */
	offset++;

	/* Port number on which the message was received */
	offset++;

	/* DLT199: length, port, then the IPMB frame; its address octet has R/W#. */
	addr_octet = tvb_get_uint8(tvb, offset);
	addr = addr_octet >> 1;
	read = (addr_octet & 0x01) != 0;
	col_append_fstr(pinfo->cinfo, COL_PROTOCOL, " %s",
	    read ? "Read" : "Write");
	col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%02x", addr);
	col_add_fstr(pinfo->cinfo, COL_INFO, "I2C %s, %d bytes",
				read ? "Read" : "Write", tvb_captured_length(tvb));

	pinfo->ptype = PT_I2C;

	ti = proto_tree_add_protocol_format(tree, proto_i2c, tvb, 0, -1,
			"Inter-Integrated Circuit (%s)", read ? "Read" : "Write");
	i2c_tree = proto_item_add_subtree(ti, ett_i2c);

	proto_tree_add_uint_format_value(i2c_tree, hf_i2c_addr, tvb, offset, 1,
			addr, "0x%02x%s", addr,
			i2c_addr_zero_suffix(addr, read));

	if (reported - (unsigned)offset < I2C_KONTRON_MIN_IPMB_LEN) {
		proto_tree_add_expert(i2c_tree, pinfo, &ei_i2c_record_too_short,
				tvb, offset, -1);
		return tvb_captured_length(tvb);
	}
	if (captured - (unsigned)offset < I2C_KONTRON_MIN_IPMB_LEN) {
		tvb_ensure_bytes_exist(tvb, offset, I2C_KONTRON_MIN_IPMB_LEN);
		return tvb_captured_length(tvb);
	}

	new_tvb = tvb_new_subset_remaining(tvb, offset);
	call_dissector(ipmb_handle, new_tvb, pinfo, tree);
	return tvb_captured_length(tvb);
}

void
proto_register_i2c(void)
{
	static hf_register_info hf[] = {
		{ &hf_i2c_bus,   { "Bus ID", "i2c.bus", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_i2c_addr,  { "Target address", "i2c.addr", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_i2c_event, { "Event", "i2c.event", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_i2c_flags, { "Flags", "i2c.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_i2c_flags_rd, { "Read", "i2c.flags.rd", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), I2C_FLAG_RD,
			"The one flag bit LINKTYPE_I2C_LINUX defines for a regular packet:"
			" if set, the packet is a read", HFILL }},
	};
	static int *ett[] = {
		&ett_i2c,
		&ett_i2c_flags
	};
	static ei_register_info ei[] = {
		{ &ei_i2c_record_too_short,
		  { "i2c.record_too_short", PI_MALFORMED, PI_ERROR,
		    "Record is shorter than the fields its link type defines,"
		    " so it cannot be dissected further", EXPFILL }},
	};
	expert_module_t *expert_i2c;
	module_t *m;

	proto_i2c = proto_register_protocol("Inter-Integrated Circuit", "I2C", "i2c");
	proto_register_field_array(proto_i2c, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_i2c = expert_register_protocol(proto_i2c);
	expert_register_field_array(expert_i2c, ei, array_length(ei));

	/* Placeholders for capture statistics */
	proto_i2c_event = proto_register_protocol_in_name_only("I2C Events", "I2C Events", "i2c_event", proto_i2c, FT_PROTOCOL);
	proto_i2c_data = proto_register_protocol_in_name_only("I2C Data", "I2C Data", "i2c_data", proto_i2c, FT_PROTOCOL);

	m = prefs_register_protocol_obsolete(proto_i2c);
	prefs_register_obsolete_preference(m, "type");

	subdissector_table = register_decode_as_next_proto(proto_i2c, "i2c.message", "I2C messages dissector", i2c_prompt);
	i2c_heur_subdissector_list = register_heur_dissector_list_with_description("i2c.message", "I2C message", proto_i2c);

	i2c_linux_handle = register_dissector("i2c_linux", dissect_i2c_linux, proto_i2c);
	i2c_linux_cap_handle = register_capture_dissector("i2c_linux", capture_i2c_linux, proto_i2c);
	i2c_kontron_handle = register_dissector("i2c_kontron", dissect_i2c_kontron, proto_i2c);
}

void
proto_reg_handoff_i2c(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_I2C_LINUX, i2c_linux_handle);
	capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_I2C_LINUX, i2c_linux_cap_handle);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_IPMB_KONTRON, i2c_kontron_handle);

	ipmb_handle = find_dissector("ipmb");
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
