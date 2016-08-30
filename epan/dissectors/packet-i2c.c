/* packet-i2c.c
 * Routines for I2C captures (using libpcap extensions)
 *
 * Pigeon Point Systems <www.pigeonpoint.com>
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

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>
#include <wiretap/wtap.h>

void proto_register_i2c(void);
void proto_reg_handoff_i2c(void);

static int proto_i2c = -1;
static int proto_i2c_event = -1;
static int proto_i2c_data = -1;


static int hf_i2c_bus = -1;
static int hf_i2c_event = -1;
static int hf_i2c_flags = -1;
static int hf_i2c_addr = -1;

static gint ett_i2c = -1;

static dissector_table_t subdissector_table;

/* I2C packet flags. */
#define I2C_FLAG_RD			0x00000001
#define I2C_FLAG_TEN			0x00000010
#define I2C_FLAG_REV_DIR_ADDR		0x00002000
#define I2C_FLAG_NOSTART		0x00004000

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

static void i2c_prompt(packet_info *pinfo _U_, gchar* result)
{
	g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Interpret I2C messages as");
}

static gpointer i2c_value(packet_info *pinfo _U_)
{
	return 0;
}

static gboolean
capture_i2c(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
	if (pseudo_header->i2c.is_event) {
		capture_dissector_increment_count(cpinfo, proto_i2c_event);
	} else {
		capture_dissector_increment_count(cpinfo, proto_i2c_data);
	}

	return TRUE;
}

static const char *
i2c_get_event_desc(guint32 event)
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
			break;
		case I2C_EVENT_ATTACHED_ON:
			desc = "The I2C controller is attached to an I2C bus";
			break;
		case I2C_EVENT_ATTACHED_OFF:
			desc = "The I2C controller is detached from an I2C bus";
			if (event & I2C_EVENT_ERR_DATA_LO) {
				desc = "The I2C controller is detached from an I2C bus: "
				       "unable to drive data LO";
			} else if (event & I2C_EVENT_ERR_DATA_HI) {
				desc = "The I2C controller is detached from an I2C bus: "
				       "unable to drive data HI";
			} else if (event & I2C_EVENT_ERR_CLOCK_LO) {
				desc = "The I2C controller is detached from an I2C bus: "
				       "unable to drive clock LO";
			} else if (event & I2C_EVENT_ERR_CLOCK_HI) {
				desc = "The I2C controller is detached from an I2C bus: "
				       "unable to drive clock HI";
			} else if (event & I2C_EVENT_ERR_CLOCK_TO) {
				desc = "The I2C controller is detached from an I2C bus: "
				       "clock low timeout";
			} else if (event & I2C_EVENT_ERR_PHYS) {
				desc = "The I2C controller is detached from an I2C bus: "
				       "the I2C bus controller has been physically "
				       "disconnected from the bus";
			} else if (event & I2C_EVENT_ERR_FAIL) {
				desc = "The I2C controller is detached from an I2C bus: "
				       "undiagnosed failure";
			}
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

static int
dissect_i2c(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *i2c_tree;
	guint8      is_event;
	guint8      bus, addr;
	guint32     flags;

	flags = pinfo->pseudo_header->i2c.flags;

	bus = pinfo->pseudo_header->i2c.bus;
	col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "I2C-%d", bus);

	is_event = pinfo->pseudo_header->i2c.is_event;
	if (is_event) {
		addr = 0;
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "I2C Event");
		col_add_fstr(pinfo->cinfo, COL_DEF_DST, "----");
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
				i2c_get_event_desc(flags));
	} else {
		/* Report 7-bit hardware address */
		addr = tvb_get_guint8(tvb, 0) >> 1;
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
				i2c_get_event_desc(flags), flags);
	} else {
		proto_tree_add_uint_format_value(i2c_tree, hf_i2c_addr, tvb, 0, 1,
				addr, "0x%02x%s", addr, addr ? "" : " (General Call)");
		proto_tree_add_uint(i2c_tree, hf_i2c_flags, tvb, 0, 0, flags);

		/* Functionality for choosing subdissector is controlled through Decode As as I2C doesn't
		   have a unique identifier to determine subdissector */
		if (!dissector_try_uint(subdissector_table, 0, tvb, pinfo, tree))
		{
			call_data_dissector(tvb, pinfo, tree);
		}
	}
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
	};
	static gint *ett[] = {
		&ett_i2c
	};
	module_t *m;

	/* Decode As handling */
	static build_valid_func i2c_da_build_value[1] = {i2c_value};
	static decode_as_value_t i2c_da_values = {i2c_prompt, 1, i2c_da_build_value};
	static decode_as_t i2c_da = {"i2c", "I2C Message", "i2c.message", 1, 0, &i2c_da_values, NULL, NULL,
									decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

	/* Placeholders for capture statistics */
	proto_i2c_event = proto_register_protocol("I2C Events", "I2C Events", "i2c_event");
	proto_i2c_data = proto_register_protocol("I2C Data", "I2C Data", "i2c_data");

	proto_i2c = proto_register_protocol("Inter-Integrated Circuit", "I2C", "i2c");
	proto_register_field_array(proto_i2c, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	subdissector_table = register_dissector_table("i2c.message", "I2C messages dissector", proto_i2c, FT_UINT32, BASE_DEC);

	m = prefs_register_protocol(proto_i2c, NULL);
	prefs_register_obsolete_preference(m, "type");

	register_decode_as(&i2c_da);
}

void
proto_reg_handoff_i2c(void)
{
	dissector_handle_t i2c_handle;

	i2c_handle = create_dissector_handle(dissect_i2c, proto_i2c);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_I2C, i2c_handle);
	register_capture_dissector("wtap_encap", WTAP_ENCAP_I2C, capture_i2c, proto_i2c);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
