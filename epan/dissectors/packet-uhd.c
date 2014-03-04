/* packet-uhd.c
 * Routines for UHD captures
 *
 * (C) 2013 by Klyuchnikov Ivan <kluchnikovi@gmail.com>, Dario Lombardo <lomato@gmail.com>
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

/*
 * Original dissector can be found here
 * https://github.com/chemeris/uhd_dissector
*/


#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_uhd(void);

static gint dissector_port_pref = 0;

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */

#define    USRP2_CTRL_ID_HUH_WHAT    0x20  /* ' ' */
#define    UMTRX_CTRL_ID_REQUEST     0x75  /* 'u' */
#define    UMTRX_CTRL_ID_RESPONSE    0x55  /* 'U' */
#define    USRP2_CTRL_ID_WAZZUP_BRO  0x61  /* 'a' */
#define    USRP2_CTRL_ID_WAZZUP_DUDE 0x41  /* 'A' */
#define    USRP2_CTRL_ID_TRANSACT_ME_SOME_SPI_BRO     0x73 /* 's' */
#define    USRP2_CTRL_ID_OMG_TRANSACTED_SPI_DUDE      0x53 /* 'S' */
#define    USRP2_CTRL_ID_DO_AN_I2C_READ_FOR_ME_BRO    0x69 /* 'i' */
#define    USRP2_CTRL_ID_HERES_THE_I2C_DATA_DUDE      0x49 /* 'I' */
#define    USRP2_CTRL_ID_WRITE_THESE_I2C_VALUES_BRO   0x68 /* 'h' */
#define    USRP2_CTRL_ID_COOL_IM_DONE_I2C_WRITE_DUDE  0x48 /* 'H' */
#define    USRP2_CTRL_ID_GET_THIS_REGISTER_FOR_ME_BRO 0x72 /* 'r' */
#define    USRP2_CTRL_ID_OMG_GOT_REGISTER_SO_BAD_DUDE 0x52 /* 'R' */
#define    USRP2_CTRL_ID_HOLLER_AT_ME_BRO 0x6c /* 'l' */
#define    USRP2_CTRL_ID_HOLLER_BACK_DUDE 0x4c /* 'L' */
#define    USRP2_CTRL_ID_PEACE_OUT        0x7e /* '~' */

#define     USRP2_REG_ACTION_FPGA_PEEK32 1
#define     USRP2_REG_ACTION_FPGA_PEEK16 2
#define     USRP2_REG_ACTION_FPGA_POKE32 3
#define     USRP2_REG_ACTION_FPGA_POKE16 4
#define     USRP2_REG_ACTION_FW_PEEK32   5
#define     USRP2_REG_ACTION_FW_POKE32   6

#define UHD_UDP_PORT				49152

/* This is the header as it is used by uhd-generating software.
 * It is not used by the wireshark dissector and provided for reference only.
typedef struct{
    uint32_t proto_ver;
    uint32_t id;
    uint32_t seq;
    union{
        uint32_t ip_addr;
        struct {
            uint32_t dev;
            uint32_t data;
            uint8_t miso_edge;
            uint8_t mosi_edge;
            uint8_t num_bits;
            uint8_t readback;
        } spi_args;
        struct {
            uint8_t addr;
            uint8_t bytes;
            uint8_t data[20];
        } i2c_args;
        struct {
            uint32_t addr;
            uint32_t data;
            uint8_t action;
        } reg_args;
        struct {
            uint32_t len;
        } echo_args;
    } data;
} usrp2_ctrl_data_t;
 */

static int proto_uhd = -1;

static int hf_uhd_version = -1;
static int hf_uhd_id = -1;
static int hf_uhd_seq = -1;
static int hf_uhd_ip_addr = -1;
static int hf_uhd_i2c_addr = -1;
static int hf_uhd_i2c_bytes = -1;
static int hf_uhd_i2c_data = -1;
static int hf_uhd_spi_dev = -1;
static int hf_uhd_spi_data = -1;
static int hf_uhd_spi_miso_edge = -1;
static int hf_uhd_spi_mosi_edge = -1;
static int hf_uhd_spi_num_bits = -1;
static int hf_uhd_spi_readback = -1;
static int hf_uhd_reg_addr = -1;
static int hf_uhd_reg_data = -1;
static int hf_uhd_reg_action = -1;
static int hf_uhd_echo_len = -1;


static gint ett_uhd = -1;


static const value_string uhd_ids[] = {
 	{ USRP2_CTRL_ID_HUH_WHAT,                     "HUH WHAT" },
	{ UMTRX_CTRL_ID_REQUEST,                      "UMTRX REQUEST" },
	{ UMTRX_CTRL_ID_RESPONSE,                     "UMTRX RESPONSE" },
	{ USRP2_CTRL_ID_WAZZUP_BRO,                   "WAZZUP BRO" },
	{ USRP2_CTRL_ID_WAZZUP_DUDE,                  "WAZZUP DUDE" },
	{ USRP2_CTRL_ID_TRANSACT_ME_SOME_SPI_BRO,     "TRANSACT ME SOME SPI BRO" },
	{ USRP2_CTRL_ID_OMG_TRANSACTED_SPI_DUDE,      "OMG TRANSACTED SPI DUDE" },
	{ USRP2_CTRL_ID_DO_AN_I2C_READ_FOR_ME_BRO,    "DO AN I2C READ FOR ME BRO" },
	{ USRP2_CTRL_ID_HERES_THE_I2C_DATA_DUDE,      "HERES THE I2C DATA DUDE" },
	{ USRP2_CTRL_ID_WRITE_THESE_I2C_VALUES_BRO,   "WRITE THESE I2C VALUES BRO" },
	{ USRP2_CTRL_ID_COOL_IM_DONE_I2C_WRITE_DUDE,  "COOL IM DONE I2C WRITE DUDE" },
	{ USRP2_CTRL_ID_GET_THIS_REGISTER_FOR_ME_BRO, "GET THIS REGISTER FOR ME BRO" },
	{ USRP2_CTRL_ID_OMG_GOT_REGISTER_SO_BAD_DUDE, "OMG GOT REGISTER SO BAD DUDE" },
	{ USRP2_CTRL_ID_HOLLER_AT_ME_BRO,             "HOLLER AT ME BRO" },
	{ USRP2_CTRL_ID_HOLLER_BACK_DUDE,             "HOLLER BACK DUDE" },
	{ USRP2_CTRL_ID_PEACE_OUT,                    "PEACE OUT" },
	{ 0, NULL }
};

static const value_string uhd_reg_actions[] = {
	{ USRP2_REG_ACTION_FPGA_PEEK32, "FPGA PEEK32" },
	{ USRP2_REG_ACTION_FPGA_PEEK16, "FPGA PEEK16" },
	{ USRP2_REG_ACTION_FPGA_POKE32, "FPGA POKE32" },
	{ USRP2_REG_ACTION_FPGA_POKE16, "FPGA POKE16" },
	{ USRP2_REG_ACTION_FW_PEEK32,   "FW PEEK32" },
	{ USRP2_REG_ACTION_FW_POKE32,   "FW POKE32" },
	{ 0, NULL }
};

void proto_reg_handoff_uhd(void);

/* dissect a UHD header and hand payload off to respective dissector */
static void
dissect_uhd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	    ind;
	proto_item *ti;
	proto_tree *uhd_tree;
	guint32	    id;
	guint8	    i2c_bytes;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "UHD");
	col_clear(pinfo->cinfo, COL_INFO);

	id = tvb_get_ntohl(tvb, 4);

	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(id, uhd_ids, "Unknown UHD message type '%c'"));

	if (tree == NULL)
		return;

	ti = proto_tree_add_protocol_format(tree, proto_uhd, tvb, 0, 34, "UHD id = %c ", id);
	uhd_tree = proto_item_add_subtree(ti, ett_uhd);

	proto_tree_add_item(uhd_tree, hf_uhd_version, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(uhd_tree, hf_uhd_id,      tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(uhd_tree, hf_uhd_seq,     tvb, 8, 4, ENC_BIG_ENDIAN);

	switch (id) {
		case UMTRX_CTRL_ID_REQUEST:
		case UMTRX_CTRL_ID_RESPONSE:
		case USRP2_CTRL_ID_WAZZUP_BRO:
		case USRP2_CTRL_ID_WAZZUP_DUDE:
			proto_tree_add_item(uhd_tree, hf_uhd_ip_addr,       tvb, 12, 4, ENC_BIG_ENDIAN);
			break;
		case USRP2_CTRL_ID_TRANSACT_ME_SOME_SPI_BRO:
		case USRP2_CTRL_ID_OMG_TRANSACTED_SPI_DUDE:
			proto_tree_add_item(uhd_tree, hf_uhd_spi_dev,	    tvb, 12, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(uhd_tree, hf_uhd_spi_data,	    tvb, 16, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(uhd_tree, hf_uhd_spi_miso_edge, tvb, 20, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(uhd_tree, hf_uhd_spi_mosi_edge, tvb, 21, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(uhd_tree, hf_uhd_spi_num_bits,  tvb, 22, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(uhd_tree, hf_uhd_spi_readback,  tvb, 23, 1, ENC_BIG_ENDIAN);
			break;
		case USRP2_CTRL_ID_DO_AN_I2C_READ_FOR_ME_BRO:
		case USRP2_CTRL_ID_HERES_THE_I2C_DATA_DUDE:
		case USRP2_CTRL_ID_WRITE_THESE_I2C_VALUES_BRO:
		case USRP2_CTRL_ID_COOL_IM_DONE_I2C_WRITE_DUDE:
			proto_tree_add_item(uhd_tree, hf_uhd_i2c_addr, tvb, 12, 1, ENC_BIG_ENDIAN);
			i2c_bytes = tvb_get_guint8(tvb, 13);
			proto_tree_add_item(uhd_tree, hf_uhd_i2c_bytes, tvb, 13, 1, ENC_BIG_ENDIAN);
			for (ind = 0; ind < i2c_bytes; ind++) {
				proto_tree_add_item(uhd_tree, hf_uhd_i2c_data, tvb, 14 + ind, 1, ENC_BIG_ENDIAN);
			}
			break;
		case USRP2_CTRL_ID_GET_THIS_REGISTER_FOR_ME_BRO:
		case USRP2_CTRL_ID_OMG_GOT_REGISTER_SO_BAD_DUDE:
			proto_tree_add_item(uhd_tree, hf_uhd_reg_addr,	 tvb, 12, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(uhd_tree, hf_uhd_reg_data,	 tvb, 16, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(uhd_tree, hf_uhd_reg_action, tvb, 20, 1, ENC_BIG_ENDIAN);
			break;
		case USRP2_CTRL_ID_HOLLER_AT_ME_BRO:
		case USRP2_CTRL_ID_HOLLER_BACK_DUDE:
		case USRP2_CTRL_ID_HUH_WHAT:
		case USRP2_CTRL_ID_PEACE_OUT:
			proto_tree_add_item(uhd_tree, hf_uhd_echo_len,   tvb, 12, 4, ENC_BIG_ENDIAN);
			break;
	}
}

void
proto_register_uhd(void)
{
	static hf_register_info hf[] = {
		{ &hf_uhd_version, { "VERSION", "uhd.version",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_id, { "ID", "uhd.id",
		  FT_UINT32, BASE_HEX, VALS(uhd_ids), 0, NULL, HFILL } },
		{ &hf_uhd_seq, { "SEQ", "uhd.seq",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_ip_addr, { "IP ADDR", "uhd.ip_addr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,"", HFILL } },
		{ &hf_uhd_i2c_addr, { "I2C ADDR", "uhd.i2c_addr",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_i2c_bytes, { "I2C BYTES", "uhd.i2c_bytes",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_i2c_data, { "I2C DATA", "uhd.i2c_data",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_spi_dev, { "SPI DEV", "uhd.spi_dev",
		  FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_spi_data, { "SPI DATA", "uhd.spi_data",
		  FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_spi_miso_edge, { "SPI MISO EDGE", "uhd.spi_miso_edge",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_spi_mosi_edge, { "SPI MOSI EDGE", "uhd.spi_mosi_edge",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_spi_num_bits, { "SPI NUM BITS", "uhd.spi_num_bits",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_spi_readback, { "SPI READBACK", "uhd.spi_readback",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_reg_addr, { "REG ADDR", "uhd.reg_addr",
		  FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_reg_data, { "REG DATA", "uhd.reg_data",
		  FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_uhd_reg_action, { "REG ACTION", "uhd.reg_action",
		  FT_UINT8, BASE_HEX, VALS(uhd_reg_actions), 0, NULL, HFILL } },
		{ &hf_uhd_echo_len, { "ECHO LEN", "uhd.echo_len",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
	};

	static gint *ett[] = {
		&ett_uhd
	};

    module_t *uhd_module;

	proto_uhd = proto_register_protocol("UHD", "UHD", "uhd");
	proto_register_field_array(proto_uhd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

    uhd_module = prefs_register_protocol(proto_uhd, proto_reg_handoff_uhd);
    prefs_register_uint_preference(uhd_module,
        "dissector_port",
        "Dissector UDP port",
        "The UDP port used by this dissector",
        10, &dissector_port_pref);
}

void
proto_reg_handoff_uhd(void)
{
	static gboolean uhd_prefs_initialized = FALSE;
	static dissector_handle_t uhd_handle;
	static gint dissector_port;

	if (!uhd_prefs_initialized) {
		uhd_handle = create_dissector_handle(dissect_uhd, proto_uhd);
		uhd_prefs_initialized = TRUE;
	} else {
		dissector_delete_uint("udp.port", dissector_port, uhd_handle);
	}

	dissector_port = dissector_port_pref;

	dissector_add_uint("udp.port", dissector_port, uhd_handle);
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
