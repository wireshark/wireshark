/* packet-isis.c
 * Routines for ISO/OSI network and transport protocol packet disassembly, core
 * bits.
 *
 * Stuart Stanley <stuarts@mxmail.net>
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
#include <epan/expert.h>
#include <epan/nlpid.h>
#include <epan/etypes.h>
#include "packet-osi.h"
#include "packet-isis.h"

void proto_register_isis(void);
void proto_reg_handoff_isis(void);

static dissector_table_t isis_dissector_table;

/* isis base header */
static int proto_isis               = -1;

static int hf_isis_irpd             = -1;
static int hf_isis_header_length    = -1;
static int hf_isis_version          = -1;
static int hf_isis_system_id_length = -1;
static int hf_isis_type             = -1;
static int hf_isis_type_reserved    = -1;
static int hf_isis_version2         = -1;
static int hf_isis_reserved         = -1;
static int hf_isis_max_area_adr     = -1;
int hf_isis_clv_key_id              = -1;

static gint ett_isis                = -1;

static expert_field ei_isis_version = EI_INIT;
static expert_field ei_isis_version2 = EI_INIT;
static expert_field ei_isis_reserved = EI_INIT;
static expert_field ei_isis_type = EI_INIT;

static dissector_handle_t isis_handle;

static const value_string isis_vals[] = {
    { ISIS_TYPE_L1_HELLO,  "L1 HELLO"},
    { ISIS_TYPE_L2_HELLO,  "L2 HELLO"},
    { ISIS_TYPE_PTP_HELLO, "P2P HELLO"},
    { ISIS_TYPE_L1_LSP,    "L1 LSP"},
    { ISIS_TYPE_L2_LSP,    "L2 LSP"},
    { ISIS_TYPE_L1_CSNP,   "L1 CSNP"},
    { ISIS_TYPE_L2_CSNP,   "L2 CSNP"},
    { ISIS_TYPE_L1_PSNP,   "L1 PSNP"},
    { ISIS_TYPE_L2_PSNP,   "L2 PSNP"},
    { 0,                   NULL}
};

static int
dissect_isis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti, *version_item, *version2_item, *reserved_item;
    proto_tree *isis_tree = NULL;
    int offset = 0;
    guint8 isis_version, isis_version2, isis_reserved;
    guint8 isis_type;
    tvbuff_t *next_tvb;
    isis_data_t subdissector_data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_isis, tvb, 0, -1, ENC_NA);
    isis_tree = proto_item_add_subtree(ti, ett_isis);

    proto_tree_add_item(isis_tree, hf_isis_irpd, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset += 1;

    subdissector_data.header_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(isis_tree, hf_isis_header_length, tvb,
            offset, 1, subdissector_data.header_length );
    offset += 1;

    isis_version = tvb_get_guint8(tvb, offset);
    version_item = proto_tree_add_uint(isis_tree, hf_isis_version, tvb,
            offset, 1, isis_version );
    if (isis_version != ISIS_REQUIRED_VERSION){
        expert_add_info(pinfo, version_item, &ei_isis_version);
    }
    offset += 1;

    subdissector_data.system_id_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(isis_tree, hf_isis_system_id_length, tvb,
            offset, 1, subdissector_data.system_id_len );
    offset += 1;

    proto_tree_add_item(isis_tree, hf_isis_type_reserved, tvb, offset, 1, ENC_BIG_ENDIAN );

    isis_type = tvb_get_guint8(tvb, offset) & ISIS_TYPE_MASK;
    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str ( isis_type, isis_vals, "Unknown (0x%x)" ) );
    proto_tree_add_item(isis_tree, hf_isis_type, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset += 1;

    isis_version2 = tvb_get_guint8(tvb, offset);
    version2_item = proto_tree_add_item(isis_tree, hf_isis_version2, tvb, offset, 1, ENC_BIG_ENDIAN );
    if (isis_version2 != 1) {
        expert_add_info(pinfo, version2_item, &ei_isis_version2);
    }
    offset += 1;

    isis_reserved = tvb_get_guint8(tvb, offset);
    reserved_item = proto_tree_add_item(isis_tree, hf_isis_reserved, tvb, offset, 1, ENC_BIG_ENDIAN );
    if (isis_reserved != 0) {
        expert_add_info(pinfo, reserved_item, &ei_isis_reserved);
    }
    offset += 1;

    proto_tree_add_item(isis_tree, hf_isis_max_area_adr, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset += 1;

    /*
     * Interpret the system ID length.
     */
    if (subdissector_data.system_id_len == 0)
        subdissector_data.system_id_len = 6;    /* zero means 6-octet ID field length */
    else if (subdissector_data.system_id_len == 255) {
        subdissector_data.system_id_len = 0;    /* 255 means null ID field */
        /* XXX - what about the LAN ID? */
    }
    /* XXX - otherwise, must be in the range 1 through 8 */

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!dissector_try_uint_new(isis_dissector_table, isis_type, next_tvb,
                                pinfo, tree, TRUE, &subdissector_data))
    {
        proto_tree_add_expert(tree, pinfo, &ei_isis_type, tvb, offset, -1);
    }
    return tvb_captured_length(tvb);
} /* dissect_isis */

void
proto_register_isis(void)
{
  static hf_register_info hf[] = {
    { &hf_isis_irpd,
      { "Intradomain Routeing Protocol Discriminator",    "isis.irpd",
        FT_UINT8, BASE_HEX, VALS(nlpid_vals), 0x0, NULL, HFILL }},

    { &hf_isis_header_length,
      { "Length Indicator", "isis.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_isis_version,
      { "Version/Protocol ID Extension", "isis.version", FT_UINT8,
         BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_isis_system_id_length,
      { "ID Length", "isis.sysid_len",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_isis_type,
      { "PDU Type", "isis.type", FT_UINT8, BASE_DEC,
        VALS(isis_vals), ISIS_TYPE_MASK, NULL, HFILL }},

    { &hf_isis_type_reserved,
      { "Reserved", "isis.type.reserved", FT_UINT8, BASE_HEX,
        NULL, ISIS_TYPE_RESERVED_MASK, NULL, HFILL }},

    { &hf_isis_version2,
      { "Version", "isis.version2", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL }},

    { &hf_isis_reserved,
      { "Reserved", "isis.reserved", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL }},

    { &hf_isis_max_area_adr,
      { "Maximum Area Addresses", "isis.max_area_adr", FT_UINT8, BASE_DEC, NULL,
        0x0, "Maximum Area Addresses, 0 means 3", HFILL }},

    { &hf_isis_clv_key_id,
      { "Key ID", "isis.clv.key_id", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL }},
  };
    /*
     * Note, we pull in the unknown CLV handler here, since it
     * is used by all ISIS packet types.
     */
    static gint *ett[] = {
      &ett_isis,
    };

    static ei_register_info ei[] = {
        { &ei_isis_version, { "isis.version.unknown", PI_PROTOCOL, PI_WARN, "Unknown ISIS version", EXPFILL }},
        { &ei_isis_version2, { "isis.version2.notone", PI_PROTOCOL, PI_WARN, "Version must be 1", EXPFILL }},
        { &ei_isis_reserved, { "isis.reserved.notzero", PI_PROTOCOL, PI_WARN, "Reserved must be 0", EXPFILL }},
        { &ei_isis_type, { "isis.type.unknown", PI_PROTOCOL, PI_WARN, "Unknown ISIS packet type", EXPFILL }},
    };

    expert_module_t* expert_isis;

    proto_isis = proto_register_protocol(PROTO_STRING_ISIS, "ISIS", "isis");
    proto_register_field_array(proto_isis, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_isis = expert_register_protocol(proto_isis);
    expert_register_field_array(expert_isis, ei, array_length(ei));

    isis_handle = register_dissector("isis", dissect_isis, proto_isis);

    isis_dissector_table = register_dissector_table("isis.type",
                                "ISIS Type", proto_isis, FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_isis(void)
{
    dissector_add_uint("osinl.incl", NLPID_ISO10589_ISIS, isis_handle);
    dissector_add_uint("ethertype", ETHERTYPE_L2ISIS, isis_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
