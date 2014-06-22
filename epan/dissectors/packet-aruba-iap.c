/* packet-aruba-iap.c
 * Routines for Aruba IAP header disassembly
 * Copyright 2014, Alexis La Goutte <alexis.lagoutte at gmail dot com>
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
 * Aruba Instant AP broadcast on L2 Layer with ethertype 0x8ffd
 * All frame start with 0xbeef (Magic number ?)
 * The address IP(v4) of Aruba Instant AP is available start in offset 11
 * the 3 octet is may be a type field(found some frame with this octet is different and data is different)
 * Octet to 7 to 10 is may be uptime of AP (the value always increment )
 */
#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>

#define ETHERTYPE_IAP   0x8ffd
#define MAGIC_IAP       0xbeef

void proto_register_aruba_iap(void);
void proto_reg_handoff_aruba_iap(void);

static int proto_aruba_iap = -1;
static gint ett_aruba_iap  = -1;

static int hf_iap_magic  = -1;
static int hf_iap_type  = -1;
static int hf_iap_ip     = -1;
static int hf_iap_unknown_uint = -1;
static int hf_iap_unknown_bytes = -1;

static int
dissect_aruba_iap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ti;
    proto_tree *aruba_iap_tree;
    guint16 magic;
    int offset = 0;

    magic = tvb_get_ntohs(tvb, offset);

    if(magic != MAGIC_IAP)
    {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IAP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_aruba_iap, tvb, 0, 0, ENC_NA);
    aruba_iap_tree = proto_item_add_subtree(ti, ett_aruba_iap);

    proto_tree_add_item(aruba_iap_tree, hf_iap_magic, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(aruba_iap_tree, hf_iap_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(aruba_iap_tree, hf_iap_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(aruba_iap_tree, hf_iap_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(aruba_iap_tree, hf_iap_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Aruba Instant AP IP: %s", tvb_ip_to_str(tvb, offset));
    offset += 4;

    proto_tree_add_item(aruba_iap_tree, hf_iap_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(aruba_iap_tree, hf_iap_unknown_uint, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(aruba_iap_tree, hf_iap_unknown_bytes, tvb, offset, -1, ENC_NA);
    offset += tvb_reported_length(tvb);

    return offset;
}

void
proto_register_aruba_iap(void)
{
    static hf_register_info hf[] = {
        { &hf_iap_magic,
        { "Magic", "aruba_iap.magic", FT_UINT16, BASE_HEX, NULL,0x0,
        "Magic Number of IAP trafic (Always 0x8ffd)", HFILL}},

        { &hf_iap_type,
        { "Type (?)", "aruba_iap.type", FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        "May type field...", HFILL}},

        { &hf_iap_ip,
        { "IP", "aruba_iap.ip", FT_IPv4, BASE_NONE, NULL, 0x0,
        "Address IP of IAP", HFILL}},

        { &hf_iap_unknown_bytes,
        { "Unknown", "aruba_iap.unknown.bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown Data...", HFILL}},

        { &hf_iap_unknown_uint,
        { "Unknown", "aruba_iap.unknown.uint", FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        "Unknown (UINT) Data...", HFILL}},


    };

    static gint *ett[] = {
        &ett_aruba_iap,
    };

    proto_aruba_iap = proto_register_protocol("Aruba Instant AP Protocol",
                    "aruba_iap", "aruba_iap");
    proto_register_field_array(proto_aruba_iap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_aruba_iap(void)
{
    dissector_handle_t iap_handle;

    iap_handle = new_create_dissector_handle(dissect_aruba_iap, proto_aruba_iap);
    dissector_add_uint("ethertype", ETHERTYPE_IAP, iap_handle);
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
