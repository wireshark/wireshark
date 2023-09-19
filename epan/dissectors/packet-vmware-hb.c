/* packet-vmware-hb.c
 * Routines for VMware HeartBeat dissection
 * Copyright 2023, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * No spec/doc is available based on reverse/analysis of protocol...
 *
 */

#include "config.h"

#include <wireshark.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/etypes.h>

void proto_reg_handoff_vmware_hb(void);
void proto_register_vmware_hb(void);

static int proto_vmware_hb = -1;
static int hf_vmware_hb_magic = -1;
static int hf_vmware_hb_build_number= -1;
static int hf_vmware_hb_uuid_length = -1;
static int hf_vmware_hb_uuid = -1;
static int hf_vmware_hb_counter = -1;
static int hf_vmware_hb_esxi_ip4_address_length = -1;
static int hf_vmware_hb_esxi_ip4_address = -1;
static int hf_vmware_hb_payload = -1;

static int hf_vmware_hb_unknown = -1;

static dissector_handle_t vmware_hb_handle;

static gint ett_vmware_hb = -1;


static int
dissect_vmware_hb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *vmware_hb_tree;
    guint       offset = 0, uuid_length, ip4_length;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VMWARE-HB");

    ti = proto_tree_add_item(tree, proto_vmware_hb, tvb, 0, -1, ENC_NA);

    vmware_hb_tree = proto_item_add_subtree(ti, ett_vmware_hb);

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_magic, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_build_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_unknown, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_tree_add_item_ret_uint(vmware_hb_tree, hf_vmware_hb_uuid_length, tvb, offset, 2, ENC_BIG_ENDIAN, &uuid_length);
    offset += 2;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_uuid, tvb, offset, uuid_length, ENC_ASCII);
    offset += uuid_length;

    /* counter ? */
    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_unknown, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_unknown, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_uint(vmware_hb_tree, hf_vmware_hb_esxi_ip4_address_length, tvb, offset, 2, ENC_BIG_ENDIAN, &ip4_length);
    offset += 2;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_esxi_ip4_address, tvb, offset, ip4_length, ENC_ASCII);
    offset += ip4_length;

    proto_tree_add_item(vmware_hb_tree, hf_vmware_hb_payload, tvb, offset, -1, ENC_NA);
    offset += tvb_reported_length_remaining(tvb, offset);

    col_add_fstr(pinfo->cinfo, COL_INFO, "UUID: %s - IP: %s",
                tvb_get_string_enc(pinfo->pool, tvb, 13, uuid_length, ENC_ASCII), /* UUID */
                tvb_get_string_enc(pinfo->pool, tvb, (13+uuid_length+17), ip4_length, ENC_ASCII)  /* ESX IPv4 Address ID*/
                );

    return offset;
}

void
proto_register_vmware_hb(void)
{

    static hf_register_info hf[] = {
        /* HeartBeat */
        { &hf_vmware_hb_magic,
            { "Magic Number", "vmware_hb.magic",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
            "Magic Number ?", HFILL }
        },

        { &hf_vmware_hb_build_number,
            { "Build Number", "vmware_hb.build_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_uuid_length,
            { "Length UUID", "vmware_hb.uuid.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_uuid,
            { "UUID", "vmware_hb.uuid",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_counter,
            { "Counter", "vmware_hb.counter",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_esxi_ip4_address_length,
            { "ESXi IP4 Address Length", "vmware_hb.esxi_ip4_address.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_esxi_ip4_address,
            { "ESXi IP4 Address", "vmware_hb.esxi_ip4_address",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_payload,
            { "Payload", "vmware_hb.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_vmware_hb_unknown,
            { "Unknown", "vmware_hb.unknown",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Always NULL ?", HFILL }
        },

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_vmware_hb
    };

    /* Register the protocol name and description */
    proto_vmware_hb = proto_register_protocol("VMware - HeartBeat",
            "vmware_hb", "vmware_hb");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_vmware_hb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    vmware_hb_handle = register_dissector("vmware_hb", dissect_vmware_hb,
            proto_vmware_hb);

}


void
proto_reg_handoff_vmware_hb(void)
{
      dissector_add_uint("udp.port", 902, vmware_hb_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
