#include "config.h"
#include <epan/packet.h>

static int proto_pldm = -1;
static int hf_pldm_reserved_bits = -1;
static int hf_pldm_instance_id = -1;
static int hf_pldm_header_version = -1;
static int hf_pldm_spec_type = -1;
static int hf_pldm_command_type = -1;
static gint ett_pldm = -1;


static const value_string specnames[] = {
    { 0, "PLDM Messaging and Discovery" },
    { 1 ,"PLDM for SMBIOS"},
    { 2, "PLDM Platform Monitoring and Control" },
    { 3, "PLDM for BIOS Control and Configuration" },
    { 4, "PLDM for FRU Data" },
    { 5, "PLDM for Firmware Update"},
    { 6, "PLDM for Redfish Device Enablement"},
    { 63,"OEM Specific"}
};

static const value_string basetypenames[] = {
    { 2, "Get Terminus ID" },
    { 3, "Get PLDM Version" },
    { 4, "Get PLDM Types "},
    { 5, "Get PLDM Commands"}
};


static int
dissect_pldm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PLDM");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    gint offset = 0;
    proto_item *ti = proto_tree_add_item(tree, proto_pldm, tvb, 0, -1, ENC_NA);
    proto_tree *pldm_tree = proto_item_add_subtree(ti, ett_pldm);
    proto_tree_add_item(pldm_tree, hf_pldm_reserved_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pldm_tree, hf_pldm_instance_id, tvb, offset , 1 , ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(pldm_tree, hf_pldm_header_version, tvb, offset , 1 , ENC_BIG_ENDIAN);
    proto_tree_add_item(pldm_tree, hf_pldm_spec_type, tvb, offset , 1 , ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(pldm_tree, hf_pldm_command_type, tvb, offset , 1 , ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

void
proto_register_pldm(void)
{
        static hf_register_info hf[] = {
                { &hf_pldm_reserved_bits,
                        { "Reserved Bits", "pldm.reserved_bits",
                        FT_UINT8, BASE_DEC,
                        NULL, 0xE0,
                        NULL, HFILL }
                },
                { &hf_pldm_instance_id,
                        { "Instance Id", "pldm.instance_id",
                        FT_UINT8, BASE_DEC,
                        NULL, 0x1F,
                        NULL, HFILL }
                },
                { &hf_pldm_header_version,
                        { "Header Version", "pldm.header_version",
                        FT_UINT8, BASE_DEC,
                        NULL, 0xC0,
                        NULL, HFILL }
                },
                { &hf_pldm_spec_type,
                        { "Spec type", "pldm.spec_type",
                        FT_UINT8, BASE_DEC,
                        VALS(specnames), 0x3F,
                        NULL, HFILL }
                },
                { &hf_pldm_command_type,
                        { "Command type", "pldm.command_type",
                        FT_UINT8, BASE_DEC,
                        VALS(basetypenames), 0x0,
                        NULL, HFILL }
                }
        };

        /*set up protocol subtree array */
        static gint *ett[] = {
                &ett_pldm
        };

    proto_pldm = proto_register_protocol (
        "PLDM Protocol", /* name        */
        "PLDM",          /* short_name  */
        "pldm"           /* filter_name */
        );

    register_dissector("pldm", dissect_pldm, proto_pldm);
    proto_register_field_array(proto_pldm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pldm(void)
{
    static dissector_handle_t pldm_handle;

    pldm_handle = create_dissector_handle(dissect_pldm, proto_pldm);
    dissector_add_uint("wtap_encap",WTAP_ENCAP_USER0, pldm_handle);
}
