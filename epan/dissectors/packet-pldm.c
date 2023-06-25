#include "config.h"
//#include "packet-pldm-base.h"
#include <epan/packet.h>
#include <stdint.h>

#define PLDM_MIN_LENGTH 4
#define PLDM_MAX_TYPES 8

static const value_string directions[]={
    {0, "response"},
    {1, "reserved"},
    {2, "request"},
    {3, "async/unack"},
    {0, NULL}
};

static const value_string pldm_types[] = {
    { 0, "PLDM Messaging and Discovery"},
    { 1 ,"PLDM for SMBIOS"},
    { 2, "PLDM Platform Monitoring and Control"},
    { 3, "PLDM for BIOS Control and Configuration"},
    { 4, "PLDM for FRU Data"},
    { 5, "PLDM for Firmware Update"},
    { 6, "PLDM for Redfish Device Enablement"},
    { 63,"OEM Specific"},
    { 0, NULL}
};

struct packet_data {
    guint8 direction;
    guint8 instance_id;
};
static int proto_pldm=-1;
static int ett_pldm=-1;

static int hf_direction = -1;
static int hf_instance_id = -1;
static int hf_header_version= -1;
static int hf_pldm_type= -1;
static int hf_reserve = -1;
static dissector_table_t pldm_dissector_table;

static int dissect_pldm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PLDM");
    col_clear(pinfo->cinfo,COL_INFO);

    tvbuff_t *next_tvb;
    guint len, direction;
    guint8 instID, pldm_type, offset;
    int reported_length;
    len=tvb_reported_length(tvb);
    if (len < PLDM_MIN_LENGTH) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Packet length %u, minimum %u",
                     len, PLDM_MIN_LENGTH);
        return tvb_captured_length(tvb);
    }
    if (tree) {
        /* first byte is the MCTP msg type */
        offset = 1;
        proto_item *ti = proto_tree_add_item(tree, proto_pldm, tvb, offset, -1, ENC_NA);
        proto_tree *pldm_tree = proto_item_add_subtree(ti, ett_pldm);

        proto_tree_add_item(pldm_tree, hf_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        direction = tvb_get_bits8(tvb, offset*8, 2);
        proto_tree_add_item(pldm_tree, hf_reserve, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pldm_tree, hf_instance_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        instID= tvb_get_guint8(tvb, offset);
        instID=instID & 0x1F;
        //instID = tvb_get_bits8(tvb, offset*8+3,  5);
        offset +=1;
        pldm_type = tvb_get_bits8(tvb, offset*8 +2, 6);
        proto_tree_add_item(pldm_tree, hf_header_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pldm_tree, hf_pldm_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset +=1;
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        offset +=1;
        reported_length = tvb_reported_length_remaining(tvb, offset);

        struct packet_data d = {direction, instID};
        if (reported_length >= 1) {
            dissector_try_uint_new(pldm_dissector_table, pldm_type & 0x3f, next_tvb, pinfo, pldm_tree, true, (void *)&d);
            return tvb_captured_length(tvb);
        }
    }
    
    return tvb_captured_length(tvb);
}

void
proto_register_pldm(void)
{
     static hf_register_info hf[] = {
        { &hf_direction,
            { "Msg Direction", "pldm.direction",
            FT_UINT8, BASE_DEC,
            VALS(directions), 0xc0,
            NULL, HFILL }
        },
        { &hf_reserve,
            { "PLDM Reserve", "pldm.rsvd",
            FT_UINT8, BASE_DEC,
            NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_instance_id,
            { "PLDM Instance Id", "pldm.instance",
              FT_UINT8, BASE_DEC,
              NULL, 0x1F,
              NULL, HFILL}
         },
        { &hf_header_version,{
            "PLDM Header Version", "pldm.hdr",
            FT_UINT8, BASE_DEC,
            NULL, 0xC0,
            NULL, HFILL}
         },
	 { &hf_pldm_type,{
             "PLDM Command Type", "pldm.type",
             FT_UINT8, BASE_HEX,
             VALS(pldm_types), 0x3f,
             NULL, HFILL}
         },
    };
    
    static gint *ett[] = {
        &ett_pldm
    };
    
    proto_pldm = proto_register_protocol (
        "PLDM Protocol", /* name        */
        "PLDM",          /* short_name  */
        "pldm"           /* filter_name */
        );
    proto_register_field_array(proto_pldm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    pldm_dissector_table = register_dissector_table("pldm.type", "PLDM type",
                                                    proto_pldm, FT_UINT8,
                                                    BASE_HEX);
}


void
proto_reg_handoff_pldm(void)
{
    static dissector_handle_t pldm_handle;
    pldm_handle = create_dissector_handle(dissect_pldm, proto_pldm);
    dissector_add_uint("wtap_encap", 147 , pldm_handle);
    dissector_add_uint("mctp.type", 1, pldm_handle);
}





