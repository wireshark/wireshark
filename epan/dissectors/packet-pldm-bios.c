#include <stdint.h>
#include "packet-pldm-base.h"

// BIOS table
static int proto_pldm_bios=-1;
static int hf_pldm_cmd=-1;
static int hf_completion_code=-1;
static int hf_bios_data_handle=-1;
static int hf_bios_transfer_op_flag=-1;
static int hf_bios_table_type=-1;
static int hf_bios_next_data_handle=-1;
static int hf_bios_transfer_flag=-1;
static int hf_bios_attr_handle=-1;
static int hf_bios_attribute_handle=-1;
static int hf_bios_attribute_type=-1;
static int hf_bios_attribute_name_handle=-1;


// Date and Time
static int hf_pldm_time=-1;
static int hf_pldm_date=-1;

static const value_string pldm_cmds[] ={
    {0x01, "GetBIOSTable"},
    {0x02, "SetBIOSTable"},
    {0x03, "UpdateBIOSTable"},
    {0x04, "GetBIOSTableTags"},
    {0x05, "SetBIOSTableTags"},
    {0x06, "AcceptBIOSAttributesPending"},
    {0x07, "SetBIOSAttributeCurrentValue"},
    {0x08, "GetBIOSAttributeCurrentValueByHandle"},
    {0x09, "GetBIOSAttributePendingValueByHandle"},
    {0x0a,  "GetBIOSAttributeCurrentValueByType"},
    {0x0b,  "GetBIOSAttributePendingValueByType"},
    {0x0c,  "GetDateTime"},
    {0x0d,  "SetDateTime"},
    {0x0e,  "GetBIOSStringTableStringType"},
    {0x0f,  "SetBIOSStringTableStringType"},
    {0, NULL}
};

static const value_string completion_codes[]={
    {0x0, "Success"},
    {0x1, "Error"},
    {0x2, "Invalid Data"},
    {0x3, "Invalid Length"},
    {0x4, "Not Ready"},
    {0x5, "Unsupported PLDM command"},
    {0x20, "Invalid PLDM type"},
    {0x80, "Invalid data transfer handle"},
    {0x81, "Invalid transfer operation flag"},
    {0x82, "Invalid transfer flag"},
    {0x83, "BIOS table unavailable"},
    {0x84, "Invalid BIOS table integrity check"},
    {0x85, "Invalid BIOS table"},
    {0x86, "BIOS table tag unavailable"},
    {0x87, "Invalid BIOS table tag type"},
    {0x88, "Invalid BIOS attr handle"},
    {0x89, "Invalid BIOS attr type"},
    {0x8a, "No date time info available"},
    {0x8b, "Invalid string type"},
    {0, NULL}
};

static const value_string bios_table_types[] ={
    {0x0,   "BIOS String Table"},
    {0x1,   "BIOS Attribute Table"},
    {0x2,   "BIOS Attribute Value Table"},
    {0x3,   "BIOS Attribute Pending Value Table"},
    {0, NULL}
};

static const value_string transfer_op_flags[] ={
    {0x0,   "Get Next Part"},
    {0x1,   "Get First Part"},
    {0, NULL}
};

static const value_string transfer_flags[] ={
    {0x1,   "Start"},
    {0x2,   "Middle"},
    {0x4,   "End"},
    {0x5,   "Start and End"},
    {0, NULL}
};

#define BCD44_TO_DEC(x)  ((((x)&0xf0) >> 4) * 10 + ((x)&0x0f))

int
dissect_bios(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *p_tree, void* data)
{
    struct packet_data *d = (struct packet_data*) data;
    guint8 request = d->direction;
    guint8 pldm_cmd = tvb_get_guint8(tvb, 0);
    guint8 offset = 0;
    guint8 hour, min, sec;
    proto_tree_add_item(p_tree, hf_pldm_cmd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    if (!request){
        proto_tree_add_item(p_tree, hf_completion_code, tvb, 1, 1, ENC_LITTLE_ENDIAN);
        guint8 completion_code = tvb_get_guint8(tvb, offset);
        if (completion_code)
            return tvb_captured_length(tvb);
        offset += 1;
    }
    switch(pldm_cmd){
    case 0x1: //Get BIOS Table
        if (request){
            proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(p_tree, hf_bios_transfer_op_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(p_tree, hf_bios_table_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            char buffer[20];
            snprintf(buffer, 20, "BIOS Table Data");
            proto_tree_add_item(p_tree, hf_bios_attribute_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(p_tree, hf_bios_attribute_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(p_tree, hf_bios_attribute_name_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(p_tree, hf_bios_attribute_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            
        }
        break;
    case 0x07: //Set BIOS Attribute Current Value by Handle
        if (request){
            proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        }
        break;
    case 0x08: //Get BIOS Attribute Current Value by Handle
        if (request){
            proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(p_tree, hf_bios_transfer_op_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(p_tree, hf_bios_attr_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	    //TODO attribute data
        }
        break;
    case 0x0c: //Get Date and Time
        if (!request){
            sec = BCD44_TO_DEC(tvb_get_guint8(tvb, offset));
            min = BCD44_TO_DEC(tvb_get_guint8(tvb, offset+1));
            hour = BCD44_TO_DEC(tvb_get_guint8(tvb, offset+2));
            if (hour > 23 || min > 59 || sec > 59)
                return -1;
            char time[9];
            snprintf(time, 9, "%02d:%02d:%02d", hour, min, sec);
            proto_tree_add_string(p_tree, hf_pldm_time, tvb, offset, 3, time);
            offset += 3;
            guint8 day = BCD44_TO_DEC(tvb_get_guint8(tvb, offset));
            guint8 month = BCD44_TO_DEC(tvb_get_guint8(tvb, offset+1));
            guint16 year = BCD44_TO_DEC(tvb_get_guint8(tvb, offset+3)) * 100 + BCD44_TO_DEC(tvb_get_guint8(tvb, offset+2));
            if (day > 31 || day < 1 || month > 12 || month < 1)
		return -1;

            char date[11];
            snprintf(date, 11, "%02d/%02d/%04d", day, month, year);
            proto_tree_add_string(p_tree, hf_pldm_date, tvb, offset, 4, date);
        }
        break;
    default:
        col_append_fstr(pinfo->cinfo, COL_INFO, "Unsupported or Invalid PLDM command");
        g_print("Invalid PLDM bios cmd %x \n", pldm_cmd);
        break;

    }
    return tvb_captured_length(tvb);
}

void
proto_register_bios(void)
{
    static hf_register_info hf[] ={
        { &hf_bios_data_handle,{
            "Data transfer handle", "pldm.bios.table.handle",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL}
         },
        { &hf_bios_transfer_op_flag,{
            "Data transfer operation flag", "pldm.bios.table.opflag",
            FT_UINT8, BASE_HEX,
            VALS(transfer_op_flags), 0x0,
            NULL, HFILL}
         },
        { &hf_bios_table_type,{
            "BIOS table type", "pldm.bios.table.type",
            FT_UINT8, BASE_HEX,
            VALS(bios_table_types), 0x0,
            NULL, HFILL}
         },
        { &hf_bios_next_data_handle,{
            "Next data transfer handle", "pldm.bios.table.nexthandle",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL}
         },
        { &hf_bios_transfer_flag,{
            "Data transfer operation flag", "pldm.bios.table.flag",
            FT_UINT8, BASE_HEX,
            VALS(transfer_flags), 0x0,
            NULL, HFILL}
         },
        { &hf_bios_attr_handle,{
            "Attribute handle", "pldm.bios.attr.handle",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL}
         },
        { &hf_pldm_time,{
            "Time", "pldm.bios.time",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
         },
        { &hf_pldm_date,{
            "Date", "pldm.bios.date",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
         },
        { &hf_pldm_cmd,{
            "PLDM Command Type", "pldm.cmd",
            FT_UINT8, BASE_HEX,
            VALS(pldm_cmds), 0x0,
            NULL, HFILL}
         },
         { &hf_completion_code,{
            "Completion Code", "pldm.cc",
            FT_UINT8, BASE_DEC,
            VALS(completion_codes), 0x0,
            NULL, HFILL}
         },
         { &hf_bios_attribute_handle,{
            "First Attribute", "pldm.first.attribute",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL}
         },
    };

    proto_pldm_bios = proto_register_protocol (
        "PLDM BIOS Control and Configuration", /* name        */
        "PLDM_bios",          /* short_name  */
        "pldm.bios"           /* filter_name */
        );
    proto_register_field_array(proto_pldm_bios, hf, array_length(hf));
}

void
proto_reg_handoff_bios(void)
{
    static dissector_handle_t bios_handle;
   
    bios_handle = create_dissector_handle(dissect_bios, proto_pldm_bios);
    dissector_add_uint("pldm.type", PLDM_BIOS, bios_handle);
}
