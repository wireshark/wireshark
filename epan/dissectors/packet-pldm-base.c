#include <stdint.h>
#include <epan/packet.h>
#include <config.h>
#include "packet-pldm-base.h"

static int pldmTA[8]={0};
static int pldmTI[32][8]={0};

static const value_string pldmBaseCmd[] = {
    {1, "Set TID"},
    {2, "Get TID"},
    {3, "Get PLDM Version"},
    {4, "Get PLDM Types"},
    {5, "GetPLDMCommands"},
    {6, "SelectPLDMVersion"},
    {7, "NegotiateTranferParameters"},
    {8, "Multipart Send"},
    {9, "Multipart Receive"},
    {0, NULL}
};

static const value_string specNames[] = {
    {0, "PLDM Messaging and Discovery"},
    {1 ,"PLDM for SMBIOS"},
    {2, "PLDM Platform Monitoring and Control"},
    {3, "PLDM for BIOS Control and Configuration"},
    {4, "PLDM for FRU Data"},
    {5, "PLDM for Firmware Update"},
    {6, "PLDM for Redfish Device Enablement"},
    {63,"OEM Specific"},
    {0, NULL}
};

static const val64_string pldmTypes[] = {
    {0, "base"},
    {1, "smbios"},
    {2, "platform"},
    {3, "bios"},
    {4, "fru"},
    {5, "fw_update"},
    {6, "rde"},
    {63,"oem"},
    {0, NULL}
};

static const value_string pldmPlatformCmds[]={
    {4, "SetEventReceiver"},
    {10,"PlatformEventMessage"},
    {17,"GetSensorReading"},
    {33,"GetStateSensorReadings"},
    {49, "SetNumericEffecterValue"},
    {50,"GetNumericEffecterValue"},
    {57, "SetStateEffecterStates"},
    {81, "GetPDR"},
    {0, NULL}
};

static const value_string pldmFruCmds[]={
    {1, "GetFRURecordTableMetadata"},
    {2, "GetFRURecordTable"},
    {4, "GetFRURecordByOption"},
    {0, NULL}
};

static const value_string pldmBIOScmd[]={
    {1, "GetBIOSTable"},
    {2, "SetBIOSTable"},
    {7, "SetBIOSAttributeCurrentValue"},
    {8, "GetBIOSAttributeCurrentValueByHandle"},
    {12,"GetDateTime"},
    {13,"SetDateTime"},
    {0, NULL}
};

static const value_string pldmOEMCmds[]={
    {1,"GetFileTable"},
    {4,"ReadFile"},
    {5,"WriteFile"},
    {6,"ReadFileInToMemory"},
    {7,"WriteFileFromMemory"},
    {8,"ReadFileByTypeIntoMemory"},
    {9,"WriteFileByTypeFromMemory"},
    {10,"NewFileAvailable"},
    {11,"ReadFileByType"},
    {12,"WriteFileByType"},
    {13,"FileAck"},
    {0, NULL}
};

static const value_string transferOperationFlags[]={
    {0,"GetNextPart"},
    {1,"GetFirstPart"},
    {0, NULL}
};

static const value_string transferFlags[]={
    {1, "Start"},
    {2, "Middle"},
    {4, "End"},
    {5, "StartAndEnd"},
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
    {0, NULL}
};

static int proto_pldm_base=-1;
static int hf_pldm_cmd=-1;
static int hf_pldmBIOScmd=-1;
static int hf_pldmFruCmds=-1;
static int hf_pldmPlatformCmds=-1;
static int hf_pldmOEMCmds=-1;
static int hf_pldm_version=-1;
static int hf_pldmSpec8=-1;
static int hf_pldm_types=-1;
static int hf_TransferOperationFlag=-1;
static int hf_NextDataTransferHandle=-1;
static int hf_TransferFlag=-1;
static int hf_DataTransferHandle=-1;
static int hf_TIDValue=-1;
static int hf_completion_code=-1;

static int print_version_field(guint8 bcd, char *buffer, size_t buffer_size)
{
	int v;
	if (bcd == 0xff)
		return 0;
	if ((bcd & 0xf0) == 0xf0) {
		v = bcd & 0x0f;
		return snprintf(buffer, buffer_size, "%d", v);
	}
	v = ((bcd >> 4) * 10) + (bcd & 0x0f);
	return snprintf(buffer, buffer_size, "%02d", v);
}

#define POINTER_MOVE(rc, buffer, buffer_size)    \
	do {                                                    \
		if (rc < 0)                                     \
			return;                                 \
		if ((size_t)rc >= buffer_size)                  \
			return;                                 \
		buffer += rc;                                   \
		buffer_size -= rc;                              \
	} while (0);

void ver2str(tvbuff_t *tvb, int offset, char *buf_ptr, size_t buffer_size)
{
	int rc;
        guint8 major = tvb_get_guint8(tvb, offset);
        offset+=1;
        guint8 minor = tvb_get_guint8(tvb, offset);
        offset+=1;
        guint8 update = tvb_get_guint8(tvb, offset);
        offset+=1;
        guint8 alpha = tvb_get_guint8(tvb, offset);

	// major, minor and update fields are all BCD encoded
        if (major != 0xff) {
            rc = print_version_field(major, buf_ptr, buffer_size);
            POINTER_MOVE(rc, buf_ptr, buffer_size);
            rc = snprintf(buf_ptr, buffer_size, ".");
            POINTER_MOVE(rc, buf_ptr, buffer_size);
        }
	else{
	    rc = snprintf(buf_ptr, buffer_size, "-");
	    POINTER_MOVE(rc, buf_ptr, buffer_size);
	}
        if (minor != 0xff) {
            rc = print_version_field(minor, buf_ptr, buffer_size);
            POINTER_MOVE(rc, buf_ptr, buffer_size);
        }
	else{
            rc = snprintf(buf_ptr, buffer_size, "-");
            POINTER_MOVE(rc, buf_ptr, buffer_size);
        }
        if (update != 0xff) {
            rc = snprintf(buf_ptr, buffer_size, ".");
            POINTER_MOVE(rc, buf_ptr, buffer_size);
            rc = print_version_field(update, buf_ptr, buffer_size);
            POINTER_MOVE(rc, buf_ptr, buffer_size);
        }
	else{
            rc = snprintf(buf_ptr, buffer_size, "-");
            POINTER_MOVE(rc, buf_ptr, buffer_size);
        }
        if (alpha != 0x00) {
            rc = snprintf(buf_ptr, buffer_size, "%c", alpha);
            POINTER_MOVE(rc, buf_ptr, buffer_size);
        }
	else{
            rc = snprintf(buf_ptr, buffer_size, "-");
            POINTER_MOVE(rc, buf_ptr, buffer_size);
        }
}

int 
dissect_base(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *p_tree, void* data){
    struct packet_data *d = (struct packet_data*) data;
    static uint8_t pldmT = -1;

    guint8 instID = d->instance_id;
    guint8 request = d->direction;

    guint8 offset = 0;
    guint8 pldm_cmd = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(p_tree, hf_pldm_cmd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset +=1;
    if(!request) {
        proto_tree_add_item(p_tree, hf_completion_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        guint8 completion_code = tvb_get_guint8(tvb, offset);
        if (completion_code)
            return tvb_captured_length(tvb);
        offset +=1;
    }

    switch(pldm_cmd) {
    case 01: //SetTID
        if (request) {
            proto_tree_add_item(p_tree, hf_TIDValue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        break;
    case 02: //GetTID
        if (!request) {
            proto_tree_add_item(p_tree, hf_TIDValue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        break;
    case 03: //GetPLDMVersion
	     //untested
        if (request) {
            proto_tree_add_item(p_tree, hf_DataTransferHandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_item(p_tree, hf_TransferOperationFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_item(p_tree, hf_pldmSpec8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        else {
            proto_tree_add_item(p_tree, hf_NextDataTransferHandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(p_tree, hf_TransferFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            char buffer[10];
            ver2str(tvb, offset, buffer, 10);
            proto_tree_add_string(p_tree, hf_pldm_version, tvb, offset, 4, buffer);
            //possibly more than one entry
        }
        break;
    case 04: //GetPLDMTypes
	     //untested
        if (!request) {
            guint64 types = tvb_get_letoh64(tvb,offset);
            guint64 flag_bit, i;
            flag_bit= 1;
            for( i = 0 ; i < 64; i++, flag_bit<<=1 )
            {
                if(types & flag_bit)
                {
                    if(i>7 && i/8==0) offset+=1;
                    proto_tree_add_uint64(p_tree, hf_pldm_types , tvb, offset, 64, i);
                }
            }
        }
        break;
    case 05: //GetPLDMCommands
	     //untested
        if (request) {
            pldmT=tvb_get_guint8(tvb, offset);//error! reponse depends on this
            // this is ok for now because values 7 -> 62 are reserved
            if (pldmT == 63)
                pldmT = 7;
            pldmTA[pldmT]=1;
            pldmTI[instID][pldmT]=1;
            proto_tree_add_item(p_tree, hf_pldmSpec8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            char buffer[10];
            ver2str(tvb, offset, buffer, 10);
            proto_tree_add_string(p_tree, hf_pldm_version, tvb, offset, 4, buffer);
        }
        else if (!request) {
            if(pldmTI[instID][3]==1){
                guint16 byte=tvb_get_letohs(tvb, offset);
                guint16 flag_bit=1;
                for(guint8 i=0; i<16; i++, flag_bit<<=1){
                    if(i>7 && i%8==0) offset+=1;
                    if(byte & flag_bit){
                        proto_tree_add_uint(p_tree, hf_pldmBIOScmd, tvb, offset, 1, i);
                    }
                }
            }
            if(pldmTI[instID][0]==1){
                offset+=1;
                guint8 byte=tvb_get_guint8(tvb, offset);
                guint8 flag_bit=1;
                for(guint8 i=0; i<8; i++, flag_bit<<=1){
                    if(byte & flag_bit){
                        proto_tree_add_uint(p_tree, hf_pldm_cmd, tvb, offset, 1, i);
                    }
                }
            }
            if(pldmTI[instID][4]==1){
                offset+=1;
                guint64 byte=tvb_get_letoh64(tvb, offset);
                guint64 flag_bit=1;
                for(guint8 i=0; i<64; i++, flag_bit<<=1){
                    if(i>7 && i%8==0) offset+=1;
                    if(byte & flag_bit){
                        proto_tree_add_uint(p_tree, hf_pldmFruCmds, tvb, offset, 1, i);
                    }
                }
            }
            if(pldmTI[instID][2]==1){
                offset+=1;
                guint64 b1=tvb_get_letoh64(tvb, offset);
                guint64 b2=tvb_get_letoh64(tvb, offset+8);
                guint64 b3=tvb_get_letoh64(tvb, offset+16);
                guint64 b4=tvb_get_letoh64(tvb, offset+24);
                guint64 byt[4];
                byt[0]=b1;
                byt[1]=b2;
                byt[2]=b3;
                byt[3]=b4;
                guint64 flag_bit=1;
                for(guint8 i=0; i<88; i++, flag_bit<<=1){
                    if(i==64){
                        flag_bit=1;
                    }
                    int j=i/64;
                    if(i>7 && i%8==0) offset+=1;
                    guint64 byte= byt[j];
                    if(byte & flag_bit){
                        proto_tree_add_uint(p_tree, hf_pldmPlatformCmds, tvb, offset, 1, i);
                    }
                }
            }
            if(pldmTI[instID][7]==1){
                offset+=1;
                guint64 b1=tvb_get_letoh64(tvb, offset);
                guint64 b2=tvb_get_letoh64(tvb, offset+8);
                guint64 b3=tvb_get_letoh64(tvb, offset+16);
                guint64 b4=tvb_get_letoh64(tvb, offset+24);
                guint64 byt[4];
                byt[0]=b1;
                byt[1]=b2;
                byt[2]=b3;
                byt[3]=b4;
                guint64 flag_bit=1;
                for(guint8 i=0; i<16; i++, flag_bit<<=1){
                    if(i==64||i==128||i==192){
                        flag_bit=1;
                    }
                    int j=i/64;
                    if(i>7 && i%8==0){
                        offset+=1;
                    }
                    guint64 byte= byt[j];
                    if(byte & flag_bit){
                        proto_tree_add_uint(p_tree, hf_pldmOEMCmds, tvb, offset, 1, i);
                    }
                }
            }
        }
        break;
        default:
            col_append_fstr(pinfo->cinfo, COL_INFO, "Invalid PLDM command");
            g_print("Invalid PLDM cmd\n");
            break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_base(void)
{
    static hf_register_info hf[] ={
         { &hf_TIDValue,{
             "TID", "pldm.base.TID",
             FT_UINT8, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL}
         },
         {&hf_DataTransferHandle,{
            "Data Transfer Handle", "pldm.base.transferHandle",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
         }},
         {&hf_TransferOperationFlag,{
            "Transfer Operation Flag", "pldm.base.operationFlag",
            FT_UINT8, BASE_DEC,
            VALS(transferOperationFlags), 0x0,
            NULL, HFILL}
         },
         {&hf_NextDataTransferHandle,{
             "NextDataTransferHandle", "pldm.base.nextDataTransferHandle",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
            NULL, HFILL
         }},   
        {&hf_TransferFlag,{
            "Transfer Flag", "pldm.base.transferFlag",
            FT_UINT8, BASE_DEC,
            VALS(transferFlags), 0x0,
            NULL, HFILL
        }},
        {&hf_pldmSpec8,{
            "PLDMType requested", "pldm.base.ty",
            FT_UINT8, BASE_DEC,
            VALS(specNames), 0x0,
            NULL, HFILL
        }},
        {&hf_pldm_version,{
            "PLDM Version", "pldm.base.version",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
        }},
        {&hf_pldm_types,{
            "pldm type supported :", "pldm.base.type",
            FT_UINT64, BASE_DEC | BASE_VAL64_STRING ,
            VALS64(pldmTypes),0x0,
            NULL,HFILL
        }},
        { &hf_pldmBIOScmd,{
            "pldm type supported :", "pldm.base.xyz",
            FT_UINT8, BASE_DEC,
            VALS(pldmBIOScmd), 0x0,
            NULL, HFILL
        }}, 
        { &hf_pldmFruCmds,{
            "pldm type supported :", "pldm.base.fru",
            FT_UINT8, BASE_DEC,
            VALS(pldmFruCmds), 0x0,
            NULL, HFILL
        }},
        { &hf_pldmPlatformCmds, {
            "pldm type supported :", "pldm.base.platform",
            FT_UINT8, BASE_DEC,
            VALS(pldmPlatformCmds), 0x0,
            NULL, HFILL
        }},
        {&hf_pldmOEMCmds, {
            "pldm type supported :", "pldm.base.oem",
            FT_UINT8, BASE_DEC,
            VALS(pldmOEMCmds), 0x0,
            NULL, HFILL
        }},
        { &hf_pldm_cmd,{
            "PLDM Command", "pldm.cmd",
            FT_UINT8, BASE_HEX,
            VALS(pldmBaseCmd), 0x0,
            NULL, HFILL}
         },
         { &hf_completion_code,{
             "Completion Code", "pldm.cc",
             FT_UINT8, BASE_DEC,
             VALS(completion_codes), 0x0,
             NULL, HFILL}
         },
    };
    
    proto_pldm_base = proto_register_protocol (
        "PLDM base Protocol", /* name        */
        "PLDM_B",             /* short_name  */
        "pldm.base"           /* filter_name */
        );
    proto_register_field_array(proto_pldm_base, hf, array_length(hf));
}

void
proto_reg_handoff_base(void)
{
    static dissector_handle_t base_handle;
   
    base_handle = create_dissector_handle(dissect_base, proto_pldm_base);
    dissector_add_uint("wtap_encap", 147 , base_handle);
    dissector_add_uint("pldm.type", PLDM_DISCOVERY, base_handle);
}
