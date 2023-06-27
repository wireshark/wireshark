#include "packet-pldm-base.h"
#include <stdint.h>

static int proto_pldm_oem = -1;
static int hf_pldm_cmd = -1;
static int hf_completion_code = -1;
static int hf_file_data_handle = -1;
static int hf_file_transfer_op_flag = -1;
static int hf_file_table_type = -1;
static int hf_file_next_data_handle = -1;
static int hf_file_transfer_flag = -1;

static int hf_file_type = -1;
static int hf_file_name_handle = -1;
static int hf_file_handle = -1;
static int hf_file_offset = -1;
static int hf_file_length = -1;
static int hf_file_length_64 = -1;
static int hf_file_address = -1;

static const value_string pldm_cmds[] = {{0x01, "GetFileTable"},
                                         {0x02, "SetFileTable"},
                                         {0x03, "UpdateFileTable"},
                                         {0x04, "ReadFile"},
                                         {0x05, "WriteFile"},
                                         {0x06, "ReadFileIntoMemory"},
                                         {0x07, "WriteFileFromMemory"},
                                         {0x08, "ReadFileByTypeIntoMemory"},
                                         {0x09, "WriteFileByTypeFromMemory"},
                                         {0x0a, "NewFileAvailable"},
                                         {0x0b, "ReadFileByType"},
                                         {0x0c, "WriteFileByType"},
                                         {0x0d, "FileAck"},
                                         {0x0e, "NewFileAvailableWithMetadata"},
                                         {0x0f, "FileAckWithMetadata"},
                                         {0, NULL}};

static const value_string completion_codes[] = {
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
    {0x83, "File table unavailable"},
    {0x84, "Invalid file table integrity check"},
    {0x85, "Invalid file table"},
    {0x86, "Invalid file handle"},
    {0x87, "Data out of range"},
    {0x88, "Read only"},
    {0x89, "Invalid file type"},
    {0x8a, "Error file discarded"},
    {0x8b, "Full file discarded"},
    {0, NULL}};

static const value_string file_table_types[] = {
    {0x0, "File Attribute Table"},
    {0x1, "OEM File Attribute Table"},
    {0, NULL}};

static const value_string transfer_op_flags[] = {
    {0x0, "Get Next Part"}, {0x1, "Get First Part"}, {0, NULL}};

static const value_string transfer_flags[] = {{0x1, "Start"},
                                              {0x2, "Middle"},
                                              {0x4, "End"},
                                              {0x5, "Start and End"},
                                              {0, NULL}};

int dissect_oem(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *p_tree,
                void *data) {
  struct packet_data *d = (struct packet_data *)data;
  guint8 request = d->direction;
  guint8 offset = 0;
  guint8 pldm_cmd = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(p_tree, hf_pldm_cmd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  if (!request) {
    proto_tree_add_item(p_tree, hf_completion_code, tvb, offset, 1,
                        ENC_LITTLE_ENDIAN);
    guint8 completion_code = tvb_get_guint8(tvb, offset);
    if (completion_code)
      return tvb_captured_length(tvb);
    offset += 1;
  }
  switch (pldm_cmd) {
  case 0x1: // Get File Table
    if (request) {
      proto_tree_add_item(p_tree, hf_file_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_transfer_op_flag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      proto_tree_add_item(p_tree, hf_file_table_type, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
    } else {
      proto_tree_add_item(p_tree, hf_file_next_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_transfer_flag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  case 0x4: // Read File
  case 0x5: // Write File
    if (request) {
      proto_tree_add_item(p_tree, hf_file_name_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_offset, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    } else {
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  case 0x6: // Read File into memory
  case 0x7: // Write File from memory
    if (request) {
      proto_tree_add_item(p_tree, hf_file_name_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_offset, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_address, tvb, offset, 8,
                          ENC_LITTLE_ENDIAN);
    } else {
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  case 0x8: // Read File by type into memory
  case 0x9: // Write File by type into memory
    if (request) {
      proto_tree_add_item(p_tree, hf_file_type, tvb, offset, 2,
                          ENC_LITTLE_ENDIAN);
      offset += 2;
      proto_tree_add_item(p_tree, hf_file_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_offset, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_address, tvb, offset, 8,
                          ENC_LITTLE_ENDIAN);
    } else {
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  case 0xa: // New File Available
    if (request) {
      proto_tree_add_item(p_tree, hf_file_type, tvb, offset, 2,
                          ENC_LITTLE_ENDIAN);
      offset += 2;
      proto_tree_add_item(p_tree, hf_file_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_length_64, tvb, offset, 8,
                          ENC_LITTLE_ENDIAN);
    } else {
    }
    break;
  case 0xb: // Read File by Type
    if (request) {
      proto_tree_add_item(p_tree, hf_file_type, tvb, offset, 2,
                          ENC_LITTLE_ENDIAN);
      offset += 2;
      proto_tree_add_item(p_tree, hf_file_name_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_offset, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    } else {
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  case 0xc: // Write File by Type
    if (request) {
      proto_tree_add_item(p_tree, hf_file_type, tvb, offset, 2,
                          ENC_LITTLE_ENDIAN);
      offset += 2;
      proto_tree_add_item(p_tree, hf_file_name_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_offset, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    } else {
      proto_tree_add_item(p_tree, hf_file_length, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  default:
    col_append_fstr(pinfo->cinfo, COL_INFO,
                    "Unsupported or Invalid PLDM command");
    g_print("Invalid PLDM oem cmd %x \n", pldm_cmd);
    break;
  }
  return tvb_captured_length(tvb);
}

void proto_register_oem(void) {
  static hf_register_info hf[] = {
      {&hf_pldm_cmd,
       {"PLDM Command Type", "pldm.cmd", FT_UINT8, BASE_HEX, VALS(pldm_cmds),
        0x0, NULL, HFILL}},
      {&hf_completion_code,
       {"Completion Code", "pldm.cc", FT_UINT8, BASE_DEC,
        VALS(completion_codes), 0x0, NULL, HFILL}},
      {&hf_file_data_handle,
       {"Data transfer handle", "pldm.file.table.handle", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_file_transfer_op_flag,
       {"Data transfer operation flag", "pldm.file.table.opflag", FT_UINT8,
        BASE_HEX, VALS(transfer_op_flags), 0x0, NULL, HFILL}},
      {&hf_file_table_type,
       {"File table type", "pldm.oem.table.type", FT_UINT8, BASE_HEX,
        VALS(file_table_types), 0x0, NULL, HFILL}},
      {&hf_file_next_data_handle,
       {"Next data transfer handle", "pldm.oem.table.nexthandle", FT_UINT32,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_file_transfer_flag,
       {"Data transfer operation flag", "pldm.file.table.flag", FT_UINT8,
        BASE_HEX, VALS(transfer_flags), 0x0, NULL, HFILL}},
      {&hf_file_type,
       {"File type", "pldm.file.type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_file_name_handle,
       {"File name handle", "pldm.file.name_handle", FT_UINT32, BASE_HEX, NULL,
        0x0, NULL, HFILL}},
      {&hf_file_handle,
       {"File handle", "pldm.file.handle", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_file_offset,
       {"File offset", "pldm.file.offset", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_file_length,
       {"File length", "pldm.file.length", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_file_length_64,
       {"File length", "pldm.file.length", FT_UINT64, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_file_address,
       {"File address", "pldm.file.address", FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},
  };

  proto_pldm_oem = proto_register_protocol("PLDM OEM Protocol", /* name */
                                           "PLDM_OEM", /* short_name  */
                                           "pldm.oem"  /* filter_name */
  );
  proto_register_field_array(proto_pldm_oem, hf, array_length(hf));
}

void proto_reg_handoff_oem(void) {
  static dissector_handle_t oem_handle;

  oem_handle = create_dissector_handle(dissect_oem, proto_pldm_oem);
  dissector_add_uint("pldm.type", PLDM_OEM, oem_handle);
}
