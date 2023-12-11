/* packet-pldm.c
  * Routines for Platform Level Data Model(PLDM) packet
  * disassembly
  * Copyright 2023, Riya Dixit <riyadixitagra@gmail.com>
  *
  * Wireshark - Network traffic analyzer
  * By Gerald Combs <gerald@wireshark.org>
  * Copyright 1998 Gerald Combs
  *
  * SPDX-License-Identifier: GPL-2.0-or-later
  */


#include "config.h"
#include <epan/packet.h>
#include <stdint.h>

#define PLDM_MIN_LENGTH 4
#define PLDM_MAX_TYPES 8

#define POINTER_MOVE(rc, buffer, buffer_size)                                  \
  do {                                                                         \
    if (rc < 0)                                                                \
      return;                                                                  \
    if ((size_t)rc >= buffer_size)                                             \
      return;                                                                  \
    buffer += rc;                                                              \
    buffer_size -= rc;                                                         \
  } while (0);


static int proto_pldm;
static int ett_pldm;

static int hf_pldm_msg_direction;
static int hf_pldm_instance_id;
static int hf_pldm_header_version;
static int hf_pldm_type;
static int hf_pldm_reserved;
static int hf_pldm_base_commands;
static int hf_pldm_BIOS_commands;
static int hf_pldm_FRU_commands;
static int hf_pldm_platform_commands;
static int hf_pldm_OEM_commands;
static int hf_pldm_base_typeVersion;
static int hf_pldm_base_PLDMtype;
static int hf_pldm_base_typesSupported;
static int hf_pldm_base_transferOperationFlag;
static int hf_pldm_base_nextDataTransferHandle;
static int hf_pldm_base_transferFlag;
static int hf_pldm_base_dataTransferHandle;
static int hf_pldm_base_TID;
static int hf_pldm_completion_code;

static int pldmTA[8] = {0}; //pldmTypes caching array for getPLDMCommands
static int pldmTI[32][8] = {0};//caching pldmTypes based on Instance ID

static const value_string directions[] = {{0, "response"},
                                          {1, "reserved"},
                                          {2, "request"},
                                          {3, "async/unack"},
                                          {0, NULL}};

static const value_string pldm_types[] = {
    {0, "PLDM Messaging and Discovery"},
    {1, "PLDM for SMBIOS"},
    {2, "PLDM Platform Monitoring and Control"},
    {3, "PLDM for BIOS Control and Configuration"},
    {4, "PLDM for FRU Data"},
    {5, "PLDM for Firmware Update"},
    {6, "PLDM for Redfish Device Enablement"},
    {63, "OEM Specific"},
    {0, NULL}};

static const value_string pldmBaseCmd[] = {{1, "Set TID"},
                                           {2, "Get TID"},
                                           {3, "Get PLDM Version"},
                                           {4, "Get PLDM Types"},
                                           {5, "GetPLDMCommands"},
                                           {6, "SelectPLDMVersion"},
                                           {7, "NegotiateTransferParameters"},
                                           {8, "Multipart Send"},
                                           {9, "Multipart Receive"},
                                           {0, NULL}};

static const value_string pldmPlatformCmds[] = {{4, "SetEventReceiver"},
                                                {10, "PlatformEventMessage"},
                                                {17, "GetSensorReading"},
                                                {33, "GetStateSensorReadings"},
                                                {49, "SetNumericEffecterValue"},
                                                {50, "GetNumericEffecterValue"},
                                                {57, "SetStateEffecterStates"},
                                                {81, "GetPDR"},
                                                {0, NULL}};

static const value_string pldmFruCmds[] = {{1, "GetFRURecordTableMetadata"},
                                           {2, "GetFRURecordTable"},
                                           {4, "GetFRURecordByOption"},
                                           {0, NULL}};

static const value_string pldmBIOScmd[] = {
    {1, "GetBIOSTable"},
    {2, "SetBIOSTable"},
    {7, "SetBIOSAttributeCurrentValue"},
    {8, "GetBIOSAttributeCurrentValueByHandle"},
    {12, "GetDateTime"},
    {13, "SetDateTime"},
    {0, NULL}};

static const value_string pldmOEMCmds[] = {{1, "GetFileTable"},
                                           {4, "ReadFile"},
                                           {5, "WriteFile"},
                                           {6, "ReadFileInToMemory"},
                                           {7, "WriteFileFromMemory"},
                                           {8, "ReadFileByTypeIntoMemory"},
                                           {9, "WriteFileByTypeFromMemory"},
                                           {10, "NewFileAvailable"},
                                           {11, "ReadFileByType"},
                                           {12, "WriteFileByType"},
                                           {13, "FileAck"},
                                           {0, NULL}};

static const value_string transferOperationFlags[] = {
    {0, "GetNextPart"}, {1, "GetFirstPart"}, {0, NULL}};

static const value_string transferFlags[] = {
    {1, "Start"}, {2, "Middle"}, {4, "End"}, {5, "StartAndEnd"}, {0, NULL}};

static const value_string completion_codes[] = {
    {0x0, "Success"},
    {0x1, "Error"},
    {0x2, "Invalid Data"},
    {0x3, "Invalid Length"},
    {0x4, "Not Ready"},
    {0x5, "Unsupported PLDM command"},
    {0x20, "Invalid PLDM type"},
    {0, NULL}};

struct packet_data {
  guint8 direction;
  guint8 instance_id;
};

static int print_version_field(guint8 bcd, char *buffer, size_t buffer_size) {
  int v;
  if (bcd == 0xff)
    return 0;
  if (((bcd) & 0xf0) == 0xf0) {
    v = (bcd) & 0x0f;
    return snprintf(buffer, buffer_size, "%d", v);
  }
  v = (((bcd) >> 4) * 10) + ((bcd) & 0x0f);
  return snprintf(buffer, buffer_size, "%02d", v);
}

static void ver2str(tvbuff_t *tvb, int offset, char *buf_ptr, size_t buffer_size) {
  int rc;
  guint8 major = tvb_get_guint8(tvb, offset);
  offset += 1;
  guint8 minor = tvb_get_guint8(tvb, offset);
  offset += 1;
  guint8 update = tvb_get_guint8(tvb, offset);
  offset += 1;
  guint8 alpha = tvb_get_guint8(tvb, offset);

  // major, minor and update fields are all BCD encoded
  if (major != 0xff) {
    rc = print_version_field(major, buf_ptr, buffer_size);
    POINTER_MOVE(rc, buf_ptr, buffer_size);
    rc = snprintf(buf_ptr, buffer_size, ".");
    POINTER_MOVE(rc, buf_ptr, buffer_size);
  } else {
    rc = snprintf(buf_ptr, buffer_size, "-");
    POINTER_MOVE(rc, buf_ptr, buffer_size);
  }
  if (minor != 0xff) {
    rc = print_version_field(minor, buf_ptr, buffer_size);
    POINTER_MOVE(rc, buf_ptr, buffer_size);
  } else {
    rc = snprintf(buf_ptr, buffer_size, "-");
    POINTER_MOVE(rc, buf_ptr, buffer_size);
  }
  if (update != 0xff) {
    rc = snprintf(buf_ptr, buffer_size, ".");
    POINTER_MOVE(rc, buf_ptr, buffer_size);
    rc = print_version_field(update, buf_ptr, buffer_size);
    POINTER_MOVE(rc, buf_ptr, buffer_size);
  } else {
    rc = snprintf(buf_ptr, buffer_size, "-");
    POINTER_MOVE(rc, buf_ptr, buffer_size);
  }
  if (alpha != 0x00) {
    rc = snprintf(buf_ptr, buffer_size, "%c", alpha);
    POINTER_MOVE(rc, buf_ptr, buffer_size);
  } else {
    rc = snprintf(buf_ptr, buffer_size, " ");
    POINTER_MOVE(rc, buf_ptr, buffer_size);
  }
}


static
int dissect_base(tvbuff_t *tvb, packet_info *pinfo, proto_tree *p_tree,
                 void *data) {
  struct packet_data *d = (struct packet_data *)data;
  static uint8_t pldmT = -1;

  guint8 instID = d->instance_id;
  guint8 request = d->direction;

  guint8 offset = 0;
  guint8 pldm_cmd = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(p_tree, hf_pldm_base_commands, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  if (!request) {//completion code in response only
    proto_tree_add_item(p_tree, hf_pldm_completion_code, tvb, offset, 1,
                        ENC_LITTLE_ENDIAN);
    guint8 completion_code = tvb_get_guint8(tvb, offset);
    if (completion_code)
      return tvb_captured_length(tvb);
    offset += 1;
  }
  switch (pldm_cmd) {
  case 01: // SetTID
    if (request) {
      proto_tree_add_item(p_tree, hf_pldm_base_TID, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  case 02: // GetTID
    if (!request) {
      proto_tree_add_item(p_tree, hf_pldm_base_TID, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  case 03: // GetPLDMVersion
    if (request) {
      proto_tree_add_item(p_tree, hf_pldm_base_dataTransferHandle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_pldm_base_transferOperationFlag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      proto_tree_add_item(p_tree, hf_pldm_base_PLDMtype, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
    } else {
      proto_tree_add_item(p_tree, hf_pldm_base_nextDataTransferHandle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_pldm_base_transferFlag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      char buffer[10];
      ver2str( tvb, offset, buffer, 10);
      proto_tree_add_string_format(p_tree, hf_pldm_base_typeVersion, tvb, offset, 4, buffer, "version : %s", buffer);
      // possibly more than one entry
    }
    break;
  case 04: // GetPLDMTypes
    if (!request) {
      guint8 flag_bit, type, supported_type;
      gint i, j;
      for( i=0; i<8; i++, offset+=1){
        type = tvb_get_guint8(tvb, offset);
        flag_bit = 1;
        for(j=0; j<8; j++, flag_bit <<=1){
          if(type & flag_bit){
            supported_type = i*8+j;
            proto_tree_add_uint(p_tree, hf_pldm_base_typesSupported, tvb, offset, 1, supported_type);
          }
        }
      }
    }
    break;
  case 05: // GetPLDMCommands
    if (request) {
      pldmT = tvb_get_guint8(tvb, offset); //reponse depends on this
      if (pldmT == 63)
        pldmT = 7;//for oem-specific inorder to avoid array of size 64
      pldmTA[pldmT] = 1;
      pldmTI[instID][pldmT] = 1;
      proto_tree_add_item(p_tree, hf_pldm_base_PLDMtype, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      char buffer[10];
      ver2str(tvb, offset, buffer, 10);
      proto_tree_add_string_format(p_tree, hf_pldm_base_typeVersion, tvb, offset, 4, buffer , "version : %s", buffer);
    } else if (!request) {
      if (pldmTI[instID][3] == 1) {
        guint16 byte = tvb_get_letohs(tvb, offset);
        guint16 flag_bit = 1;
        for (gint i = 0; i < 16; i++, flag_bit <<= 1) {
          if (i > 7 && i % 8 == 0)
            offset += 1;
          if (byte & flag_bit) {
            proto_tree_add_uint(p_tree, hf_pldm_BIOS_commands, tvb, offset, 1, i);
          }
        }
      }
      if (pldmTI[instID][0] == 1) {
        guint8 byte = tvb_get_guint8(tvb, offset);
        guint8 flag_bit = 1;
        for (gint i = 0; i < 8; i++, flag_bit <<= 1) {
          if (byte & flag_bit) {
            proto_tree_add_uint(p_tree, hf_pldm_base_commands, tvb, offset, 1, i);
          }
        }
      }
      if (pldmTI[instID][4] == 1) {
        guint64 byte = tvb_get_letoh64(tvb, offset);
        guint64 flag_bit = 1;
        for (gint i = 0; i < 64; i++, flag_bit <<= 1) {
          if (i > 7 && i % 8 == 0)
            offset += 1;
          if (byte & flag_bit) {
            proto_tree_add_uint(p_tree, hf_pldm_FRU_commands, tvb, offset, 1, i);
          }
        }
      }
      if (pldmTI[instID][2] == 1) {
        guint64 b1 = tvb_get_letoh64(tvb, offset);
        guint64 b2 = tvb_get_letoh64(tvb, offset + 8);
        guint64 b3 = tvb_get_letoh64(tvb, offset + 16);
        guint64 b4 = tvb_get_letoh64(tvb, offset + 24);
        guint64 byt[4];
        byt[0] = b1;
        byt[1] = b2;
        byt[2] = b3;
        byt[3] = b4;
        guint64 flag_bit = 1;
        for (gint i = 0; i < 88; i++, flag_bit <<= 1) {
          if (i == 64) {
            flag_bit = 1;
          }
          int j = i / 64;
          if (i > 7 && i % 8 == 0)
            offset += 1;
          guint64 byte = byt[j];
          if (byte & flag_bit) {
            proto_tree_add_uint(p_tree, hf_pldm_platform_commands, tvb, offset, 1, i);
          }
        }
      }
      if (pldmTI[instID][7] == 1) {
        guint64 b1 = tvb_get_letoh64(tvb, offset);
        guint64 b2 = tvb_get_letoh64(tvb, offset + 8);
        guint64 b3 = tvb_get_letoh64(tvb, offset + 16);
        guint64 b4 = tvb_get_letoh64(tvb, offset + 24);
        guint64 byt[4];
        byt[0] = b1;
        byt[1] = b2;
        byt[2] = b3;
        byt[3] = b4;
        guint64 flag_bit = 1;
        for (gint i = 0; i < 16; i++, flag_bit <<= 1) {
          if (i == 64 || i == 128 || i == 192) {
            flag_bit = 1;
          }
          int j = i / 64;
          if (i > 7 && i % 8 == 0) {
            offset += 1;
          }
          guint64 byte = byt[j];
          if (byte & flag_bit) {
            proto_tree_add_uint(p_tree, hf_pldm_OEM_commands, tvb, offset, 1, i);
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

static int dissect_pldm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        void *data _U_) {
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PLDM");
  col_clear(pinfo->cinfo, COL_INFO);

  tvbuff_t *next_tvb;
  guint len, direction;
  guint8 instID, pldm_type, offset;
  int reported_length;
  len = tvb_reported_length(tvb);
  if (len < PLDM_MIN_LENGTH) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "Packet length %u, minimum %u", len,
                 PLDM_MIN_LENGTH);
    return tvb_captured_length(tvb);
  }
  if (tree) {
    /* first byte is the MCTP msg type, it is 01 for PLDM over MCTP */
    offset = 1;
    proto_item *ti =
        proto_tree_add_item(tree, proto_pldm, tvb, offset, -1, ENC_NA);
    proto_tree *pldm_tree = proto_item_add_subtree(ti, ett_pldm);

    proto_tree_add_item(pldm_tree, hf_pldm_msg_direction, tvb, offset, 1,
                        ENC_LITTLE_ENDIAN);
    direction = tvb_get_bits8(tvb, offset * 8, 2);
    proto_tree_add_item(pldm_tree, hf_pldm_reserved, tvb, offset, 1,
                        ENC_LITTLE_ENDIAN);
    proto_tree_add_item(pldm_tree, hf_pldm_instance_id, tvb, offset, 1,
                        ENC_LITTLE_ENDIAN);
    instID = tvb_get_guint8(tvb, offset);
    instID = instID & 0x1F;
    offset += 1;
    pldm_type = tvb_get_bits8(tvb, offset * 8 + 2, 6);
    proto_tree_add_item(pldm_tree, hf_pldm_header_version, tvb, offset, 1,
                        ENC_LITTLE_ENDIAN);
    proto_tree_add_item(pldm_tree, hf_pldm_type, tvb, offset, 1,
                        ENC_LITTLE_ENDIAN);
    offset += 1;
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    reported_length = tvb_reported_length_remaining(tvb, offset);

    struct packet_data d = {direction, instID};
    if (reported_length >= 1) {
      switch(pldm_type){
        case 0:
               dissect_base(next_tvb, pinfo, pldm_tree, (void *)&d);
          break;
      }
    }
  }
  return tvb_captured_length(tvb);
}

void proto_register_pldm(void) {
  static hf_register_info hf[] = {
      {&hf_pldm_msg_direction,
       {"PLDM Message Direction", "pldm.direction", FT_UINT8, BASE_DEC, VALS(directions),
        0xc0, NULL, HFILL}},
      {&hf_pldm_reserved,
       {"PLDM Reserved Bit", "pldm.reservedBit", FT_UINT8, BASE_DEC, NULL, 0x20, NULL,
        HFILL}},
      {&hf_pldm_instance_id,
       {"PLDM Instance Id", "pldm.instanceID", FT_UINT8, BASE_DEC, NULL, 0x1F,
        NULL, HFILL}},
      {&hf_pldm_header_version,
       {"PLDM Header Version", "pldm.headerVersion", FT_UINT8, BASE_DEC, NULL, 0xC0, NULL,
        HFILL}},
      {&hf_pldm_type,
       {"PLDM Type", "pldm.type", FT_UINT8, BASE_HEX, VALS(pldm_types),
        0x3f, "PLDM Specification Type", HFILL}},
      {&hf_pldm_base_TID,
       {"TID Value", "pldm.base.TID", FT_UINT8, BASE_DEC, NULL, 0x0, "Terminus ID", HFILL}},
      {&hf_pldm_base_dataTransferHandle,
       {"Data Transfer Handle", "pldm.base.dataTransferHandle", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
      {&hf_pldm_base_transferOperationFlag,
       {"Transfer Operation Flag", "pldm.base.transferOperationFlag", FT_UINT8,
        BASE_HEX, VALS(transferOperationFlags), 0x0, NULL, HFILL}},
      {&hf_pldm_base_nextDataTransferHandle,
       {"Next Data Transfer Handle", "pldm.base.nextDataTransferHandle", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL}},
      {&hf_pldm_base_transferFlag,
       {"Transfer Flag", "pldm.base.transferFlag", FT_UINT8, BASE_HEX,
        VALS(transferFlags), 0x0, NULL, HFILL}},
      {&hf_pldm_base_PLDMtype,
       {"PLDM Type Requested", "pldm.base.pldmType", FT_UINT8, BASE_HEX,
        VALS(pldm_types), 0x0, "Requested PLDM Specification Type", HFILL}},
      {&hf_pldm_base_typeVersion,
       {"PLDM Type Version", "pldm.base.pldmTypeVersion", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
      {&hf_pldm_base_typesSupported,
       {"PLDM Type Supported", "pldm.base.typeSupported", FT_UINT8,
        BASE_HEX, VALS(pldm_types), 0x0, NULL, HFILL}},
      {&hf_pldm_BIOS_commands,
       {"BIOS Command", "pldm.biosCommands", FT_UINT8, BASE_HEX,
        VALS(pldmBIOScmd), 0x0, "BIOS Command Supported", HFILL}},
      {&hf_pldm_FRU_commands,
       {"FRU Command", "pldm.fruCommands", FT_UINT8, BASE_HEX,
        VALS(pldmFruCmds), 0x0, "FRU Command Supported", HFILL}},
      {&hf_pldm_platform_commands,
       {"Platform Command", "pldm.platformCommands", FT_UINT8, BASE_HEX,
        VALS(pldmPlatformCmds), 0x0, "Platform Command Supported", HFILL}},
      {&hf_pldm_OEM_commands,
       {"OEM Command", "pldm.oemCommands", FT_UINT8, BASE_HEX,
        VALS(pldmOEMCmds), 0x0, "OEM Command Supported", HFILL}},
      {&hf_pldm_base_commands,
       {"PLDM Base Command", "pldm.baseCommands", FT_UINT8, BASE_HEX, VALS(pldmBaseCmd), 0x0,
        "PLDM Messaging and Discovery Command Supported", HFILL}},
      {&hf_pldm_completion_code,
       {"Completion Code", "pldm.completionCode", FT_UINT8, BASE_DEC,
        VALS(completion_codes), 0x0, NULL, HFILL}},
  };

  static gint *ett[] = {&ett_pldm};
  proto_pldm = proto_register_protocol("PLDM Protocol", /* name        */
                                       "PLDM",          /* short_name  */
                                       "pldm"           /* filter_name */
  );
  proto_register_field_array(proto_pldm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("pldm", dissect_pldm, proto_pldm);
}

void proto_reg_handoff_pldm(void) {
  static dissector_handle_t pldm_handle;
  pldm_handle = create_dissector_handle(dissect_pldm, proto_pldm);
  dissector_add_uint("wtap_encap", 147, pldm_handle);
  dissector_add_uint("mctp.type", 1, pldm_handle);
}
