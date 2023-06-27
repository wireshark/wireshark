#include "packet-pldm-base.h"
#include <stdint.h>

// BIOS table
static int proto_pldm_bios = -1;
static int hf_pldm_cmd = -1;
static int hf_completion_code = -1;
static int hf_bios_data_handle = -1;
static int hf_bios_transfer_op_flag = -1;
static int hf_bios_table_type = -1;
static int hf_bios_next_data_handle = -1;
static int hf_bios_transfer_flag = -1;
static int hf_bios_attr_handle = -1;
static int hf_bios_attr_type = -1;
static int hf_bios_attr_name_handle = -1;
static int hf_bios_enumer_num_pos_values = -1;
static int hf_bios_enumer_pos_value_str_hndl = -1;
static int hf_bios_enumer_num_default_values = -1;
static int hf_bios_enumer_default_value_str_hndl = -1;
static int hf_bios_attr_table_pad_bytes = -1;
static int hf_bios_attr_table_checksum = -1;
static int hf_bios_str_handle = -1;
static int hf_bios_str_len = -1;
static int hf_bios_str = -1;
static int hf_bios_string_type = -1;
static int hf_bios_min_str_len = -1;
static int hf_bios_max_str_len = -1;
static int hf_bios_def_str_len = -1;
static int hf_bios_def_str = -1;
static int hf_bios_int_lower_bound = -1;
static int hf_bios_int_upper_bound = -1;
static int hf_bios_int_scalar_inc = -1;
static int hf_bios_int_def_val = -1;
static int hf_bios_boot_config_type = -1;
static int hf_bios_fail_through_modes = -1;
static int hf_bios_min_num_boot_src = -1;
static int hf_bios_max_num_boot_src = -1;
static int hf_bios_pos_num_boot_src = -1;
static int hf_bios_src_str_hndl = -1;
static int hf_bios_col_name_str_hndl = -1;
static int hf_bios_max_num_attr = -1;
static int hf_bios_col_type = -1;
static int hf_bios_num_pos_config = -1;
static int hf_bios_pos_config_str_hndl = -1;
static int hf_bios_enumer_num_cur_values = -1;
static int hf_bios_enumer_cur_value_str_hndl = -1;
static int hf_bios_cur_str_len = -1;
static int hf_bios_cur_str = -1;
static int hf_bios_cur_pass_len = -1;
static int hf_bios_cur_pass = -1;
static int hf_bios_cur_val = -1;
static int hf_bios_num_boot_src = -1;
static int hf_bios_boot_src_str_hndl = -1;
static int hf_bios_num_attr = -1;
static int hf_bios_attr_hndl = -1;
static int hf_bios_cur_config_set_str_hndl = -1;
static int hf_bios_enumer_num_pen_values = -1;
static int hf_bios_enumer_pen_value_str_hndl = -1;
static int hf_bios_pen_str_len = -1;
static int hf_bios_pen_str = -1;
static int hf_bios_pen_pass_len = -1;
static int hf_bios_pen_pass = -1;
static int hf_bios_pen_val = -1;
static int hf_bios_config_set_str_hndl = -1;
static int hf_bios_pass_type = -1;
static int hf_bios_min_pass_len = -1;
static int hf_bios_max_pass_len = -1;
static int hf_bios_def_pass_len = -1;
static int hf_bios_def_pass = -1;
static int hf_bios_num_pen_boot_src = -1;

// Date and Time
static int hf_pldm_time = -1;
static int hf_pldm_date = -1;
guint8 table_type = 0;

static const value_string pldm_cmds[] = {
    {0x01, "GetBIOSTable"},
    {0x02, "SetBIOSTable"},
    {0x03, "UpdateBIOSTable"},
    {0x04, "GetBIOSTableTags"},
    {0x05, "SetBIOSTableTags"},
    {0x06, "AcceptBIOSAttributesPending"},
    {0x07, "SetBIOSAttributeCurrentValue"},
    {0x08, "GetBIOSAttributeCurrentValueByHandle"},
    {0x09, "GetBIOSAttributePendingValueByHandle"},
    {0x0a, "GetBIOSAttributeCurrentValueByType"},
    {0x0b, "GetBIOSAttributePendingValueByType"},
    {0x0c, "GetDateTime"},
    {0x0d, "SetDateTime"},
    {0x0e, "GetBIOSStringTableStringType"},
    {0x0f, "SetBIOSStringTableStringType"},
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
    {0x83, "BIOS table unavailable"},
    {0x84, "Invalid BIOS table integrity check"},
    {0x85, "Invalid BIOS table"},
    {0x86, "BIOS table tag unavailable"},
    {0x87, "Invalid BIOS table tag type"},
    {0x88, "Invalid BIOS attr handle"},
    {0x89, "Invalid BIOS attr type"},
    {0x8a, "No date time info available"},
    {0x8b, "Invalid string type"},
    {0, NULL}};

static const value_string bios_table_types[] = {
    {0x0, "BIOS String Table"},
    {0x1, "BIOS Attribute Table"},
    {0x2, "BIOS Attribute Value Table"},
    {0x3, "BIOS Attribute Pending Value Table"},
    {0, NULL}};

static const value_string transfer_op_flags[] = {
    {0x0, "Get Next Part"}, {0x1, "Get First Part"}, {0, NULL}};

static const value_string transfer_flags[] = {{0x1, "Start"},
                                              {0x2, "Middle"},
                                              {0x4, "End"},
                                              {0x5, "Start and End"},
                                              {0, NULL}};

static const value_string bios_attribute_type[] = {
    {0x0, "BIOSEnumeration"},
    {0x1, "BIOSString"},
    {0x2, "BIOSPassword"},
    {0x3, "BIOSInteger"},
    {0x4, "BIOSBootConfigSetting"},
    {0x5, "BIOSCollection"},
    {0x6, "BIOSConfigSet"},
    {0x80, "BIOSEnumerationReadOnly"},
    {0x81, "BIOSStringRaedOnly"},
    {0x82, "BIOSPasswordReadOnly"},
    {0x83, "BIOSIntegerReadOnly"},
    {0x84, "BiosPasswordReadOnly"},
    {0x85, "BIOSCollectionReadOnly"},
    {0x86, "BIOSConfigSetReadOnly"}};

#define BCD44_TO_DEC(x) ((((x)&0xf0) >> 4) * 10 + ((x)&0x0f))

void dissect_bios_string_table(tvbuff_t *tvb, proto_tree *p_tree,
                               guint16 *offset, packet_info *pinfo) {
  guint16 len = tvb_reported_length(tvb);
  guint16 rem_bytes = len - 27;
  guint16 str_len = 0;
  int num_pad_bytes = 0;
  while (rem_bytes >= 8) {
    proto_tree_add_item(p_tree, hf_bios_str_handle, tvb, *offset, 2,
                        ENC_LITTLE_ENDIAN);
    *offset += 2;
    str_len = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(p_tree, hf_bios_str_len, tvb, *offset, 2,
                        ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(p_tree, hf_bios_str, tvb, *offset, str_len, ENC_ASCII);
    proto_item_append_text(
        p_tree, ": %s",
        tvb_get_string_enc(pinfo->pool, tvb, *offset, str_len, ENC_ASCII));
    *offset += str_len;
    rem_bytes = rem_bytes - 4 - str_len;
    str_len = 0;
  }
  proto_tree_add_item(p_tree, hf_bios_attr_table_pad_bytes, tvb, *offset,
                      num_pad_bytes, ENC_LITTLE_ENDIAN);
  *offset += num_pad_bytes;
  proto_tree_add_item(p_tree, hf_bios_attr_table_checksum, tvb, *offset, 4,
                      ENC_LITTLE_ENDIAN);
  return;
}

void dissect_bios_attribute_table(tvbuff_t *tvb, proto_tree *p_tree,
                                  guint16 *offset, packet_info *pinfo) {
  guint16 len = tvb_reported_length(tvb);
  guint16 rem_bytes = len - 27;
  int len_attr_fields = 0;
  guint16 num_values = 0;
  guint8 attr_type = 0;
  int num_pad_bytes = 0;
  while (rem_bytes >= 8) {
    proto_tree_add_item(p_tree, hf_bios_attr_handle, tvb, *offset, 2,
                        ENC_LITTLE_ENDIAN);
    *offset += 2;
    attr_type = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(p_tree, hf_bios_attr_type, tvb, *offset, 1,
                        ENC_LITTLE_ENDIAN);
    *offset += 1;
    proto_tree_add_item(p_tree, hf_bios_attr_name_handle, tvb, *offset, 2,
                        ENC_LITTLE_ENDIAN);
    *offset += 2;
    if (attr_type == 0 || attr_type == 128) {
      num_values = tvb_get_guint8(tvb, *offset);
      proto_tree_add_item(p_tree, hf_bios_enumer_num_pos_values, tvb, *offset,
                          1, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values > 0) {
        proto_tree_add_item(p_tree, hf_bios_enumer_pos_value_str_hndl, tvb,
                            *offset, 2, ENC_LITTLE_ENDIAN);
        *offset += 2;
        len_attr_fields += 2;
        num_values--;
      }
      num_values = tvb_get_guint8(tvb, *offset);
      proto_tree_add_item(p_tree, hf_bios_enumer_num_default_values, tvb,
                          *offset, 1, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values > 0) {
        proto_tree_add_item(p_tree, hf_bios_enumer_default_value_str_hndl, tvb,
                            *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
        len_attr_fields += 1;
        num_values--;
      }
    } else if (attr_type == 1 || attr_type == 129) {
      proto_tree_add_item(p_tree, hf_bios_string_type, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_min_str_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      proto_tree_add_item(p_tree, hf_bios_max_str_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      proto_tree_add_item(p_tree, hf_bios_def_str_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      guint16 def_str_len = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      if (def_str_len != 0) {
        proto_tree_add_item(p_tree, hf_bios_def_str, tvb, *offset, def_str_len,
                            ENC_ASCII);
        proto_item_append_text(p_tree, ": %s",
                               tvb_get_string_enc(pinfo->pool, tvb, *offset,
                                                  def_str_len, ENC_ASCII));
        *offset += def_str_len;
        len_attr_fields += def_str_len;
      }
    } else if (attr_type == 2 || attr_type == 130) {
      proto_tree_add_item(p_tree, hf_bios_pass_type, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_min_pass_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      proto_tree_add_item(p_tree, hf_bios_max_pass_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      guint8 def_pass_len = tvb_get_guint8(tvb, *offset);
      proto_tree_add_item(p_tree, hf_bios_def_pass_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      if (def_pass_len != 0) {
        proto_tree_add_item(p_tree, hf_bios_def_pass, tvb, *offset,
                            hf_bios_def_str_len, ENC_LITTLE_ENDIAN);
        *offset += def_pass_len;
        len_attr_fields += def_pass_len;
      }
    } else if (attr_type == 3 || attr_type == 131) {
      proto_tree_add_item(p_tree, hf_bios_int_lower_bound, tvb, *offset, 8,
                          ENC_LITTLE_ENDIAN);
      *offset += 8;
      len_attr_fields += 8;
      proto_tree_add_item(p_tree, hf_bios_int_upper_bound, tvb, *offset, 8,
                          ENC_LITTLE_ENDIAN);
      *offset += 8;
      len_attr_fields += 8;
      proto_tree_add_item(p_tree, hf_bios_int_scalar_inc, tvb, *offset, 4,
                          ENC_LITTLE_ENDIAN);
      *offset += 4;
      len_attr_fields += 4;
      proto_tree_add_item(p_tree, hf_bios_int_def_val, tvb, *offset, 8,
                          ENC_LITTLE_ENDIAN);
      *offset += 8;
      len_attr_fields += 8;
    } else if (attr_type == 4 || attr_type == 132) {
      proto_tree_add_item(p_tree, hf_bios_boot_config_type, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_fail_through_modes, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_min_num_boot_src, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_max_num_boot_src, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_pos_num_boot_src, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      num_values = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values > 0) {
        proto_tree_add_item(p_tree, hf_bios_src_str_hndl, tvb, *offset, 2,
                            ENC_LITTLE_ENDIAN);
        *offset += 2;
        len_attr_fields += 2;
        num_values--;
      }
    } else if (attr_type == 5 || attr_type == 133) {
      proto_tree_add_item(p_tree, hf_bios_col_name_str_hndl, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      proto_tree_add_item(p_tree, hf_bios_max_num_attr, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_col_type, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
    } else if (attr_type == 6 || attr_type == 134) {
      proto_tree_add_item(p_tree, hf_bios_num_pos_config, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      num_values = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values > 0) {
        proto_tree_add_item(p_tree, hf_bios_pos_config_str_hndl, tvb, *offset,
                            2, ENC_LITTLE_ENDIAN);
        *offset += 2;
        len_attr_fields += 2;
        num_values--;
      }
    }
    if (rem_bytes == 8)
      break;
    else if (rem_bytes < len_attr_fields + 5) {
      num_pad_bytes = rem_bytes % 4;
      rem_bytes = 8;
    } else
      rem_bytes = rem_bytes - 5 - len_attr_fields;
    len_attr_fields = 0;
  }
  proto_tree_add_item(p_tree, hf_bios_attr_table_pad_bytes, tvb, *offset,
                      num_pad_bytes, ENC_LITTLE_ENDIAN);
  *offset += num_pad_bytes;
  proto_tree_add_item(p_tree, hf_bios_attr_table_checksum, tvb, *offset, 4,
                      ENC_LITTLE_ENDIAN);
  return;
}

void dissect_bios_attribute_val_table(tvbuff_t *tvb, proto_tree *p_tree,
                                      guint16 *offset) {
  guint16 len = tvb_reported_length(tvb);
  guint16 rem_bytes = len - 27;
  int len_attr_fields = 0;
  guint16 num_values = 0;
  guint8 attr_type = 0;
  int num_pad_bytes = 0;
  while (rem_bytes >= 8 && rem_bytes > 0) {
    proto_tree_add_item(p_tree, hf_bios_attr_handle, tvb, *offset, 2,
                        ENC_LITTLE_ENDIAN);
    *offset += 2;
    attr_type = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(p_tree, hf_bios_attr_type, tvb, *offset, 1,
                        ENC_LITTLE_ENDIAN);
    *offset += 1;
    if (attr_type == 0 || attr_type == 128) {
      num_values = tvb_get_guint8(tvb, *offset);
      proto_tree_add_item(p_tree, hf_bios_enumer_num_cur_values, tvb, *offset,
                          1, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values > 0) {
        proto_tree_add_item(p_tree, hf_bios_enumer_cur_value_str_hndl, tvb,
                            *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
        len_attr_fields += 1;
        num_values--;
      }
    } else if (attr_type == 1 || attr_type == 129) {
      proto_tree_add_item(p_tree, hf_bios_cur_str_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      guint16 cur_str_len = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(p_tree, hf_bios_cur_str, tvb, *offset,
                          hf_bios_cur_str_len, ENC_LITTLE_ENDIAN);
      *offset += cur_str_len;
      len_attr_fields += cur_str_len;
    } else if (attr_type == 2 || attr_type == 130) {
      proto_tree_add_item(p_tree, hf_bios_cur_pass_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      guint16 cur_pass_len = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(p_tree, hf_bios_cur_pass, tvb, *offset,
                          hf_bios_cur_pass_len, ENC_LITTLE_ENDIAN);
      *offset += cur_pass_len;
      len_attr_fields += cur_pass_len;
    } else if (attr_type == 3 || attr_type == 131) {
      proto_tree_add_item(p_tree, hf_bios_cur_val, tvb, *offset, 8,
                          ENC_LITTLE_ENDIAN);
      *offset += 8;
      len_attr_fields += 8;
    } else if (attr_type == 4 || attr_type == 132) {
      proto_tree_add_item(p_tree, hf_bios_boot_config_type, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_fail_through_modes, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_num_boot_src, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      num_values = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values >= 0) {
        proto_tree_add_item(p_tree, hf_bios_boot_src_str_hndl, tvb, *offset, 1,
                            ENC_LITTLE_ENDIAN);
        *offset += 1;
        len_attr_fields += 1;
        num_values--;
      }
    } else if (attr_type == 5 || attr_type == 133) {
      proto_tree_add_item(p_tree, hf_bios_num_attr, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      num_values = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values > 0) {
        proto_tree_add_item(p_tree, hf_bios_attr_hndl, tvb, *offset, 2,
                            ENC_LITTLE_ENDIAN);
        *offset += 2;
        len_attr_fields += 2;
        num_values--;
      }
    } else if (attr_type == 6 || attr_type == 134) {
      proto_tree_add_item(p_tree, hf_bios_cur_config_set_str_hndl, tvb,
                          (*offset), 1, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
    }
    if (rem_bytes == 8)
      break;
    else if (rem_bytes < len_attr_fields + 3) {
      num_pad_bytes = rem_bytes % 4;
      rem_bytes = 8;
    } else
      rem_bytes = rem_bytes - 3 - len_attr_fields;
    len_attr_fields = 0;
  }
  proto_tree_add_item(p_tree, hf_bios_attr_table_pad_bytes, tvb, *offset,
                      num_pad_bytes, ENC_LITTLE_ENDIAN);
  *offset += num_pad_bytes;
  proto_tree_add_item(p_tree, hf_bios_attr_table_checksum, tvb, *offset, 4,
                      ENC_LITTLE_ENDIAN);
  return;
}

void dissect_bios_attribute_pending_val_table(tvbuff_t *tvb, proto_tree *p_tree,
                                              guint16(*offset)) {
  guint16 len = tvb_reported_length(tvb);
  guint16 rem_bytes = len - 27;
  int len_attr_fields = 0;
  guint16 num_values = 0;
  guint8 attr_type = 0;
  int num_pad_bytes = 0;
  while (rem_bytes >= 8 && rem_bytes > 0) {
    proto_tree_add_item(p_tree, hf_bios_attr_handle, tvb, *offset, 2,
                        ENC_LITTLE_ENDIAN);
    *offset += 2;
    attr_type = tvb_get_guint8(tvb, *offset);
    proto_tree_add_item(p_tree, hf_bios_attr_type, tvb, *offset, 1,
                        ENC_LITTLE_ENDIAN);
    *offset += 1;
    if (attr_type == 0) {
      num_values = tvb_get_guint8(tvb, *offset);
      proto_tree_add_item(p_tree, hf_bios_enumer_num_pen_values, tvb, *offset,
                          1, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values > 0) {
        proto_tree_add_item(p_tree, hf_bios_enumer_pen_value_str_hndl, tvb,
                            *offset, 1, ENC_LITTLE_ENDIAN);
        *offset += 1;
        len_attr_fields += 1;
        num_values--;
      }
    } else if (attr_type == 1) {
      guint16 pen_str_len = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(p_tree, hf_bios_pen_str_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      proto_tree_add_item(p_tree, hf_bios_pen_str, tvb, *offset,
                          hf_bios_cur_str_len, ENC_LITTLE_ENDIAN);
      *offset += pen_str_len;
      len_attr_fields += pen_str_len;
    } else if (attr_type == 2) {
      guint16 pen_pass_len = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(p_tree, hf_bios_pen_pass_len, tvb, *offset, 2,
                          ENC_LITTLE_ENDIAN);
      *offset += 2;
      len_attr_fields += 2;
      proto_tree_add_item(p_tree, hf_bios_pen_pass, tvb, *offset,
                          hf_bios_cur_pass_len, ENC_LITTLE_ENDIAN);
      *offset += pen_pass_len;
      len_attr_fields += pen_pass_len;
    } else if (attr_type == 3) {
      proto_tree_add_item(p_tree, hf_bios_pen_val, tvb, *offset, 8,
                          ENC_LITTLE_ENDIAN);
      *offset += 8;
      len_attr_fields += 8;
    } else if (attr_type == 4) {
      proto_tree_add_item(p_tree, hf_bios_boot_config_type, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_fail_through_modes, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      proto_tree_add_item(p_tree, hf_bios_num_pen_boot_src, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      num_values = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values > 0) {
        proto_tree_add_item(p_tree, hf_bios_boot_src_str_hndl, tvb, *offset, 1,
                            ENC_LITTLE_ENDIAN);
        *offset += 1;
        len_attr_fields += 1;
        num_values--;
      }
    } else if (attr_type == 5 || attr_type == 133) {
      proto_tree_add_item(p_tree, hf_bios_num_attr, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      num_values = tvb_get_guint16(tvb, *offset, ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
      while (num_values > 0) {
        proto_tree_add_item(p_tree, hf_bios_attr_hndl, tvb, *offset, 2,
                            ENC_LITTLE_ENDIAN);
        *offset += 2;
        len_attr_fields += 2;
        num_values--;
      }
    } else if (attr_type == 6) {
      proto_tree_add_item(p_tree, hf_bios_config_set_str_hndl, tvb, *offset, 1,
                          ENC_LITTLE_ENDIAN);
      *offset += 1;
      len_attr_fields += 1;
    }
    if (rem_bytes == 8)
      break;
    else if (rem_bytes < len_attr_fields + 3) {
      num_pad_bytes = rem_bytes % 4;
      rem_bytes = 8;
    } else
      rem_bytes = rem_bytes - 3 - len_attr_fields;
    len_attr_fields = 0;
  }
  proto_tree_add_item(p_tree, hf_bios_attr_table_pad_bytes, tvb, *offset,
                      num_pad_bytes, ENC_LITTLE_ENDIAN);
  *offset += num_pad_bytes;
  proto_tree_add_item(p_tree, hf_bios_attr_table_checksum, tvb, *offset, 4,
                      ENC_LITTLE_ENDIAN);
  return;
}

int dissect_bios(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *p_tree,
                 void *data) {
  struct packet_data *d = (struct packet_data *)data;
  guint8 request = d->direction;
  guint8 pldm_cmd = tvb_get_guint8(tvb, 0);
  guint16 offset = 0;
  guint8 hour, min, sec;
  proto_tree_add_item(p_tree, hf_pldm_cmd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  if (!request) {
    proto_tree_add_item(p_tree, hf_completion_code, tvb, 1, 1,
                        ENC_LITTLE_ENDIAN);
    guint8 completion_code = tvb_get_guint8(tvb, offset);
    if (completion_code)
      return tvb_captured_length(tvb);
    offset += 1;
  }
  switch (pldm_cmd) {
  case 0x1: // Get BIOS Table
    if (request) {
      proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_bios_transfer_op_flag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      proto_tree_add_item(p_tree, hf_bios_table_type, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      table_type = tvb_get_guint8(tvb, offset);
    } else {
      proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      if (table_type == 0) {
        dissect_bios_string_table(tvb, p_tree, &offset, pinfo);
      } else if (table_type == 1) {
        dissect_bios_attribute_table(tvb, p_tree, &offset, pinfo);
      } else if (table_type == 2) {
        dissect_bios_attribute_val_table(tvb, p_tree, &offset);
      } else if (table_type == 3) {
        dissect_bios_attribute_pending_val_table(tvb, p_tree, &offset);
      }
    }
    break;
  case 0x02: // Set BIOS Table
    if (request) {
      proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      proto_tree_add_item(p_tree, hf_bios_table_type, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      table_type = tvb_get_guint8(tvb, offset);
      offset += 1;
      if (table_type == 0) {
        dissect_bios_string_table(tvb, p_tree, &offset, pinfo);
      } else if (table_type == 1) {
        dissect_bios_attribute_table(tvb, p_tree, &offset, pinfo);
      } else if (table_type == 2) {
        dissect_bios_attribute_val_table(tvb, p_tree, &offset);
      }
    } else {
      proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  case 0x07: // Set BIOS Attribute Current Value
    if (request) {
      proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
    } else {
      proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
    }
    break;
  case 0x08: // Get BIOS Attribute Current Value by Handle
    if (request) {
      proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_bios_transfer_op_flag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      proto_tree_add_item(p_tree, hf_bios_attr_handle, tvb, offset, 2,
                          ENC_LITTLE_ENDIAN);
    } else {
      proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4,
                          ENC_LITTLE_ENDIAN);
      offset += 4;
      proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1,
                          ENC_LITTLE_ENDIAN);
      offset += 1;
      dissect_bios_attribute_val_table(tvb, p_tree, &offset);
    }
    break;
  case 0x0c: // Get Date and Time
    if (!request) {
      sec = BCD44_TO_DEC(tvb_get_guint8(tvb, offset));
      min = BCD44_TO_DEC(tvb_get_guint8(tvb, offset + 1));
      hour = BCD44_TO_DEC(tvb_get_guint8(tvb, offset + 2));
      if (hour > 23 || min > 59 || sec > 59)
        return -1;
      char time[9];
      snprintf(time, 9, "%02d:%02d:%02d", hour, min, sec);
      proto_tree_add_string(p_tree, hf_pldm_time, tvb, offset, 3, time);
      offset += 3;
      guint8 day = BCD44_TO_DEC(tvb_get_guint8(tvb, offset));
      guint8 month = BCD44_TO_DEC(tvb_get_guint8(tvb, offset + 1));
      guint16 year = BCD44_TO_DEC(tvb_get_guint8(tvb, offset + 3)) * 100 +
                     BCD44_TO_DEC(tvb_get_guint8(tvb, offset + 2));
      if (day > 31 || day < 1 || month > 12 || month < 1)
        return -1;

      char date[11];
      snprintf(date, 11, "%02d/%02d/%04d", day, month, year);
      proto_tree_add_string(p_tree, hf_pldm_date, tvb, offset, 4, date);
    }
    break;
  default:
    col_append_fstr(pinfo->cinfo, COL_INFO,
                    "Unsupported or Invalid PLDM command");
    g_print("Invalid PLDM bios cmd %x \n", pldm_cmd);
    break;
  }
  return tvb_captured_length(tvb);
}

void proto_register_bios(void) {
  static hf_register_info hf[] = {
      {&hf_bios_data_handle,
       {"Data transfer handle", "pldm.bios.table.handle", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_transfer_op_flag,
       {"Data transfer operation flag", "pldm.bios.table.opflag", FT_UINT8,
        BASE_HEX, VALS(transfer_op_flags), 0x0, NULL, HFILL}},
      {&hf_bios_table_type,
       {"BIOS table type", "pldm.bios.table.type", FT_UINT8, BASE_HEX,
        VALS(bios_table_types), 0x0, NULL, HFILL}},
      {&hf_bios_next_data_handle,
       {"Next data transfer handle", "pldm.bios.table.nexthandle", FT_UINT32,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_transfer_flag,
       {"Data transfer operation flag", "pldm.bios.table.flag", FT_UINT8,
        BASE_HEX, VALS(transfer_flags), 0x0, NULL, HFILL}},
      {&hf_bios_attr_handle,
       {"Attribute handle", "pldm.bios.attr.handle", FT_UINT16, BASE_HEX, NULL,
        0x0, NULL, HFILL}},
      {&hf_bios_attr_type,
       {"Attribute type", "pldm.bios.attr.type", FT_UINT8, BASE_HEX,
        VALS(bios_attribute_type), 0x0, NULL, HFILL}},
      {&hf_bios_attr_name_handle,
       {"BIOS attribute name handle", "bios.attr.name.handle", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_enumer_num_pos_values,
       {"BIOS enumeration number of possible values",
        "bios.enumer.num.pos.values", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_bios_enumer_pos_value_str_hndl,
       {"BIOS enumeration possible value string handle",
        "bios.enumer.pos.value.str.hndl", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_bios_enumer_num_default_values,
       {"BIOS enumeration number of default values",
        "bios.enumer.num.default.values", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_bios_enumer_default_value_str_hndl,
       {"BIOS enumeration default value string handle",
        "bios.enumer.default.value.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},
      {&hf_bios_attr_table_pad_bytes,
       {"BIOS attribute table pad bytes", "bios.attribute.pad.bytes", FT_UINT64,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_attr_table_checksum,
       {"BIOS attribute table checksum", "bios.attr.table.checksum", FT_UINT32,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_str_handle,
       {"BIOS attribute string handle", "bios.str.handle", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_str_len,
       {"BIOS attribute string length", "bios.str.len", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_str,
       {"BIOS attribute string", "bios.str", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
      {&hf_bios_string_type,
       {"BIOS attribute string type", "bios.string.type", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_min_str_len,
       {"BIOS attribute min string length", "bios.min.str.len", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_max_str_len,
       {"BIOS attribute max string length", "bios.max.str.len", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_def_str_len,
       {"BIOS attribute default string length", "bios.def.str.len", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_def_str,
       {"BIOS attribute default string", "bios.def.str", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_pass_type,
       {"BIOS attribute password type", "bios.pass.type", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_min_pass_len,
       {"BIOS attribute min password length", "bios.min.pass.len", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_max_pass_len,
       {"BIOS attribute max password length", "bios.max.pass.len", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_def_pass_len,
       {"BIOS attribute default password length", "bios.def.pass.len",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_def_pass,
       {"BIOS attribute default password", "bios.def.pass", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_int_lower_bound,
       {"BIOS attribute integer lower bound", "bios.int.lower.bound", FT_UINT64,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_int_upper_bound,
       {"BIOS attribute integer upper bound", "bios.int.upper.bound", FT_UINT64,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_int_scalar_inc,
       {"BIOS attribute integer scalar inc", "bios.int.scalar.inc", FT_UINT32,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_int_def_val,
       {"BIOS attribute integer default value", "bios.int.def.val", FT_UINT64,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_boot_config_type,
       {"BIOS boot config type", "bios.boot.config.type", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_fail_through_modes,
       {"BIOS attribute suuported and ordered fail through modes",
        "bios.fail.through.modes", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_min_num_boot_src,
       {"BIOS attribute minimum number of boot source settings",
        "bios.min.num.boot.src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_max_num_boot_src,
       {"BIOS attribute maximum number of boot source settings",
        "bios.max.num.boot.src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_pos_num_boot_src,
       {"BIOS attribute number of possible boot source settings",
        "bios.pos.num.boot.src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_src_str_hndl,
       {"BIOS attribute possible boot source string handle",
        "bios.src.str.hndl", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_col_name_str_hndl,
       {"BIOS attribute collection name string handle",
        "bios.col.name.str.hndl", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_max_num_attr,
       {"BIOS attribute max number of attributes", "bios.max.num.attr",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_col_type,
       {"BIOS attribute collection type", "bios.col.type", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_num_pos_config,
       {"BIOS attribute number of possible BIOS config", "bios.num.pos.config",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_pos_config_str_hndl,
       {"BIOS attribute possible BIOS config string handle",
        "bios.pos.config.str.hndl", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_bios_enumer_num_cur_values,
       {"BIOS attribute enumeration number of current values",
        "bios.enumer.num.cur.values", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_bios_enumer_cur_value_str_hndl,
       {"BIOS attribute enumeration current value string handle",
        "bios.enumer.cur.value.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_bios_cur_str_len,
       {"BIOS attribute current string length", "bios.cur.str.len", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_cur_str,
       {"BIOS attribute current string", "bios.cur.str", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_cur_pass_len,
       {"BIOS attribute current password length", "bios.cur.pass.len",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_cur_pass,
       {"BIOS attribute current password", "bios.cur.pass", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_cur_val,
       {"BIOS attribute current value", "bios.cur.val", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_num_boot_src,
       {"BIOS attribute number of boot source settings", "bios.num.boot.src",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_boot_src_str_hndl,
       {"BIOS attribute boot source setting string handle",
        "bios.boot.src.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_num_attr,
       {"BIOS collection number of attributes", "bios.num.attr", FT_UINT8,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_attr_hndl,
       {"BIOS collection attribute handle", "bios.attr.hndl", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_cur_config_set_str_hndl,
       {"BIOS cuurent config set string handle index",
        "bios.cur.config.set.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_bios_enumer_num_pen_values,
       {"BIOS attribute enumeration pending of current values",
        "bios.enumer.num.pen.values", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_bios_enumer_pen_value_str_hndl,
       {"BIOS attribute enumeration pending value string handle",
        "bios.enumer.pen.value.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_bios_pen_str_len,
       {"BIOS attribute pending string length", "bios.pen.str.len", FT_UINT16,
        BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_pen_str,
       {"BIOS attribute pending string", "bios.pen.str", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_pen_pass_len,
       {"BIOS attribute pending password length", "bios.pen.pass.len",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_pen_pass,
       {"BIOS attribute pending password", "bios.pen.pass", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_pen_val,
       {"BIOS attribute pending value", "bios.pen.val", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_bios_num_pen_boot_src,
       {"BIOS attribute number of pending boot source settings",
        "bios.num.pen.boot.src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_bios_config_set_str_hndl,
       {"BIOS config set string handle index", "bios.config.set.str.hndl",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_pldm_time,
       {"Time", "pldm.bios.time", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
        HFILL}},
      {&hf_pldm_date,
       {"Date", "pldm.bios.date", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
        HFILL}},
      {&hf_pldm_cmd,
       {"PLDM Command Type", "pldm.cmd", FT_UINT8, BASE_HEX, VALS(pldm_cmds),
        0x0, NULL, HFILL}},
      {&hf_completion_code,
       {"Completion Code", "pldm.cc", FT_UINT8, BASE_DEC,
        VALS(completion_codes), 0x0, NULL, HFILL}},

  };

  proto_pldm_bios =
      proto_register_protocol("PLDM BIOS Control and Configuration", /* name */
                              "PLDM_bios", /* short_name  */
                              "pldm.bios"  /* filter_name */
      );
  proto_register_field_array(proto_pldm_bios, hf, array_length(hf));
}

void proto_reg_handoff_bios(void) {
  static dissector_handle_t bios_handle;

  bios_handle = create_dissector_handle(dissect_bios, proto_pldm_bios);
  dissector_add_uint("pldm.type", PLDM_BIOS, bios_handle);
}
