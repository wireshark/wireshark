/* packet-slsk.c
 * Routines for SoulSeek Protocol dissection
 * Copyright 2003, Christian Wagner <Christian.Wagner@stud.uni-karlsruhe.de>
 * Institute of Telematics - University of Karlsruhe
 * part of this work supported by
 *  Deutsche Forschungsgemeinschaft (DFG) Grant Number FU448/1
 *
 * SoulSeek Protocol dissector based on protocol descriptions from SoleSeek Project:
 * http://cvs.sourceforge.net/viewcvs.py/soleseek/SoleSeek/doc/protocol.html?rev=HEAD
 * Updated for SoulSeek client version 151
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/expert.h>
#include "packet-tcp.h"

void proto_register_slsk(void);
void proto_reg_handoff_slsk(void);

static dissector_handle_t slsk_handle;

/* Initialize the protocol and registered fields */
static int proto_slsk;

static int hf_slsk_integer;
static int hf_slsk_string;
static int hf_slsk_byte;
static int hf_slsk_message_length;
static int hf_slsk_message_code;
static int hf_slsk_embedded_message_type;
static int hf_slsk_client_ip;
/* static int hf_slsk_server_ip; */
static int hf_slsk_directory_name;
static int hf_slsk_username;
static int hf_slsk_password;
static int hf_slsk_version;
static int hf_slsk_login_successful;
static int hf_slsk_login_message;
static int hf_slsk_port;
static int hf_slsk_ip;
static int hf_slsk_user_exists;
static int hf_slsk_status_code;
static int hf_slsk_room;
static int hf_slsk_chat_message;
static int hf_slsk_users_in_room;
static int hf_slsk_token;
static int hf_slsk_connection_type;
static int hf_slsk_chat_message_id;
static int hf_slsk_timestamp;
static int hf_slsk_search_text;
static int hf_slsk_folder_count;
static int hf_slsk_file_count;
static int hf_slsk_average_speed;
static int hf_slsk_download_number;
static int hf_slsk_files;
static int hf_slsk_directories;
static int hf_slsk_slotsfull;
static int hf_slsk_place_in_queue;
static int hf_slsk_number_of_rooms;
static int hf_slsk_filename;
static int hf_slsk_filename_ext;
static int hf_slsk_directory;
static int hf_slsk_size;
/* static int hf_slsk_checksum; */
static int hf_slsk_code;
static int hf_slsk_number_of_users;
static int hf_slsk_number_of_days;
static int hf_slsk_transfer_direction;
static int hf_slsk_user_description;
static int hf_slsk_picture_exists;
static int hf_slsk_picture;
/* static int hf_slsk_user_uploads; */
static int hf_slsk_total_uploads;
static int hf_slsk_queued_uploads;
static int hf_slsk_slots_available;
static int hf_slsk_allowed;
static int hf_slsk_compr_packet;
static int hf_slsk_parent_min_speed;
static int hf_slsk_parent_speed_connection_ratio;
static int hf_slsk_seconds_parent_inactivity_before_disconnect;
static int hf_slsk_seconds_server_inactivity_before_disconnect;
static int hf_slsk_nodes_in_cache_before_disconnect;
static int hf_slsk_seconds_before_ping_children;
static int hf_slsk_recommendation;
static int hf_slsk_user;
static int hf_slsk_ranking;
static int hf_slsk_compressed_packet_length;
static int hf_slsk_uncompressed_packet_length;
static int hf_slsk_num_directories;
static int hf_slsk_upload_speed;
static int hf_slsk_in_queue;
static int hf_slsk_num_slotsfull_records;
static int hf_slsk_num_recommendations;
static int hf_slsk_num_files;
static int hf_slsk_num_strings;
static int hf_slsk_file_code;
static int hf_slsk_file_size1;
static int hf_slsk_file_size2;
static int hf_slsk_file_num_attributes;
static int hf_slsk_file_attribute_type;
static int hf_slsk_file_attribute_value;
static int hf_slsk_free_upload_slots;
static int hf_slsk_bytes;
static int hf_slsk_same_recommendation;
static int hf_slsk_number_of_priv_users;
static int hf_slsk_num_parent_address;

/* Initialize the subtree pointers */
static int ett_slsk;
static int ett_slsk_compr_packet;
static int ett_slsk_directory;
static int ett_slsk_file;
static int ett_slsk_file_attribute;
static int ett_slsk_user;
static int ett_slsk_recommendation;
static int ett_slsk_room;
static int ett_slsk_string;

static expert_field ei_slsk_unknown_data;
static expert_field ei_slsk_zlib_decompression_failed;
static expert_field ei_slsk_decompression_failed;

#define SLSK_TCP_PORT_RANGE   "2234,2240,5534"


/* desegmentation of SoulSeek Message over TCP */
static bool slsk_desegment = true;
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
static bool slsk_decompress = true;
#else
static bool slsk_decompress;
#endif

static const value_string slsk_tcp_msgs[] = {
  { 1, "Login"},
  { 2, "Set Wait Port"},
  { 3, "Get Peer Address"},
  { 4, "Get Shared File List"},
  { 5, "User Exists / Shared File List"},
  { 7, "Get User Status"},
  { 9, "File Search Result"},
  { 13, "Say ChatRoom"},
  { 14, "Join Room"},
  { 15, "Leave Room / User Info Request"},
  { 16, "User Joined Room / User Info Reply"},
  { 17, "User Left Room"},
  { 18, "Connect To Peer"},
  { 22, "Message User"},
  { 23, "Message User Ack"},
  { 26, "File Search"},
  { 28, "Set Status"},
  { 32, "Ping"},
  { 34, "Update Upload Speed"},
  { 35, "Shared Files & Folders"},
  { 36, "Get User Stats / Folder Contents Request"},
  { 37, "Folder Contents Response"},
  { 40, "Queued Downloads / Transfer Request"},
  { 41, "Transfer Response"},
  { 42, "Placehold Upload"},
  { 43, "Queue Upload"},
  { 44, "Place In Queue"},
  { 46, "Upload Failed"},
  { 50, "Queue Failed / Own Recommendation"},
  { 51, "Add Things I like / Place In Queue Request"},
  { 52, "Remove Things I like"},
  { 54, "Get Recommendations"},
  { 55, "Type 55"},
  { 56, "Get Global Rankings"},
  { 57, "Get User Recommendations"},
  { 58, "Admin Command"},
  { 60, "Place In Line Response"},
  { 62, "Room Added"},
  { 63, "Room Removed"},
  { 64, "Room List"},
  { 65, "Exact File Search"},
  { 66, "Admin Message"},
  { 67, "Global User List"},
  { 68, "Tunneled Message"},
  { 69, "Privileged User List"},
  { 71, "Get Parent List"},
  { 73, "Type 73"},
  { 83, "Parent Min Speed"},
  { 84, "Parent Speed Connection Ratio"},
  { 86, "Parent Inactivity Before Disconnect"},
  { 87, "Server Inactivity Before Disconnect"},
  { 88, "Nodes In Cache Before Disconnect"},
  { 90, "Seconds Before Ping Children"},
  { 91, "Add To Privileged"},
  { 92, "Check Privileges"},
  { 93, "Embedded Message"},
  { 100, "Become Parent"},
  { 102, "Random Parent Addresses"},
  { 103, "Send Wishlist Entry"},
  { 104, "Type 104"},
  { 110, "Get Similar Users"},
  { 111, "Get Recommendations for Item"},
  { 112, "Get Similar Users for Item"},
  { 1001, "Can't Connect To Peer"},
  { 0, NULL }
};

static const value_string slsk_status_codes[] = {
  { -1, "Unknown"},
  { 0, "Offline"},
  { 1, "Away"},
  { 2, "Online"},
  { 0, NULL }
};

static const value_string slsk_transfer_direction[] = {
  { 0, "Download"},
  { 1, "Upload"},
  { 0, NULL }
};

static const value_string slsk_yes_no[] = {
  { 0, "No"},
  { 1, "Yes"},
  { 0, NULL }
};

static const value_string slsk_attr_type[] = {
  { 0, "Bitrate"},
  { 1, "Length"},
  { 2, "VBR"},
  { 0, NULL }
};

static const char* connection_type(char con_type[]) {
  if (strlen(con_type) != 1) return "Unknown";
  if (con_type[0] == 'D') return "Distributed Search";
  if (con_type[0] == 'P') return "Peer Connection";    /* "File Search Result / User Info Request / Get Shared File List" */
  if (con_type[0] == 'F') return "File Transfer";
  return "Unknown";
}

// NOLINTNEXTLINE(misc-no-recursion)
static bool check_slsk_format(tvbuff_t *tvb, packet_info *pinfo, int offset, const char format[]){

  /*
  * Returns true if tvbuff beginning at offset matches a certain format
  * The format is given by an array of characters standing for a special field type
  *     i - integer  (4 bytes)
  *     b - byte  (1 byte)
  *    s - string  (string_length + 4 bytes)
  *
  *    * - can be used at the end of a format to ignore any following bytes
  */

  switch ( format[0] ) {
    case 'i':
      if (tvb_captured_length_remaining(tvb, offset) < 4) return false;
      offset += 4;
    break;
    case 'b':
      if (tvb_captured_length_remaining(tvb, offset) < 1) return false;
      offset += 1;
    break;
    case 's':
      if (tvb_captured_length_remaining(tvb, offset) < 4) return false;
      if (tvb_captured_length_remaining(tvb, offset) < (int)tvb_get_letohl(tvb, offset)+4) return false;
      offset += tvb_get_letohl(tvb, offset)+4;
    break;
    case '*':
      return true;
    default:
      return false;
  }

  if (format[1] == '\0' ) {
    if (tvb_captured_length_remaining(tvb, offset) > 0) /* Checks for additional bytes at the end */
      return false;
    return true;
  }
  increment_dissection_depth(pinfo);
  bool valid = check_slsk_format(tvb, pinfo, offset, &format[1]);
  decrement_dissection_depth(pinfo);
  return valid;

}

static const char* get_message_type(tvbuff_t *tvb, packet_info *pinfo) {
  /*
  * Checks if the Message Code is known.
  * If unknown checks if the Message Code is stored in a byte.
  * Returns the Message Type.
  */
  int msg_code = tvb_get_letohl(tvb, 4);
  const char *message_type =  try_val_to_str(msg_code, slsk_tcp_msgs);
  if (message_type == NULL) {
    if (check_slsk_format(tvb, pinfo, 4, "bisis"))
      message_type = "Distributed Search";
    else if (check_slsk_format(tvb, pinfo, 4, "bssi"))
      message_type = "Peer Init";
    else if (check_slsk_format(tvb, pinfo, 4, "bi"))
      message_type = "Pierce Fw";
    else
      message_type = "Unknown";
  }
  return message_type;
}

static unsigned get_slsk_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                              int offset, void *data _U_)
{
  uint32_t msg_len;
  msg_len = tvb_get_letohl(tvb, offset);
  /* That length doesn't include the length field itself; add that in. */
  msg_len += 4;
  return msg_len;
}

/* Code to actually dissect the packets */

static int dissect_slsk_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

/* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti, *ti_len, *ti_subtree, *ti_subtree2;
  proto_tree *slsk_tree, *subtree, *subtree2, *subtree3;

  int offset = 0, i, j;
  uint32_t msg_len, msg_code;
  uint8_t *str;
  int str_len, start_offset, start_offset2;

  int comprlen = 0, uncomprlen = 0, uncompr_tvb_offset = 0;
  int i2 = 0, j2 = 0;
  int i3 = 0, j3 = 0;

/* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "slsk");

/* This field shows up as the "Info" column in the display  */

  col_set_str(pinfo->cinfo, COL_INFO, "SoulSeek Message");

  col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", get_message_type(tvb, pinfo));

/* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_slsk, tvb, 0, -1, ENC_NA);
    slsk_tree = proto_item_add_subtree(ti, ett_slsk);

/* Continue adding tree items to process the packet here */

    ti_len = proto_tree_add_item_ret_uint(slsk_tree, hf_slsk_message_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &msg_len);
    offset += 4;
    msg_code = tvb_get_letohl(tvb, offset);

    switch (msg_code) {

      case  1:
        if (check_slsk_format(tvb, pinfo, offset, "issi")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Login (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_password, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "ibs") || check_slsk_format(tvb, pinfo, offset, "ibsi")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Login Reply (Code: %02d)", msg_code);
          offset += 4;
          i=tvb_get_uint8(tvb, offset);
          proto_tree_add_item(slsk_tree, hf_slsk_login_successful, tvb, offset, 1, ENC_NA);
          offset += 1;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_login_message, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          if (i == 1){
            proto_tree_add_item(slsk_tree, hf_slsk_client_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
          }
        }
      break;

      case  2:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Set Wait Port (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case  3:
        if (check_slsk_format(tvb, pinfo, offset, "isii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Peer Address Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Peer Address (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 4:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Shared File List (Code: %02d)", msg_code);
          offset += 4;
        }
      break;

      case  5:
        if (check_slsk_format(tvb, pinfo, offset, "isb")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "User Exists Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_user_exists, tvb, offset, 1, ENC_NA);
          offset += 1;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "User Exists Request (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "i*")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Shared File List (Code: %02d)", msg_code);
          offset += 4;

          /* [zlib compressed] */
          comprlen = tvb_captured_length_remaining(tvb, offset);

          if (slsk_decompress == true){

            tvbuff_t *uncompr_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, comprlen);

            if (uncompr_tvb == NULL) {
              proto_tree_add_expert(slsk_tree, pinfo, &ei_slsk_zlib_decompression_failed, tvb, offset, -1);
              offset += tvb_captured_length_remaining(tvb, offset);
            } else {

              proto_item *ti2 = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, -1, ENC_NA);
              proto_tree *slsk_compr_packet_tree = proto_item_add_subtree(ti2, ett_slsk_compr_packet);
              proto_item_set_generated(ti2);

              ti = proto_tree_add_uint(slsk_tree, hf_slsk_compressed_packet_length, tvb, offset, 0, comprlen);
              proto_item_set_generated(ti);
              uncomprlen = tvb_reported_length_remaining(uncompr_tvb, 0);
              ti = proto_tree_add_uint(slsk_tree, hf_slsk_uncompressed_packet_length, tvb, offset, 0, uncomprlen);
              proto_item_set_generated(ti);

              add_new_data_source(pinfo, uncompr_tvb, "Uncompressed SoulSeek data");
              uncompr_tvb_offset = 0;
              if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "i*")) {
                proto_tree_add_item_ret_int(slsk_compr_packet_tree, hf_slsk_num_directories, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN, &j);
                uncompr_tvb_offset += 4;
                for (i = 0; i < j; i++) {
                  if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "si*")) {
                    start_offset = uncompr_tvb_offset;
                    subtree = proto_tree_add_subtree_format(slsk_compr_packet_tree, uncompr_tvb, uncompr_tvb_offset, 1, ett_slsk_directory, &ti_subtree, "Directory #%d", i+1);
                    proto_tree_add_item_ret_length(subtree, hf_slsk_directory_name, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
                    uncompr_tvb_offset += str_len;
                    proto_tree_add_item_ret_int(subtree, hf_slsk_num_files, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN, &j2);
                    uncompr_tvb_offset += 4;
                    for (i2 = 0; i2 < j2; i2++) {
                      if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "bsiisi*")) {
                        start_offset2 = uncompr_tvb_offset;
                        subtree2 = proto_tree_add_subtree_format(subtree, uncompr_tvb, uncompr_tvb_offset, 1, ett_slsk_file, &ti_subtree2, "File #%d", i2+1);
                        proto_tree_add_item(subtree2, hf_slsk_file_code, uncompr_tvb, uncompr_tvb_offset, 1, ENC_NA);
                        uncompr_tvb_offset += 1;
                        proto_tree_add_item_ret_length(subtree2, hf_slsk_filename, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
                        uncompr_tvb_offset += str_len;
                        proto_tree_add_item(subtree2, hf_slsk_file_size1, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                        uncompr_tvb_offset += 4;
                        proto_tree_add_item(subtree2, hf_slsk_file_size2, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                        uncompr_tvb_offset += 4;
                        proto_tree_add_item_ret_length(subtree2, hf_slsk_filename_ext, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
                        uncompr_tvb_offset += str_len;
                        proto_tree_add_item_ret_int(subtree2, hf_slsk_file_num_attributes, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN, &j3);
                        uncompr_tvb_offset += 4;
                        for (i3 = 0; i3 < j3; i3++) {
                          if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "ii*")) {
                            subtree3 = proto_tree_add_subtree_format(subtree2, uncompr_tvb, uncompr_tvb_offset, 8, ett_slsk_file_attribute, NULL, "Attribute #%d", i3+1);
                            proto_tree_add_item(subtree3, hf_slsk_file_attribute_type, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                            uncompr_tvb_offset += 4;
                            proto_tree_add_item(subtree3, hf_slsk_file_attribute_value, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                            uncompr_tvb_offset += 4;
                          } else {
                            break; /* invalid format */
                          }
                        }
                        proto_item_set_len(ti_subtree2, uncompr_tvb_offset-start_offset2);
                      } else {
                        break; /* invalid format */
                      }
                    }
                    proto_item_set_len(ti_subtree, uncompr_tvb_offset-start_offset);
                  } else {
                    break; /* invalid format */
                  }
                }
              }
            }
          }else {
            ti = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, -1, ENC_NA);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(slsk_tree, hf_slsk_compressed_packet_length, tvb, offset, 0, comprlen);
            proto_item_set_generated(ti);
            offset += tvb_captured_length_remaining(tvb, offset);
          }
        }
      break;

      case  7:
        if (check_slsk_format(tvb, pinfo, offset, "isi")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get User Status Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_status_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get User Status (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 9:
        if (check_slsk_format(tvb, pinfo, offset, "i*")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "File Search Result (Code: %02d)", msg_code);
          offset += 4;

          /* [zlib compressed] */
          comprlen = tvb_captured_length_remaining(tvb, offset);

          if (slsk_decompress == true){

            tvbuff_t *uncompr_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, comprlen);

            if (uncompr_tvb == NULL) {
              ti = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
              proto_item_set_generated(ti);
              offset += tvb_captured_length_remaining(tvb, offset);
              expert_add_info(pinfo, ti, &ei_slsk_decompression_failed);
            } else {

              proto_item *ti2 = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, -1, ENC_NA);
              proto_tree *slsk_compr_packet_tree = proto_item_add_subtree(ti2, ett_slsk_compr_packet);
              proto_item_set_generated(ti2);

              ti = proto_tree_add_uint(slsk_tree, hf_slsk_compressed_packet_length, tvb, offset, 0, comprlen);
              proto_item_set_generated(ti);
              uncomprlen = tvb_captured_length_remaining(uncompr_tvb, 0);
              ti = proto_tree_add_uint(slsk_tree, hf_slsk_uncompressed_packet_length, tvb, offset, 0, uncomprlen);
              proto_item_set_generated(ti);

              add_new_data_source(pinfo, uncompr_tvb, "Uncompressed SoulSeek data");
              uncompr_tvb_offset = 0;
              if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "sii*")) {
                proto_tree_add_item_ret_length(slsk_compr_packet_tree, hf_slsk_username, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_NA, &str_len);
                uncompr_tvb_offset += str_len;
                proto_tree_add_item(slsk_compr_packet_tree, hf_slsk_token, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                uncompr_tvb_offset += 4;
                proto_tree_add_item_ret_int(slsk_compr_packet_tree, hf_slsk_num_files, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN, &j);
                uncompr_tvb_offset += 4;
                for (i = 0; i < j; i++) {
                  if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "bsiisi*")) {
                    start_offset2 = uncompr_tvb_offset;
                    subtree2 = proto_tree_add_subtree_format(slsk_compr_packet_tree, uncompr_tvb, uncompr_tvb_offset, 1, ett_slsk_file, &ti_subtree2, "File #%d", i+1);
                    proto_tree_add_item(subtree2, hf_slsk_file_code, uncompr_tvb, uncompr_tvb_offset, 1, ENC_NA);
                    uncompr_tvb_offset += 1;
                    proto_tree_add_item_ret_length(subtree2, hf_slsk_filename, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
                    uncompr_tvb_offset += str_len;
                    proto_tree_add_item(subtree2, hf_slsk_file_size1, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                    uncompr_tvb_offset += 4;
                    proto_tree_add_item(subtree2, hf_slsk_file_size2, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                    uncompr_tvb_offset += 4;
                    proto_tree_add_item_ret_length(subtree2, hf_slsk_filename_ext, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
                    uncompr_tvb_offset += str_len;
                    proto_tree_add_item_ret_int(subtree2, hf_slsk_file_num_attributes, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN, &j2);
                    uncompr_tvb_offset += 4;
                    for (i2 = 0; i2 < j2; i2++) {
                      if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "ii*")) {
                        subtree3 = proto_tree_add_subtree_format(subtree2, uncompr_tvb, uncompr_tvb_offset, 8, ett_slsk_file_attribute, NULL, "Attribute #%d", i2+1);
                        proto_tree_add_item(subtree3, hf_slsk_file_attribute_type, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                        uncompr_tvb_offset += 4;
                        proto_tree_add_item(subtree3, hf_slsk_file_attribute_value, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                        uncompr_tvb_offset += 4;
                      } else {
                        break; /* invalid format */
                      }
                    }
                    proto_item_set_len(ti_subtree2, uncompr_tvb_offset-start_offset2);
                  } else {
                    break; /* invalid format */
                  }
                }

                proto_tree_add_item(slsk_compr_packet_tree, hf_slsk_free_upload_slots, uncompr_tvb, uncompr_tvb_offset, 1, ENC_LITTLE_ENDIAN);
                uncompr_tvb_offset += 1;
                proto_tree_add_item(slsk_compr_packet_tree, hf_slsk_upload_speed, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                uncompr_tvb_offset += 4;
                proto_tree_add_item(slsk_compr_packet_tree, hf_slsk_in_queue, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
              }
            }
          }else {
            ti = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, -1, ENC_NA);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(slsk_tree, hf_slsk_compressed_packet_length, tvb, offset, 0, comprlen);
            proto_item_set_generated(ti);
            offset += tvb_captured_length_remaining(tvb, offset);
          }
        }
      break;

      case 13:
        if (check_slsk_format(tvb, pinfo, offset, "isss")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Say ChatRoom (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_chat_message, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "iss")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Say ChatRoom (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_chat_message, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 14:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Join/Add Room (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "isi*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Join Room User List (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "s*")) {
              proto_tree_add_item_ret_length(slsk_tree, hf_slsk_user, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
            } else {
              break; /* invalid format */
            }
          }
          if (check_slsk_format(tvb, pinfo, offset, "i*")) {
            proto_tree_add_item_ret_int(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
            offset += 4;
            if (j > tvb_reported_length_remaining(tvb, offset))
              break;
            for (i = 0; i < j; i++) {
              if (check_slsk_format(tvb, pinfo, offset, "i*")) {
                proto_tree_add_item(slsk_tree, hf_slsk_status_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
              } else {
                break; /* invalid format */
              }
            }
          }
          if (check_slsk_format(tvb, pinfo, offset, "i*")) {
            proto_tree_add_item_ret_int(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
            offset += 4;
            if (j > tvb_reported_length_remaining(tvb, offset))
              break;
            for (i = 0; i < j; i++) {
              if (check_slsk_format(tvb, pinfo, offset, "iiiii*")) {
                subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 20, ett_slsk_user, NULL, "User #%d", i+1);
                proto_tree_add_item(subtree, hf_slsk_average_speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(subtree, hf_slsk_download_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(subtree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(subtree, hf_slsk_files, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(subtree, hf_slsk_directories, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
              } else {
                break; /* invalid format */
              }
            }
          }
          if (check_slsk_format(tvb, pinfo, offset, "i*")) {
            proto_tree_add_item_ret_int(slsk_tree, hf_slsk_num_slotsfull_records, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
            offset += 4;
            if (j > tvb_reported_length_remaining(tvb, offset))
              break;
            for (i = 0; i < j; i++) {
              if (check_slsk_format(tvb, pinfo, offset, "i*")) {
                subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 4, ett_slsk_user, NULL, "User #%d", i+1);
                proto_tree_add_item(subtree, hf_slsk_slotsfull, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
              } else {
                break; /* invalid format */
              }
            }
          }
        }
      break;

      case 15:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server & Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Leave Room (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "User Info Request (Code: %02d)", msg_code);
          offset += 4;
        }
      break;

      case 16:
        if (check_slsk_format(tvb, pinfo, offset, "issiiiiiii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "User Joined Room (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_total_uploads, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_average_speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_download_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_files, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_directories, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_slotsfull, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "isbiib") || check_slsk_format(tvb, pinfo, offset, "isbsiib")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "User Info Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_user_description, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_picture_exists, tvb, offset, 1, ENC_NA);
          offset += 1;
          if ( tvb_get_uint8(tvb, offset -1 ) == 1 ) {
            proto_tree_add_item_ret_length(slsk_tree, hf_slsk_picture, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
            offset += str_len;
          }
          proto_tree_add_item(slsk_tree, hf_slsk_total_uploads, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_queued_uploads, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_slots_available, tvb, offset, 1, ENC_NA);
          offset += 1;
        }
      break;

      case 17:
        if (check_slsk_format(tvb, pinfo, offset, "iss")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "User Left Room (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 18:
        if (check_slsk_format(tvb, pinfo, offset, "iiss")) {
          /* Client-to-Server */
          uint32_t len;

          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Connect To Peer (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          len = tvb_get_letohl(tvb, offset);
          str = tvb_get_string_enc(pinfo->pool, tvb, offset+4, len, ENC_ASCII);
          proto_tree_add_string_format_value(slsk_tree, hf_slsk_connection_type, tvb, offset, 4+len, str,
            "%s (Char: %s)", connection_type(str),
            format_text(pinfo->pool, str, len));
          offset += 4+len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "issiii")) {
          /* Server-to-Client */
          uint32_t len;

          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Connect To Peer (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          len = tvb_get_letohl(tvb, offset);
          str = tvb_get_string_enc(pinfo->pool, tvb, offset+4, len, ENC_ASCII);
          proto_tree_add_string_format_value(slsk_tree, hf_slsk_connection_type, tvb, offset, 4+len, str,
            "%s (Char: %s)", connection_type(str),
            format_text(pinfo->pool, str, len));
          offset += 4+len;
          proto_tree_add_item(slsk_tree, hf_slsk_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 22:
        if (check_slsk_format(tvb, pinfo, offset, "iss")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Message User Send (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_chat_message, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "iiiss")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Message User Receive (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_chat_message_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_chat_message, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 23:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Message User Receive Ack (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_chat_message_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 26:
        if (check_slsk_format(tvb, pinfo, offset, "iis")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "File Search (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_search_text, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 28:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Set Status (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_status_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 32:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Ping (Code: %02d)", msg_code);
          offset += 4;
        }
      break;

      case 34:
        if (check_slsk_format(tvb, pinfo, offset, "isi")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Update Upload Speed (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_average_speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 35:
        if (check_slsk_format(tvb, pinfo, offset, "iii")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Shared Files & Folders (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_folder_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_file_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 36:
        if (check_slsk_format(tvb, pinfo, offset, "isiiiii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get User Stats Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_average_speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_download_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_files, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_directories, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Client */
          /* Client-to-Server: send after login successful */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get User Stats (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "iis")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Folder Contents Request (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_directory, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 37:
        if (check_slsk_format(tvb, pinfo, offset, "i*")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Folder Contents Response (Code: %02d)", msg_code);
          offset += 4;

          /* [zlib compressed] */
          comprlen = tvb_captured_length_remaining(tvb, offset);

          if (slsk_decompress == true){

            tvbuff_t *uncompr_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, comprlen);

            if (uncompr_tvb == NULL) {
              proto_tree_add_expert(slsk_tree, pinfo, &ei_slsk_zlib_decompression_failed, tvb, offset, -1);
              offset += tvb_captured_length_remaining(tvb, offset);
            } else {

              proto_item *ti2 = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, -1, ENC_NA);
              proto_tree *slsk_compr_packet_tree = proto_item_add_subtree(ti2, ett_slsk_compr_packet);
              proto_item_set_generated(ti2);

              ti = proto_tree_add_uint(slsk_tree, hf_slsk_compressed_packet_length, tvb, offset, 0, comprlen);
              proto_item_set_generated(ti);
              uncomprlen = tvb_captured_length_remaining(uncompr_tvb, 0);
              ti = proto_tree_add_uint(slsk_tree, hf_slsk_uncompressed_packet_length, tvb, offset, 0, uncomprlen);
              proto_item_set_generated(ti);
              add_new_data_source(pinfo, uncompr_tvb, "Uncompressed SoulSeek data");

              uncompr_tvb_offset = 0;
              if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "isi*")) {
                uint32_t len;

                proto_tree_add_item(slsk_compr_packet_tree, hf_slsk_token, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                uncompr_tvb_offset += 4;
                proto_tree_add_item_ret_length(slsk_compr_packet_tree, hf_slsk_directory_name, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &len);
                uncompr_tvb_offset += len;

                proto_tree_add_item_ret_int(slsk_compr_packet_tree, hf_slsk_num_directories, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN, &j);
                uncompr_tvb_offset += 4;
                for (i = 0; i < j; i++) {
                  if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "si*")) {
                    start_offset = uncompr_tvb_offset;
                    subtree = proto_tree_add_subtree_format(slsk_compr_packet_tree, uncompr_tvb, uncompr_tvb_offset, 1, ett_slsk_directory, &ti_subtree, "Directory #%d", i+1);
                    proto_tree_add_item_ret_length(subtree, hf_slsk_directory_name, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
                    uncompr_tvb_offset += str_len;
                    proto_tree_add_item_ret_int(subtree, hf_slsk_num_files, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN, &j2);
                    uncompr_tvb_offset += 4;
                    for (i2 = 0; i2 < j2; i2++) {
                      if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "bsiisi*")) {
                        start_offset2 = uncompr_tvb_offset;
                        subtree2 = proto_tree_add_subtree_format(subtree, uncompr_tvb, uncompr_tvb_offset, 1, ett_slsk_file, &ti_subtree2, "File #%d", i2+1);
                        proto_tree_add_item(subtree2, hf_slsk_file_code, uncompr_tvb, uncompr_tvb_offset, 1, ENC_NA);
                        uncompr_tvb_offset += 1;
                        proto_tree_add_item_ret_length(subtree2, hf_slsk_filename, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
                        uncompr_tvb_offset += str_len;
                        proto_tree_add_item(subtree2, hf_slsk_file_size1, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                        uncompr_tvb_offset += 4;
                        proto_tree_add_item(subtree2, hf_slsk_file_size2, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                        uncompr_tvb_offset += 4;
                        proto_tree_add_item_ret_length(subtree2, hf_slsk_filename_ext, uncompr_tvb, uncompr_tvb_offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
                        uncompr_tvb_offset += str_len;
                        proto_tree_add_item_ret_int(subtree2, hf_slsk_file_num_attributes, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN, &j3);
                        uncompr_tvb_offset += 4;
                        for (i3 = 0; i3 < j3; i3++) {
                          if (check_slsk_format(uncompr_tvb, pinfo, uncompr_tvb_offset, "ii*")) {
                            subtree3 = proto_tree_add_subtree_format(subtree2, uncompr_tvb, uncompr_tvb_offset, 8, ett_slsk_file_attribute, NULL, "Attribute #%d", i3+1);
                            proto_tree_add_item(subtree3, hf_slsk_file_attribute_type, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                            uncompr_tvb_offset += 4;
                            proto_tree_add_item(subtree3, hf_slsk_file_attribute_value, uncompr_tvb, uncompr_tvb_offset, 4, ENC_LITTLE_ENDIAN);
                            uncompr_tvb_offset += 4;
                          } else {
                            break; /* invalid format */
                          }
                        }
                        proto_item_set_len(ti_subtree2, uncompr_tvb_offset-start_offset2);
                      } else {
                        break; /* invalid format */
                      }
                    }
                    proto_item_set_len(ti_subtree, uncompr_tvb_offset-start_offset);
                  } else {
                    break; /* invalid format */
                  }
                }
              }
            }
          }else {
            ti = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, -1, ENC_NA);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(slsk_tree, hf_slsk_compressed_packet_length, tvb, offset, 0, comprlen);
            proto_item_set_generated(ti);
            offset += tvb_captured_length_remaining(tvb, offset);
          }
        }
      break;

      case 40:
        if (check_slsk_format(tvb, pinfo, offset, "isi")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Queued Downloads (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_slotsfull, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "iiis") || check_slsk_format(tvb, pinfo, offset, "iiisii")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Transfer Request (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_transfer_direction, tvb, offset, 4, ENC_LITTLE_ENDIAN, &i);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          if (i == 1){
            proto_tree_add_item(slsk_tree, hf_slsk_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(slsk_tree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
          }
        }

      break;

      case 41:
        if (check_slsk_format(tvb, pinfo, offset, "iibs") || check_slsk_format(tvb, pinfo, offset, "iibii") || check_slsk_format(tvb, pinfo, offset, "iib")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Transfer Response (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          i = tvb_get_uint8(tvb, offset);
          proto_tree_add_item(slsk_tree, hf_slsk_allowed, tvb, offset, 1, ENC_NA);
          offset += 1;
          if ( i == 1 ) {
            if ( tvb_reported_length_remaining(tvb, offset) == 8 ) {
              proto_tree_add_item(slsk_tree, hf_slsk_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
              proto_tree_add_item(slsk_tree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
            }
          } else {
            proto_tree_add_item_ret_length(slsk_tree, hf_slsk_string, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
            offset += str_len;
          }
        }
      break;

      case 42:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Placehold Upload (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 43:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Queue Upload (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 44:
        if (check_slsk_format(tvb, pinfo, offset, "isi")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Place In Queue (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_place_in_queue, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 46:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Upload Failed (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 50:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Make Own Recommendation (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "isi")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Remove Own Recommendation (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_ranking, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "iss")) {
          /* Client-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Queue Failed (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_string, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 51:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server: "Add Things I like" */
          /* Client-to-Client:  "Place In Queue Request" */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Add Things I like / Place In Queue Request (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 52:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Remove Things I like (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 54:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Recommendations (Code: %02d)", msg_code);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "ii*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Recommendations Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_num_recommendations, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "si*")) {
              start_offset = offset;
              subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 1, ett_slsk_recommendation, &ti_subtree, "Recommendation #%d", i+1);
              proto_tree_add_item_ret_length(subtree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
              proto_tree_add_item(subtree, hf_slsk_ranking, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
              proto_item_set_len(ti_subtree, offset-start_offset);
            } else {
              break; /* invalid format */
            }
          }
        }
      break;

      case 55:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Type 55 (Code: %02d)", msg_code);
          offset += 4;
        }
      break;

      case 56:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Global Rankings (Code: %02d)", msg_code);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "ii*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Global Rankings Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_num_recommendations, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "si*")) {
              start_offset = offset;
              subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 1, ett_slsk_recommendation, &ti_subtree, "Recommendation #%d", i+1);
              proto_tree_add_item_ret_length(subtree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
              proto_tree_add_item(subtree, hf_slsk_ranking, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
              proto_item_set_len(ti_subtree, offset-start_offset);
            } else {
              break; /* invalid format */
            }
          }
        }
      break;

      case 57:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get User Recommendations (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "isi*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get User Recommendations Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_num_recommendations, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "s*")) {
              start_offset = offset;
              subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 1, ett_slsk_recommendation, &ti_subtree, "Recommendation #%d", i+1);
              proto_tree_add_item_ret_length(subtree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
              proto_item_set_len(ti_subtree, offset-start_offset);
            } else {
              break; /* invalid format */
            }
          }
        }
      break;

      case 58:
        if (check_slsk_format(tvb, pinfo, offset, "isi*")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Admin Command (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_string, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_num_strings, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "s*")) {
              start_offset = offset;
              subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 1, ett_slsk_string, &ti_subtree, "String #%d", i+1);
              proto_tree_add_item_ret_length(subtree, hf_slsk_string, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
              proto_item_set_len(ti_subtree, offset-start_offset);
            } else {
              break; /* invalid format */
            }
          }
        }
      break;

      case 60:
        if (check_slsk_format(tvb, pinfo, offset, "isii")) {
          /* Client-to-Server & Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Place In Line Response (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_place_in_queue, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 62:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Room Added (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 63:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Room Removed (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 64:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Room List Request (Code: %02d)", msg_code);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "ii*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Room List (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_number_of_rooms, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "s*")) {
              start_offset = offset;
              subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 1, ett_slsk_room, &ti_subtree, "Room #%d", i+1);
              proto_tree_add_item_ret_length(subtree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
              proto_item_set_len(ti_subtree, offset-start_offset);
            } else {
              break; /* invalid format */
            }
          }
          if (check_slsk_format(tvb, pinfo, offset, "i*")) {
            proto_tree_add_item_ret_int(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
            offset += 4;
            for (i = 0; i < j; i++) {
              if (check_slsk_format(tvb, pinfo, offset, "i*")) {
                subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 4, ett_slsk_room, &ti_subtree, "Room #%d", i+1);
                proto_tree_add_item(subtree, hf_slsk_users_in_room, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
              } else {
                break; /* invalid format */
              }
            }
          }
        }
      break;

      case 65:
        if (check_slsk_format(tvb, pinfo, offset, "isissiii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Exact File Search (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_directory, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_bytes, tvb, offset, 16, ENC_NA);
          offset += 12;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "iissiiib")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Exact File Search (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_filename, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_directory, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_bytes, tvb, offset, 13, ENC_NA);
          offset += 13;
        }
      break;

      case 66:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Admin Message (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_chat_message, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 67:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Global User List Request (Code: %02d)", msg_code);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "isi*")) {     /* same as case 14 */
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Global User List (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_room, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "s*")) {
              proto_tree_add_item_ret_length(slsk_tree, hf_slsk_user, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
            } else {
              break; /* invalid format */
            }
          }
          if (check_slsk_format(tvb, pinfo, offset, "i*")) {
            proto_tree_add_item_ret_int(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
            offset += 4;
            for (i = 0; i < j; i++) {
              if (check_slsk_format(tvb, pinfo, offset, "i*")) {
                proto_tree_add_item(slsk_tree, hf_slsk_status_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
              } else {
                break; /* invalid format */
              }
            }
          }
          if (check_slsk_format(tvb, pinfo, offset, "i*")) {
            proto_tree_add_item_ret_int(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
            offset += 4;
            if (j > tvb_reported_length_remaining(tvb, offset))
              break;
            for (i = 0; i < j; i++) {
              if (check_slsk_format(tvb, pinfo, offset, "iiiii*")) {
                subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 20, ett_slsk_user, NULL, "User #%d", i+1);
                proto_tree_add_item(subtree, hf_slsk_average_speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(subtree, hf_slsk_download_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(subtree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(subtree, hf_slsk_files, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(subtree, hf_slsk_directories, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
              } else {
                break; /* invalid format */
              }
            }
          }
          if (check_slsk_format(tvb, pinfo, offset, "i*")) {
            proto_tree_add_item_ret_int(slsk_tree, hf_slsk_num_slotsfull_records, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
            offset += 4;
            if (j > tvb_reported_length_remaining(tvb, offset))
              break;
            for (i = 0; i < j; i++) {
              if (check_slsk_format(tvb, pinfo, offset, "i*")) {
                subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 4, ett_slsk_user, NULL, "User #%d", i+1);
                proto_tree_add_item(subtree, hf_slsk_slotsfull, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
              } else {
                break; /* invalid format */
              }
            }
          }
        }
      break;

      case 68:
        if (check_slsk_format(tvb, pinfo, offset, "isiiiis")) {
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Tunneled Message (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item(slsk_tree, hf_slsk_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_chat_message, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 69:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Privileged User List Request (Code: %02d)", msg_code);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "ii*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Privileged User List (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_number_of_priv_users, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "s*")) {
              proto_tree_add_item_ret_length(slsk_tree, hf_slsk_user, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
            } else {
              break; /* invalid format */
            }
          }
        }
      break;

      case 71:
        if (check_slsk_format(tvb, pinfo, offset, "ib")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Parent List (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_byte, tvb, offset, 1, ENC_NA);
          offset += 1;
        }
      break;

      case 73:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Type 73 (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 83:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Parent Min Speed (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_parent_min_speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 84:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Parent Speed Connection Ratio (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_parent_speed_connection_ratio, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 86:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Parent Inactivity Before Disconnect (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_seconds_parent_inactivity_before_disconnect, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 87:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Server Inactivity Before Disconnect (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_seconds_server_inactivity_before_disconnect, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 88:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Nodes In Cache Before Disconnect (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_nodes_in_cache_before_disconnect, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 90:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Seconds Before Ping Children (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_seconds_before_ping_children, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 91:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Add To Privileged (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 92:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Check Privileges (Code: %02d)", msg_code);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Check Privileges Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_number_of_days, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 93:
        if (check_slsk_format(tvb, pinfo, offset, "ibisis")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Embedded Message (Code: %02d)", msg_code);
          offset += 4;
          if ( tvb_get_uint8(tvb, offset) == 3 ){
            /* Client-to-Client */
            proto_tree_add_uint_format_value(slsk_tree, hf_slsk_embedded_message_type, tvb, offset, 1, msg_code,
                       "Distributed Search (Byte: %d)", 3);
            offset += 1;
            proto_tree_add_item(slsk_tree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
            offset += str_len;
            proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item_ret_length(slsk_tree, hf_slsk_search_text, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
            offset += str_len;
          }
        }
      break;

      case 100:
        if (check_slsk_format(tvb, pinfo, offset, "ib")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Become Parent (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_byte, tvb, offset, 1, ENC_NA);
          offset += 1;
        }
      break;

      case 102:
        if (check_slsk_format(tvb, pinfo, offset, "ii*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Random Parent Addresses (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_num_parent_address, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "sii*")) {

              proto_tree_add_item_ret_length(slsk_tree, hf_slsk_user, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
              proto_tree_add_item(slsk_tree, hf_slsk_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
              offset += 4;
              proto_tree_add_item(slsk_tree, hf_slsk_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
            } else {
              break; /* invalid format */
            }
          }
        }
      break;

      case 103:
        if (check_slsk_format(tvb, pinfo, offset, "iis")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Send Wishlist Entry (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_search_text, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
      break;

      case 104:
        if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Type 104 (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      case 110:
        if (check_slsk_format(tvb, pinfo, offset, "i")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Similar Users (Code: %02d)", msg_code);
          offset += 4;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "ii*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Similar Users Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_number_of_users, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "si*")) {
              start_offset = offset;
              subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 4, ett_slsk_user, &ti_subtree, "User #%d", i+1);
              proto_tree_add_item_ret_length(subtree, hf_slsk_user, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
              proto_tree_add_item(subtree, hf_slsk_same_recommendation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
              proto_item_set_len(ti_subtree, offset-start_offset);
            } else {
              break; /* invalid format */
            }
          }
        }
      break;

      case 111:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Recommendations for Item (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "isi*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Recommendations for Item Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_num_recommendations, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "si*")) {
              start_offset = offset;
              subtree = proto_tree_add_subtree_format(slsk_tree, tvb, offset, 1, ett_slsk_recommendation, &ti_subtree, "Recommendation #%d", i+1);
              proto_tree_add_item_ret_length(subtree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
              proto_tree_add_item(subtree, hf_slsk_ranking, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
              proto_item_set_len(ti_subtree, offset-start_offset);
            } else {
              break; /* invalid format */
            }
          }
        }
      break;

      case 112:
        if (check_slsk_format(tvb, pinfo, offset, "is")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Similar Users for Item (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "isi*")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Get Similar Users for Item Reply (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_recommendation, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
          proto_tree_add_item_ret_int(slsk_tree, hf_slsk_num_recommendations, tvb, offset, 4, ENC_LITTLE_ENDIAN, &j);
          offset += 4;
          if (j > tvb_reported_length_remaining(tvb, offset))
            break;
          for (i = 0; i < j; i++) {
            if (check_slsk_format(tvb, pinfo, offset, "s*")) {
              proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
              offset += str_len;
            } else {
              break; /* invalid format */
            }
          }
        }
      break;

      case 1001:
        if (check_slsk_format(tvb, pinfo, offset, "iis")) {
          /* Client-to-Server */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Can't Connect To Peer (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
          proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
          offset += str_len;
        }
        else if (check_slsk_format(tvb, pinfo, offset, "ii")) {
          /* Server-to-Client */
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Can't Connect To Peer (Code: %02d)", msg_code);
          offset += 4;
          proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
          offset += 4;
        }
      break;

      default:
        if (check_slsk_format(tvb, pinfo, offset, "bisis")) {
          if ( tvb_get_uint8(tvb, offset) == 3 ){
            /* Client-to-Client */
            proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 1, msg_code,
                       "Distributed Search (Byte: %d)", 3);
            offset += 1;
            proto_tree_add_item(slsk_tree, hf_slsk_integer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
            offset += str_len;
            proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item_ret_length(slsk_tree, hf_slsk_search_text, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
            offset += str_len;
          }
        }
        else if (check_slsk_format(tvb, pinfo, offset, "bssi")) {
          if ( tvb_get_uint8(tvb, offset) == 1 ){
            /* Client-to-Client */
            uint32_t len;

            proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 1, msg_code,
                       "Peer Init (Byte: %d)", 1);
            offset += 1;
            proto_tree_add_item_ret_length(slsk_tree, hf_slsk_username, tvb, offset, 4, ENC_ASCII|ENC_LITTLE_ENDIAN, &str_len);
            offset += str_len;
            len = tvb_get_letohl(tvb, offset);
            str = tvb_get_string_enc(pinfo->pool, tvb, offset+4, len, ENC_ASCII);
            proto_tree_add_string_format_value(slsk_tree, hf_slsk_connection_type, tvb, offset, 4+len, str,
              "%s (Char: %s)", connection_type(str),
              format_text(pinfo->pool, str, len));
            offset += 4+len;
            proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
          }
        }
        else if (check_slsk_format(tvb, pinfo, offset, "bi")) {
          if ( tvb_get_uint8(tvb, offset) == 0 ){
            /* Client-to-Client */
            proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 1, msg_code,
                       "Pierce Fw (Byte: %d)", 0);
            offset += 1;
            proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
          }
        }
        else {
          proto_tree_add_uint_format_value(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
                     "Unknown (Code: %02d)", msg_code);
          offset += 4;
        }
      break;

    }

  if(offset < (int)msg_len){
   expert_add_info(pinfo, ti_len, &ei_slsk_unknown_data);
  }

  return tvb_captured_length(tvb);
}


static int dissect_slsk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, slsk_desegment, 4, get_slsk_pdu_len, dissect_slsk_pdu, data);
  return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */

void
proto_register_slsk(void)
{

/* Setup list of header fields  */
  static hf_register_info hf[] = {
    { &hf_slsk_integer,
      { "Integer", "slsk.integer",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_string,
      { "String", "slsk.string",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_byte,
      { "Byte", "slsk.byte",
      FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_message_length,
      { "Message Length", "slsk.message.length",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_message_code,
      { "Message Type", "slsk.message.code",
      FT_UINT32, BASE_DEC, NULL, 0, "Message Code with type string", HFILL } },
    { &hf_slsk_embedded_message_type,
      { "Embedded Message Type", "slsk.embedded_message.code",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_client_ip,
      { "Client IP", "slsk.client.ip",
      FT_IPv4, BASE_NONE, NULL, 0, "Client IP Address", HFILL } },
#if 0
    { &hf_slsk_server_ip,
      { "SoulSeek Server IP", "slsk.server.ip",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
#endif
    { &hf_slsk_directory_name,
      { "Directory name", "slsk.directory_name",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_username,
      { "Username", "slsk.username",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_password,
      { "Password", "slsk.password",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_version,
      { "Version", "slsk.version",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_login_successful,
      { "Login successful", "slsk.login.successful",
      FT_UINT8, BASE_DEC, VALS(slsk_yes_no), 0, NULL, HFILL } },
    { &hf_slsk_login_message,
      { "Login Message", "slsk.login.message",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_port,
      { "Port Number", "slsk.port.number",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_ip,
      { "IP Address", "slsk.ip.address",
      FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_user_exists,
      { "User exists", "slsk.user.exists",
      FT_UINT8, BASE_DEC, VALS(slsk_yes_no), 0, NULL, HFILL } },
    { &hf_slsk_status_code,
      { "Status Code", "slsk.status.code",
      FT_UINT32, BASE_DEC, VALS(slsk_status_codes), 0, NULL, HFILL } },
    { &hf_slsk_room,
      { "Room", "slsk.room",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_chat_message,
      { "Chat Message", "slsk.chat.message",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_users_in_room,
      { "Users in Room", "slsk.room.users",
      FT_INT32, BASE_DEC, NULL, 0, "Number of Users in Room", HFILL } },
    { &hf_slsk_token,
      { "Token", "slsk.token",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_connection_type,
      { "Connection Type", "slsk.connection.type",
      FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_chat_message_id,
      { "Chat Message ID", "slsk.chat.message.id",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_timestamp,
      { "Timestamp", "slsk.timestamp",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_search_text,
      { "Search Text", "slsk.search.text",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_folder_count,
      { "Folder Count", "slsk.folder.count",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_file_count,
      { "File Count", "slsk.file.count",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_average_speed,
      { "Average Speed", "slsk.average.speed",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_download_number,
      { "Download Number", "slsk.download.number",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_files,
      { "Files", "slsk.files",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_directories,
      { "Directories", "slsk.directories",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_slotsfull,
      { "Slots full", "slsk.slots.full",
      FT_UINT32, BASE_DEC, NULL, 0, "Upload Slots Full", HFILL } },
    { &hf_slsk_place_in_queue,
      { "Place in Queue", "slsk.queue.place",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_number_of_rooms,
      { "Number of Rooms", "slsk.room.count",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_filename,
      { "Filename", "slsk.filename",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_filename_ext,
      { "Filename ext", "slsk.filename_ext",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_directory,
      { "Directory", "slsk.directory",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_size,
      { "Size", "slsk.size",
      FT_UINT32, BASE_DEC, NULL, 0, "File Size", HFILL } },
#if 0
    { &hf_slsk_checksum,
      { "Checksum", "slsk.checksum",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
#endif
    { &hf_slsk_code,
      { "Code", "slsk.code",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_number_of_users,
      { "Number of Users", "slsk.user.count",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_number_of_days,
      { "Number of Days", "slsk.day.count",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_transfer_direction,
      { "Transfer Direction", "slsk.transfer.direction",
      FT_INT32, BASE_DEC, VALS(slsk_transfer_direction), 0, NULL, HFILL } },
    { &hf_slsk_user_description,
      { "User Description", "slsk.user.description",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_picture_exists,
      { "Picture exists", "slsk.user.picture.exists",
      FT_UINT8, BASE_DEC, VALS(slsk_yes_no), 0, "User has a picture", HFILL } },
    { &hf_slsk_picture,
      { "User Picture", "slsk.user.picture",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
#if 0
    { &hf_slsk_user_uploads,
      { "User uploads", "slsk.uploads.user",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
#endif
    { &hf_slsk_total_uploads,
      { "Total uploads allowed", "slsk.uploads.total",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_queued_uploads,
      { "Queued uploads", "slsk.uploads.queued",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_slots_available,
      { "Upload Slots available", "slsk.uploads.available",
      FT_UINT8, BASE_DEC, VALS(slsk_yes_no), 0, NULL, HFILL } },
    { &hf_slsk_allowed,
      { "Download allowed", "slsk.user.allowed",
      FT_UINT8, BASE_DEC, VALS(slsk_yes_no), 0, NULL, HFILL } },
    { &hf_slsk_compr_packet,
      { "zlib compressed packet", "slsk.compr.packet",
      FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_parent_min_speed,
      { "Parent Min Speed", "slsk.parent.min.speed",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_parent_speed_connection_ratio,
      { "Parent Speed Connection Ratio", "slsk.parent.speed.connection.ratio",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_seconds_parent_inactivity_before_disconnect,
      { "Seconds Parent Inactivity Before Disconnect", "slsk.seconds.parent.inactivity.before.disconnect",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_seconds_server_inactivity_before_disconnect,
      { "Seconds Server Inactivity Before Disconnect", "slsk.seconds.server.inactivity.before.disconnect",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_nodes_in_cache_before_disconnect,
      { "Nodes In Cache Before Disconnect", "slsk.nodes.in.cache.before.disconnect",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_seconds_before_ping_children,
      { "Seconds Before Ping Children", "slsk.seconds.before.ping.children",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_recommendation,
      { "Recommendation", "slsk.recommendation",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_user,
      { "User", "slsk.user",
      FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_ranking,
      { "Ranking", "slsk.ranking",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_compressed_packet_length,
      { "Compressed packet length", "slsk.compressed_packet_length",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_uncompressed_packet_length,
      { "Uncompressed packet length", "slsk.uncompressed_packet_length",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_num_directories,
      { "Number of directories", "slsk.num_directories",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_upload_speed,
      { "Upload speed", "slsk.upload_speed",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_in_queue,
      { "In Queue", "slsk.in_queue",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_num_slotsfull_records,
      { "Number of Slotsfull Records", "slsk.num_slotsfull_records",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_num_recommendations,
      { "Number of Recommendations", "slsk.num_recommendations",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_num_files,
      { "Number of Files", "slsk.num_files",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_num_strings,
      { "Number of strings", "slsk.num_strings",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_file_code,
      { "Code", "slsk.file_code",
      FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_file_size1,
      { "Size1", "slsk.file_size1",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_file_size2,
      { "Size2", "slsk.file_size2",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_file_num_attributes,
      { "Number of attributes", "slsk.file_num_attributes",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_file_attribute_type,
      { "File attribute type", "slsk.file_attribute_type",
      FT_UINT32, BASE_DEC, VALS(slsk_attr_type), 0, NULL, HFILL } },
    { &hf_slsk_file_attribute_value,
      { "File attribute value", "slsk.file_attribute_value",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_free_upload_slots,
      { "Free upload slots", "slsk.free_upload_slots",
      FT_UINT32, BASE_DEC, VALS(slsk_yes_no), 0, NULL, HFILL } },
    { &hf_slsk_bytes,
      { "Bytes", "slsk.bytes",
      FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_slsk_same_recommendation,
      { "Same Recommendation", "slsk.same_recommendation",
      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_number_of_priv_users,
      { "Number of Privileged Users", "slsk.priv_user.count",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_slsk_num_parent_address,
      { "Number of Parent Addresses", "slsk.parent_addr.count",
      FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },

  };

/* Setup protocol subtree array */
  static int *ett[] = {
    &ett_slsk,
    &ett_slsk_compr_packet,
    &ett_slsk_directory,
    &ett_slsk_file,
    &ett_slsk_file_attribute,
    &ett_slsk_user,
    &ett_slsk_recommendation,
    &ett_slsk_room,
    &ett_slsk_string,
  };

  static ei_register_info ei[] = {
     { &ei_slsk_unknown_data, { "slsk.unknown_data", PI_UNDECODED, PI_WARN, "Unknown Data (not interpreted)", EXPFILL }},
     { &ei_slsk_zlib_decompression_failed, { "slsk.zlib_decompression_failed", PI_PROTOCOL, PI_WARN, "zlib compressed packet failed to decompress", EXPFILL }},
     { &ei_slsk_decompression_failed, { "slsk.decompression_failed", PI_PROTOCOL, PI_WARN, "decompression failed", EXPFILL }},
  };

  module_t *slsk_module;
  expert_module_t* expert_slsk;

/* Registers the protocol name and description */
  proto_slsk = proto_register_protocol("SoulSeek Protocol", "SoulSeek", "slsk");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_slsk, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_slsk = expert_register_protocol(proto_slsk);
  expert_register_field_array(expert_slsk, ei, array_length(ei));

  /* Register the dissector handle */
  slsk_handle = register_dissector("slsk", dissect_slsk, proto_slsk);

/* Registers the options in the menu preferences */
  slsk_module = prefs_register_protocol(proto_slsk, NULL);
  prefs_register_bool_preference(slsk_module, "desegment",
      "Reassemble SoulSeek messages spanning multiple TCP segments",
      "Whether the SoulSeek dissector should reassemble messages spanning multiple TCP segments."
      " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
      &slsk_desegment);
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
  prefs_register_bool_preference(slsk_module, "decompress",
      "Decompress zlib compressed packets inside SoulSeek messages",
      "Whether the SoulSeek dissector should decompress all zlib compressed packets inside messages",
      &slsk_decompress);
#endif

}


void
proto_reg_handoff_slsk(void)
{
  dissector_add_uint_range_with_preference("tcp.port", SLSK_TCP_PORT_RANGE, slsk_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
