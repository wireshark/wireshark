/* packet-autosar-nm.c
 * AUTOSAR-NM Dissector
 * By Dr. Lars Voelker <lars.voelker@bmw.de>
 * Copyright 2014-2017 Dr. Lars Voelker, BMW
 * Copyright 2019 Maksim Salau <maksim.salau@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * AUTOSAR-NM is an automotive communication protocol as standardized by
 * AUTOSAR (www.autosar.org) and is specified in AUTOSAR_SWS_UDPNetworkManagement.pdf
 * and AUTOSAR_SWS_CANNetworkManagement.pdf which can be accessed on:
 * autosar.org -> Classic Platform -> Software Arch -> Comm Stack.
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include "packet-socketcan.h"

void proto_reg_handoff_autosar_nm(void);
void proto_register_autosar_nm(void);

typedef struct _user_data_field_t {
  gchar*  udf_name;
  gchar*  udf_desc;
  guint32 udf_offset;
  guint32 udf_length;
  guint32 udf_mask;
  gchar*  udf_value_desc;
} user_data_field_t;

static int proto_autosar_nm = -1;
static int proto_can = -1;
static int proto_canfd = -1;
static int proto_caneth = -1;
static int proto_udp = -1;

/*** header fields ***/
static int hf_autosar_nm_source_node_identifier = -1;
static int hf_autosar_nm_control_bit_vector = -1;
static int hf_autosar_nm_control_bit_vector_repeat_msg_req = -1;
static int hf_autosar_nm_control_bit_vector_reserved1 = -1;
static int hf_autosar_nm_control_bit_vector_reserved2 = -1;
static int hf_autosar_nm_control_bit_vector_nm_coord_id = -1;
static int hf_autosar_nm_control_bit_vector_nm_coord_sleep = -1;
static int hf_autosar_nm_control_bit_vector_active_wakeup = -1;
static int hf_autosar_nm_control_bit_vector_reserved5 = -1;
static int hf_autosar_nm_control_bit_vector_pni = -1;
static int hf_autosar_nm_control_bit_vector_reserved7 = -1;
static int hf_autosar_nm_user_data = -1;

/*** protocol tree items ***/
static gint ett_autosar_nm = -1;
static gint ett_autosar_nm_cbv = -1;
static gint ett_autosar_nm_user_data = -1;

/*** Bit meanings ***/
static const true_false_string tfs_autosar_nm_control_rep_msg_req = {
  "Repeat Message State requested", "Repeat Message State not requested" };

static const true_false_string tfs_autosar_nm_control_sleep_bit = {
  "Start of synchronized shutdown requested", "Start of synchronized shutdown not requested" };

static const true_false_string tfs_autosar_nm_control_active_wakeup = {
  "Node has woken up the network", "Node has not woken up the network" };

static const true_false_string tfs_autosar_nm_control_pni = {
  "NM message contains no Partial Network request information", "NM message contains Partial Network request information" };

/*** Configuration items ***/
/* Set the order of the first two fields (Source Node Identifier and Control Bit Vector */
static gboolean g_autosar_nm_swap_first_fields = TRUE;

/* Read bits 1 and 2 of Control Bit Vector as NM Coordinator Id */
static gboolean g_autosar_nm_interpret_coord_id = FALSE;

/* Id and mask of CAN frames to be dissected */
static guint32 g_autosar_nm_can_id = 0;
static guint32 g_autosar_nm_can_id_mask = 0;

/*******************************
 ****** User data fields  ******
 *******************************/

/*** stolen from the HTTP disector ;-) ***/

static user_data_field_t* user_data_fields;
static guint num_user_data_fields;
static GHashTable* user_data_fields_hash_hf;
static hf_register_info* dynamic_hf;
static guint dynamic_hf_size;
static wmem_map_t* user_data_fields_hash_ett;

static gboolean
user_data_fields_update_cb(void *r, char **err)
{
  user_data_field_t *rec = (user_data_field_t *)r;
  char c;
  *err = NULL;

  if (rec->udf_length == 0) {
    *err = g_strdup_printf("length of user data field can't be 0 Bytes (name: %s offset: %i length: %i)", rec->udf_name, rec->udf_offset, rec->udf_length);
    return (*err == NULL);
  }

  if (rec->udf_length > 4) {
    *err = g_strdup_printf("length of user data field can't be greater 4 Bytes (name: %s offset: %i length: %i)", rec->udf_name, rec->udf_offset, rec->udf_length);
    return (*err == NULL);
  }

  if (rec->udf_offset < 2) {
    *err = g_strdup_printf("offset of user data field can't be short than 2 (name: %s offset: %i length: %i)", rec->udf_name, rec->udf_offset, rec->udf_length);
    return (*err == NULL);
  }

  if (rec->udf_mask >= G_MAXUINT32) {
    *err = g_strdup_printf("mask can only be up to 32bits (name: %s)", rec->udf_name);
    return (*err == NULL);
  }

  if (rec->udf_name == NULL) {
    *err = g_strdup_printf("Name of user data field can't be empty");
    return (*err == NULL);
  }

  g_strstrip(rec->udf_name);
  if (rec->udf_name[0] == 0) {
    *err = g_strdup_printf("Name of user data field can't be empty");
    return (*err == NULL);
  }

  /* Check for invalid characters (to avoid asserting out when
   * registering the field).
   */
  c = proto_check_field_name(rec->udf_name);
  if (c) {
    *err = g_strdup_printf("Name of user data field can't contain '%c'", c);
    return (*err == NULL);
  }

  return (*err == NULL);
}

static void *
user_data_fields_copy_cb(void* n, const void* o, size_t siz _U_)
{
  user_data_field_t* new_rec = (user_data_field_t*)n;
  const user_data_field_t* old_rec = (const user_data_field_t*)o;

  new_rec->udf_name       = g_strdup(old_rec->udf_name);
  new_rec->udf_desc       = g_strdup(old_rec->udf_desc);
  new_rec->udf_offset     = old_rec->udf_offset;
  new_rec->udf_length     = old_rec->udf_length;
  new_rec->udf_mask       = old_rec->udf_mask;
  new_rec->udf_value_desc = g_strdup(old_rec->udf_value_desc);

  return new_rec;
}

static void
user_data_fields_free_cb(void*r)
{
  user_data_field_t* rec = (user_data_field_t*)r;

  g_free(rec->udf_name);
  g_free(rec->udf_desc);
  g_free(rec->udf_value_desc);
}

UAT_CSTRING_CB_DEF(user_data_fields, udf_name, user_data_field_t)
UAT_CSTRING_CB_DEF(user_data_fields, udf_desc, user_data_field_t)
UAT_DEC_CB_DEF(user_data_fields, udf_offset, user_data_field_t)
UAT_DEC_CB_DEF(user_data_fields, udf_length, user_data_field_t)
UAT_HEX_CB_DEF(user_data_fields, udf_mask, user_data_field_t)
UAT_CSTRING_CB_DEF(user_data_fields, udf_value_desc, user_data_field_t)

static guint64
calc_ett_key(guint32 offset, guint32 length)
{
  guint64 ret = offset;
  return (ret * 0x100000000) ^ length;
}

/*
 * This creates a string for you that can be used as key for the hash table.
 * YOU must g_free that string!
 */
static gchar*
calc_hf_key(user_data_field_t udf)
{
  gchar* ret = NULL;
  ret = g_strdup_printf("%i-%i-%i-%s", udf.udf_offset, udf.udf_length, udf.udf_mask, udf.udf_name);
  return ret;
}

/*
 *
 */
static gint*
get_hf_for_user_data(gchar* key)
{
  gint* hf_id = NULL;

  if (user_data_fields_hash_hf) {
    hf_id = (gint*)g_hash_table_lookup(user_data_fields_hash_hf, key);
  }
  else {
    hf_id = NULL;
  }

  return hf_id;
}

/*
 *
 */
static gint*
get_ett_for_user_data(guint32 offset, guint32 length)
{
  gint* ett_id = NULL;

  guint64 key = calc_ett_key(offset, length);

  if (user_data_fields_hash_ett) {
    ett_id = (gint*)wmem_map_lookup(user_data_fields_hash_ett, &key);
  }
  else {
    ett_id = NULL;
  }

  return ett_id;
}

/*
 *
 */
static void
deregister_user_data(void)
{
  if (dynamic_hf) {
    /* Unregister all fields */
    for (guint i = 0; i < dynamic_hf_size; i++) {
      proto_deregister_field(proto_autosar_nm, *(dynamic_hf[i].p_id));
      g_free(dynamic_hf[i].p_id);
    }

    proto_add_deregistered_data(dynamic_hf);
    dynamic_hf = NULL;
    dynamic_hf_size = 0;
  }

  if (user_data_fields_hash_hf) {
    g_hash_table_destroy(user_data_fields_hash_hf);
    user_data_fields_hash_hf = NULL;
  }
}

static void
user_data_post_update_cb(void)
{
  gint* hf_id;
  gint *ett_id;
  gchar* tmp = NULL;
  guint64* key = NULL;

  static gint ett_dummy = -1;
  static gint *ett[] = {
    &ett_dummy,
  };

  deregister_user_data();

  // we cannot unregister ETTs, so we should try to limit the damage of an update
  if (num_user_data_fields) {
    user_data_fields_hash_hf = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    dynamic_hf = g_new0(hf_register_info, num_user_data_fields);
    dynamic_hf_size = num_user_data_fields;

    if (user_data_fields_hash_ett == NULL) {
      user_data_fields_hash_ett = wmem_map_new(wmem_epan_scope(), g_int64_hash, g_int64_equal);
    }

    for (guint i = 0; i < dynamic_hf_size; i++) {
      hf_id = g_new(gint, 1);
      *hf_id = -1;

      dynamic_hf[i].p_id = hf_id;
      dynamic_hf[i].hfinfo.strings = NULL;
      dynamic_hf[i].hfinfo.bitmask = user_data_fields[i].udf_mask;
      dynamic_hf[i].hfinfo.same_name_next = NULL;
      dynamic_hf[i].hfinfo.same_name_prev_id = -1;

      if (user_data_fields[i].udf_mask == 0 || user_data_fields[i].udf_length <= 0 || user_data_fields[i].udf_length>4) {
        dynamic_hf[i].hfinfo.name = g_strdup(user_data_fields[i].udf_name);
        dynamic_hf[i].hfinfo.abbrev = g_strdup_printf("nm.user_data.%s", user_data_fields[i].udf_name);
        dynamic_hf[i].hfinfo.type = FT_BYTES;
        dynamic_hf[i].hfinfo.display = BASE_NONE;
        dynamic_hf[i].hfinfo.bitmask = 0;
        dynamic_hf[i].hfinfo.blurb = g_strdup(user_data_fields[i].udf_desc);
      }
      else {
        dynamic_hf[i].hfinfo.name = g_strdup(user_data_fields[i].udf_value_desc);
        dynamic_hf[i].hfinfo.abbrev = g_strdup_printf("nm.user_data.%s.%s", user_data_fields[i].udf_name, user_data_fields[i].udf_value_desc);
        dynamic_hf[i].hfinfo.type = FT_BOOLEAN;
        dynamic_hf[i].hfinfo.display = 8 * (user_data_fields[i].udf_length);
        // dynamic_hf[i].hfinfo.bitmask = 0;
        dynamic_hf[i].hfinfo.blurb = g_strdup(user_data_fields[i].udf_value_desc);
      }

      tmp = calc_hf_key(user_data_fields[i]);
      g_hash_table_insert(user_data_fields_hash_hf, tmp, hf_id);

      // generate etts for new fields only
      if (get_ett_for_user_data(user_data_fields[i].udf_offset, user_data_fields[i].udf_length) == NULL) {
        ett_dummy = -1;
        proto_register_subtree_array(ett, array_length(ett));

        ett_id = wmem_new(wmem_epan_scope(), gint);
        *ett_id = ett_dummy;

        key = wmem_new(wmem_epan_scope(), guint64);
        *key = calc_ett_key(user_data_fields[i].udf_offset, user_data_fields[i].udf_length);

        wmem_map_insert(user_data_fields_hash_ett, key, ett_id);
      }
    }

    proto_register_field_array(proto_autosar_nm, dynamic_hf, dynamic_hf_size);
  }
}

static void
user_data_reset_cb(void)
{
  deregister_user_data();
}


/**********************************
 ****** The dissector itself ******
 **********************************/

static int
dissect_autosar_nm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
  wmem_list_frame_t *prev_layer;
  proto_item *ti;
  proto_tree *autosar_nm_tree;
  proto_tree *autosar_nm_subtree = NULL;
  gchar* tmp = NULL;
  guint32 offset = 0;
  guint32 length = 0;
  guint32 msg_length = 0;
  guint32 ctrl_bit_vector;
  guint32 src_node_id = 0;
  guint i = 0;
  int* hf_id;
  int ett_id;

  // AUTOSAR says default is Source Node ID first and Ctrl Bit Vector second but this can be also swapped
  guint32 offset_ctrl_bit_vector = 1;
  guint32 offset_src_node_id = 0;

  static int * const control_bits_legacy[] = {
    &hf_autosar_nm_control_bit_vector_repeat_msg_req,
    &hf_autosar_nm_control_bit_vector_nm_coord_id,
    &hf_autosar_nm_control_bit_vector_nm_coord_sleep,
    &hf_autosar_nm_control_bit_vector_active_wakeup,
    &hf_autosar_nm_control_bit_vector_reserved5,
    &hf_autosar_nm_control_bit_vector_pni,
    &hf_autosar_nm_control_bit_vector_reserved7,
    NULL
  };

  static int * const control_bits[] = {
    &hf_autosar_nm_control_bit_vector_repeat_msg_req,
    &hf_autosar_nm_control_bit_vector_reserved1,
    &hf_autosar_nm_control_bit_vector_reserved2,
    &hf_autosar_nm_control_bit_vector_nm_coord_sleep,
    &hf_autosar_nm_control_bit_vector_active_wakeup,
    &hf_autosar_nm_control_bit_vector_reserved5,
    &hf_autosar_nm_control_bit_vector_pni,
    &hf_autosar_nm_control_bit_vector_reserved7,
    NULL
  };

  prev_layer = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));

  if (prev_layer) {
    const int prev_proto = GPOINTER_TO_INT(wmem_list_frame_data(prev_layer));

    if (prev_proto != proto_udp) {
      const struct can_info *can_info       = (struct can_info *)data;
      const gboolean          is_can_frame =
        (prev_proto == proto_can) ||
        (prev_proto == proto_canfd) ||
        (wmem_list_find(pinfo->layers, GINT_TO_POINTER(proto_caneth)) != NULL);

      if (!is_can_frame) {
        /* Only UDP and CAN transports are supported. */
        return 0;
      }

      DISSECTOR_ASSERT(can_info);

      if (can_info->id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) {
        /* Error and RTR frames are not for us. */
        return 0;
      }

      if ((can_info->id & g_autosar_nm_can_id_mask) != (g_autosar_nm_can_id & g_autosar_nm_can_id_mask)) {
        /* Id doesn't match. The frame is not for us. */
        return 0;
      }
    }
  }

  if (g_autosar_nm_swap_first_fields == TRUE) {
    offset_ctrl_bit_vector = 0;
    offset_src_node_id = 1;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AUTOSAR NM");
  col_clear(pinfo->cinfo, COL_INFO);

  msg_length = tvb_reported_length(tvb);

  ti = proto_tree_add_item(tree, proto_autosar_nm, tvb, 0, -1, ENC_NA);
  autosar_nm_tree = proto_item_add_subtree(ti, ett_autosar_nm);

  if (g_autosar_nm_swap_first_fields == FALSE) {
    proto_tree_add_item_ret_uint(autosar_nm_tree, hf_autosar_nm_source_node_identifier, tvb, offset_src_node_id, 1, ENC_BIG_ENDIAN, &src_node_id);
  }

  proto_tree_add_bitmask(autosar_nm_tree, tvb, offset_ctrl_bit_vector, hf_autosar_nm_control_bit_vector, ett_autosar_nm_cbv,
                         (g_autosar_nm_interpret_coord_id ? control_bits_legacy : control_bits), ENC_BIG_ENDIAN);
  ctrl_bit_vector = tvb_get_guint8(tvb, offset_ctrl_bit_vector);

  if (g_autosar_nm_swap_first_fields == TRUE) {
    proto_tree_add_item_ret_uint(autosar_nm_tree, hf_autosar_nm_source_node_identifier, tvb, offset_src_node_id, 1, ENC_BIG_ENDIAN, &src_node_id);
  }

  col_add_fstr(pinfo->cinfo, COL_INFO, "Control Bit Vector: 0x%02x, Source Node: 0x%02x", ctrl_bit_vector, src_node_id);
  proto_item_append_text(ti, ", Control Bit Vector: 0x%02x, Source Node: %i", ctrl_bit_vector, src_node_id);

  offset = 2;

  /* now we need to process the user defined fields ... */
  ti = proto_tree_add_item(autosar_nm_tree, hf_autosar_nm_user_data, tvb, offset, msg_length - offset, ENC_NA);
  autosar_nm_tree = proto_item_add_subtree(ti, ett_autosar_nm_user_data);

  for (i = 0; i < num_user_data_fields; i++) {
    tmp = calc_hf_key(user_data_fields[i]);
    hf_id = get_hf_for_user_data(tmp);

    offset = user_data_fields[i].udf_offset;
    length = user_data_fields[i].udf_length;
    ett_id = *(get_ett_for_user_data(offset, length));

    if (hf_id && msg_length >= length + offset) {
      if (user_data_fields[i].udf_mask == 0) {
        ti = proto_tree_add_item(autosar_nm_tree, *hf_id, tvb, offset, length, ENC_BIG_ENDIAN);
        autosar_nm_subtree = proto_item_add_subtree(ti, ett_id);
      }
      else {
        if (autosar_nm_subtree != NULL) {
          proto_tree_add_item(autosar_nm_subtree, *hf_id, tvb, offset, length, ENC_BIG_ENDIAN);
        }
      }
    }
    else {
      /* should we warn? */
    }

    g_free(tmp);
  }

  return 8;
}

void proto_register_autosar_nm(void)
{
  module_t *autosar_nm_module;
  uat_t* user_data_fields_uat;

  static hf_register_info hf_autosar_nm[] = {
    { &hf_autosar_nm_control_bit_vector,
    { "Control Bit Vector", "autosar-nm.ctrl", FT_UINT8, BASE_HEX, NULL, 0x0, "The Control Bit Vector", HFILL } },
    { &hf_autosar_nm_control_bit_vector_repeat_msg_req,
    { "Repeat Message Request", "autosar-nm.ctrl.repeat_msg_req", FT_BOOLEAN, 8, TFS(&tfs_autosar_nm_control_rep_msg_req), 0x01, "The Repeat Message Request Bit", HFILL } },
    { &hf_autosar_nm_control_bit_vector_reserved1,
    { "Reserved Bit 1", "autosar-nm.ctrl.reserved1", FT_UINT8, BASE_DEC, NULL, 0x02, "The Reserved Bit 1", HFILL } },
    { &hf_autosar_nm_control_bit_vector_reserved2,
    { "Reserved Bit 2", "autosar-nm.ctrl.reserved2", FT_UINT8, BASE_DEC, NULL, 0x04, "The Reserved Bit 2", HFILL } },
    { &hf_autosar_nm_control_bit_vector_nm_coord_id,
    { "NM Coordinator Id", "autosar-nm.ctrl.nm_coord_id", FT_UINT8, BASE_DEC, NULL, 0x06, "The NM Coordinator Identifier", HFILL } },
    { &hf_autosar_nm_control_bit_vector_nm_coord_sleep,
    { "NM Coordinator Sleep", "autosar-nm.ctrl.nm_coord_sleep", FT_BOOLEAN, 8, TFS(&tfs_autosar_nm_control_sleep_bit), 0x08, "NM Coordinator Sleep Bit", HFILL } },
    { &hf_autosar_nm_control_bit_vector_active_wakeup,
    { "Active Wakeup", "autosar-nm.ctrl.active_wakeup", FT_BOOLEAN, 8, TFS(&tfs_autosar_nm_control_active_wakeup), 0x10, "Active Wakeup Bit", HFILL } },
    { &hf_autosar_nm_control_bit_vector_reserved5,
    { "Reserved Bit 5", "autosar-nm.ctrl.reserved5", FT_UINT8, BASE_DEC, NULL, 0x20, "The Reserved Bit 5", HFILL } },
    { &hf_autosar_nm_control_bit_vector_pni,
    { "Partial Network Information", "autosar-nm.ctrl.pni", FT_BOOLEAN, 8, TFS(&tfs_autosar_nm_control_pni), 0x40, "Partial Network Information Bit", HFILL } },
    { &hf_autosar_nm_control_bit_vector_reserved7,
    { "Reserved Bit 7", "autosar-nm.ctrl.reserved7", FT_UINT8, BASE_DEC, NULL, 0x80, "The Reserved Bit 7", HFILL } },

    { &hf_autosar_nm_source_node_identifier,
    { "Source Node Identifier", "autosar-nm.src", FT_UINT8, BASE_DEC, NULL, 0x0, "The identification of the sending node", HFILL } },

    { &hf_autosar_nm_user_data,
    { "User Data", "autosar-nm.user_data", FT_BYTES, BASE_NONE, NULL, 0x0, "The User Data", HFILL } },
  };

  static gint *ett[] = {
    &ett_autosar_nm,
    &ett_autosar_nm_cbv,
    &ett_autosar_nm_user_data,
  };

  /* UAT for user_data fields */
  static uat_field_t user_data_uat_fields[] = {
    UAT_FLD_CSTRING(user_data_fields, udf_name, "User data name", "Name of user data field"),
    UAT_FLD_CSTRING(user_data_fields, udf_desc, "User data desc", "Description of user data field"),
    UAT_FLD_DEC(user_data_fields, udf_offset, "User data offset", "Offset of the user data field in the AUTOSAR-NM message (uint32)"),
    UAT_FLD_DEC(user_data_fields, udf_length, "User data length", "Length of the user data field in the AUTOSAR-NM message (uint32)"),
    UAT_FLD_DEC(user_data_fields, udf_mask, "User data mask", "Relevant bits of the user data field in the AUTOSAR-NM message (uint32)"),
    UAT_FLD_CSTRING(user_data_fields, udf_value_desc, "User data value", "Description what the masked bits mean"),
    UAT_END_FIELDS
  };

  /* Register the protocol name and description */
  proto_autosar_nm = proto_register_protocol("AUTOSAR Network Management", "AUTOSAR NM", "autosar-nm");
  proto_register_field_array(proto_autosar_nm, hf_autosar_nm, array_length(hf_autosar_nm));
  proto_register_alias(proto_autosar_nm, "nm");
  proto_register_subtree_array(ett, array_length(ett));

  /* Register configuration options */
  autosar_nm_module = prefs_register_protocol(proto_autosar_nm, NULL);

  prefs_register_bool_preference(autosar_nm_module, "swap_ctrl_and_src",
    "Swap Source Node Identifier and Control Bit Vector",
    "In the standard the Source Node Identifier is the first byte "
    "and the Control Bit Vector is the second byte. "
    "Using this parameter they can be swapped",
    &g_autosar_nm_swap_first_fields);

  prefs_register_bool_preference(autosar_nm_module, "interpret_coord_id",
    "Interpret bits 1 and 2 of Control Bit Vector as 'NM Coordinator Id'",
    "Revision 4.3.1 of the specification doesn't have 'NM Coordinator Id' in Control Bit Vector. "
    "Using this parameter one may switch to a mode compatible with revision 3.2 of the specification.",
    &g_autosar_nm_interpret_coord_id);

  prefs_register_uint_preference(
    autosar_nm_module, "can_id",
    "CAN id",
    "Identifier that is used to filter packets that should be dissected. "
    "Set bit 31 when defining an extended id. "
    "(works with the mask defined below)",
    16, &g_autosar_nm_can_id);

  prefs_register_uint_preference(
    autosar_nm_module, "can_id_mask",
    "CAN id mask",
    "Mask applied to CAN identifiers when decoding whether a packet should dissected. "
    "Use 0xFFFFFFFF mask to require exact match.",
    16, &g_autosar_nm_can_id_mask);

  /* UAT */
  user_data_fields_uat = uat_new("NM User Data Fields Table",
    sizeof(user_data_field_t),       /* record size            */
    "NM_user_data_fields",        /* filename              */
    TRUE,                             /* from_profile          */
    &user_data_fields,                /* data_ptr              */
    &num_user_data_fields,            /* numitems_ptr          */
    UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,  /* specifies named fields, so affects dissection and the set of named fields */
    NULL,                             /* help                  */
    user_data_fields_copy_cb,         /* copy callback         */
    user_data_fields_update_cb,       /* update callback       */
    user_data_fields_free_cb,         /* free callback         */
    user_data_post_update_cb,         /* post update callback  */
    user_data_reset_cb,               /* reset callback        */
    user_data_uat_fields);            /* UAT field definitions */

  prefs_register_uat_preference(autosar_nm_module, "autosar_nm_user_data_fields", "User Data Field Configuration",
    "A table to define user defined fields in the NM payload",
    user_data_fields_uat);
}

void proto_reg_handoff_autosar_nm(void)
{
  dissector_handle_t nm_handle = create_dissector_handle(dissect_autosar_nm, proto_autosar_nm);

  dissector_add_for_decode_as_with_preference("udp.port", nm_handle);
  dissector_add_for_decode_as("can.subdissector", nm_handle);

  proto_can    = proto_get_id_by_filter_name("can");
  proto_canfd  = proto_get_id_by_filter_name("canfd");
  proto_caneth = proto_get_id_by_filter_name("caneth");
  proto_udp    = proto_get_id_by_filter_name("udp");
}

/*
 * Editor modelines
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
