/* packet-autosar-nm.c
 * AUTOSAR-NM Dissector
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de> / <lars.voelker@bmw.de>
 * Copyright 2014-2021 Dr. Lars Voelker
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

#define AUTOSAR_NM_NAME "AUTOSAR NM"

typedef struct _user_data_field_t {
  gchar*  udf_name;
  gchar*  udf_desc;
  guint32 udf_offset;
  guint32 udf_length;
  guint64 udf_mask;
  gchar*  udf_value_desc;
} user_data_field_t;

static int proto_autosar_nm = -1;

static dissector_handle_t nm_handle;
static dissector_handle_t nm_handle_can;

/*** header fields ***/
static int hf_autosar_nm_source_node_identifier = -1;
static int hf_autosar_nm_control_bit_vector = -1;
static int hf_autosar_nm_control_bit_vector_repeat_msg_req = -1;
static int hf_autosar_nm_control_bit_vector_reserved1 = -1;
static int hf_autosar_nm_control_bit_vector_pn_shutdown_request = -1;
static int hf_autosar_nm_control_bit_vector_reserved2 = -1;
static int hf_autosar_nm_control_bit_vector_nm_coord_id = -1;
static int hf_autosar_nm_control_bit_vector_reserved3 = -1;
static int hf_autosar_nm_control_bit_vector_nm_coord_sleep = -1;
static int hf_autosar_nm_control_bit_vector_reserved4 = -1;
static int hf_autosar_nm_control_bit_vector_active_wakeup = -1;
static int hf_autosar_nm_control_bit_vector_reserved5 = -1;
static int hf_autosar_nm_control_bit_vector_pn_learning = -1;
static int hf_autosar_nm_control_bit_vector_pni = -1;
static int hf_autosar_nm_control_bit_vector_reserved6 = -1;
static int hf_autosar_nm_control_bit_vector_reserved7 = -1;
static int hf_autosar_nm_user_data = -1;

/*** protocol tree items ***/
static gint ett_autosar_nm = -1;
static gint ett_autosar_nm_cbv = -1;
static gint ett_autosar_nm_user_data = -1;

/*** Bit meanings ***/
static const true_false_string tfs_autosar_nm_control_rep_msg_req = {
  "Repeat Message State requested", "Repeat Message State not requested" };

static const true_false_string tfs_autosar_nm_control_pn_shutdown_req= {
  "NM message contains synchronized PN shutdown request", "NM message does not contain synchronized PN shutdown request" };

static const true_false_string tfs_autosar_nm_control_sleep_bit = {
  "Start of synchronized shutdown requested", "Start of synchronized shutdown not requested" };

static const true_false_string tfs_autosar_nm_control_active_wakeup = {
  "Node has woken up the network", "Node has not woken up the network" };

static const true_false_string tfs_autosar_nm_control_pn_learning = {
  "PNC learning is requested", "PNC learning is not requested" };

static const true_false_string tfs_autosar_nm_control_pni = {
  "NM message contains Partial Network request information", "NM message contains no Partial Network request information" };

/*** Configuration items ***/

enum parameter_byte_position_value {
    byte_pos_off = -1,
    byte_pos_0 = 0,
    byte_pos_1 = 1
};

static const enum_val_t byte_position_vals[] = {
    {"0", "Byte Position 0", byte_pos_0},
    {"1", "Byte Position 1", byte_pos_1},
    {"off", "Turned off", byte_pos_off},
    {NULL, NULL, -1}
};

/* Set positions of the first two fields (Source Node Identifier and Control Bit Vector */
static gint g_autosar_nm_pos_cbv = (gint)byte_pos_0;
static gint g_autosar_nm_pos_sni = (gint)byte_pos_1;

enum parameter_cbv_version_value {
    autosar_3_0_or_newer = 0,
    autosar_3_2,
    autosar_4_0,
    autosar_4_1_or_newer,
    autosar_20_11
};

static const enum_val_t cbv_version_vals[] = {
    {"3.0", "AUTOSAR 3.0 or 3.1", autosar_3_0_or_newer},
    {"3.2", "AUTOSAR 3.2", autosar_3_2},
    {"4.0", "AUTOSAR 4.0", autosar_4_0},
    {"4.1", "AUTOSAR 4.1 or newer", autosar_4_1_or_newer},
    {"20-11", "AUTOSAR 20-11", autosar_20_11},
    {NULL, NULL, -1}
};

static gint g_autosar_nm_cbv_version = (gint)autosar_4_1_or_newer;

/* Id and mask of CAN frames to be dissected */
static guint32 g_autosar_nm_can_id = 0;
static guint32 g_autosar_nm_can_id_mask = 0xffffffff;

/* Relevant PDUs */
static range_t *g_autosar_nm_pdus = NULL;
static range_t *g_autosar_nm_ipdum_pdus = NULL;


/*******************************
 ****** User data fields  ******
 *******************************/

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
    *err = ws_strdup_printf("length of user data field can't be 0 Bytes (name: %s offset: %i length: %i)", rec->udf_name, rec->udf_offset, rec->udf_length);
    return (*err == NULL);
  }

  if (rec->udf_length > 8) {
    *err = ws_strdup_printf("length of user data field can't be greater 8 Bytes (name: %s offset: %i length: %i)", rec->udf_name, rec->udf_offset, rec->udf_length);
    return (*err == NULL);
  }

  if (rec->udf_mask >= G_MAXUINT64) {
    *err = ws_strdup_printf("mask can only be up to 64bits (name: %s)", rec->udf_name);
    return (*err == NULL);
  }

  if (rec->udf_name == NULL) {
    *err = ws_strdup_printf("Name of user data field can't be empty");
    return (*err == NULL);
  }

  g_strstrip(rec->udf_name);
  if (rec->udf_name[0] == 0) {
    *err = ws_strdup_printf("Name of user data field can't be empty");
    return (*err == NULL);
  }

  /* Check for invalid characters (to avoid asserting out when registering the field). */
  c = proto_check_field_name(rec->udf_name);
  if (c) {
    *err = ws_strdup_printf("Name of user data field can't contain '%c'", c);
    return (*err == NULL);
  }

  return (*err == NULL);
}

static void *
user_data_fields_copy_cb(void* n, const void* o, size_t size _U_)
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
UAT_HEX64_CB_DEF(user_data_fields, udf_mask, user_data_field_t)
UAT_CSTRING_CB_DEF(user_data_fields, udf_value_desc, user_data_field_t)

static guint64
calc_ett_key(guint32 offset, guint32 length)
{
  guint64 ret = (guint64)offset;
  return (ret << 32) ^ length;
}

/*
 * This creates a string for you that can be used as key for the hash table.
 * YOU must g_free that string!
 */
static gchar*
calc_hf_key(user_data_field_t udf)
{
  gchar* ret = NULL;
  ret = ws_strdup_printf("%i-%i-%" PRIu64 "-%s", udf.udf_offset, udf.udf_length, udf.udf_mask, udf.udf_name);
  return ret;
}

/*
 * Lookup the hf for the user data based on the key
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
 * Lookup the ett for the user data based on the key
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
 * clean up user data
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

  /* we cannot unregister ETTs, so we should try to limit the damage of an update */
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

      if (user_data_fields[i].udf_mask == 0 || user_data_fields[i].udf_length <= 0 || user_data_fields[i].udf_length>8) {
        dynamic_hf[i].hfinfo.name = g_strdup(user_data_fields[i].udf_name);
        dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("autosar-nm.user_data.%s", user_data_fields[i].udf_name);
        dynamic_hf[i].hfinfo.type = FT_BYTES;
        dynamic_hf[i].hfinfo.display = BASE_NONE;
        dynamic_hf[i].hfinfo.bitmask = 0;
        dynamic_hf[i].hfinfo.blurb = g_strdup(user_data_fields[i].udf_desc);
      } else {
        dynamic_hf[i].hfinfo.name = g_strdup(user_data_fields[i].udf_value_desc);
        dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("autosar-nm.user_data.%s.%s", user_data_fields[i].udf_name, user_data_fields[i].udf_value_desc);
        dynamic_hf[i].hfinfo.type = FT_BOOLEAN;
        dynamic_hf[i].hfinfo.display = 8 * (user_data_fields[i].udf_length);
        /* dynamic_hf[i].hfinfo.bitmask = 0; */
        dynamic_hf[i].hfinfo.blurb = g_strdup(user_data_fields[i].udf_value_desc);
      }

      tmp = calc_hf_key(user_data_fields[i]);
      g_hash_table_insert(user_data_fields_hash_hf, tmp, hf_id);

      /* generate etts for new fields only */
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

static gboolean
is_relevant_can_message(void *data)
{
    const struct can_info *can_info = (struct can_info *)data;
    DISSECTOR_ASSERT(can_info);

    if (can_info->id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) {
        /* Error and RTR frames are not for us. */
        return FALSE;
    }

    if ((can_info->id & CAN_EFF_MASK & g_autosar_nm_can_id_mask) != (g_autosar_nm_can_id & CAN_EFF_MASK & g_autosar_nm_can_id_mask)) {
        /* Id doesn't match. The frame is not for us. */
        return FALSE;
    }

    return TRUE;
}

static int
dissect_autosar_nm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_tree *autosar_nm_tree;
  proto_tree *autosar_nm_subtree = NULL;
  gchar *tmp = NULL;
  guint32 offset = 0;
  guint32 length = 0;
  guint32 msg_length = 0;
  guint32 ctrl_bit_vector = 0;
  guint32 src_node_id = 0;
  guint i = 0;
  int *hf_id;
  int *ett_id;

  static int * const control_bits_3_0[] = {
    &hf_autosar_nm_control_bit_vector_repeat_msg_req,
    &hf_autosar_nm_control_bit_vector_reserved1,
    &hf_autosar_nm_control_bit_vector_reserved2,
    &hf_autosar_nm_control_bit_vector_reserved3,
    &hf_autosar_nm_control_bit_vector_reserved4,
    &hf_autosar_nm_control_bit_vector_reserved5,
    &hf_autosar_nm_control_bit_vector_reserved6,
    &hf_autosar_nm_control_bit_vector_reserved7,
    NULL
  };

  static int * const control_bits_3_2[] = {
    &hf_autosar_nm_control_bit_vector_repeat_msg_req,
    &hf_autosar_nm_control_bit_vector_nm_coord_id,
    &hf_autosar_nm_control_bit_vector_nm_coord_sleep,
    &hf_autosar_nm_control_bit_vector_active_wakeup,
    &hf_autosar_nm_control_bit_vector_reserved5,
    &hf_autosar_nm_control_bit_vector_pni,
    &hf_autosar_nm_control_bit_vector_reserved7,
    NULL
  };

  static int * const control_bits_4_0[] = {
    &hf_autosar_nm_control_bit_vector_repeat_msg_req,
    &hf_autosar_nm_control_bit_vector_reserved1,
    &hf_autosar_nm_control_bit_vector_reserved2,
    &hf_autosar_nm_control_bit_vector_nm_coord_sleep,
    &hf_autosar_nm_control_bit_vector_reserved4,
    &hf_autosar_nm_control_bit_vector_reserved5,
    &hf_autosar_nm_control_bit_vector_reserved6,
    &hf_autosar_nm_control_bit_vector_reserved7,
    NULL
  };

  static int * const control_bits_4_1[] = {
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

  static int * const control_bits_20_11[] = {
    &hf_autosar_nm_control_bit_vector_repeat_msg_req,
    &hf_autosar_nm_control_bit_vector_pn_shutdown_request,
    &hf_autosar_nm_control_bit_vector_reserved2,
    &hf_autosar_nm_control_bit_vector_nm_coord_sleep,
    &hf_autosar_nm_control_bit_vector_active_wakeup,
    &hf_autosar_nm_control_bit_vector_pn_learning,
    &hf_autosar_nm_control_bit_vector_pni,
    &hf_autosar_nm_control_bit_vector_reserved7,
    NULL
  };

  col_set_str(pinfo->cinfo, COL_PROTOCOL, AUTOSAR_NM_NAME);
  col_clear(pinfo->cinfo, COL_INFO);

  msg_length = tvb_reported_length(tvb);

  ti = proto_tree_add_item(tree, proto_autosar_nm, tvb, 0, -1, ENC_NA);
  autosar_nm_tree = proto_item_add_subtree(ti, ett_autosar_nm);

  if (g_autosar_nm_pos_sni != byte_pos_off && g_autosar_nm_pos_sni < g_autosar_nm_pos_cbv) {
    proto_tree_add_item_ret_uint(autosar_nm_tree, hf_autosar_nm_source_node_identifier, tvb, g_autosar_nm_pos_sni, 1, ENC_BIG_ENDIAN, &src_node_id);
  }

  if (g_autosar_nm_pos_cbv != byte_pos_off) {

      switch (g_autosar_nm_cbv_version) {
      case autosar_3_0_or_newer:
        proto_tree_add_bitmask(autosar_nm_tree, tvb, g_autosar_nm_pos_cbv, hf_autosar_nm_control_bit_vector, ett_autosar_nm_cbv, control_bits_3_0, ENC_BIG_ENDIAN);
        break;
      case autosar_3_2:
          proto_tree_add_bitmask(autosar_nm_tree, tvb, g_autosar_nm_pos_cbv, hf_autosar_nm_control_bit_vector, ett_autosar_nm_cbv, control_bits_3_2, ENC_BIG_ENDIAN);
      break;
      case autosar_4_0:
          proto_tree_add_bitmask(autosar_nm_tree, tvb, g_autosar_nm_pos_cbv, hf_autosar_nm_control_bit_vector, ett_autosar_nm_cbv, control_bits_4_0, ENC_BIG_ENDIAN);
      break;
      case autosar_4_1_or_newer:
          proto_tree_add_bitmask(autosar_nm_tree, tvb, g_autosar_nm_pos_cbv, hf_autosar_nm_control_bit_vector, ett_autosar_nm_cbv, control_bits_4_1, ENC_BIG_ENDIAN);
      break;
      case autosar_20_11:
          proto_tree_add_bitmask(autosar_nm_tree, tvb, g_autosar_nm_pos_cbv, hf_autosar_nm_control_bit_vector, ett_autosar_nm_cbv, control_bits_20_11, ENC_BIG_ENDIAN);
      break;
      }

      ctrl_bit_vector = tvb_get_guint8(tvb, g_autosar_nm_pos_cbv);
  }

  if (g_autosar_nm_pos_sni != byte_pos_off && g_autosar_nm_pos_sni >= g_autosar_nm_pos_cbv) {
    proto_tree_add_item_ret_uint(autosar_nm_tree, hf_autosar_nm_source_node_identifier, tvb, g_autosar_nm_pos_sni, 1, ENC_BIG_ENDIAN, &src_node_id);
  }

  if (g_autosar_nm_pos_cbv > g_autosar_nm_pos_sni) {
      offset = g_autosar_nm_pos_cbv + 1;
  } else {
      /* This covers the case that both are turned off since -1 + 1 = 0 */
      offset = g_autosar_nm_pos_sni + 1;
  }

  col_add_fstr(pinfo->cinfo, COL_INFO, "NM (");
  if (g_autosar_nm_pos_cbv != byte_pos_off) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "CBV: 0x%02x", ctrl_bit_vector);
      proto_item_append_text(ti, ", Control Bit Vector: 0x%02x", ctrl_bit_vector);
      if (g_autosar_nm_pos_sni != byte_pos_off) {
          col_append_fstr(pinfo->cinfo, COL_INFO, ", SNI: 0x%02x", src_node_id);
          proto_item_append_text(ti, ", Source Node: %i", src_node_id);
      }
  } else {
      if (g_autosar_nm_pos_sni != byte_pos_off) {
          col_append_fstr(pinfo->cinfo, COL_INFO, "SNI: 0x%02x", src_node_id);
          proto_item_append_text(ti, ", Source Node: %i", src_node_id);
      }
  }
  col_append_fstr(pinfo->cinfo, COL_INFO, ")");

  /* now we need to process the user defined fields ... */
  ti = proto_tree_add_item(autosar_nm_tree, hf_autosar_nm_user_data, tvb, offset, msg_length - offset, ENC_NA);
  autosar_nm_tree = proto_item_add_subtree(ti, ett_autosar_nm_user_data);

  for (i = 0; i < num_user_data_fields; i++) {
    tmp = calc_hf_key(user_data_fields[i]);
    hf_id = get_hf_for_user_data(tmp);

    offset = user_data_fields[i].udf_offset;
    length = user_data_fields[i].udf_length;
    ett_id = (get_ett_for_user_data(offset, length));

    if (hf_id && msg_length >= length + offset) {
      if (user_data_fields[i].udf_mask == 0) {
        ti = proto_tree_add_item(autosar_nm_tree, *hf_id, tvb, offset, length, ENC_BIG_ENDIAN);
        if (ett_id == NULL) {
            autosar_nm_subtree = NULL;
        } else {
            autosar_nm_subtree = proto_item_add_subtree(ti, *ett_id);
        }
      } else {
        if (autosar_nm_subtree != NULL) {
          proto_tree_add_item(autosar_nm_subtree, *hf_id, tvb, offset, length, ENC_BIG_ENDIAN);
        }
      }
    } else {
      /* should we warn? */
    }

    g_free(tmp);
  }

  col_set_fence(pinfo->cinfo, COL_INFO);

  return msg_length;
}

static int
dissect_autosar_nm_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!is_relevant_can_message(data)) {
        return 0;
    }
    return dissect_autosar_nm(tvb, pinfo, tree, data);
}

static gboolean
dissect_autosar_nm_can_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!is_relevant_can_message(data)) {
        return FALSE;
    }
    dissect_autosar_nm(tvb, pinfo, tree, data);
    return TRUE;
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
    { &hf_autosar_nm_control_bit_vector_pn_shutdown_request,
    { "PN Shutdown Request", "autosar-nm.ctrl.pn_shutdown_request", FT_BOOLEAN, 8, TFS(&tfs_autosar_nm_control_pn_shutdown_req), 0x02, "The Partial Network Shutdown Request Bit", HFILL } },
    { &hf_autosar_nm_control_bit_vector_reserved2,
    { "Reserved Bit 2", "autosar-nm.ctrl.reserved2", FT_UINT8, BASE_DEC, NULL, 0x04, "The Reserved Bit 2", HFILL } },
    { &hf_autosar_nm_control_bit_vector_nm_coord_id,
    { "NM Coordinator ID", "autosar-nm.ctrl.nm_coord_id", FT_UINT8, BASE_DEC, NULL, 0x06, "The NM Coordinator Identifier", HFILL } },
    { &hf_autosar_nm_control_bit_vector_reserved3,
    { "Reserved Bit 3", "autosar-nm.ctrl.reserved3", FT_UINT8, BASE_DEC, NULL, 0x08, "The Reserved Bit 3", HFILL } },
    { &hf_autosar_nm_control_bit_vector_nm_coord_sleep,
    { "NM Coordinator Sleep Ready", "autosar-nm.ctrl.nm_coord_sleep", FT_BOOLEAN, 8, TFS(&tfs_autosar_nm_control_sleep_bit), 0x08, "NM Coordinator Sleep Ready Bit", HFILL } },
    { &hf_autosar_nm_control_bit_vector_reserved4,
    { "Reserved Bit 4", "autosar-nm.ctrl.reserved4", FT_UINT8, BASE_DEC, NULL, 0x10, "The Reserved Bit 4", HFILL } },
    { &hf_autosar_nm_control_bit_vector_active_wakeup,
    { "Active Wakeup", "autosar-nm.ctrl.active_wakeup", FT_BOOLEAN, 8, TFS(&tfs_autosar_nm_control_active_wakeup), 0x10, "Active Wakeup Bit", HFILL } },
    { &hf_autosar_nm_control_bit_vector_reserved5,
    { "Reserved Bit 5", "autosar-nm.ctrl.reserved5", FT_UINT8, BASE_DEC, NULL, 0x20, "The Reserved Bit 5", HFILL } },
    { &hf_autosar_nm_control_bit_vector_pn_learning,
    { "PN Learning", "autosar-nm.ctrl.pn_learning", FT_BOOLEAN, 8, TFS(&tfs_autosar_nm_control_pn_learning), 0x20, "The Partial Network Learning Bit", HFILL } },
    { &hf_autosar_nm_control_bit_vector_reserved6,
    { "Reserved Bit 6", "autosar-nm.ctrl.reserved6",FT_UINT8, BASE_DEC, NULL, 0x40, "Partial Network Information Bit", HFILL } },
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
    UAT_FLD_HEX64(user_data_fields, udf_mask, "User data mask", "Relevant bits of the user data field in the AUTOSAR-NM message (uint64)"),
    UAT_FLD_CSTRING(user_data_fields, udf_value_desc, "User data value", "Description what the masked bits mean"),
    UAT_END_FIELDS
  };

  /* Register the protocol name and description */
  proto_autosar_nm = proto_register_protocol("AUTOSAR Network Management", AUTOSAR_NM_NAME, "autosar-nm");
  proto_register_field_array(proto_autosar_nm, hf_autosar_nm, array_length(hf_autosar_nm));
  proto_register_alias(proto_autosar_nm, "nm");
  proto_register_subtree_array(ett, array_length(ett));

  /* Register configuration options */
  autosar_nm_module = prefs_register_protocol(proto_autosar_nm, proto_reg_handoff_autosar_nm);

  prefs_register_enum_preference(autosar_nm_module, "cbv_version",
      "Control Bit Vector version",
      "Define the standard version that applies to the CBV field",
      &g_autosar_nm_cbv_version, cbv_version_vals, FALSE);

  prefs_register_enum_preference(autosar_nm_module, "cbv_position",
    "Control Bit Vector position",
    "Make the NM dissector interpret this byte as Control Bit Vector (CBV)",
    &g_autosar_nm_pos_cbv, byte_position_vals, FALSE);

  prefs_register_enum_preference(autosar_nm_module, "sni_position",
    "Source Node Identifier position",
    "Make the NM dissector interpret this byte as Source Node Identifier (SNI)",
    &g_autosar_nm_pos_sni, byte_position_vals, FALSE);

  /* UAT */
  user_data_fields_uat = uat_new("NM User Data Fields Table",
    sizeof(user_data_field_t),        /* record size           */
    "NM_user_data_fields",            /* filename              */
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

  prefs_register_uint_preference(
      autosar_nm_module, "can_id",
      "AUTOSAR NM CAN id",
      "Identifier that is used to filter packets that should be dissected. "
      "Set bit 31 when defining an extended id. "
      "(works with the mask defined below)",
      16, &g_autosar_nm_can_id);

  prefs_register_uint_preference(
      autosar_nm_module, "can_id_mask",
      "AUTOSAR NM CAN id mask",
      "Mask applied to CAN identifiers when decoding whether a packet should dissected. "
      "Use 0xFFFFFFFF mask to require exact match.",
      16, &g_autosar_nm_can_id_mask);

  range_convert_str(wmem_epan_scope(), &g_autosar_nm_pdus, "", 0xffffffff);
  prefs_register_range_preference(autosar_nm_module, "pdu_transport.ids", "AUTOSAR NM PDU IDs",
      "PDU Transport IDs.",
      &g_autosar_nm_pdus, 0xffffffff);

  range_convert_str(wmem_epan_scope(), &g_autosar_nm_ipdum_pdus, "", 0xffffffff);
  prefs_register_range_preference(autosar_nm_module, "ipdum.pdu.id", "AUTOSAR I-PduM PDU IDs",
      "I-PDU Multiplexer PDU IDs.",
      &g_autosar_nm_ipdum_pdus, 0xffffffff);
}

void proto_reg_handoff_autosar_nm(void)
{
  static gboolean initialized = FALSE;

  if (!initialized) {
      nm_handle = create_dissector_handle(dissect_autosar_nm, proto_autosar_nm);
      dissector_add_for_decode_as_with_preference("udp.port", nm_handle);

      nm_handle_can = create_dissector_handle(dissect_autosar_nm_can, proto_autosar_nm);
      dissector_add_for_decode_as("can.subdissector", nm_handle_can);

      /* heuristics default on since they do nothing without IDs being configured */
      heur_dissector_add("can", dissect_autosar_nm_can_heur, "AUTOSAR NM over CAN", "autosar_nm_can_heur", proto_autosar_nm, HEURISTIC_ENABLE);

      initialized = TRUE;
  } else {
      dissector_delete_all("pdu_transport.id", nm_handle);
      dissector_delete_all("ipdum.pdu.id", nm_handle);
  }

  dissector_add_uint_range("pdu_transport.id", g_autosar_nm_pdus, nm_handle);
  dissector_add_uint_range("ipdum.pdu.id", g_autosar_nm_ipdum_pdus, nm_handle);
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
